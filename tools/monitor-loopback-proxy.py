#!/usr/bin/env python3
"""Local-only monitor browser proxy over authenticated SSH stdio forwarding.

No remote configuration, shell, credentials store, access log, or POST retries.
Start explicitly on a trusted workstation; existing SSH host keys must be known.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import os
import re
import selectors
import subprocess
import threading
import time
from urllib.parse import urlsplit

AUTHORITY = "127.0.0.1:8080"
ORIGIN = "http://" + AUTHORITY
MAX_BODY = 65536
MAX_HEADERS = 16384
MAX_RESPONSE = 16 * 1024 * 1024
TIMEOUT = 30
CONTROLS = {
    "/monitor/control/ztp-monitor": "ZTPMonitorControl",
    "/monitor/control/switch-collection": "SwitchCollectionControl",
    "/monitor/control/manual-ztp": "ManualZTPControl",
}


class Rejected(Exception):
    """A local rejection whose details must never contain request data."""


@dataclass(frozen=True)
class Config:
    service_ip: str
    bastion: str
    ssh_port: int = 22

    def __post_init__(self):
        address = ipaddress.IPv4Address(self.service_ip)
        if (str(address) != self.service_ip or address.is_loopback or address.is_unspecified
                or address.is_multicast or int(address) == 0xffffffff):
            raise ValueError("service-ip must be a canonical unicast service IPv4")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9.-]*", self.bastion):
            raise ValueError("bastion must be an explicit safe user@hostname")
        if type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535:
            raise ValueError("invalid SSH port")

    def ssh_argv(self):
        return ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "ConnectTimeout=10", "-p", str(self.ssh_port),
                "-W", self.service_ip + ":80", self.bastion]


def validate_request(method, target, pairs):
    if method not in {"GET", "HEAD", "POST"}:
        raise Rejected("unsupported method")
    if (len(target) > 2048 or not target.startswith("/") or target.startswith("//")
            or any(ord(c) < 33 or ord(c) > 126 for c in target) or "\\" in target):
        raise Rejected("invalid target")
    parsed = urlsplit(target)
    if parsed.fragment or parsed.scheme or parsed.netloc:
        raise Rejected("invalid target")
    diagram_prefix = "/monitor/99-output-p2p/"
    diagram_basename = (
        parsed.path[len(diagram_prefix):]
        if parsed.path.startswith(diagram_prefix) else ""
    )
    # The monitor page quotes real P2P filenames, including spaces.  Decode
    # only its canonical space escape; every other percent escape (including
    # encoded separators, dot segments, or a second encoding layer) is denied.
    diagram = (
        method in {"GET", "HEAD"}
        and "%" not in diagram_basename.replace("%20", "")
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_. -]{0,159}\.(?:html|xlsx)",
            diagram_basename.replace("%20", " "),
        ) is not None
    )
    if parsed.path not in {*CONTROLS, "/monitor/monitor.html"} and not diagram:
        raise Rejected("unsupported path")
    fields = {}
    total = 0
    for name, value in pairs:
        total += len(name) + len(value) + 4
        key = name.lower()
        if (total > MAX_HEADERS or key in fields or not re.fullmatch(r"[A-Za-z0-9-]+", name)
                or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise Rejected("invalid headers")
        if key in {"transfer-encoding", "expect", "upgrade", "forwarded", "proxy-authorization"} or key.startswith("x-forwarded-"):
            raise Rejected("unsupported headers")
        fields[key] = value
    if fields.get("host") != AUTHORITY:
        raise Rejected("invalid local authority")
    length = fields.get("content-length", "0")
    if not re.fullmatch(r"0|[1-9][0-9]{0,5}", length) or int(length) > MAX_BODY:
        raise Rejected("invalid body length")
    size = int(length)
    if method == "POST":
        if (parsed.path not in CONTROLS or parsed.query
                or fields.get("origin") != ORIGIN
                or fields.get("sec-fetch-site") != "same-origin"
                or fields.get("x-requested-with") != CONTROLS[parsed.path]
                or fields.get("content-type") != "application/x-www-form-urlencoded"
                or "content-length" not in fields or not size):
            raise Rejected("local POST origin or framing rejected")
        if not fields.get("authorization", "").startswith("Basic "):
            raise Rejected("Basic authentication required")
    elif size or fields.get("sec-fetch-site", "none") not in {"same-origin", "none"}:
        raise Rejected("invalid read request")
    if "authorization" in fields:
        try:
            auth = fields["authorization"]
            if not auth.startswith("Basic ") or len(auth) > 4096:
                raise ValueError()
            decoded = base64.b64decode(auth[6:], validate=True)
            if b":" not in decoded or b"\x00" in decoded or b"\r" in decoded or b"\n" in decoded:
                raise ValueError()
        except ValueError as exc:
            raise Rejected("invalid authentication header") from exc
    return fields, size


def upstream_request(config, method, target, fields, body):
    pairs = [("Host", config.service_ip), ("Connection", "close"), ("Accept-Encoding", "identity")]
    if "authorization" in fields:
        pairs.append(("Authorization", fields["authorization"]))
    if method == "POST":
        pairs.extend([("Origin", "http://" + config.service_ip), ("Sec-Fetch-Site", "same-origin"),
                      ("X-Requested-With", fields["x-requested-with"]),
                      ("Content-Type", "application/x-www-form-urlencoded"), ("Content-Length", str(len(body)))])
    return (method + " " + target + " HTTP/1.1\r\n" + "".join(name + ": " + value + "\r\n" for name, value in pairs) + "\r\n").encode("ascii") + body


def ssh_exchange(config, request):
    """One bounded child, with no shell/retry and no stderr/credential logging."""
    process = subprocess.Popen(config.ssh_argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    offset = 0
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected("upstream timeout")
                for key, _event in selector.select(remaining):
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), request[offset:offset + 8192])
                        if offset == len(request):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_RESPONSE + MAX_HEADERS:
                                raise Rejected("upstream response too large")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise Rejected("upstream transport failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout):
            if stream and not stream.closed:
                stream.close()


class MemorySocket:
    def __init__(self, payload):
        self.payload = payload

    def makefile(self, *_args, **_kwargs):
        return io.BytesIO(self.payload)


def parse_response(raw, method):
    if len(raw) > MAX_RESPONSE + MAX_HEADERS or b"\r\n\r\n" not in raw:
        raise Rejected("invalid upstream response")
    header = raw.split(b"\r\n\r\n", 1)[0]
    if len(header) > MAX_HEADERS:
        raise Rejected("upstream headers too large")
    if not re.fullmatch(rb"HTTP/1\.[01] [245][0-9]{2}(?: [\x20-\x7e]*)?", header.split(b"\r\n", 1)[0]):
        raise Rejected("upstream status or interim response refused")
    for line in header.split(b"\r\n")[1:]:
        if not re.fullmatch(rb"[A-Za-z0-9-]+:[\x20-\x7e]*", line):
            raise Rejected("invalid upstream header line")
    try:
        response = http.client.HTTPResponse(MemorySocket(raw), method=method)
        response.begin()
        seen = set()
        for key, value in response.getheaders():
            lowered = key.lower()
            if lowered in seen or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise Rejected("ambiguous upstream headers")
            seen.add(lowered)
        if response.status < 200 or 300 <= response.status < 400:
            raise Rejected("upstream redirect or interim response refused")
        if "transfer-encoding" in seen and "content-length" in seen:
            raise Rejected("ambiguous upstream framing")
        if response.getheader("Content-Encoding", "identity") != "identity":
            raise Rejected("unsupported upstream encoding")
        if response.getheader("Transfer-Encoding", "chunked") != "chunked":
            raise Rejected("unsupported upstream framing")
        if response.chunked and method != "HEAD":
            # Validate the complete buffered wire framing; HTTPResponse alone
            # ignores extra bytes after the last chunk and tolerates short trailers.
            wire = raw.split(b"\r\n\r\n", 1)[1]
            offset = 0
            while True:
                end = wire.find(b"\r\n", offset)
                token = wire[offset:end] if end >= 0 else b""
                if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", token):
                    raise Rejected("invalid upstream chunk")
                size = int(token, 16)
                offset = end + 2
                if not size:
                    if wire[offset:] != b"\r\n":
                        raise Rejected("incomplete or trailing chunked response")
                    break
                if size > MAX_RESPONSE or wire[offset + size:offset + size + 2] != b"\r\n":
                    raise Rejected("incomplete upstream chunk")
                offset += size + 2
        body = response.read(MAX_RESPONSE + 1)
        declared = response.getheader("Content-Length")
        if len(body) > MAX_RESPONSE or (method != "HEAD" and declared is not None and (not declared.isdigit() or len(body) != int(declared))):
            raise Rejected("incomplete upstream response")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_RESPONSE):
            raise Rejected("invalid upstream length")
        if method != "HEAD" and declared is not None and len(raw.split(b"\r\n\r\n", 1)[1]) != int(declared):
            raise Rejected("trailing upstream bytes")
        if method != "HEAD" and not response.chunked and declared is None:
            raise Rejected("unframed upstream response")
        fields = {"Content-Type": response.getheader("Content-Type", "application/octet-stream")}
        challenge = response.getheader("WWW-Authenticate")
        if response.status == 401 and challenge and challenge.startswith("Basic "):
            fields["WWW-Authenticate"] = challenge
        return response.status, fields, body
    except (http.client.HTTPException, ValueError, OSError) as exc:
        raise Rejected("invalid upstream response") from exc


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, config, address=("127.0.0.1", 8080)):
        if address[0] != "127.0.0.1":
            raise ValueError("only loopback binding is supported")
        self.config = config
        self.slots = threading.BoundedSemaphore(8)
        self.exchange = ssh_exchange
        super().__init__(address, Handler)

    def handle_error(self, *_args):
        pass  # Never traceback request/authentication data.


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(TIMEOUT)

    def log_message(self, *_args):
        pass

    def parse_request(self):
        if not super().parse_request():
            return False
        tokens = self.raw_requestline.rstrip(b"\r\n").split(b" ")
        if (len(tokens) != 3 or tokens[1].decode("iso-8859-1") != self.path
                or self.request_version not in {"HTTP/1.0", "HTTP/1.1"}):
            self.fail(400, "请求未发送：请求行不规范。")
            return False
        return True

    def handle_expect_100(self):
        self.fail(400, "请求未发送：不支持 Expect。")
        return False

    def reply(self, status, fields, body):
        self.close_connection = True
        self.send_response(status)
        for name, value in fields.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def fail(self, status, message):
        self.reply(status, {"Content-Type": "application/json; charset=utf-8"},
                   json.dumps({"error": message}, ensure_ascii=False).encode("utf-8"))

    def handle_proxy(self):
        try:
            fields, size = validate_request(self.command, self.path, self.headers.raw_items())
            body = self.rfile.read(size)
            if len(body) != size:
                raise Rejected("incomplete body")
        except (Rejected, OSError, ValueError):
            self.fail(400, "请求未发送：本机代理拒绝请求来源、路径、头部或长度。")
            return
        if not self.server.slots.acquire(blocking=False):
            self.fail(503, "请求未发送：本机代理繁忙。")
            return
        try:
            request = upstream_request(self.server.config, self.command, self.path, fields, body)
            raw = self.server.exchange(self.server.config, request)
            status, headers, payload = parse_response(raw, self.command)
            self.reply(status, headers, payload)
        except (Rejected, OSError, subprocess.SubprocessError):
            self.fail(502, "提交结果未知：上游响应未完整验证；先查看状态，不要自动重试。"
                      if self.command == "POST" else "状态读取失败：SSH 或上游响应未通过完整性检查。")
        finally:
            self.server.slots.release()

    do_GET = handle_proxy
    do_HEAD = handle_proxy
    do_POST = handle_proxy


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-ip", required=True, help="fixed target service IPv4 (port 80)")
    parser.add_argument("--bastion", required=True, help="existing trusted SSH user@hostname")
    parser.add_argument("--ssh-port", type=int, default=22)
    args = parser.parse_args(argv)
    try:
        config = Config(args.service_ip, args.bastion, args.ssh_port)
        server = ProxyServer(config)
    except (ValueError, OSError):
        parser.error("invalid configuration or 127.0.0.1:8080 is unavailable")
    print("Local monitor proxy: http://127.0.0.1:8080/monitor/monitor.html (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
