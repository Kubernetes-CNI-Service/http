"""Real local HTTP proxy → unchanged CGI guard, with SSH transport fixtures."""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import http.client
from importlib.machinery import SourceFileLoader
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import threading
import tempfile
import tarfile
import unittest
from unittest import mock

from test_cases.test_monitor_loopback_proxy import PROXY, ROOT
from test_cases.module_loader import load_script

MONITOR_PAGE = load_script("monitor_loopback_proxy_page", ROOT / "monitor/generate-monitor-html.py")


def load_cgi(filename):
    loader = SourceFileLoader("proxy_workflow_" + filename.replace("-", "_"), str(ROOT / "monitor" / filename))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@contextmanager
def local_proxy(exchange):
    server = PROXY.ProxyServer(PROXY.Config("192.0.2.40", "user@bastion.example", 29789), ("127.0.0.1", 0))
    server.exchange = exchange
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


class LoopbackProxyWorkflowTests(unittest.TestCase):
    def test_generated_spaced_diagram_link_reaches_read_only_proxy_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "VisionBay Staging P2P v1.3-lldpq.html").write_text(
                "<html>fixture</html>", encoding="utf-8"
            )
            diagram = MONITOR_PAGE.load_latest_diagram(directory, "*-lldpq.html")
        self.assertEqual(
            "99-output-p2p/VisionBay%20Staging%20P2P%20v1.3-lldpq.html",
            diagram["href"],
        )
        called = []
        def exchange(_config, request):
            called.append(request.split(b"\r\n", 1)[0])
            return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<html>fixture</html>"
        with local_proxy(exchange) as port:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", "/monitor/" + diagram["href"], headers={
                "Host": PROXY.AUTHORITY, "Sec-Fetch-Site": "same-origin",
            })
            response = connection.getresponse()
            self.assertEqual(200, response.status)
            self.assertEqual(b"<html>fixture</html>", response.read())
            connection.close()
        self.assertEqual(
            [b"GET /monitor/99-output-p2p/VisionBay%20Staging%20P2P%20v1.3-lldpq.html HTTP/1.1"],
            called,
        )

    def test_workstation_proxy_excluded_from_upload_and_sync(self):
        from test_cases.test_upload_package_contract import package
        from test_cases.test_project_contracts import load_module
        sync = load_module("proxy_sync_boundary", ROOT / "tools/sync-code.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / "fixture"
            project.mkdir(parents=True)
            (root / "requirements-container-top-level.lock").write_text("fixture==1\n")
            (root / "tools/lldp-analyze-tool").mkdir(parents=True)
            for name in ("monitor-loopback-proxy.py", "control-auth.py"):
                (root / "tools" / name).write_text("# synthetic source\n")
            with mock.patch.multiple(package, ROOT=root, DAY0=root / "DAY0-Prepare"), mock.patch.object(package, "setup_managed_links", return_value=set()):
                selector = package.PackageFilter(project, root / "out.tar.gz", include_images=False,
                    include_apps=False, include_firmware=False, max_file_size=1024, day0_all=False)
                self.assertIsNone(selector(tarfile.TarInfo("./tools/monitor-loopback-proxy.py")))
                self.assertIsNotNone(selector(tarfile.TarInfo("./tools/control-auth.py")))
            with mock.patch.multiple(sync, ROOT=root, DAY0=root / "DAY0-Prepare", CODE_DIRECTORIES=("tools",), DAY0_CODE_DIRECTORIES=()), mock.patch.object(sync, "package_setup_managed_links", return_value=set()):
                jobs = sync.build_jobs(project, "/synthetic/remote")
                sources = {str(source.relative_to(root)) for job in jobs for source in job.sources}
                self.assertNotIn("tools/monitor-loopback-proxy.py", sources)
                self.assertIn("tools/control-auth.py", sources)

    def test_all_three_real_guards_accept_forwarded_authority_not_raw_localhost(self):
        called = []
        cgis = {
            "/monitor/control/ztp-monitor": load_cgi("ztp-monitor-control.cgi"),
            "/monitor/control/switch-collection": load_cgi("switch-collection-control.cgi"),
            "/monitor/control/manual-ztp": load_cgi("manual-ztp-control.cgi"),
        }
        def exchange(_config, request):
            headers = request.split(b"\r\n\r\n", 1)[0].decode("ascii").split("\r\n")
            target = headers[0].split()[1]
            values = dict(line.split(": ", 1) for line in headers[1:])
            called.append(target)
            environment = {
                "SERVER_ADDR": "192.0.2.40", "SERVER_PORT": "80", "CONTROL_SERVICE_PORT": "80",
                "REQUEST_SCHEME": "http", "HTTPS": "off", "HTTP_HOST": values["Host"],
                "HTTP_ORIGIN": values["Origin"], "HTTP_SEC_FETCH_SITE": values["Sec-Fetch-Site"],
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                self.assertEqual((True, ""), cgis[target].post_control_guard())
                os.environ["HTTP_HOST"] = "127.0.0.1:8080"
                os.environ["HTTP_ORIGIN"] = "http://127.0.0.1:8080"
                self.assertFalse(cgis[target].post_control_guard()[0])
            self.assertEqual("Basic dXNlcjpzZWNyZXQ=", values["Authorization"])
            return b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
        captured_out, captured_err = io.StringIO(), io.StringIO()
        with redirect_stdout(captured_out), redirect_stderr(captured_err), local_proxy(exchange) as port:
            for path, xrw in PROXY.CONTROLS.items():
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", path, "action=preview", headers={
                    "Host": PROXY.AUTHORITY, "Origin": PROXY.ORIGIN, "Sec-Fetch-Site": "same-origin",
                    "X-Requested-With": xrw, "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Basic dXNlcjpzZWNyZXQ=",
                })
                response = connection.getresponse()
                self.assertEqual(200, response.status)
                self.assertEqual(b"{}", response.read())
                connection.close()
        self.assertEqual(3, len(called))
        self.assertEqual("", captured_out.getvalue())
        self.assertEqual("", captured_err.getvalue())

    def test_rejected_request_has_zero_transport_and_partial_post_is_not_retried(self):
        calls = []
        def exchange(_config, request):
            calls.append(request)
            return b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial'
        with local_proxy(exchange) as port:
            headers = {"Host": PROXY.AUTHORITY, "Origin": "http://evil.example",
                       "Sec-Fetch-Site": "same-origin", "X-Requested-With": "ManualZTPControl",
                       "Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic dXNlcjpzZWNyZXQ="}
            for valid in (False, True):
                if valid:
                    headers["Origin"] = PROXY.ORIGIN
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/monitor/control/manual-ztp", "action=preview", headers)
                response = connection.getresponse()
                self.assertEqual(502 if valid else 400, response.status)
                body = response.read().decode()
                self.assertIn("提交结果未知" if valid else "请求未发送", body)
                self.assertNotIn("secret", body)
                connection.close()
        self.assertEqual(1, len(calls))

    def test_malformed_basic_post_returns_fixed_local_error_without_transport_or_echo(self):
        calls = []
        def exchange(_config, request):
            calls.append(request)
            return b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        with local_proxy(exchange) as port:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("POST", "/monitor/control/manual-ztp", "action=preview", headers={
                "Host": PROXY.AUTHORITY, "Origin": PROXY.ORIGIN,
                "Sec-Fetch-Site": "same-origin", "X-Requested-With": "ManualZTPControl",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic !secret!",
            })
            response = connection.getresponse()
            self.assertEqual(400, response.status)
            body = response.read().decode("utf-8")
            self.assertIn("请求未发送", body)
            self.assertNotIn("secret", body)
            connection.close()
        self.assertEqual([], calls)

    def test_transport_uses_one_bounded_child_with_no_shell_or_stderr_capture(self):
        original = subprocess.Popen
        calls = []
        def local_child(argv, **kwargs):
            calls.append((argv, kwargs))
            return original([sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\n{}')"], **kwargs)
        with mock.patch.object(PROXY.subprocess, "Popen", side_effect=local_child):
            raw = PROXY.ssh_exchange(PROXY.Config("192.0.2.40", "user@bastion.example"), b"fixture request")
        self.assertEqual(b"{}", PROXY.parse_response(raw, "GET")[2])
        self.assertEqual(1, len(calls))
        self.assertNotIn("shell", calls[0][1])
        self.assertEqual(subprocess.DEVNULL, calls[0][1]["stderr"])
