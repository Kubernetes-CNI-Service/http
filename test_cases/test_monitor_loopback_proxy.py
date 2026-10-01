"""Independent request/response and SSH transport contracts for local proxy."""
import base64
import unittest
from test_cases.module_loader import load_script
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY = load_script("monitor_loopback_proxy_direct", ROOT / "tools/monitor-loopback-proxy.py")


class LoopbackProxyTests(unittest.TestCase):
    def setUp(self):
        self.config = PROXY.Config("192.0.2.40", "operator@bastion.example", 29789)
        self.headers = [
            ("Host", "127.0.0.1:8080"), ("Origin", "http://127.0.0.1:8080"),
            ("Sec-Fetch-Site", "same-origin"), ("X-Requested-With", "ManualZTPControl"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", "14"), ("Authorization", "Basic " + base64.b64encode(b"user:secret").decode()),
        ]

    def test_exact_authority_and_fixed_ssh_target(self):
        headers, size = PROXY.validate_request("POST", "/monitor/control/manual-ztp", self.headers)
        self.assertEqual(14, size)
        request = PROXY.upstream_request(self.config, "POST", "/monitor/control/manual-ztp", headers, b"action=preview")
        self.assertIn(b"Host: 192.0.2.40\r\n", request)
        self.assertIn(b"Origin: http://192.0.2.40\r\n", request)
        self.assertNotIn(b"127.0.0.1", request)
        argv = self.config.ssh_argv()
        self.assertEqual("/usr/bin/ssh", argv[0])
        self.assertEqual(["-W", "192.0.2.40:80", "operator@bastion.example"], argv[-3:])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ControlPath=none", argv)

    def test_invalid_authorities_and_framing_never_forward(self):
        for key, bad in (("Host", "localhost:8080"), ("Origin", "null"),
                         ("Origin", "http://evil.example"), ("Sec-Fetch-Site", "cross-site"),
                         ("X-Requested-With", "wrong"), ("Content-Length", "-1"),
                         ("Content-Length", "99999999"), ("Content-Type", "application/json")):
            with self.subTest(key=key, value=bad):
                headers = [(name, bad if name == key else value) for name, value in self.headers]
                with self.assertRaises(PROXY.Rejected):
                    PROXY.validate_request("POST", "/monitor/control/manual-ztp", headers)
        for extra in (("Host", "127.0.0.1:8080"), ("Transfer-Encoding", "chunked"),
                      ("Expect", "100-continue"), ("X-Forwarded-Host", "192.0.2.40"),
                      ("Forwarded", "for=127.0.0.1"), ("Upgrade", "websocket")):
            with self.subTest(extra=extra), self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("POST", "/monitor/control/manual-ztp", self.headers + [extra])
        for path in ("http://other/monitor/control/manual-ztp", "/monitor/control/manual-ztp?x=1",
                     "/monitor/control/%6danual-ztp", "/monitor/../secret", "/cgi-bin/manual-ztp-control"):
            with self.subTest(path=path), self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("POST", path, self.headers)

    def test_status_get_preserves_basic_challenge_and_no_post_requirement(self):
        headers, size = PROXY.validate_request("GET", "/monitor/control/manual-ztp", [("Host", "127.0.0.1:8080")])
        self.assertEqual(0, size)
        self.assertNotIn("authorization", headers)
        status, fields, body = PROXY.parse_response(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="monitor"\r\nContent-Length: 0\r\n\r\n', "GET")
        self.assertEqual(401, status)
        self.assertEqual('Basic realm="monitor"', fields["WWW-Authenticate"])
        self.assertEqual(b"", body)

    def test_malformed_basic_encoding_is_locally_rejected(self):
        for authorization in ("Basic !secret!", "Basic dXNlcj"):
            with self.subTest(authorization=authorization), self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("POST", "/monitor/control/manual-ztp", [
                    (name, authorization if name == "Authorization" else value)
                    for name, value in self.headers
                ])

    def test_partial_oversized_redirect_and_ambiguous_responses_rejected(self):
        for raw in (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                    b"HTTP/1.1 302 Found\r\nLocation: http://other/\r\nContent-Length: 0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nx"):
            with self.subTest(raw=raw), self.assertRaises(PROXY.Rejected):
                PROXY.parse_response(raw, "POST")

    def test_service_and_bastion_are_not_option_or_url_inputs(self):
        for service, bastion, port in (("127.0.0.1", "u@host", 22), ("192.0.2.40", "-oProxyCommand=x", 22),
                                       ("192.0.2.40", "u@host;id", 22), ("0.0.0.0", "u@host", 22),
                                       ("192.0.2.40", "u@host", 0)):
            with self.subTest(service=service, bastion=bastion), self.assertRaises(ValueError):
                PROXY.Config(service, bastion, port)

    def test_read_only_diagram_paths_are_narrow(self):
        for path in ("/monitor/99-output-p2p/p2p-air.html", "/monitor/99-output-p2p/p2p-air.xlsx"):
            PROXY.validate_request("GET", path, [("Host", "127.0.0.1:8080")])
            with self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("POST", path, self.headers)
        for path in ("/monitor/99-output-p2p/.secret.html", "/monitor/99-output-p2p/a/b.html",
                     "/monitor/99-output-p2p/../a.html", "/monitor/99-output-p2p/a.py"):
            with self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("GET", path, [("Host", "127.0.0.1:8080")])

    def test_quoted_spaces_in_diagram_basename_allow_only_canonical_space_escapes(self):
        valid = "/monitor/99-output-p2p/VisionBay%20Staging%20P2P%20v1.3-lldpq.html"
        PROXY.validate_request("GET", valid, [("Host", PROXY.AUTHORITY)])
        PROXY.validate_request("HEAD", valid, [("Host", PROXY.AUTHORITY)])
        with self.assertRaises(PROXY.Rejected):
            PROXY.validate_request("POST", valid, self.headers)
        for path in (
            "/monitor/99-output-p2p/a%2Fb.html",
            "/monitor/99-output-p2p/a%5Cb.html",
            "/monitor/99-output-p2p/%2e%2e/a.html",
            "/monitor/99-output-p2p/%252e%252e.html",
            "/monitor/99-output-p2p/a%2520b.html",
            "/monitor/99-output-p2p/a%2Eb.html",
            "/monitor/99-output-p2p/a%20b.py",
            "/monitor/99-output-p2p/../a%20b.html",
            "/monitor/control/manual-ztp%20",
        ):
            with self.subTest(path=path), self.assertRaises(PROXY.Rejected):
                PROXY.validate_request("GET", path, [("Host", PROXY.AUTHORITY)])

    def test_chunked_complete_and_ambiguous_tail(self):
        prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertEqual(b"{}", PROXY.parse_response(prefix + b"2\r\n{}\r\n0\r\n\r\n", "POST")[2])
        for raw in (prefix + b"2\r\n{}\r\n0\r\n\r\nextra",
                    prefix + b"2\r\n{}\r\n0\r\n",
                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
            with self.assertRaises(PROXY.Rejected):
                PROXY.parse_response(raw, "POST")
