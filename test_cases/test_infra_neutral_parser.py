#!/usr/bin/env python3
"""v3.1.2 WP-2 (D-3): one strict reader of infra's neutral DNS/NTP/TIMEZONE defaults, in infra/ubuntu24_host.py.

Every expected value is written from the sources below, never read back from the implementation:
- docs/deployment/README.md (Native infra 中性值): infra/infra-neutral.conf is the one authority, strict and
  inert KEY=VALUE data.  The value rules both infra readers already share, and the kept infra-setup.sh records
  (its neutral block from neutral_config= to the "incomplete or invalid" check): exactly DNS, NTP, TIMEZONE in
  this order; DNS one dotted-quad IPv4 address without leading zeros; NTP one host name; TIMEZONE a safe
  IANA name -- never "../etc".
- v3.1.2 详细工作指导 §3.2 O2 (owner 2026-11-07「同意你在v3.1.2里的默认建议」, http dev 转述): strict -- a
  last line without its newline and CRLF line ends are both refused.  Before this version deploy_infra.py took
  both and infra-setup.py took CRLF.
- 详细工作指导 WP-2: one pure function ubuntu24_host.parse_neutral_defaults(text) -> (dns, ntp, timezone) that
  raises HostConfigError; deploy_infra.load_neutral_defaults keeps its name and turns every refusal, a file that
  is not UTF-8 included, into DeployError; infra-setup.py keeps exit 1 and its four ERROR texts (the existing
  test_infra_setup_py.py::InfraSetupPyInputs::test_invalid_neutral_defaults_fail).
- 计划表原则 7「一个模块」and test_infra_setup_py.py::…test_overlapping_duties_have_no_second_implementation:
  deploy_infra.py and infra-setup.py reach the same verdict on every input.
- The kept infra-setup.sh is a cross-check only, run as test_infra_setup_py.RecordedShellContractMatchesKeptScript
  runs it, never the source of an expectation: the strict reader agrees with it except where O2 is deliberately
  stricter (SHELL_LAXER: `while read` drops a last line that has no newline).
Samples use 192.0.2.x and example.test only.
"""

from __future__ import annotations

from contextlib import redirect_stderr
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from test_cases import test_infra_setup_py as INFRA_SETUP_TESTS
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
HOST = load_script("infra_neutral_parser_host", ROOT / "infra/ubuntu24_host.py")
DEPLOY = load_script("infra_neutral_parser_deploy", ROOT / "infra/deploy_infra.py")
SETUP_PY = load_script("infra_neutral_parser_setup_py", ROOT / "infra/infra-setup.py")
SHELL = ROOT / "infra/infra-setup.sh"

CANONICAL = "DNS=192.0.2.53\nNTP=ntp.example.test\nTIMEZONE=Etc/UTC\n"
ACCEPTED = {
    "canonical": (CANONICAL, ("192.0.2.53", "ntp.example.test", "Etc/UTC")),
    "address as NTP, nested zone": (
        "DNS=192.0.2.1\nNTP=192.0.2.123\nTIMEZONE=America/Argentina/Buenos_Aires\n",
        ("192.0.2.1", "192.0.2.123", "America/Argentina/Buenos_Aires"),
    ),
}
LINE_ENDS = {   # O2
    "missing final newline": CANONICAL[:-1],
    "CRLF": CANONICAL.replace("\n", "\r\n"),
    "CRLF on the last line only": CANONICAL[:-1] + "\r\n",
    "unterminated extra line": CANONICAL + "EXTRA=x",
}
LAYOUT = {      # strict KEY=VALUE, the three keys in order
    "empty file": "",
    "comment line": "# neutral services\n" + CANONICAL,
    "blank line at the end": CANONICAL + "\n",
    "blank line first": "\n" + CANONICAL,
    "reordered": "NTP=ntp.example.test\nDNS=192.0.2.53\nTIMEZONE=Etc/UTC\n",
    "lower-case key": CANONICAL.replace("DNS=", "dns="),
    "spaces around the separator": CANONICAL.replace("DNS=", "DNS = "),
}
KEYS = {
    "duplicate key": "DNS=192.0.2.53\nDNS=192.0.2.54\nTIMEZONE=Etc/UTC\n",
    "extra key": CANONICAL + "SYSLOG=192.0.2.10\n",
    "missing key": "DNS=192.0.2.53\nNTP=ntp.example.test\n",
    "empty value": CANONICAL.replace("TIMEZONE=Etc/UTC", "TIMEZONE="),
}
VALUES = {
    "DNS host name": CANONICAL.replace("DNS=192.0.2.53", "DNS=dns.example.test"),
    "DNS octet above 255": CANONICAL.replace("DNS=192.0.2.53", "DNS=192.0.2.256"),
    "DNS leading zero": CANONICAL.replace("DNS=192.0.2.53", "DNS=192.0.2.053"),
    "DNS two addresses": CANONICAL.replace("DNS=192.0.2.53", "DNS=192.0.2.53 192.0.2.54"),
    "DNS IPv6": CANONICAL.replace("DNS=192.0.2.53", "DNS=2001:db8::53"),
    "NTP not a host name": CANONICAL.replace("NTP=ntp.example.test", "NTP=ntp/example.test"),
    "NTP command substitution": CANONICAL.replace("NTP=ntp.example.test", "NTP=$(id)"),
    "zone traversal": CANONICAL.replace("TIMEZONE=Etc/UTC", "TIMEZONE=../etc"),
    "zone absolute path": CANONICAL.replace("TIMEZONE=Etc/UTC", "TIMEZONE=/etc/localtime"),
    "zone empty component": CANONICAL.replace("TIMEZONE=Etc/UTC", "TIMEZONE=Etc//UTC"),
}
NOT_UTF8 = b"DNS=192.0.2.53\nNTP=ntp.example.test\nTIMEZONE=Etc/\xffUTC\n"
REFUSED = {**LINE_ENDS, **LAYOUT, **KEYS, **VALUES}
# The kept shell's `while read` drops a last line without its newline; O2 refuses it.
SHELL_LAXER = {"unterminated extra line"}


def parse():
    if not hasattr(HOST, "parse_neutral_defaults"):
        raise AssertionError("详细工作指导 WP-2: infra/ubuntu24_host.py::parse_neutral_defaults(text) is the one reader")
    return HOST.parse_neutral_defaults


def all_inputs() -> dict[str, bytes]:
    cases = {name: text.encode("utf-8") for name, (text, _values) in ACCEPTED.items()}
    cases.update({name: text.encode("utf-8") for name, text in REFUSED.items()})
    cases["not UTF-8"] = NOT_UTF8
    return cases


def deploy_verdict(path: Path):
    """deploy_infra's verdict: its values, or the exception it raised -- a crash is a verdict too, and every
    refusal must be a DeployError (详细工作指导 WP-2)."""
    try:
        return DEPLOY.load_neutral_defaults(path)
    except Exception as exc:  # noqa: BLE001
        return exc


def setup_py_verdict(directory: Path):
    """infra-setup.py's verdict: its neutral values, or (exit code, stderr) of the SetupExit it raised."""
    holder = SimpleNamespace(source_dir=directory)
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr):
            SETUP_PY.InfraSetup.load_neutral_defaults(holder)
    except SETUP_PY.SetupExit as exc:
        return exc.code, stderr.getvalue()
    return holder.neutral


def shell_fragment() -> str:
    """The kept infra-setup.sh's neutral block, unchanged, followed by a print of what it accepted."""
    source = SHELL.read_text(encoding="utf-8")
    start = source.index('neutral_config="${source_dir}/infra-neutral.conf"\n')
    end_marker = 'echo "ERROR: neutral defaults are incomplete or invalid" >&2\n  exit 2\nfi\n'
    end = source.index(end_marker, start) + len(end_marker)
    return source[start:end] + 'printf "%s\\n" "$neutral_dns" "$neutral_ntp" "$neutral_timezone"\n'


class NeutralParserTests(unittest.TestCase):
    def assert_refused(self, raw: str) -> None:
        with self.assertRaises(HOST.HostConfigError):
            parse()(raw)

    def test_canonical_three_lines_accepted(self):
        for name, (text, values) in ACCEPTED.items():
            with self.subTest(case=name):
                self.assertEqual(values, tuple(parse()(text)))

    def test_missing_final_newline_rejected(self):
        # O2; the same input test_infra_setup_py.py::…test_invalid_neutral_defaults_fail already refuses.
        self.assert_refused(LINE_ENDS["missing final newline"])
        self.assert_refused(LINE_ENDS["unterminated extra line"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "infra-neutral.conf"
            path.write_bytes(LINE_ENDS["missing final newline"].encode("ascii"))
            verdict = deploy_verdict(path)
            self.assertIsInstance(verdict, DEPLOY.DeployError, f"deploy_infra refuses it too (O2): {verdict!r}")

    def test_crlf_rejected(self):
        for name in ("CRLF", "CRLF on the last line only"):
            with self.subTest(case=name):
                self.assert_refused(LINE_ENDS[name])
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "infra-neutral.conf"
                    path.write_bytes(LINE_ENDS[name].encode("ascii"))
                    verdict = deploy_verdict(path)
                    self.assertIsInstance(verdict, DEPLOY.DeployError, f"deploy_infra refuses it (O2): {verdict!r}")
                    self.assertEqual(1, setup_py_verdict(Path(directory))[0], "infra-setup.py refuses it (O2)")

    def test_comment_blank_or_reordered_lines_rejected(self):
        for name, text in LAYOUT.items():
            with self.subTest(case=name):
                self.assert_refused(text)

    def test_duplicate_extra_or_missing_key_rejected(self):
        for name, text in KEYS.items():
            with self.subTest(case=name):
                self.assert_refused(text)

    def test_invalid_values_rejected(self):
        for name, text in VALUES.items():
            with self.subTest(case=name):
                self.assert_refused(text)

    def test_non_utf8_is_deploy_error_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "infra-neutral.conf"
            path.write_bytes(NOT_UTF8)
            verdict = deploy_verdict(path)
            self.assertIsInstance(verdict, DEPLOY.DeployError, f"a refusal, not a crash: {verdict!r}")

    def test_deploy_infra_and_infra_setup_agree_on_every_case(self):
        expected = {name: values for name, (_text, values) in ACCEPTED.items()}
        for name, raw in all_inputs().items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "infra-neutral.conf"
                path.write_bytes(raw)
                deploy = deploy_verdict(path)
                setup_py = setup_py_verdict(Path(directory))
                if name in expected:
                    dns, ntp, zone = expected[name]
                    self.assertEqual(([dns], [ntp], zone), tuple(deploy))
                    self.assertEqual(([dns], [ntp], zone), tuple(setup_py))
                else:
                    self.assertIsInstance(deploy, DEPLOY.DeployError, repr(deploy))
                    self.assertEqual(1, setup_py[0], setup_py)

    def test_infra_setup_keeps_exit_1_on_invalid_input(self):
        # The real entry in test_infra_setup_py's sandbox: exit 1, its ERROR text, nothing changed on the host.
        cases = (
            ("missing final newline", "ERROR: neutral defaults are incomplete or invalid"),
            ("CRLF", "ERROR: invalid neutral defaults line 1"),
        )
        for name, message in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="infra-neutral-parser-") as directory:
                box = INFRA_SETUP_TESTS.Sandbox(Path(directory))
                (box.infra / "infra-neutral.conf").write_bytes(LINE_ENDS[name].encode("ascii"))
                result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
                self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertEqual(INFRA_SETUP_TESTS.UBUNTU_RESOLVED, box.read("etc/systemd/resolved.conf"))

    def test_kept_shell_cross_check(self):
        fragment = shell_fragment()
        expected = {name: values for name, (_text, values) in ACCEPTED.items()}
        for name, raw in all_inputs().items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "infra-neutral.conf").write_bytes(raw)
                shell = subprocess.run(
                    ["/bin/bash", "-c", 'source_dir="$1"\n' + fragment, "neutral-cross-check", directory],
                    capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
                    env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"},
                )
                if name in expected:
                    self.assertEqual((0, "\n".join(expected[name]) + "\n"), (shell.returncode, shell.stdout.decode()))
                elif name in SHELL_LAXER:
                    self.assertEqual(0, shell.returncode, "the shell is laxer here; O2 is not")
                    self.assert_refused(raw.decode("utf-8"))
                else:
                    self.assertEqual(2, shell.returncode, shell.stdout)
                    text = raw.decode("utf-8", errors="replace")
                    with self.assertRaises(HOST.HostConfigError) as refused:
                        parse()(text)
                    # Same refusal, same words: infra-setup.py prints "ERROR: <message>" as the shell did.
                    self.assertEqual("ERROR: " + str(refused.exception) + "\n", shell.stderr.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
