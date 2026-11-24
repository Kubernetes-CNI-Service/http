"""r757 WP8/D7 independent PUBLIC config-mode contracts; author NOT RUN.

API/program proposals were frozen in the author handoff before product code.
The product is loaded only inside setUp; no shell, device or native backend is
executed by these pure cases. Real MAIN/stages are exercised by the companion
workflow, not by fabricated result records here.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
NAMES = ("EXAMPLE-IB001", "EXAMPLE-IB002")
MACS = ("02:00:00:00:00:11", "02:00:00:00:00:12")
RELEASE_ERROR = "replace release is invalid; run load to regenerate configuration"
YAML_ERROR = "replace YAML is missing or invalid"
WARNING = "整份替换（会清掉 yaml 以外的配置）"
EXPECTED_REPLACE_SCRIPT = (
    'set -eu\n'
    'umask 077\n'
    "fail() { printf '%s\\n' 'IB configuration replace failed' >&2; exit 1; }\n"
    '[ "$#" -eq 2 ] || fail\n'
    'payload=$1\n'
    'expected=$2\n'
    '[ "${#expected}" -eq 64 ] || fail\n'
    'case "$expected" in \'\'|*[!0-9a-f]*) fail ;; esac\n'
    'case "${HOME-}" in /*) ;; *) fail ;; esac\n'
    'config="$HOME/initial-setup-replace.yaml"\n'
    '[ ! -L "$config" ] || fail\n'
    'if [ -e "$config" ] && [ ! -f "$config" ]; then fail; fi\n'
    'tmp=\n'
    'trap \'if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi\' EXIT\n'
    "trap 'exit 1' HUP INT TERM\n"
    'tmp=$(mktemp "${config}.tmp.XXXXXX" 2>/dev/null) || fail\n'
    'chmod 600 "$tmp" || fail\n'
    'printf \'%s\' "$payload" | base64 -d > "$tmp" 2>/dev/null || fail\n'
    '[ -s "$tmp" ] || fail\n'
    'actual=$(sha256sum "$tmp" 2>/dev/null) || fail\n'
    '[ "${actual%% *}" = "$expected" ] || fail\n'
    'mv -fT -- "$tmp" "$config" || fail\n'
    'tmp=\n'
    'if nv config replace "$config" > /dev/null 2>&1; then\n'
    '    :\n'
    'else\n'
    '    rc=$?\n'
    '    case "$rc" in\n'
    '        [1-9]|[1-9][0-9]|1[01][0-9]|12[0-5])\n'
    '            printf \'rc=%s\\nfailed_operation=replace\\n\' "$rc"\n'
    '            exit 1 ;;\n'
    '        *) fail ;;\n'
    '    esac\n'
    'fi\n'
    'printf \'path=%s\\nsha256=%s\\n\' "$config" "$expected"\n'
)


# Independently frozen in the typed-completion contract, before implementation.
# Raw literals preserve the exact one-backslash shell text and terminal LF.
EXPECTED_D7_LAUNCH_SCRIPT = r"""set -eu
umask 077
fail() { printf '%s\n' 'IB deferred configuration launch failed' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
stamp=$1
case "$stamp" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) fail ;;
esac
case "${HOME-}" in /*) ;; *) fail ;; esac
rc_file="$HOME/.initial-setup-${stamp}.rc"
[ ! -e "$rc_file" ] && [ ! -L "$rc_file" ] || fail
(set -C; : > "$rc_file") 2>/dev/null || fail
chmod 600 "$rc_file" || fail
setsid nohup sh -c '
set -u
umask 077
rc_file=$1
sleep 3 || exit 1
nv config apply -y
status=$?
failed_operation=apply
if [ "$status" -eq 0 ]; then
    nv config save
    status=$?
    failed_operation=save
    if [ "$status" -eq 0 ]; then failed_operation=none; fi
fi
tmp=
trap '\''if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi'\'' EXIT
trap '\''exit 1'\'' HUP INT TERM
tmp=$(mktemp "${rc_file}.tmp.XXXXXX" 2>/dev/null) || exit 1
printf "rc=%s\nfailed_operation=%s\n" "$status" "$failed_operation" > "$tmp" || exit 1
chmod 600 "$tmp" || exit 1
mv -fT -- "$tmp" "$rc_file" || exit 1
tmp=
exit "$status"
' -- "$rc_file" > /dev/null 2>&1 < /dev/null &
exit 0
"""
EXPECTED_D7_READ_RC_SCRIPT = r"""set -eu
fail() { printf '%s\n' 'IB deferred configuration result is unverified' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
stamp=$1
case "$stamp" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) fail ;;
esac
case "${HOME-}" in /*) ;; *) fail ;; esac
rc_file="$HOME/.initial-setup-${stamp}.rc"
[ ! -L "$rc_file" ] || fail
if [ ! -e "$rc_file" ]; then printf 'rc=\nfailed_operation=pending\n'; exit 0; fi
[ -f "$rc_file" ] || fail
if [ ! -s "$rc_file" ]; then printf 'rc=\nfailed_operation=pending\n'; exit 0; fi
{
    IFS= read -r rc_line || fail
    IFS= read -r operation_line || fail
} < "$rc_file"
case "$rc_line" in
    rc=*) status=${rc_line#rc=} ;;
    *) fail ;;
esac
case "$status" in
    0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
    *) fail ;;
esac
case "$operation_line" in
    failed_operation=none) [ "$status" -eq 0 ] || fail ;;
    failed_operation=apply|failed_operation=save) [ "$status" -ne 0 ] || fail ;;
    *) fail ;;
esac
bytes=$(wc -c < "$rc_file" | tr -d '[:space:]') || fail
case "$bytes" in ''|*[!0-9]*) fail ;; esac
[ "$bytes" -eq "$((${#rc_line} + ${#operation_line} + 2))" ] || fail
printf '%s\n%s\n' "$rc_line" "$operation_line"
"""


class Facade:
    """Module-local overrides, never mutate shared subprocess/os/time modules."""
    def __init__(self, original, **overrides):
        self.original, self.overrides = original, overrides

    def __getattr__(self, name):
        return self.overrides[name] if name in self.overrides else getattr(self.original, name)


def yaml_bytes(name, *, quoted=False):
    hostname = '"' + name + '"' if quoted else name
    # Real generator shape: a sequence, empty flow maps, nonterminal hostname.
    return ("- set:\n    interface:\n      eth0:\n        ipv4:\n"
            "          address:\n            203.0.113.11/24: {}\n"
            "    system:\n      hostname: " + hostname + "\n"
            "      ztp:\n        config-save: enabled\n").encode("ascii")


def write_parent(project, release, manifest):
    """Handwritten DAY0 schema2; never ask the SUT to make expected metadata."""
    manifest_path = release / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="ascii")
    paths = {"global": "01-global.yaml", "devices": "02-devices_config.csv",
             "subnet": "02-dhcp-subnet_config.csv", "p2p": "p2p.xlsx"}
    parent = {"schema_version": 2, "release_id": "PUBLIC-parent-71",
        "generated_at": "2026-11-18T00:00:00+08:00", "validation": "passed",
        "project": project.name, "deployment_scope": "all", "switch_scope": "ib",
        "dhcp_status": "disabled", "input_paths": paths,
        "inputs": {key: hashlib.sha256((project / path).read_bytes()).hexdigest()
                   for key, path in paths.items()},
        "components": {"nvos": {"release_id": manifest["release_id"],
            "release_dir": release.relative_to(project).as_posix(),
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "published_marker_sha256": hashlib.sha256(
                (release / ".published-complete").read_bytes()).hexdigest()}}}
    destination = project / "99-output-ztp/current-release.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(parent, sort_keys=True), encoding="ascii")
    return parent


def public_release(parent):
    project = parent / "PUBLIC-project"
    release = project / "99-output-ib_nvl/20261118_010203-ib"
    release.mkdir(parents=True)
    for name, data in (("01-global.yaml", b"switches: []\n"),
                       ("02-devices_config.csv", b"PUBLIC inventory\n"),
                       ("02-dhcp-subnet_config.csv", b"PUBLIC subnet\n"),
                       ("p2p.xlsx", b"PUBLIC opaque workbook\n")):
        (project / name).write_bytes(data)
    manifest = {"schema_version": 1, "deployment_scope": "all", "switch_scope": "ib",
                "release_id": "20261118_010203-nvos", "types": ["ib"],
                "identity_pending": 0, "devices": []}
    for name, mac in zip(NAMES, MACS):
        body = yaml_bytes(name)
        (release / (name + ".yaml")).write_bytes(body)
        (release / (mac.replace(":", "") + ".yaml")).symlink_to(name + ".yaml")
        manifest["devices"].append({"hostname": name, "type": "ib", "config": name + ".yaml",
            "config_sha256": hashlib.sha256(body).hexdigest(), "macs": [mac], "identity_state": "managed"})
    (release / "default_ib.yaml").write_bytes(yaml_bytes("PUBLIC-NEVER-SELECT-DEFAULT"))
    (release / ".published-complete").write_text("PUBLIC complete\n", encoding="ascii")
    (release.parent / "latest").symlink_to(release.name)
    write_parent(project, release, manifest)
    return project, release, manifest


class ConfigModeTests(unittest.TestCase):
    def setUp(self):
        owned = owned_test_root()
        if os.environ.get("TMPDIR") != str(owned):
            raise RuntimeError("FIXTURE HOLD: TMPDIR must equal explicit owned root")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-pure-", dir=owned))
        self.root = Path(directory)
        home = self.root / "home"
        home.mkdir(mode=0o700)
        self.stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
        self.stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
        self.stack.enter_context(mock.patch.dict(sys.modules))
        self.app = load_script("d7_pure_" + format(id(self), "x"), INITIAL)
        self.effects = []
        self.addCleanup(self.check_effects)
        for name, module in (("subprocess", subprocess), ("socket", socket), ("os", os)):
            overrides = ({"run": self.deny, "Popen": self.deny} if name == "subprocess" else
                         {"socket": self.deny, "create_connection": self.deny} if name == "socket" else
                         {item: self.deny for item in (
                             "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe",
                             "execl", "execlp", "execlpe", "posix_spawn", "posix_spawnp",
                             "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
                             "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")})
            self.stack.enter_context(mock.patch.object(self.app, name, Facade(module, **overrides)))
        self.stack.enter_context(mock.patch.object(self.app, "pty", Facade(self.app.pty,
            fork=self.deny, openpty=self.deny)))
        self.stack.enter_context(mock.patch.object(self.app, "getpass", Facade(self.app.getpass,
            getpass=self.deny)))
        self.stack.enter_context(mock.patch.object(self.app, "interactive_run", self.deny))
        self.project, self.release, self.manifest = public_release(self.root)

    def deny(self, *_args, **_kwargs):
        self.effects.append("unknown-effect")
        raise RuntimeError("FIXTURE HOLD: pure D7 case attempted external IO")

    def check_effects(self):
        if self.effects:
            raise RuntimeError("FIXTURE HOLD: refused external IO is not a business verdict")

    def target(self, *, mac=MACS[0], name=NAMES[0]):
        device = self.app.Device(name, "ib", "203.0.113.11", "203.0.113.11/24", "203.0.113.1", mac, "", "")
        return self.app.Target(device, None, "", "eth0")

    def select(self, *, target=None):
        return self.app.select_replace_yaml(target or self.target(), self.release, self.manifest)

    def test_config_mode_argument_defaults_and_exact_choices(self):
        for words, expected in (([], "patch"), (["--config-mode", "patch"], "patch"),
                                (["--config-mode", "replace"], "replace")):
            with self.subTest(words=words), mock.patch.object(sys, "argv", [str(INITIAL), *words]):
                self.assertEqual(expected, self.app.parse_args().config_mode)
        for value in ("REPLACE", "", "replace;true"):
            with self.subTest(value=value), mock.patch.object(sys, "argv", [str(INITIAL), "--config-mode", value]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    self.app.parse_args()
                self.assertEqual(2, error.exception.code)

    def test_whole_release_check_accepts_explicit_and_inferred_project_not_cwd(self):
        cwd = Path.cwd()
        try:
            os.chdir(self.root)
            self.assertEqual(self.manifest, self.app.validate_replace_release(self.release, self.project))
            self.assertEqual(self.manifest, self.app.validate_replace_release(self.release))
        finally:
            os.chdir(cwd)

    def test_whole_release_check_blocks_each_input_marker_and_manifest_binding(self):
        variants = ("global", "devices", "subnet", "p2p", "marker-missing", "marker-empty",
                    "manifest-missing", "manifest-hash", "release-dir", "other-host-tamper")
        for index, variant in enumerate(variants):
            with self.subTest(variant=variant):
                branch = self.root / ("bad-" + str(index))
                project, release, manifest = public_release(branch)
                path = project / "99-output-ztp/current-release.json"
                parent = json.loads(path.read_text())
                if variant in {"global", "devices", "subnet", "p2p"}:
                    source = project / parent["input_paths"][variant]
                    source.write_bytes(source.read_bytes() + b"PUBLIC changed\n")
                elif variant == "marker-missing":
                    (release / ".published-complete").unlink()
                elif variant == "marker-empty":
                    (release / ".published-complete").write_bytes(b"")
                elif variant == "manifest-missing":
                    (release / "release-manifest.json").unlink()
                elif variant == "manifest-hash":
                    parent["components"]["nvos"]["manifest_sha256"] = "0" * 64
                elif variant == "release-dir":
                    parent["components"]["nvos"]["release_dir"] = "99-output-ib_nvl/other"
                else:
                    (release / (NAMES[1] + ".yaml")).write_bytes(b"PUBLIC tampered existing YAML\n")
                path.write_text(json.dumps(parent))
                with self.assertRaises(self.app.SetupError) as error:
                    self.app.validate_replace_release(release, project)
                self.assertEqual(RELEASE_ERROR, str(error.exception))

    def test_external_p2p_path_is_allowed_but_other_external_inputs_are_not(self):
        parent_path = self.project / "99-output-ztp/current-release.json"
        parent = json.loads(parent_path.read_text())
        external = self.root / "PUBLIC-external.xlsx"
        external.write_bytes(b"PUBLIC selected external workbook\n")
        parent["input_paths"]["p2p"] = str(external)
        parent["inputs"]["p2p"] = hashlib.sha256(external.read_bytes()).hexdigest()
        parent_path.write_text(json.dumps(parent))
        self.assertEqual(self.manifest, self.app.validate_replace_release(self.release))
        parent["input_paths"]["global"] = str(external)
        parent["inputs"]["global"] = hashlib.sha256(external.read_bytes()).hexdigest()
        parent_path.write_text(json.dumps(parent))
        with self.assertRaises(self.app.SetupError):
            self.app.validate_replace_release(self.release)

    def test_selection_normalizes_mac_and_reads_nonterminal_quoted_hostname(self):
        path = self.release / (NAMES[0] + ".yaml")
        body = yaml_bytes(NAMES[0], quoted=True)
        path.write_bytes(body)
        self.manifest["devices"][0]["config_sha256"] = hashlib.sha256(body).hexdigest()
        self.manifest["devices"][0]["macs"] = ["02-00-00-00-00-11"]
        actual = self.select(target=self.target(mac="0200.0000.0011"))
        self.assertEqual({"verdict": "WOULD_REPLACE", "file": str(path.resolve()),
                          "sha256": hashlib.sha256(body).hexdigest(), "reason": ""}, actual)

    def test_selection_refuses_each_bad_host_without_default_or_batch_failure(self):
        variants = ("missing", "symlink", "directory", "empty", "manifest-absent", "wrong-config",
                    "pending", "wrong-mac", "wrong-link", "hostname", "hostname-unreadable")
        for index, variant in enumerate(variants):
            with self.subTest(variant=variant):
                project, release, manifest = public_release(self.root / ("host-" + str(index)))
                path = release / (NAMES[0] + ".yaml")
                if variant in {"missing", "symlink", "directory"}:
                    path.unlink()
                    if variant == "symlink":
                        path.symlink_to("default_ib.yaml")
                    elif variant == "directory":
                        path.mkdir()
                elif variant == "empty":
                    path.write_bytes(b"")
                elif variant == "manifest-absent":
                    manifest["devices"].pop(0)
                elif variant == "wrong-config":
                    manifest["devices"][0]["config"] = "default_ib.yaml"
                elif variant == "pending":
                    manifest["devices"][0]["identity_state"] = "identity_pending"
                elif variant == "wrong-mac":
                    manifest["devices"][0]["macs"] = [MACS[1]]
                elif variant == "wrong-link":
                    link = release / "020000000011.yaml"
                    link.unlink()
                    link.symlink_to(NAMES[1] + ".yaml")
                else:
                    path.write_bytes(yaml_bytes("PUBLIC-WRONG") if variant == "hostname" else b"- set:\n  system: {}\n")
                    manifest["devices"][0]["config_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                result = self.app.select_replace_yaml(self.target(), release, manifest)
                self.assertEqual({"verdict", "file", "sha256", "reason"}, set(result))
                self.assertEqual("YAML_MISSING_OR_INVALID", result["verdict"])
                self.assertEqual(YAML_ERROR, result["reason"])
                other = self.app.select_replace_yaml(self.target(name=NAMES[1], mac=MACS[1]), release, manifest)
                self.assertEqual("WOULD_REPLACE", other["verdict"], "one invalid YAML must not swallow another host")
                self.assertEqual(str(release / (NAMES[1] + ".yaml")), other["file"])

    def test_missing_host_file_is_per_device_not_existing_file_hash_tamper(self):
        (self.release / (NAMES[0] + ".yaml")).unlink()
        self.assertEqual(self.manifest, self.app.validate_replace_release(self.release, self.project))
        self.assertEqual("YAML_MISSING_OR_INVALID", self.select()["verdict"])

    def test_admin_target_policy_still_rejects_absent_or_ambiguous_ib_hash(self):
        for text in ("switches: []\n", "switches:\n- ib:\n    system:\n      hostname: PUBLIC\n",
                     "switches:\n- ib:\n    system:\n      hostname: PUBLIC-A\n"
                     "- ib:\n    system:\n      hostname: PUBLIC-B\n"):
            with self.subTest(shape=text.splitlines()[0]):
                global_path = self.project / "01-global.yaml"
                global_path.write_text(text)
                with self.assertRaises(self.app.SetupError):
                    self.app.ProjectPasswordPolicy(global_path, "admin", interactive=False)

    def test_replace_program_exact_vector_and_nvue_classification(self):
        body = yaml_bytes(NAMES[0])
        expected = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                    base64.b64encode(body).decode("ascii"), hashlib.sha256(body).hexdigest()]
        actual = self.app.replace_command(body)
        self.assertEqual(expected, actual)
        self.assertEqual(expected, self.app.ib_command_argv(list(expected)))
        self.assertEqual("nvue", self.app._ib_write_category(list(expected)))
        self.assertEqual(["nv", "config", "detach"], self.app.ib_command_argv(["nv", "config", "detach"]))
        self.assertEqual("nvue", self.app._ib_write_category(["nv", "config", "detach"]))

    def test_replace_program_near_miss_vectors_stay_closed(self):
        body = yaml_bytes(NAMES[0])
        valid = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                 base64.b64encode(body).decode("ascii"), hashlib.sha256(body).hexdigest()]
        variants = [valid[:-1], [*valid, "extra"], [*valid[:2], EXPECTED_REPLACE_SCRIPT + " ", *valid[3:]],
                    [*valid[:4], "!bad!", valid[5]], [*valid[:4], "", valid[5]],
                    [*valid[:4], "A" * 131073, valid[5]], [*valid[:5], "f" * 63],
                    [*valid[:5], "F" * 64], [*valid[:5], 7],
                    ["nv", "config", "replace", "PUBLIC"], ["nv", "config", "replace"],
                    ["sh", "-c", "printf PUBLIC", "--", "QUFBQQ=="]]
        for index, supplied in enumerate(variants):
            with self.subTest(vector=index), self.assertRaises(self.app.SetupError):
                self.app.ib_command_argv(supplied)
        for bad in (b"", "PUBLIC-not-bytes", b"A" * 98305):
            with self.subTest(kind=type(bad).__name__), self.assertRaises(self.app.SetupError):
                self.app.replace_command(bad)

    def test_replace_and_detach_never_join_either_explicit_key_read_boundary(self):
        paths = self.app._import_tools("tools.login_path")
        target = self.app.Target(self.target().ib, None, "", "eth0", route=paths.Route(
            NAMES[0], "direct", "NO_MGMT_LINK", None, None, None))
        point = self.app.DirectEndpoint("203.0.113.11", None)
        key = self.root / "PUBLIC-key-shape-only"
        key.write_bytes(b"PUBLIC synthetic file; never passed to a key parser or child\n")
        key.chmod(0o600)
        self.assertIsNone(self.app._validate_direct_endpoint(target, point))
        accepted = self.app.direct_ssh_command(target, point, "admin", 10,
            ["nv", "config", "show", "-o", "commands"], _key_file=key)
        self.assertIn(str(key), accepted, "valid endpoint/file must reach the original key-only builder")
        body = yaml_bytes(NAMES[0])
        replace = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                   base64.b64encode(body).decode("ascii"), hashlib.sha256(body).hexdigest()]
        for command in (replace, ["nv", "config", "detach"]):
            with self.subTest(command=command[0]):
                self.assertEqual(command, self.app.ib_command_argv(command))
                with self.assertRaises(self.app.SetupError):
                    self.app.direct_ssh_command(target, point, "admin", 10, command, _key_file=key)
                with self.assertRaises(self.app.SetupError):
                    self.app._run_direct_key_read(target, point, "admin", key, 10, command)

    @contextmanager
    def _e1_public_main_case(self, *, copied=False, missing_host=False):
        """Fresh PUBLIC files and a real MAIN; no credentials or child allowed."""
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="e1-", dir=self.root)))
            home = root / "home"
            home.mkdir(mode=0o700)
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.dict(sys.modules))
            project, release, manifest = public_release(root)
            header = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac\n"
            csv_text = (header
                + "EXAMPLE-IB001,ib,leaf,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,NA,NA,NA,NA\n"
                + "EXAMPLE-IB002,ib,leaf,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,NA,NA,NA,NA\n"
                + "EXAMPLE-JUMP01,eth_jump,leaf,192.0.2.10,NA,NA,NA,NA,NA,NA,NA\n")
            for filename in ("ib.csv", "02-devices_config.csv"):
                (project / filename).write_text(csv_text, encoding="ascii")
            self.assertNotEqual((project / "ib.csv").stat().st_ino,
                                (project / "02-devices_config.csv").stat().st_ino)
            # Independent OOXML DATA. Neither the product nor a real generator
            # supplies the expected column selection, names, MACs or topology.
            ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
            rows = (("name", "port", "name", "port"),
                    ("EXAMPLE-IB001", "eth0", "EXAMPLE-JUMP01", "swp1"),
                    ("EXAMPLE-IB002", "eth0", "EXAMPLE-JUMP01", "swp2"))
            sheet = '<worksheet xmlns="' + ns + '"><sheetData>'
            for number, row in enumerate(rows, 1):
                sheet += '<row r="' + str(number) + '">'
                for column, value in zip("ABCD", row):
                    sheet += ('<c r="' + column + str(number)
                              + '" t="inlineStr"><is><t>' + value + '</t></is></c>')
                sheet += '</row>'
            sheet += '</sheetData></worksheet>'
            with zipfile.ZipFile(project / "p2p.xlsx", "w") as archive:
                archive.writestr("xl/workbook.xml", '<workbook xmlns="' + ns
                    + '" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                      '<sheets><sheet name="PUBLIC" sheetId="1" r:id="rId1"/></sheets></workbook>')
                archive.writestr("xl/_rels/workbook.xml.rels",
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
                archive.writestr("xl/worksheets/sheet1.xml", sheet)
            (project / "01-global.yaml").write_text(
                "switches:\n- ib:\n    system:\n      dns:\n        server:\n        - 203.0.113.53\n"
                "      ntp:\n        server:\n        - ntp.ubuntu.com\n"
                "      date-time:\n        timezone: Etc/UTC\n", encoding="ascii")
            neutral = project / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
            neutral.parent.mkdir(parents=True)
            neutral.write_text("DNS=192.0.2.53\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
            # This is pre-admission fixture construction, not mutation repair.
            write_parent(project, release, manifest)
            if missing_host:
                (release / "EXAMPLE-IB001.yaml").unlink()
            script = INITIAL
            loader = load_script
            copied_tools = None
            if copied:
                repository = root / "repository"
                script = repository / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
                script.parent.mkdir(parents=True)
                script.write_bytes(INITIAL.read_bytes())
                self.assertEqual(INITIAL.read_bytes(), script.read_bytes())
                copied_tools = repository / "tools"
                copied_tools.mkdir()
                for name in ("device_identity", "hostname_ranges", "login_path", "inventory_subset"):
                    source = ROOT / "tools" / (name + ".py")
                    target = copied_tools / source.name
                    target.write_bytes(source.read_bytes())
                    self.assertEqual(source.read_bytes(), target.read_bytes())
                helper_path = repository / "test_cases/module_loader.py"
                helper_path.parent.mkdir()
                helper_path.write_bytes((ROOT / "test_cases/module_loader.py").read_bytes())
                helper = load_script("e1_private_loader_" + format(id(root), "x"), helper_path)
                self.assertEqual((ROOT / "test_cases/module_loader.py").read_bytes(), helper_path.read_bytes())
                self.assertEqual(helper_path.resolve(), Path(helper.__file__).resolve())
                self.assertIs(helper.load_script.__globals__, helper.__dict__)
                self.assertEqual(helper_path.resolve(), Path(helper.load_script.__code__.co_filename).resolve())
                helper.ROOT = repository  # Only this private same-source loader.
                loader = helper.load_script
                for name in tuple(sys.modules):
                    if name == "tools" or name.startswith("tools."):
                        sys.modules.pop(name)
                sys.path[:] = [str(repository), str(copied_tools),
                    *(entry for entry in sys.path if Path(entry or ".").resolve()
                      not in {ROOT, ROOT / "tools"})]
                service = repository / "ztp/config/nvos"
                (service / "template").mkdir(parents=True)
                (service / "template/99-output-ib_nvl").symlink_to(project / "99-output-ib_nvl")
                (service / "latest_yaml").symlink_to("template/99-output-ib_nvl/latest")
                (script.parent / "latest_yaml").symlink_to("../../../ztp/config/nvos/latest_yaml")
                (script.parent / "01-global.yaml").symlink_to(project / "01-global.yaml")
                (script.parent / "infra-neutral.conf").symlink_to(neutral)
                (repository / "infiniband/02-devices_config.csv").symlink_to(project / "02-devices_config.csv")
                self.assertEqual(release, (script.parent / "latest_yaml").resolve(strict=True))
            app = loader("e1_public_main_" + format(id(root), "x"), script)
            real_dispatch = app.run_prepared_tasks
            effects, authorities, parsed = [], [], []
            def deny(*_args, **_kwargs):
                effects.append("unknown-external-effect")
                raise RuntimeError("FIXTURE HOLD: E1 PUBLIC MAIN refused an external effect")
            for name in ("prompt_ethernet_passwords", "collect_jump_snapshot_passes",
                         "collect_ethernet_interfaces", "collect_ethernet_network_tables",
                         "run_on_ethernet", "inspect_ib_device", "interactive_run",
                         "run_prepared_tasks", "_read_local_interfaces", "obtain_write_permit"):
                stack.enter_context(mock.patch.object(app, name, deny))
            stack.enter_context(mock.patch.object(app, "subprocess", Facade(subprocess, run=deny, Popen=deny)))
            stack.enter_context(mock.patch.object(app, "socket", Facade(socket, socket=deny,
                create_connection=deny, gethostname=lambda: "PUBLIC-management",
                getfqdn=lambda: "PUBLIC-management.example.test")))
            stack.enter_context(mock.patch.object(app, "os", Facade(os, **{name: deny for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle",
                "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                "kill", "killpg", "waitpid")})))
            stack.enter_context(mock.patch.object(app, "pty", Facade(app.pty, fork=deny, openpty=deny)))
            stack.enter_context(mock.patch.object(app, "multiprocessing", Facade(app.multiprocessing,
                get_context=deny, Process=deny)))
            stack.enter_context(mock.patch.object(app, "getpass", Facade(app.getpass, getpass=deny)))
            stack.enter_context(mock.patch.object(app, "input", deny, create=True))
            paths = app._import_tools("tools.login_path")
            expected_tools = copied_tools if copied else ROOT / "tools"
            self.assertEqual(expected_tools / "login_path.py", Path(paths.__file__).resolve())
            stack.enter_context(mock.patch.object(paths, "subprocess", Facade(subprocess, run=deny, Popen=deny)))
            original_parse, original_init = app.parse_args, app.RuntimeInputAuthority.__init__
            def parse():
                result = original_parse()
                parsed.append(result)
                return result
            def observe_authority(instance, paths):
                original_init(instance, paths)
                authorities.append(instance)
            stack.enter_context(mock.patch.object(app, "parse_args", side_effect=parse))
            stack.enter_context(mock.patch.object(app.RuntimeInputAuthority, "__init__", observe_authority))
            report, cache, snapshots = (root / "out/report.log", root / "out/targets.json", root / "out/snapshots")
            argv = [str(script), "--ib-csv", str(project / "ib.csv"), "--p2p", str(project / "p2p.xlsx"),
                    "--report", str(report), "--target-cache", str(cache), "--snapshot-dir", str(snapshots),
                    "--execution-mode", "management", "--config-mode", "replace", "--devices", "EXAMPLE-IB001"]
            if not copied:
                argv += ["--project-dir", str(project)]
            case = SimpleNamespace(app=app, root=root, project=project, release=release,
                latest=(script.parent / "latest_yaml" if copied else project / "99-output-ib_nvl/latest"),
                script=script, report=report, cache=cache, snapshots=snapshots, argv=argv,
                effects=effects, authorities=authorities, parsed=parsed, copied_tools=copied_tools, deny=deny,
                real_dispatch=real_dispatch)
            try:
                yield case
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
                if effects:
                    raise RuntimeError("FIXTURE HOLD: rejected E1 IO is not a valid scope or business result")

    def _e1_run_main(self, case, *, extra=(), managed=False):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", [*case.argv, *extra]), redirect_stdout(output), redirect_stderr(errors):
            if managed:
                try:
                    code = case.app.main(method_cycle=SimpleNamespace(start=case.deny, close=case.deny,
                        admit_paths=case.deny))
                except case.app.SetupError as error:
                    print("ERROR: " + str(error), file=sys.stderr)
                    code = 2
            else:
                code = case.app._standalone_main_with_report_cleanup()
        self.assertTrue(case.parsed, "the real parser must accept the requested options")
        self.assertEqual("replace", case.parsed[-1].config_mode)
        self.assertEqual([], case.effects)
        if case.app.REPORT_HANDLE is not None:
            self.assertTrue(case.app.REPORT_HANDLE.closed)
            self.assertEqual(case.report.resolve(), Path(case.app.REPORT_HANDLE.name).resolve())
        return code, output.getvalue() + errors.getvalue()

    def test_replace_main_plan_and_scope_keep_device_and_invalid_outputs_untouched(self):
        scopes = (("ethernet", ("--execution-mode", "ethernet", "--local-ethernet-hostname", "EXAMPLE-JUMP01"), False),
                  ("auto", ("--execution-mode", "auto", "--local-ethernet-hostname", "EXAMPLE-JUMP01"), False),
                  ("generate-json", ("--generate-json",), False), ("managed", (), True))
        for scope, options, managed in scopes:
            with self.subTest(scope=scope), self._e1_public_main_case() as case:
                code, text = self._e1_run_main(case, extra=options, managed=managed)
                self.assertEqual(2, code)
                self.assertIn("replace", text.casefold())
                self.assertNotIn("awaits verified workflow wiring", text)
                self.assertIn(scope if scope in {"ethernet", "generate-json", "managed"} else "leaf", text.casefold())
                self.assertFalse((case.root / "out").exists(), "scope rejection must precede every output directory")
        for missing in (False, True):
            with self.subTest(missing_host=missing), self._e1_public_main_case(missing_host=missing) as case:
                code, text = self._e1_run_main(case, extra=("--plan",))
                self.assertEqual(0, code)
                self.assertIn("EXAMPLE-IB001.yaml", text)
                self.assertIn(WARNING, text)
                self.assertNotIn("default_ib.yaml", text)
                if missing:
                    self.assertIn("YAML_MISSING_OR_INVALID", text)
                else:
                    self.assertIn(str(case.release / "EXAMPLE-IB001.yaml"), text)
                    self.assertIn(hashlib.sha256(yaml_bytes("EXAMPLE-IB001")).hexdigest(), text)
                    self.assertNotIn(yaml_bytes("EXAMPLE-IB001").decode("ascii"), text)
                    self.assertNotIn(base64.b64encode(yaml_bytes("EXAMPLE-IB001")).decode("ascii"), text)

    def test_replace_main_bound_runtime_inputs_refuse_each_changed_source(self):
        variants = ("current", "latest", "master", "subnet", "global", "p2p", "marker", "manifest",
                    "selected-host", "unselected-host", "mac-alias")
        for variant in variants:
            with self.subTest(source=variant), self._e1_public_main_case() as case:
                code, _text = self._e1_run_main(case, extra=("--plan",))
                self.assertEqual(0, code, "a valid actual MAIN binding must precede the mutation")
                self.assertTrue(case.authorities, "MAIN must construct its real input authority")
                # In MAIN the final construction before the plan return is
                # runtime_authority, later passed to snapshots/dispatch. Never
                # select an object by whether it contains our expected paths.
                authority = case.authorities[-1]
                coordinator = case.app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=True), None, "", [], authority)
                coordinator.assert_unchanged()
                subset_before = (case.project / "ib.csv").read_bytes()
                default = case.release / "default_ib.yaml"
                default.write_bytes(default.read_bytes() + b"# PUBLIC unrelated default\n")
                coordinator.assert_unchanged()  # No directory/default wildcard authority.
                if variant == "current":
                    path = case.project / "99-output-ztp/current-release.json"
                    parent = json.loads(path.read_text())
                    parent["components"]["nvos"]["release_dir"] = "99-output-ib_nvl/PUBLIC-other"
                    path.write_text(json.dumps(parent), encoding="ascii")
                elif variant == "latest":
                    other = case.release.with_name("PUBLIC-same-bytes-release")
                    shutil.copytree(case.release, other, symlinks=True)
                    self.assertEqual((case.release / "release-manifest.json").read_bytes(),
                                     (other / "release-manifest.json").read_bytes())
                    case.latest.unlink()
                    case.latest.symlink_to(other.name)
                elif variant == "mac-alias":
                    path = case.release / "020000000011.yaml"
                    other = case.release / "PUBLIC-same-bytes-host.yaml"
                    other.write_bytes((case.release / "EXAMPLE-IB001.yaml").read_bytes())
                    self.assertEqual(yaml_bytes("EXAMPLE-IB001"), other.read_bytes())
                    path.unlink()
                    path.symlink_to(other.name)
                else:
                    path = {"master": case.project / "02-devices_config.csv",
                            "subnet": case.project / "02-dhcp-subnet_config.csv",
                            "global": case.project / "01-global.yaml", "p2p": case.project / "p2p.xlsx",
                            "marker": case.release / ".published-complete",
                            "manifest": case.release / "release-manifest.json",
                            "selected-host": case.release / "EXAMPLE-IB001.yaml",
                            "unselected-host": case.release / "EXAMPLE-IB002.yaml"}[variant]
                    path.write_bytes(path.read_bytes() + (b" \n" if variant == "manifest" else b"\n# PUBLIC changed input\n"))
                self.assertEqual(subset_before, (case.project / "ib.csv").read_bytes(),
                                 "master authority cannot be replaced by a still-identical derived ib.csv")
                with self.assertRaises(case.app.ProjectInputChanged):
                    coordinator.assert_unchanged()
                with self.assertRaises(case.app.ProjectInputChanged):
                    coordinator.before_write("nvue")
                self.assertFalse(coordinator.writes_attempted)
                self.assertEqual({}, coordinator.metrics)
                self.assertEqual([], case.effects)

    def test_replace_apply_main_binds_selection_before_cache_or_device_access(self):
        # A cache-boundary witness, not evidence of a device write or success.
        for direct, missing_host in ((False, False), (True, False), (False, True)):
            with self.subTest(direct=direct, missing_host=missing_host), self._e1_public_main_case(
                    missing_host=missing_host) as case:
                cache_stop = "PUBLIC stopped at the cache boundary"
                staged = []

                def cache_boundary(*_args, **_kwargs):
                    args = case.parsed[-1]
                    staged.append((args._replace_runtime_authority, dict(args._replace_selected)))
                    raise case.app.SetupError(cache_stop)

                extra = ("--apply", "--yes") + (("--direct-access", "EXAMPLE-IB001") if direct else ())
                with mock.patch.object(case.app, "load_target_cache", side_effect=cache_boundary), \
                     mock.patch.object(case.app.ProjectPasswordPolicy, "password", case.deny), \
                     mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                    code, text = self._e1_run_main(case, extra=extra)
                self.assertEqual(2, code)
                self.assertIn(cache_stop, text)
                self.assertEqual(1, len(staged))
                authority, selected = staged[0]
                self.assertIs(case.authorities[-1], authority)
                self.assertEqual({"example-ib001"}, set(selected))
                host = case.release / "EXAMPLE-IB001.yaml"
                row = selected["example-ib001"]
                bound = {path: (resolved, digest) for path, resolved, _, digest in authority.entries}
                global_input = case.project / "01-global.yaml"
                self.assertEqual((global_input, hashlib.sha256(global_input.read_bytes()).hexdigest()),
                                 bound[global_input])
                self.assertEqual(str(host), row["file"])
                self.assertNotIn(case.latest / "default_ib.yaml", bound)
                if missing_host:
                    self.assertEqual("YAML_MISSING_OR_INVALID", row["verdict"])
                    self.assertEqual("", row["sha256"])
                    self.assertNotIn(case.latest / host.name, bound)
                else:
                    digest = hashlib.sha256(yaml_bytes("EXAMPLE-IB001")).hexdigest()
                    self.assertEqual("WOULD_REPLACE", row["verdict"])
                    self.assertEqual(digest, row["sha256"])
                    self.assertEqual((host, digest), bound[case.latest / host.name])

    def test_replace_apply_main_refuses_bytes_changed_after_selection(self):
        with self._e1_public_main_case() as case:
            original = case.app.select_replace_yaml
            observed = []
            host = case.release / "EXAMPLE-IB001.yaml"

            def select_then_change(*args, **kwargs):
                result = original(*args, **kwargs)
                observed.append(result["verdict"])
                host.write_bytes(host.read_bytes() + b"\n# PUBLIC changed after selection\n")
                return result

            with mock.patch.object(case.app, "select_replace_yaml", side_effect=select_then_change), \
                 mock.patch.object(case.app, "load_target_cache", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", case.deny), \
                 mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                code, text = self._e1_run_main(case, extra=("--apply", "--yes"))
            self.assertEqual(2, code)
            self.assertIn("replace input changed after validation; run load", text)
            self.assertEqual(["WOULD_REPLACE"], observed)
            self.assertFalse(case.cache.exists())
            self.assertFalse(case.snapshots.exists())

    def test_replace_apply_main_keeps_existing_scope_refusals_before_outputs(self):
        scopes = (
            (("--execution-mode", "ethernet"), False, "ethernet execution mode"),
            (("--execution-mode", "auto", "--local-ethernet-hostname", "EXAMPLE-JUMP01"), False, "local Leaf"),
            (("--generate-json",), False, "--generate-json"),
            (("--plan",), False, "--plan cannot be combined with --apply"),
            ((), True, "managed entry"),
        )
        for extra, managed, message in scopes:
            with self.subTest(message=message), self._e1_public_main_case() as case:
                with mock.patch.object(case.app.ProjectPasswordPolicy, "password", case.deny), \
                     mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                    code, text = self._e1_run_main(case, extra=("--apply", "--yes", *extra), managed=managed)
                self.assertEqual(2, code)
                self.assertIn(message, text)
                self.assertFalse((case.root / "out").exists())
                self.assertEqual([], case.authorities)

    def test_replace_apply_main_keeps_unqualified_project_out_of_dispatch(self):
        # This published fixture has services but no IB account authorization.
        # Native hash validation is not needed to reject that missing field.
        with self._e1_public_main_case() as case:
            original = case.app.ProjectPasswordPolicy.__init__
            attempts = []

            def observe_policy(policy, path, *args, **kwargs):
                self.assertEqual(case.project / "01-global.yaml", path)
                try:
                    original(policy, path, *args, **kwargs)
                except case.app.SetupError as error:
                    attempts.append(str(error))
                    raise
                self.fail("a global without the IB account authorization was admitted")

            with mock.patch.object(case.app.ProjectPasswordPolicy, "__init__", observe_policy), \
                 mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", case.deny), \
                 mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                code, text = self._e1_run_main(case, extra=("--apply", "--yes"))
            self.assertEqual(2, code)
            self.assertIn("IB phase project authority failed; device state is UNKNOWN", text)
            self.assertEqual(["global has no unambiguous target password for the IB account"], attempts)
            self.assertTrue(case.cache.is_file(), "the actual project gate follows cache admission")
            self.assertFalse(case.snapshots.exists())
            self.assertEqual(1, len(case.authorities))

    def test_replace_apply_main_direct_dispatch_preserves_project_and_input_authority(self):
        with self._e1_public_main_case() as case:
            global_file = case.project / "01-global.yaml"
            # Public invalid-for-authentication hash-shaped fixture; the only
            # qualification seam stops native authentication and supplies a model value.
            shaped_hash = "$6$PUBLIC$" + "a" * 86
            with global_file.open("a", encoding="ascii") as stream:
                stream.write("      aaa:\n        user:\n          admin:\n            password: '"
                             + shaped_hash + "'\n")
            write_parent(case.project, case.release, json.loads(
                (case.release / "release-manifest.json").read_text(encoding="ascii")))
            token = "PUBLIC-NOT-A-REAL-PASSWORD"
            stop = "PUBLIC stopped before task execution"
            policies, calls = [], []
            own_sessions = mock.Mock(spec_set=["close_jump_masters"])

            def model_qualification(policy):
                policy.assert_unchanged()
                policies.append(policy)
                return token

            def empty_jump_targets(targets, *_args, **_kwargs):
                self.assertEqual([], targets, "an explicitly selected direct target cannot use the Jump")
                return {}

            def stop_dispatch(tasks, args, policy, *_args, authority, method_cycle, preflight_records):
                calls.append((tasks, args, policy, authority, method_cycle, preflight_records))
                raise case.app.SetupError(stop)

            with mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", model_qualification), \
                 mock.patch.object(case.app, "_read_local_interfaces", return_value=()), \
                 mock.patch.object(case.app, "_new_jump_sessions", return_value=own_sessions), \
                 mock.patch.object(case.app, "prompt_ethernet_passwords", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "collect_jump_snapshot_passes", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "resolve_initial_ib_password", return_value=token), \
                 mock.patch.object(case.app, "run_prepared_tasks", side_effect=stop_dispatch):
                code, text = self._e1_run_main(case, extra=(
                    "--apply", "--yes", "--direct-access", "EXAMPLE-IB001"))
            self.assertEqual(2, code)
            self.assertIn(stop, text)
            self.assertNotIn(token, text)
            self.assertEqual(1, len(calls))
            tasks, args, policy, authority, method_cycle, records = calls[0]
            self.assertIs(case.parsed[-1], args)
            self.assertIs(args._on_management_server, True)
            self.assertEqual((case.project / "ib.csv", case.project / "p2p.xlsx", global_file),
                             args._strict_cache[1:])
            self.assertEqual(str(global_file.resolve(strict=True)), args._strict_cache[0]["global"])
            self.assertEqual([policy], policies)
            self.assertIs(type(policy), case.app.ProjectPasswordPolicy)
            self.assertEqual(str(global_file.resolve(strict=True)), policy.binding[0])
            self.assertEqual(hashlib.sha256(global_file.read_bytes()).hexdigest(), policy.binding[3])
            self.assertIs(case.authorities[-1], authority)
            self.assertIs(args._replace_runtime_authority, authority)
            self.assertIsNone(method_cycle)
            self.assertEqual({}, records)
            self.assertEqual(["EXAMPLE-IB001"], [task.target.ib.hostname for task in tasks])
            self.assertEqual("direct", tasks[0].target.route.path)
            self.assertIsNone(tasks[0].target.ethernet)
            self.assertEqual("203.0.113.11", tasks[0].neighbor.address)
            self.assertEqual("WOULD_REPLACE", args._replace_selected["example-ib001"]["verdict"])
            own_sessions.close_jump_masters.assert_called_once_with()

    def test_replace_main_missing_yaml_stays_check_only_through_real_inline_dispatch(self):
        with self._e1_public_main_case(missing_host=True) as case:
            global_file = case.project / "01-global.yaml"
            shaped_hash = "$6$PUBLIC$" + "a" * 86
            with global_file.open("a", encoding="ascii") as stream:
                stream.write("      aaa:\n        user:\n          admin:\n            password: '"
                             + shaped_hash + "'\n")
            write_parent(case.project, case.release, json.loads(
                (case.release / "release-manifest.json").read_text(encoding="ascii")))
            token = "PUBLIC-NOT-A-REAL-PASSWORD"
            own_sessions = mock.Mock(spec_set=["close_jump_masters"])
            observed = []
            execute = case.app.execute_ib_task

            def model_qualification(policy):
                policy.assert_unchanged()
                return token

            def empty_jump_targets(targets, *_args, **_kwargs):
                self.assertEqual([], targets)
                return {}

            def observe_execute(task, args, policy, *extra):
                coordinator = case.app._ACTIVE_COORDINATOR
                self.assertIs(type(coordinator), case.app.RuntimeCoordinator)
                self.assertIs(coordinator.current_target, task.target)
                self.assertIs(coordinator.args, args)
                self.assertIs(coordinator.policy, policy)
                self.assertIs(coordinator.authority, case.authorities[-1])
                self.assertIs(args._replace_runtime_authority, coordinator.authority)
                observed.append(task.target.ib.hostname)
                return execute(task, args, policy, *extra)

            with mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", model_qualification), \
                 mock.patch.object(case.app.RuntimeCoordinator, "authorize", case.deny), \
                 mock.patch.object(case.app, "_read_local_interfaces", return_value=()), \
                 mock.patch.object(case.app, "_new_jump_sessions", return_value=own_sessions), \
                 mock.patch.object(case.app, "prompt_ethernet_passwords", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "collect_jump_snapshot_passes", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "resolve_initial_ib_password", return_value=token), \
                 mock.patch.object(case.app, "run_prepared_tasks", case.real_dispatch), \
                 mock.patch.object(case.app, "execute_ib_task", side_effect=observe_execute):
                code, text = self._e1_run_main(case, extra=(
                    "--apply", "--yes", "--max-workers", "1", "--direct-access", "EXAMPLE-IB001"))
            self.assertEqual(2, code)
            self.assertEqual(["EXAMPLE-IB001"], observed)
            summary_path, = case.report.parent.glob("devices-*/summary.json")
            raw_summary = summary_path.read_text()
            summary = json.loads(raw_summary)
            self.assertEqual("INCOMPLETE", summary["result"])
            self.assertEqual("replace", summary["config_mode"])
            self.assertEqual(["EXAMPLE-IB001"], summary["selection"]["selected"])
            self.assertEqual(1, summary["workers"])
            self.assertEqual({"example-ib001"}, set(summary["records"]))
            row = summary["records"]["example-ib001"]
            self.assertEqual("CHECK_ONLY", row["outcome"])
            self.assertEqual("YAML_MISSING_OR_INVALID", row["replace"]["verdict"])
            self.assertEqual("", row["replace"]["sha256"])
            self.assertIs(row["writes_attempted"], False)
            self.assertIs(row["verified_complete"], False)
            self.assertIsNone(row["backup"])
            self.assertEqual("NOT_REACHED", row["stage_status"]["authentication"])
            self.assertNotIn(token, text + raw_summary)
            own_sessions.close_jump_masters.assert_called_once_with()

    def test_replace_main_current_release_reaches_only_the_bound_inspection_seam(self):
        with self._e1_public_main_case() as case:
            global_file = case.project / "01-global.yaml"
            public_hash_shape = "$6$PUBLIC$" + "a" * 86
            with global_file.open("a", encoding="ascii") as stream:
                stream.write("      aaa:\n        user:\n          admin:\n            password: '"
                             + public_hash_shape + "'\n")
            write_parent(case.project, case.release, json.loads(
                (case.release / "release-manifest.json").read_text(encoding="ascii")))
            token = "PUBLIC-NOT-A-REAL-PASSWORD"
            stop = "PUBLIC inspection stopped before transport"
            own_sessions = mock.Mock(spec_set=["close_jump_masters"])
            observed = []

            def model_qualification(policy):
                # Preserve the real unchanged check. The model never supplies
                # actual authenticated device evidence or performs a write.
                policy.assert_unchanged()
                return token

            def empty_jump_targets(targets, *_args, **_kwargs):
                self.assertEqual([], targets)
                return {}

            def stop_inspection(target, endpoint, _eth_user, _eth_password, ib_user,
                                _initial, _timeout, policy, *, apply, authorized, local,
                                strict, _management_private_key):
                coordinator = case.app._ACTIVE_COORDINATOR
                self.assertIs(type(coordinator), case.app.RuntimeCoordinator)
                self.assertIs(coordinator.current_target, target)
                self.assertIs(coordinator.policy, policy)
                self.assertIs(coordinator.authority, case.authorities[-1])
                self.assertIs(coordinator.args._replace_runtime_authority, coordinator.authority)
                self.assertIs(apply, True)
                self.assertIs(authorized, True)
                self.assertIs(strict, True)
                self.assertIs(local, False)
                self.assertEqual("admin", ib_user)
                self.assertEqual("203.0.113.11", endpoint.address)
                self.assertIsNone(endpoint.interface)
                self.assertIsNone(_management_private_key)
                observed.append(target.ib.hostname)
                raise case.app.SetupError(stop)

            with mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", model_qualification), \
                 mock.patch.object(case.app.RuntimeCoordinator, "authorize", case.deny), \
                 mock.patch.object(case.app, "_read_local_interfaces", return_value=()), \
                 mock.patch.object(case.app, "_new_jump_sessions", return_value=own_sessions), \
                 mock.patch.object(case.app, "prompt_ethernet_passwords", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "collect_jump_snapshot_passes", side_effect=empty_jump_targets), \
                 mock.patch.object(case.app, "resolve_initial_ib_password", return_value=token), \
                 mock.patch.object(case.app, "run_prepared_tasks", case.real_dispatch), \
                 mock.patch.object(case.app, "inspect_ib_device", side_effect=stop_inspection):
                code, text = self._e1_run_main(case, extra=(
                    "--apply", "--yes", "--max-workers", "1", "--direct-access", "EXAMPLE-IB001"))
            self.assertEqual(["EXAMPLE-IB001"], observed)
            self.assertEqual(2, code)
            summary_path, = case.report.parent.glob("devices-*/summary.json")
            raw_summary = summary_path.read_text()
            summary = json.loads(raw_summary)
            self.assertEqual("INCOMPLETE", summary["result"])
            self.assertEqual({"example-ib001"}, set(summary["records"]))
            row = summary["records"]["example-ib001"]
            self.assertEqual("FAILED", row["outcome"])
            self.assertEqual("WOULD_REPLACE", row["replace"]["verdict"])
            self.assertEqual(str(case.release / "EXAMPLE-IB001.yaml"), row["replace"]["file"])
            self.assertEqual(hashlib.sha256(yaml_bytes("EXAMPLE-IB001")).hexdigest(),
                             row["replace"]["sha256"])
            self.assertEqual("authentication", row["failed_stage"])
            self.assertEqual(stop, row["reason"])
            self.assertIs(row["writes_attempted"], False)
            self.assertIs(row["verified_complete"], False)
            self.assertIsNone(row["backup"])
            self.assertNotIn(token, text + raw_summary)
            own_sessions.close_jump_masters.assert_called_once_with()

    def test_replace_apply_main_rechecks_the_original_snapshot_after_project_qualification(self):
        with self._e1_public_main_case() as case:
            global_file = case.project / "01-global.yaml"
            public_hash_shape = "$6$PUBLIC$" + "a" * 86
            with global_file.open("a", encoding="ascii") as stream:
                stream.write("      aaa:\n        user:\n          admin:\n            password: '"
                             + public_hash_shape + "'\n")
            write_parent(case.project, case.release, json.loads(
                (case.release / "release-manifest.json").read_text(encoding="ascii")))
            token = "PUBLIC-NOT-A-REAL-PASSWORD"
            host = case.release / "EXAMPLE-IB001.yaml"
            qualified = []

            def model_qualification(policy):
                policy.assert_unchanged()
                qualified.append(policy)
                host.write_bytes(host.read_bytes() + b"\n# PUBLIC changed during qualification\n")
                return token

            with mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app.ProjectPasswordPolicy, "password", model_qualification), \
                 mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                code, text = self._e1_run_main(case, extra=("--apply", "--yes"))
            self.assertEqual(2, code)
            self.assertEqual(1, len(qualified))
            self.assertEqual(1, len(case.authorities))
            self.assertIn("input bytes changed:", text)
            self.assertIn("EXAMPLE-IB001.yaml", text)
            self.assertNotIn(token, text)
            self.assertFalse(case.snapshots.exists())
            self.assertEqual([], list(case.report.parent.glob("devices-*")))

    def test_public_release_workflow_feeds_real_replace_plan_without_native_inputs(self):
        # Keep this public-only producer/publisher/consumer witness independent
        # of the existing mixed authentication and apply tests.
        with self._e1_public_main_case() as case:
            output = case.project / "99-output-ib_nvl"
            produced = output / "20261119_162600-ib"
            service = case.root / "PUBLIC-service"
            (service / "template").mkdir(parents=True, mode=0o700)
            (service / "template/99-output-ib_nvl").symlink_to(output)
            (service / "template/01-global.yaml").symlink_to(case.project / "01-global.yaml")
            (service / "default.yaml").write_text(
                "- set:\n    system:\n      ztp:\n        config-save: enabled\n", encoding="ascii")
            master = case.project / "02-devices_config.csv"
            generator = load_script("d7_public_generator_" + format(id(case), "x"),
                ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py")
            publisher = load_script("d7_public_publisher_" + format(id(case), "x"),
                ROOT / "ztp/config/cumulus/d-hostname2mac.py")
            devices = [{"hostname": name, "eth0_ip": "203.0.113." + str(number),
                        "eth0_pfx": "24", "eth0_gw": "203.0.113.1", "has_eth1": False}
                       for name, number in (("EXAMPLE-IB001", 11), ("EXAMPLE-IB002", 12))]
            producer_log = io.StringIO()
            with redirect_stdout(producer_log), redirect_stderr(producer_log):
                counts = generator._generate_group_ib(devices,
                    {"system": {"ztp": {"config-save": "enabled"}}}, str(produced))
                inventory = publisher.load_csv(master, switch_scope="ib")
                publish_context = publisher._nvos_dir_context(
                    str(service / "template/99-output-ib_nvl" / produced.name))
                published = publisher._publish_single_nvos(
                    publish_context, inventory, switch_scope="ib")
            self.assertEqual((2, 0), counts)
            self.assertIs(published, True)
            self.assertEqual(produced, case.latest.resolve(strict=True))
            self.assertEqual(produced, (service / "latest_yaml").resolve(strict=True))
            host = produced / "EXAMPLE-IB001.yaml"
            digest = hashlib.sha256(host.read_bytes()).hexdigest()
            self.assertIn(b"hostname: EXAMPLE-IB001", host.read_bytes())
            self.assertEqual(host, (produced / "020000000011.yaml").resolve(strict=True))
            manifest = (produced / "release-manifest.json").read_bytes()
            marker = (produced / ".published-complete").read_bytes()
            rows = {item["hostname"]: item for item in json.loads(manifest)["devices"]}
            self.assertEqual({"EXAMPLE-IB001", "EXAMPLE-IB002"}, set(rows))
            self.assertEqual(digest, rows["EXAMPLE-IB001"]["config_sha256"])

            # Only the enclosing schema2 parent is test DATA, not a product load.
            # Its authority binds exact publisher output bytes; never rewrite the manifest.
            parent_path = case.project / "99-output-ztp/current-release.json"
            parent = json.loads(parent_path.read_text(encoding="ascii"))
            parent["components"]["nvos"] = {
                "release_id": "20261119_162600-nvos",
                "release_dir": "99-output-ib_nvl/20261119_162600-ib",
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "published_marker_sha256": hashlib.sha256(marker).hexdigest(),
            }
            parent_path.write_text(json.dumps(parent, sort_keys=True), encoding="ascii")
            with mock.patch.object(case.app.ProjectPasswordPolicy, "password", case.deny), \
                 mock.patch.object(case.app, "verify_password_hash", case.deny), \
                 mock.patch.object(case.app, "_new_jump_sessions", case.deny):
                code, text = self._e1_run_main(case, extra=("--plan",))
            self.assertEqual(0, code)
            self.assertIn(str(host), text)
            self.assertIn("sha256=" + digest, text)
            self.assertIn(WARNING, text)
            self.assertNotIn("EXAMPLE-IB002.yaml", text)
            self.assertFalse(case.snapshots.exists())
            self.assertEqual(manifest, (produced / "release-manifest.json").read_bytes())

    def test_replace_main_default_latest_resolves_the_real_script_chain_not_cwd(self):
        with self._e1_public_main_case(copied=True) as case:
            cwd = case.root / "unrelated-cwd"
            decoy_project, decoy_release, decoy_manifest = public_release(cwd)
            decoy = decoy_release / "EXAMPLE-IB001.yaml"
            decoy.write_bytes(yaml_bytes("PUBLIC-DECOY"))
            decoy_manifest["devices"][0]["config_sha256"] = hashlib.sha256(decoy.read_bytes()).hexdigest()
            write_parent(decoy_project, decoy_release, decoy_manifest)
            (cwd / "latest_yaml").symlink_to(decoy_release)
            previous = Path.cwd()
            try:
                os.chdir(cwd)
                code, text = self._e1_run_main(case, extra=("--plan",))
            finally:
                os.chdir(previous)
            self.assertEqual(0, code)
            self.assertIn(str(case.release / "EXAMPLE-IB001.yaml"), text)
            self.assertIn(hashlib.sha256(yaml_bytes("EXAMPLE-IB001")).hexdigest(), text)
            self.assertIn(WARNING, text)
            self.assertNotIn("PUBLIC-DECOY", text)
            self.assertNotIn(str(decoy_release), text)
            self.assertNotIn(base64.b64encode(yaml_bytes("EXAMPLE-IB001")).decode("ascii"), text)
            self.assertEqual("../../../ztp/config/nvos/latest_yaml", os.readlink(case.script.parent / "latest_yaml"))
            for name in ("device_identity", "hostname_ranges", "login_path", "inventory_subset"):
                self.assertEqual(case.copied_tools / (name + ".py"), Path(sys.modules["tools." + name].__file__).resolve())

    def test_replace_default_global_alias_cannot_retarget_after_initial_check_before_authority(self):
        for changed_bytes in (False, True):
            with self.subTest(changed_bytes=changed_bytes), self._e1_public_main_case(copied=True) as case:
                alias = case.script.parent / "01-global.yaml"
                original_global = case.project / "01-global.yaml"
                original_bytes = original_global.read_bytes()
                original_digest = hashlib.sha256(original_bytes).hexdigest()
                self.assertTrue(alias.is_symlink())
                self.assertEqual(original_global, alias.resolve(strict=True))
                alternate = case.root / "PUBLIC-alternate-global.yaml"
                alternate.write_bytes(original_bytes + (b"# PUBLIC alternate global\n" if changed_bytes else b""))
                self.assertEqual(not changed_bytes, alternate.read_bytes() == original_bytes)
                protected = [original_global, case.project / "ib.csv", case.project / "02-devices_config.csv",
                    case.project / "02-dhcp-subnet_config.csv", case.project / "p2p.xlsx",
                    case.project / "99-output-ztp/current-release.json", case.release / "release-manifest.json",
                    case.release / ".published-complete", case.release / "EXAMPLE-IB001.yaml",
                    case.release / "EXAMPLE-IB002.yaml"]
                before = {path: path.read_bytes() for path in protected}
                global_hashes, constructor_calls = [], []
                real_hash = case.app._file_sha256
                observed_init = case.app.RuntimeInputAuthority.__init__
                def observe_hash(path):
                    digest = real_hash(path)
                    if Path(path).resolve(strict=True) == original_global:
                        global_hashes.append(digest)
                    return digest
                def retarget_before_real_init(instance, paths):
                    # The validator's project-global read and MAIN's actual
                    # profile-global read must both have completed first.
                    self.assertGreaterEqual(len(global_hashes), 2)
                    self.assertTrue(all(value == original_digest for value in global_hashes))
                    self.assertEqual([], constructor_calls)
                    self.assertEqual(original_global, alias.resolve(strict=True))
                    constructor_calls.append("retarget-before-original-init")
                    alias.unlink()
                    alias.symlink_to(alternate)
                    observed_init(instance, paths)  # Original observer AND real constructor.
                with mock.patch.object(case.app, "_file_sha256", side_effect=observe_hash), \
                        mock.patch.object(case.app.RuntimeInputAuthority, "__init__", retarget_before_real_init):
                    code, text = self._e1_run_main(case, extra=("--plan",))
                self.assertEqual(["retarget-before-original-init"], constructor_calls)
                self.assertEqual(1, len(case.authorities), "the real authority constructor must finish once")
                self.assertEqual(alternate, alias.resolve(strict=True))
                self.assertEqual(2, code, "newly sampled alias bytes cannot self-authorize a different global")
                self.assertIn("input changed", text.casefold())
                self.assertIn("load", text.casefold())
                self.assertNotIn("awaits verified", text)
                self.assertFalse(case.cache.exists(), "reject before any profile/cache generation")
                self.assertFalse(case.cache.with_name(case.cache.name + ".sha256").exists())
                self.assertEqual(before, {path: path.read_bytes() for path in protected})
                self.assertEqual([], case.effects)

    def test_d7_typed_program_literals_exact_vectors_and_closed_near_misses(self):
        from test_cases.test_initial_setup_identity_and_backup import (
            EXPECTED_LAUNCH_SCRIPT, EXPECTED_READ_RC_SCRIPT)

        class PublicString(str):
            pass

        class PublicList(list):
            pass

        stamp = "20261118-010203"
        programs = (("launch", EXPECTED_D7_LAUNCH_SCRIPT, "nvue", "_REPLACE_DEFERRED_APPLY_SCRIPT"),
                    ("reader", EXPECTED_D7_READ_RC_SCRIPT, None, "_REPLACE_DEFERRED_RC_SCRIPT"))
        rejected = 0
        for name, program, category, symbol in programs:
            valid = ["sh", "-c", program, "--", stamp]
            with self.subTest(program=name, vector="exact"):
                self.assertEqual(program, getattr(self.app, symbol))
                self.assertEqual(valid, self.app.ib_command_argv(valid))
                self.assertEqual(category, self.app._ib_write_category(valid))
            variants = (tuple(valid), valid[:-1], [*valid, stamp],
                ["bash", *valid[1:]], [valid[0], "-lc", *valid[2:]],
                [*valid[:3], "x", stamp], [*valid[:2], program + " ", "--", stamp],
                [*valid[:2], program[:-1], "--", stamp], [*valid[:2], program + "\n", "--", stamp],
                [*valid[:2], program + "\0", "--", stamp], [*valid[:4], "20261118_010203"],
                [*valid[:4], stamp + "\n"], [*valid[:4], stamp + ";PUBLIC"],
                [*valid[:4], None], [*valid[:4], PublicString(stamp)], PublicList(valid))
            self.assertEqual(16, len(variants))
            for number, supplied in enumerate(variants, 1):
                with self.subTest(program=name, near_miss=number), self.assertRaises(self.app.SetupError):
                    self.app.ib_command_argv(supplied)
                rejected += 1
        self.assertEqual(32, rejected)
        for name, program, category in (("old-launch", EXPECTED_LAUNCH_SCRIPT, "nvue"),
                                         ("old-reader", EXPECTED_READ_RC_SCRIPT, None)):
            with self.subTest(program=name):
                command = ["sh", "-c", program, "--", stamp]
                self.assertEqual(command, self.app.ib_command_argv(command))
                self.assertEqual(category, self.app._ib_write_category(command))
        self.assertEqual([], self.effects)

    def test_d7_typed_receipt_parser_exact_pairs_and_malformed_wires(self):
        parse = self.app._parse_replace_completion
        accepted = (("rc=\nfailed_operation=pending\n", (None, "pending")),
            ("rc=0\nfailed_operation=none\n", (0, "none")),
            ("rc=1\nfailed_operation=apply\n", (1, "apply")),
            ("rc=7\nfailed_operation=apply\n", (7, "apply")),
            ("rc=255\nfailed_operation=apply\n", (255, "apply")),
            ("rc=1\nfailed_operation=save\n", (1, "save")),
            ("rc=7\nfailed_operation=save\n", (7, "save")),
            ("rc=255\nfailed_operation=save\n", (255, "save")))
        rejected = ("", "rc=\n", "rc=0\n", "rc=7\n", "rc=0\nfailed_operation=none",
            "rc=0failed_operation=none\n", "rc=0\nfailed_operation=none\nextra\n",
            "rc=0\nfailed_operation=none\n\n", "rc=0\r\nfailed_operation=none\r\n",
            "failed_operation=none\nrc=0\n", "rc=0\nrc=0\n",
            "rc=7\nfailed_operation=other\n", "rc=7\nfailed_operation=Apply\n",
            "rc=0\nfailed_operation=apply\n", "rc=0\nfailed_operation=save\n",
            "rc=7\nfailed_operation=none\n", "rc=\nfailed_operation=none\n",
            "rc=0\nfailed_operation=pending\n", "rc=7\nfailed_operation=pending\n",
            "rc=-7\nfailed_operation=apply\n", "rc=+7\nfailed_operation=apply\n",
            "rc=07\nfailed_operation=apply\n", "rc=256\nfailed_operation=apply\n",
            "rc=\u0667\nfailed_operation=apply\n", "rc= 7\nfailed_operation=apply\n",
            "rc=0\nfailed_operation=none\n\0", "rc=7\0\nfailed_operation=apply\n",
            "rc=7\nfailed_operation=apply \n", "rc=7\nfailed_operation=\n",
            "extra\nrc=0\nfailed_operation=none\n")
        self.assertEqual((8, 30), (len(accepted), len(rejected)))
        for number, (wire, expected) in enumerate(accepted, 1):
            with self.subTest(accepted=number):
                actual = parse(wire)
                self.assertIs(type(actual), tuple)
                self.assertEqual(expected, actual)
                self.assertIs(type(actual[1]), str)
                if expected[0] is None:
                    self.assertIsNone(actual[0])
                else:
                    self.assertIs(type(actual[0]), int)
        for number, wire in enumerate(rejected, 1):
            with self.subTest(rejected=number), self.assertRaises(self.app.SetupError):
                parse(wire)
        self.assertEqual([], self.effects)

    def test_replace_execution_requires_current_runtime_authority_before_inspection(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        previous_config = object()
        marker = "PUBLIC fixture stopped at the inspection boundary"

        for scenario in ("missing", "wrong-type", "stale", "valid"):
            with self.subTest(scenario=scenario):
                args = SimpleNamespace(
                    config_mode="replace", apply=False, ib_user="admin",
                    eth_user="admin", execution_mode="management", connect_timeout=10,
                    run_stamp="20261118-010203",
                    _replace_selected={"example-ib001": {
                        "verdict": "WOULD_REPLACE",
                        "file": str(selected),
                        "sha256": hashlib.sha256(yaml_bytes("EXAMPLE-IB001")).hexdigest(),
                        "reason": "",
                    }},
                )
                bound = self.root / ("public-authority-" + scenario)
                if scenario == "wrong-type":
                    args._replace_runtime_authority = object()
                elif scenario in ("stale", "valid"):
                    bound.write_bytes(b"PUBLIC original input\n")
                    args._replace_runtime_authority = app.RuntimeInputAuthority([bound])
                    if scenario == "stale":
                        bound.write_bytes(b"PUBLIC changed input with a different size\n")
                calls = []

                def stop_at_inspection(device, neighbor, *_args, **kwargs):
                    calls.append((device, neighbor, kwargs["apply"]))
                    raise app.SetupError(marker)

                with mock.patch.object(app, "inspect_ib_device", stop_at_inspection), \
                        mock.patch.object(app, "_TASK_IB_CONFIG", previous_config):
                    result = app.execute_ib_task(task, args, None, "", None, [], None)
                    self.assertIs(app._TASK_IB_CONFIG, previous_config)
                self.assertEqual([(target, endpoint, False)] if scenario == "valid" else [], calls)
                self.assertEqual("FAILED", result["outcome"])
                self.assertFalse(result["writes_attempted"])
                self.assertIsNone(result["backup"])
                self.assertIsNone(result["identity"])
                self.assertFalse(result["verified_complete"])
                if scenario == "valid":
                    self.assertEqual(marker, result["reason"])
                    self.assertEqual("", result["batch_error"])
                elif scenario == "stale":
                    self.assertEqual(f"input bytes changed: {bound}", result["batch_error"])
                    self.assertEqual(result["batch_error"], result["reason"])
                    self.assertEqual("UNVERIFIED", result["stage_status"]["authentication"])
                else:
                    self.assertTrue(result["reason"], "unqualified replace context must report its failure")
                    self.assertEqual("", result["batch_error"])
                self.assertEqual([], self.effects)

    def test_replace_plan_warns_in_every_device_block(self):
        expected = {"EXAMPLE-IB001": "YAML_MISSING_OR_INVALID", "EXAMPLE-IB002": "WOULD_REPLACE"}
        with self._e1_public_main_case(missing_host=True) as case:
            selector = case.argv.index("--devices")
            del case.argv[selector:selector + 2]
            code, text = self._e1_run_main(case, extra=("--plan",))
            self.assertEqual(0, code)

            blocks = []
            for line in text.splitlines():
                names = [name for name in expected if f"[{name}]" in line]
                self.assertLessEqual(len(names), 1, line)
                if names and (not blocks or blocks[-1][0] != names[0]):
                    blocks.append((names[0], []))
                if blocks:
                    blocks[-1][1].append(line)
            self.assertCountEqual(list(expected), [name for name, _ in blocks])
            for name, lines in blocks:
                with self.subTest(device=name):
                    block = "\n".join(lines)
                    self.assertIn(expected[name], block)
                    self.assertIn(name + ".yaml", block)
                    self.assertNotIn("default_ib.yaml", block)
                    self.assertEqual(1, block.count(WARNING), block)

    def test_replace_readonly_unusable_yaml_warns_without_device_work(self):
        app = self.app
        target = self.target()
        unavailable = self.release / "EXAMPLE-IB001.yaml"
        unavailable.unlink()
        expected_selection = {"verdict": "YAML_MISSING_OR_INVALID",
                              "file": str(unavailable), "sha256": "", "reason": YAML_ERROR}
        selection = self.select(target=target)
        self.assertEqual(expected_selection, selection)
        authority = app.RuntimeInputAuthority([self.project / "01-global.yaml",
                                               self.release / "EXAMPLE-IB002.yaml"])
        args = SimpleNamespace(config_mode="replace", apply=False, ib_user="admin",
                               eth_user="admin", execution_mode="management", connect_timeout=10,
                               run_stamp="20261118-010203", _replace_runtime_authority=authority,
                               _replace_selected={"example-ib001": selection})
        task = app.PreparedIBTask(target, app.DirectEndpoint("203.0.113.11"), "", False)
        device_log = []
        with ExitStack() as guards:
            guards.enter_context(mock.patch.object(app, "_TASK_LOG_BUFFER", device_log))
            for boundary in ("inspect_ib_device", "_stage_ib_command", "obtain_write_permit"):
                guards.enter_context(mock.patch.object(app, boundary, self.deny))
            result = app.execute_ib_task(task, args, None, "", None, [], None)

        self.assertEqual([], self.effects)
        self.assertEqual("CHECK_ONLY", result["outcome"])
        self.assertEqual(expected_selection, result["replace"])
        self.assertEqual(YAML_ERROR, result["reason"])
        self.assertEqual("NOT_REACHED", result["stage_status"]["authentication"])
        self.assertIsNone(result["identity"])
        self.assertIsNone(result["backup"])
        self.assertFalse(result["writes_attempted"])
        self.assertFalse(result["verified_complete"])
        self.assertEqual([], result["direct_rows"])
        text = "\n".join(device_log)
        self.assertIn("[EXAMPLE-IB001]", text)
        self.assertEqual(1, text.count(WARNING), text)

    def test_replace_readonly_default_console_reports_device_warning_once(self):
        app = self.app
        target = self.target()
        unavailable = self.release / "EXAMPLE-IB001.yaml"
        unavailable.unlink()
        expected_selection = {"verdict": "YAML_MISSING_OR_INVALID",
                              "file": str(unavailable), "sha256": "", "reason": YAML_ERROR}
        selection = self.select(target=target)
        self.assertEqual(expected_selection, selection)
        authority = app.RuntimeInputAuthority([self.project / "01-global.yaml",
                                               self.release / "EXAMPLE-IB002.yaml"])
        report_path = self.root / "report.log"
        args = SimpleNamespace(config_mode="replace", apply=False, yes=False,
                               ib_user="admin", eth_user="admin", execution_mode="management",
                               connect_timeout=10, run_stamp="20261118-010203", report=str(report_path),
                               max_workers=1, verbose=False, _replace_runtime_authority=authority,
                               _replace_selected={"example-ib001": selection})
        task = app.PreparedIBTask(target, app.DirectEndpoint("203.0.113.11"), "", False)
        output = io.StringIO()
        with report_path.open("x", encoding="utf-8") as report, ExitStack() as guards:
            guards.enter_context(mock.patch.object(app, "REPORT_HANDLE", report))
            guards.enter_context(redirect_stdout(output))
            guards.enter_context(mock.patch.object(app, "multiprocessing",
                Facade(app.multiprocessing, get_context=self.deny, Process=self.deny)))
            for boundary in ("inspect_ib_device", "_stage_ib_command", "obtain_write_permit"):
                guards.enter_context(mock.patch.object(app, boundary, self.deny))
            run = app.run_prepared_tasks([task], args, None, "", None, [], None, authority=authority)

        self.assertEqual([], self.effects)
        self.assertEqual(1, run["workers"])
        self.assertEqual("", run["fatal"])
        self.assertEqual({"example-ib001": "CHECK_ONLY"}, run["outcomes"])
        self.assertEqual({"example-ib001"}, set(run["records"]))
        self.assertEqual([], run["direct_rows"])
        record = run["records"]["example-ib001"]
        self.assertEqual("EXAMPLE-IB001", record["hostname"])
        self.assertEqual("CHECK_ONLY", record["outcome"])
        self.assertEqual("replace", record["config_mode"])
        self.assertEqual(expected_selection, record["replace"])
        self.assertEqual(YAML_ERROR, record["reason"])
        self.assertEqual("NOT_REACHED", record["stage_status"]["authentication"])
        self.assertIs(record["needs_change"], True)
        self.assertIsNone(record["identity"])
        self.assertIsNone(record["backup"])
        self.assertFalse(record["writes_attempted"])
        self.assertFalse(record["verified_complete"])
        self.assertEqual([], record["direct_rows"])

        log_dir = Path(run["log_dir"]).resolve(strict=True)
        self.assertEqual(self.root.resolve(), log_dir.parent)
        local_path = Path(record["log"])
        self.assertEqual(log_dir, local_path.resolve(strict=True).parent)
        local = local_path.read_text(encoding="utf-8")
        self.assertIn("[EXAMPLE-IB001]", local)
        self.assertIn(WARNING, local)
        aggregate = report_path.read_text(encoding="utf-8")
        _, begin, after_begin = aggregate.partition("===== DEVICE LOG BEGIN: EXAMPLE-IB001 =====")
        self.assertTrue(begin, aggregate)
        device_section, end, _ = after_begin.partition("===== DEVICE LOG END: EXAMPLE-IB001 ")
        self.assertTrue(end, aggregate)
        self.assertIn(WARNING, device_section)

        terminal = output.getvalue()
        self.assertNotIn("===== DEVICE LOG ", terminal)
        self.assertNotIn("IB direct path:", terminal)
        lines = terminal.splitlines()
        done = [index for index, line in enumerate(lines)
                if line.startswith("[DONE ") and " EXAMPLE-IB001:" in line]
        self.assertEqual(1, len(done), terminal)
        self.assertEqual(1, terminal.count(WARNING), terminal)
        self.assertIn(WARNING, "\n".join(lines[done[0]:]), terminal)

    def test_replace_restore_services_keeps_default_and_verifies_auto_save(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        enable = ["nv", "set", "system", "config", "auto-save", "state", "enabled"]
        apply_config = ["nv", "config", "apply", "-y"]
        save_config = ["nv", "config", "save"]
        read_config = ["nv", "config", "show", "-o", "commands"]
        disabled = "nv set system config auto-save state disabled\n"
        enabled = "nv set system config auto-save state enabled\n"
        present = (enabled + "nv set system dns server 203.0.113.53\n"
                   "nv set system ntp server 203.0.113.54\n"
                   "nv set system date-time timezone Etc/UTC\n")
        profile = {"dns": ["203.0.113.53"], "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}
        restore_steps = [enable, apply_config, save_config, read_config]
        for label, options, services, current, observed, expected_steps, expected_return in (
                ("default-no-profile", {}, None, disabled, "", [], (True, True)),
                ("restore-no-profile", {"_replace_restore": True}, None,
                 disabled, enabled, restore_steps, (True, False)),
                ("restore-already-complete", {"_replace_restore": True}, profile,
                 present, "", [], (True, True)),
                ("restore-readback-still-disabled", {"_replace_restore": True}, None,
                 disabled, disabled, restore_steps, None)):
            with self.subTest(case=label):
                calls = []

                def stage(device, neighbor, eth_user, eth_password, ib_user, ib_password,
                          timeout, command, *, local, strict, policy=None):
                    self.assertIs(target, device)
                    self.assertEqual(endpoint, neighbor)
                    self.assertEqual(("", "", "admin", "", 10), (
                        eth_user, eth_password, ib_user, ib_password, timeout))
                    self.assertIs(local, False)
                    self.assertIs(strict, False)
                    self.assertIsNone(policy)
                    if command not in restore_steps:
                        return self.deny()
                    calls.append(list(command))
                    return app.SessionResult(observed if command == read_config else "", 0)

                def invoke():
                    return app.run_service_stage(target, endpoint, "", "", "admin", 10,
                        services, current, local=False, apply=True, authorized=True, ib_password="", **options)

                with mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    if expected_return is None:
                        with self.assertRaisesRegex(app.IBConfigurationStageUncertain,
                                                    "services were not fully verified"):
                            invoke()
                    else:
                        self.assertEqual(expected_return, invoke())
                self.assertEqual(expected_steps, calls)
                self.assertEqual([], self.effects)

    def test_replace_restore_rejects_indeterminate_local_configuration(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        scenarios = (
            ("truncated-fact", None,
             "nv set system hostname EXAMPLE-IB001\nnv set system config\n"),
            ("unreadable-configuration", {"dns": ["203.0.113.53"],
             "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}, None),
        )
        for label, profile, observation in scenarios:
            with self.subTest(case=label):
                attempted = []

                def stage(*_args, **_kwargs):
                    attempted.append("stage")
                    raise app.SetupError("PUBLIC model declined action on indeterminate input")

                with mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    with self.assertRaises(app.SetupError):
                        app.run_service_stage(target, endpoint, "", "", "admin", 10,
                            profile, observation, local=False, apply=True,
                            authorized=True, ib_password="", _replace_restore=True)
                self.assertEqual([], attempted)
                self.assertEqual([], self.effects)

    def test_replace_restore_checks_empty_pending_before_services_transaction(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        profile = {"dns": ["203.0.113.53"], "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}
        enable = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
        ntp = ("nv", "set", "system", "ntp", "server", "203.0.113.54")
        pending = ("nv", "config", "diff", "-o", "commands")
        apply_config = ("nv", "config", "apply", "-y")
        save_config = ("nv", "config", "save")
        read_config = ("nv", "config", "show", "-o", "commands")
        dns_timezone = ("nv set system dns server 203.0.113.53\n"
                        "nv set system date-time timezone Etc/UTC\n")
        missing = "nv set system config auto-save state disabled\n" + dns_timezone
        present = ("nv set system config auto-save state enabled\n"
                   "nv set system ntp server 203.0.113.54\n" + dns_timezone)
        for label, rc, diff, configured, current, expected, result in (
                ("missing-services", 0, "", profile, missing,
                 [pending, enable, ntp, apply_config, save_config, read_config], (True, False)),
                ("no-profile", 0, "", None, missing,
                 [pending, enable, apply_config, save_config, read_config], (True, False)),
                ("already-complete", 0, "", profile, present, [pending], (True, True)),
                ("same-value-pending-is-not-owned", 0, "nv set system config auto-save state enabled\n",
                 None, missing, [pending], None),
                ("unreadable-pending-is-not-empty", 1, "", None, missing, [pending], None)):
            with self.subTest(case=label):
                calls = []

                def read_pending(device, neighbor, eth_user, eth_password, ib_user, ib_password,
                                 timeout, argv, *, local, allow_password_change):
                    self.assertEqual((target, endpoint, "", "", "admin", "", 10),
                                     (device, neighbor, eth_user, eth_password, ib_user, ib_password, timeout))
                    self.assertIs(local, False)
                    self.assertIs(allow_password_change, False)
                    self.assertEqual(pending, tuple(argv))
                    calls.append(tuple(argv))
                    return app.SessionResult(diff, rc)

                def stage(device, neighbor, eth_user, eth_password, ib_user, ib_password,
                          timeout, command, *, local, strict, policy=None):
                    self.assertEqual((target, endpoint, "", "", "admin", "", 10),
                                     (device, neighbor, eth_user, eth_password, ib_user, ib_password, timeout))
                    self.assertIs(local, False)
                    self.assertIs(strict, False)
                    self.assertIsNone(policy)
                    argv = tuple(command)
                    if argv not in (enable, ntp, apply_config, save_config, read_config):
                        return self.deny()
                    calls.append(argv)
                    return app.SessionResult(present if argv == read_config else "", 0)

                def invoke():
                    return app._restore_replace_services(target, endpoint, "", "", "admin", "", 10,
                                                         configured, current, local=False, authorized=True)

                with mock.patch.object(app, "run_on_ib", read_pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    if result is None:
                        with self.assertRaisesRegex(app.SetupError, "pre-existing pending configuration"):
                            invoke()
                    else:
                        self.assertEqual(result, invoke())
                self.assertEqual(expected, calls)
                self.assertEqual([], self.effects)

    def test_replace_restore_requires_existing_authorization_before_pending(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        with mock.patch.object(app, "run_on_ib", self.deny), \
                mock.patch.object(app, "_stage_ib_command", self.deny), \
                mock.patch.object(app, "confirm_first_device_change", self.deny):
            with self.assertRaisesRegex(app.SetupError, "requires existing authorization"):
                app._restore_replace_services(target, endpoint, "", "", "admin", "", 10,
                    None, "nv set system config auto-save state disabled\n", local=False, authorized=False)
        self.assertEqual([], self.effects)

    def test_replace_command_receipt_binds_verified_backup_parent_and_yaml_digest(self):
        app = self.app
        # SHA256 of the fixed independent byte fixture b"abc"; not obtained from
        # a replace command, response, local HOME or generated expected path.
        digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        backup_path = "/devices/PUBLIC-IB001/current_20261119-031124.yaml"
        path = "path=/devices/PUBLIC-IB001/initial-setup-replace.yaml\n"
        sha = "sha256=" + digest + "\n"
        receipt = path + sha
        invoke = lambda result: app._verify_replace_command_receipt(result, backup_path, digest)
        self.assertIsNone(invoke(app.SessionResult(receipt, 0)))
        negatives = [
            ("different-parent", app.SessionResult(
                "path=/devices/PUBLIC-IB002/initial-setup-replace.yaml\n" + sha, 0)),
            ("different-name", app.SessionResult(
                "path=/devices/PUBLIC-IB001/another.yaml\n" + sha, 0)),
            ("wrong-bytes", app.SessionResult(path + "sha256=" + "0" * 64 + "\n", 0)),
            ("extra", app.SessionResult(receipt + "PUBLIC extra\n", 0)),
            ("missing-final-line-end", app.SessionResult(receipt[:-1], 0)),
            ("wrong-order", app.SessionResult(sha + path, 0)),
            ("exit-nonzero", app.SessionResult(receipt, 7)),
            ("bool-not-exit-code", app.SessionResult(receipt, False)),
            ("bytes-not-text", app.SessionResult(receipt.encode("ascii"), 0)),
            ("not-a-session", SimpleNamespace(output=receipt, exit_code=0)),
        ]
        for flag in ("password_changed", "password_change_required",
                     "password_change_attempted", "ib_authentication_rejected"):
            negatives.append((flag, app.SessionResult(receipt, 0, **{flag: True})))
        negatives.append(("non-bool-auth-fact", app.SessionResult(receipt, 0, password_changed=None)))
        for label, result in negatives:
            with self.subTest(case=label), self.assertRaises(app.SetupError):
                invoke(result)
        self.assertEqual([], self.effects)

    def test_replace_failure_detach_candidate_requires_proven_stage_and_nonzero_rc(self):
        app = self.app
        # The positive pairs are already proven command/operation evidence, not
        # transport return codes, unqualified errors, or permission to detach.
        cases = (("replace", 7, True), ("apply", 7, True), ("apply", 255, True),
                 ("replace", 1, True), ("save", 7, False), ("restore", 7, False),
                 ("post-ztp", 7, False), ("launch", 7, False), ("pending", 7, False),
                 (None, 7, False), ("unknown", 7, False), ("apply", None, False),
                 ("apply", 0, False), ("apply", True, False), ("apply", "7", False),
                 ("apply", -1, False), ("apply", 256, False), ("Apply", 7, False))
        for operation, rc, expected in cases:
            with self.subTest(operation=operation, rc=rc):
                self.assertIs(expected, app._replace_failure_is_detach_candidate(operation, rc))
        self.assertEqual([], self.effects)

    def test_replace_sync_failure_evidence_requires_current_scope_and_verified_frame(self):
        app = self.app
        marker = "PUBLIC_SYNC_1"
        # These are fixed model observations, not an invocation of the transport.
        frame = "__HTTP_IB_BEGIN_PUBLIC_SYNC_1__\n\n__HTTP_IB_END_PUBLIC_SYNC_1__=7\n"
        task, different_task = object(), object()
        endpoint = app.DirectEndpoint("fe80::11", "public0")
        different_endpoint = app.DirectEndpoint("fe80::12", "public0")
        apply = app._ReplaceSyncFailureScope(task, endpoint, "apply", marker)
        save = app._ReplaceSyncFailureScope(task, endpoint, "save", marker)
        replace = app._ReplaceSyncFailureScope(task, endpoint, "replace", marker)
        unsupported = app._ReplaceSyncFailureScope(task, endpoint, "pending", marker)
        old_dispatch = app._ReplaceSyncFailureScope(task, endpoint, "apply", marker)
        other_task = app._ReplaceSyncFailureScope(different_task, endpoint, "apply", marker)
        other_endpoint = app._ReplaceSyncFailureScope(task, different_endpoint, "apply", marker)
        result = app.SessionResult(frame, 7)
        uncertain = app.SetupError("PUBLIC cleanup absent")
        uncertain.cleanup_uncertain = True
        # Transport errors carry errno independently. Even the same numeric value
        # as a modeled device status must not substitute for command provenance.
        cases = (
            ("apply", apply, apply, result, {}, ("apply", 7)),
            ("save", save, save, result, {}, ("save", 7)),
            ("replace-without-operation-receipt", replace, replace, result, {}, None),
            ("unsupported", unsupported, unsupported, result, {}, None),
            ("different-phase", apply, save, result, {}, None),
            ("previous-dispatch", apply, old_dispatch, result, {}, None),
            ("different-task", apply, other_task, result, {}, None),
            ("different-endpoint", apply, other_endpoint, result, {}, None),
            ("bare-code", apply, apply, app.SessionResult("", 7), {}, None),
            ("incomplete", apply, apply, app.SessionResult("__HTTP_IB_BEGIN_PUBLIC_SYNC_1__\n", 7), {}, None),
            ("wrong-marker", apply, apply, app.SessionResult(frame.replace("SYNC_1", "SYNC_2"), 7), {}, None),
            ("mismatched-code", apply, apply, app.SessionResult(frame, 8), {}, None),
            ("duplicate-frame", apply, apply, app.SessionResult(frame * 2, 7), {}, None),
            ("success-is-not-failure", apply, apply, app.SessionResult(frame.replace("=7", "=0"), 0), {}, None),
            ("authentication", apply, apply, app.SessionResult(frame, 7, ib_authentication_rejected=True), {}, None),
            ("cancelled", apply, apply, result, {"cancelled": True}, None),
            ("input-changed", apply, apply, result, {"input_changed": True}, None),
            ("transport-errno", apply, apply, result, {"transport_error": OSError(7, "PUBLIC fixture")}, None),
            ("cleanup-uncertain", apply, apply, result, {"transport_error": uncertain}, None),
        )
        for name, active, observed, reply, options, expected in cases:
            with self.subTest(case=name):
                before = vars(reply).copy()
                self.assertEqual(expected, app._qualify_replace_sync_failure(
                    reply, active, observed, **options))
                self.assertEqual(before, vars(reply))
        self.assertEqual([], self.effects)

    def test_sync_replace_qualification_requires_operation_receipt_not_staging_failure(self):
        app = self.app
        task = object()
        endpoint = app.DirectEndpoint("fe80::11", "public0")
        begin = "__HTTP_IB_BEGIN_PUBLIC_REPL_1__\n"
        end = "__HTTP_IB_END_PUBLIC_REPL_1__="
        receipt = "rc=7\nfailed_operation=replace\n"
        for name, operation, body, framed_rc, return_code, expected in (
                ("replace-returned", "replace", receipt, 1, 1, ("replace", 7)),
                ("prepare-failed", "replace", "IB configuration replace failed\n", 1, 1, None),
                ("no-proof", "replace", "", 1, 1, None),
                ("duplicate", "replace", receipt * 2, 1, 1, None),
                ("other-phase", "replace", "rc=7\nfailed_operation=apply\n", 1, 1, None),
                ("extra-body", "replace", receipt + "PUBLIC unmatched\n", 1, 1, None),
                ("other-wrapper-status", "replace", receipt, 2, 2, None),
                ("frame-does-not-match", "replace", receipt, 1, 7, None),
                ("not-a-device-failure", "replace", "rc=0\nfailed_operation=replace\n", 1, 1, None),
                ("noncanonical-device-status", "replace", "rc=07\nfailed_operation=replace\n", 1, 1, None),
                ("shell-refused", "replace", "rc=126\nfailed_operation=replace\n", 1, 1, None),
                ("shell-missing", "replace", "rc=127\nfailed_operation=replace\n", 1, 1, None),
                ("interrupted", "replace", "rc=143\nfailed_operation=replace\n", 1, 1, None),
                ("apply-retains-frame-contract", "apply", "", 7, 7, ("apply", 7)),
                ("save-retains-frame-contract", "save", "", 7, 7, ("save", 7))):
            with self.subTest(case=name):
                scope = app._ReplaceSyncFailureScope(task, endpoint, operation, "PUBLIC_REPL_1")
                reply = app.SessionResult(begin + body + end + str(framed_rc) + "\n", return_code)
                original = vars(reply).copy()
                self.assertEqual(expected, app._qualify_replace_sync_failure(reply, scope, scope))
                self.assertEqual(original, vars(reply))
        self.assertEqual([], self.effects)

    def test_nested_replace_sync_failure_provenance_stays_on_original_error_path(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = app.Target(ib, jump, "swp1", "eth0")
        endpoint = app.Neighbor("fe80::11", "public0", MACS[0], "oob")
        task = app.PreparedIBTask(target, endpoint, "", False)
        state = app._IBConfigWriteState(task, "admin", "cumulus", "20261119-035125", True,
            endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
            backup_state="VERIFIED", backup_receipt={
                "path": "/devices/PUBLIC/current_20261119-035125.yaml", "bytes": 137})
        # Fixed local nonce, independent of the production builder or parser.
        nonce = "12121212121212121212121212121212"
        frame = ("__HTTP_IB_BEGIN_" + nonce + "__\nPUBLIC action failed\n"
                 "__HTTP_IB_END_" + nonce + "__=7\n")
        replace_start = "__HTTP_IB_BEGIN_" + nonce + "__\n"
        replace_end = "__HTTP_IB_END_" + nonce + "__=1\n"
        replace_receipt = replace_start + "rc=7\nfailed_operation=replace\n" + replace_end
        foreign_detail = "rc=7\nfailed_operation=apply"
        preparation_failure = "IB configuration replace failed"
        replace_argv = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--", "YWJj",
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]
        cases = (
            ("apply", "apply", frame, {}, (True, True), ("apply", 7)),
            ("save", "save", frame, {}, (True, True), ("save", 7)),
            ("replace-nvue", "replace", replace_receipt, {}, (True, True), ("replace", 7)),
            ("replace-unopted", "replace", replace_receipt, {}, (False, True), None),
            ("replace-late-stop", "replace", replace_receipt, {}, (True, True), None),
            ("replace-foreign-detail", "replace", replace_start + foreign_detail + "\n" + replace_end,
             {}, (True, True), None),
            ("replace-prepare", "replace", replace_start + preparation_failure + "\n" + replace_end,
             {}, (True, True), None),
            ("legacy", "apply", frame, {}, (False, True), None),
            ("stale-task", "apply", frame, {}, (True, True), None),
            ("unframed", "apply", "PUBLIC action failed\n", {}, (True, True), None),
            ("auth-state", "apply", frame, {"password_change_attempted": True}, (True, True), None),
            ("changed-input", "apply", frame, {}, (True, False), None),
        )
        for strict in (False, True):
            for name, operation, output, flags, (opt_in, unchanged), expected in cases:
                if not strict and not unchanged:
                    continue  # The non-strict API has no project policy.
                with self.subTest(strict=strict, case=name):
                    events = []
                    policy_checks = []
                    cancellations = []
                    exit_code = 1 if operation == "replace" else 7

                    def captured(vector, responder, timeout):
                        self.assertIs(type(vector), list)
                        self.assertEqual("admin@fe80::11", responder.ib_destination)
                        self.assertIn("__HTTP_IB_BEGIN_" + nonce + "__", vector[-1])
                        self.assertEqual(60, timeout)
                        events.append("transport-model")
                        return app.SessionResult(output, exit_code, **flags)

                    def check_project():
                        post_transport = "transport-model" in events
                        policy_checks.append(post_transport)
                        if not unchanged and post_transport:
                            raise app.ProjectInputChanged("PUBLIC changed")

                    def check_cancelled():
                        if name == "replace-late-stop" and "transport-model" in events:
                            cancellations.append("after transport")
                            raise app.BatchStopped("PUBLIC stopped after receipt")

                    policy = SimpleNamespace(assert_unchanged=check_project)
                    invoke = app._run_authorized_ib_command if strict else app.run_on_ib
                    options = {"_password_policy": policy} if strict else {}
                    if opt_in:
                        options["_replace_sync_failure_task"] = app.replace(state) if name == "stale-task" else state
                    command = (replace_argv if operation == "replace" else
                               ["nv", "config", operation] + (["-y"] if operation == "apply" else []))
                    with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                            mock.patch.object(app, "check_task_cancelled", check_cancelled), \
                            mock.patch.object(app, "os", Facade(app.os, urandom=lambda count: b"\x12" * count)), \
                            mock.patch.object(app, "_ib_project_value", return_value="PUBLIC-POLICY"), \
                            mock.patch.object(app, "_ensure_ib_config_backup",
                                              side_effect=lambda *_a, **_k: events.append("backup-check")), \
                            mock.patch.object(app, "obtain_write_permit",
                                              side_effect=lambda category: events.append(category)), \
                            mock.patch.object(app, "interactive_run", captured), \
                            mock.patch.object(app, "_AUTHORIZED_FAILURE_NOTE", []):
                        with self.assertRaises(app.SetupError) as caught:
                            invoke(target, endpoint, "cumulus", "", "admin", "PUBLIC-MODEL-VALUE",
                                   10, command, **options)
                        public_summary = app._authorized_failure_text(caught.exception)
                        error = caught.exception
                        self.assertIs(type(error), app.SetupError)
                        self.assertEqual(expected, getattr(error, "_replace_sync_failure", None))
                        self.assertEqual(["backup-check", "nvue", "transport-model"], events)
                        self.assertEqual(["after transport"] if name == "replace-late-stop" else [], cancellations)
                        withheld_summary = ("nested SSH to EXAMPLE-IB001 via EXAMPLE-JUMP01 failed, "
                                            f"exit={exit_code}; device output withheld")
                        if strict:
                            self.assertEqual("management IB operation failed; device state is UNKNOWN", str(error))
                            self.assertEqual(str(error) + ": " + withheld_summary, public_summary)
                            self.assertIsNone(error.__cause__)
                            self.assertIsNone(error.__context__)
                            if not unchanged:
                                self.assertIn(True, policy_checks)
                        else:
                            detail = preparation_failure if operation == "replace" else "PUBLIC action failed"
                            if name == "replace-foreign-detail":
                                detail = foreign_detail
                            self.assertEqual("nested SSH to EXAMPLE-IB001 via EXAMPLE-JUMP01 failed, "
                                             f"exit={exit_code}: {detail}", str(error))
                            self.assertEqual(withheld_summary, error.report_summary)
        self.assertEqual([], self.effects)

    def test_direct_replace_sync_failure_only_qualifies_link_local_and_keeps_original_error(self):
        app = self.app
        routes = app._import_tools("tools.login_path")
        ib = self.target().ib
        route = routes.Route(NAMES[0], "direct", "PUBLIC", None, None, "public0")
        target = app.Target(ib, None, "", "eth0", route=route)
        link_local = app.DirectEndpoint("fe80::ff:fe00:11", "public0")
        ipv4 = app.DirectEndpoint("203.0.113.11")
        nonce = "34343434343434343434343434343434"
        frame = ("__HTTP_IB_BEGIN_" + nonce + "__\nPUBLIC action failed\n"
                 "__HTTP_IB_END_" + nonce + "__=7\n")
        replace_start = "__HTTP_IB_BEGIN_" + nonce + "__\n"
        replace_end = "__HTTP_IB_END_" + nonce + "__=1\n"
        replace = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--", "YWJj",
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]
        apply = ["nv", "config", "apply", "-y"]
        save = ["nv", "config", "save"]
        detach = ["nv", "config", "detach"]
        cases = (
            ("replace", link_local, replace, replace_start + "rc=7\nfailed_operation=replace\n" + replace_end,
             ("replace", 7)),
            ("replace-preparation", link_local, replace,
             replace_start + "IB configuration replace failed\n" + replace_end, None),
            ("direct-ipv4-replace", ipv4, replace, replace_start + "rc=7\nfailed_operation=replace\n" + replace_end,
             None),
            ("apply", link_local, apply, frame, ("apply", 7)),
            ("save", link_local, save, frame, ("save", 7)),
            ("legacy", link_local, apply, frame, None),
            ("stale", link_local, apply, frame, None),
            ("unframed", link_local, apply, "PUBLIC failure\n", None),
            ("unverified-identity", link_local, apply, frame, None),
            ("direct-ipv4", ipv4, apply, frame, None),
            ("other-operation", link_local, detach, frame, None),
        )
        for strict in (False, True):
            for case, endpoint, command, output, expected in cases:
                with self.subTest(strict=strict, case=case):
                    events = []
                    task = app.PreparedIBTask(target, endpoint, "", False)
                    state = app._IBConfigWriteState(task, "admin", "", "20261119-040125", True,
                        endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE",
                        identity_verified=case != "unverified-identity", backup_state="VERIFIED",
                        backup_receipt={"path": "/devices/PUBLIC/current_20261119-040125.yaml", "bytes": 137})

                    def captured(vector, responder, timeout):
                        peer = ("admin@203.0.113.11" if endpoint is ipv4
                                else "admin@fe80::ff:fe00:11%public0")
                        self.assertEqual(["ssh", "-4" if endpoint is ipv4 else "-6"], vector[:2])
                        self.assertEqual(peer, vector[-2])
                        self.assertEqual(peer, responder.ib_destination)
                        self.assertIn("__HTTP_IB_BEGIN_" + nonce + "__", vector[-1])
                        self.assertEqual(60, timeout)
                        events.append("transport-model")
                        return app.SessionResult(output, 1 if command == replace else 7)

                    policy = SimpleNamespace(assert_unchanged=lambda: None)
                    invoke = app._run_authorized_ib_direct_command if strict else app.run_on_ib
                    options = {"_password_policy": policy} if strict else {}
                    if case != "legacy":
                        options["_replace_sync_failure_task"] = app.replace(state) if case == "stale" else state
                    with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                            mock.patch.object(app, "os", Facade(app.os, urandom=lambda count: b"\x34" * count)), \
                            mock.patch.object(app, "_ib_project_value", return_value="PUBLIC-POLICY"), \
                            mock.patch.object(app, "_ensure_ib_config_backup",
                                              side_effect=lambda *_a, **_k: events.append("backup-check")), \
                            mock.patch.object(app, "obtain_write_permit",
                                              side_effect=lambda category: events.append(category)), \
                            mock.patch.object(app, "interactive_run", captured), \
                            mock.patch.object(app, "_AUTHORIZED_FAILURE_NOTE", []):
                        with self.assertRaises(app.SetupError) as caught:
                            invoke(target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10, command, **options)
                        original = "direct IB command failed; device state is UNKNOWN"
                        error = caught.exception
                        expected_text = ("management IB operation failed; device state is UNKNOWN"
                                         if strict else original)
                        self.assertIs(type(error), app.SetupError)
                        self.assertEqual(expected_text, str(error))
                        self.assertEqual(expected_text + ": " + original if strict else original,
                                         app._authorized_failure_text(error))
                        if strict:
                            self.assertIsNone(error.__cause__)
                            self.assertIsNone(error.__context__)
                        self.assertEqual(expected, getattr(error, "_replace_sync_failure", None))
                        self.assertEqual(["backup-check", "nvue", "transport-model"], events)
        self.assertEqual([], self.effects)

    def test_replace_cleanup_preflight_checks_selected_inputs_and_core_cancellation_without_permit(self):
        app = self.app
        stable_global = self.project / "01-global.yaml"
        selected = self.release / "EXAMPLE-IB001.yaml"
        before_global = stable_global.read_bytes()
        before_selected = selected.read_bytes()
        for case in ("ready", "save-not-a-candidate", "no-proof", "not-authority",
                     "selected-input-change", "already-cancelled", "cancelled-during-read"):
            with self.subTest(case=case):
                selected.write_bytes(before_selected)
                authority = app.RuntimeInputAuthority((stable_global, selected))
                if case == "selected-input-change":
                    selected.write_bytes(before_selected + b"\n# PUBLIC selected input changed\n")
                stopped = [case == "already-cancelled"]
                worker_stop = SimpleNamespace(is_set=lambda: stopped[0])
                checks = []
                real_unchanged = authority.assert_unchanged

                def checked():
                    checks.append("complete-owned-inputs")
                    real_unchanged()
                    if case == "cancelled-during-read":
                        stopped[0] = True

                candidate = authority
                if case == "not-authority":
                    candidate = SimpleNamespace(assert_unchanged=self.deny)
                operation, rc = {
                    "save-not-a-candidate": ("save", 7),
                    "no-proof": ("apply", None),
                }.get(case, ("apply", 7))
                with mock.patch.object(authority, "assert_unchanged", side_effect=checked), \
                        mock.patch.object(app, "_WORKER_STOP", worker_stop), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "worker_request", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "run_on_ib", self.deny):
                    invoke = lambda: app._check_replace_detach_preconditions(candidate, operation, rc)
                    if case == "selected-input-change":
                        with self.assertRaisesRegex(app.ProjectInputChanged, "input bytes changed"):
                            invoke()
                    elif case in {"already-cancelled", "cancelled-during-read"}:
                        with self.assertRaises(app.BatchStopped):
                            invoke()
                    else:
                        self.assertIs(case == "ready", invoke())
                self.assertEqual(["complete-owned-inputs"] if case in {
                    "ready", "selected-input-change", "cancelled-during-read"} else [], checks)
                self.assertEqual(before_global, stable_global.read_bytes())
                self.assertEqual(before_selected + (b"\n# PUBLIC selected input changed\n"
                    if case == "selected-input-change" else b""), selected.read_bytes())
        self.assertEqual([], self.effects)

    def test_replace_sync_stage_requires_verified_receipt_and_fresh_read_in_order(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = app.Target(ib, jump, "swp1", "eth0")
        endpoint = app.Neighbor("fe80::11", "public0", MACS[0], "oob")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        authority = app.RuntimeInputAuthority((self.project / "01-global.yaml", selected))
        data = selected.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        expected_replace = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                            base64.b64encode(data).decode("ascii"), digest]
        readback = "nv set system hostname EXAMPLE-IB001\n"
        cases = (
            ("ready", ["pending", "replace", "apply", "save", "read"]),
            ("identity-unverified", []),
            ("not-authorized", []),
            ("pending", ["pending"]),
            ("missing-backup", ["pending", "replace"]),
            ("bad-receipt", ["pending", "replace"]),
            ("save-failure", ["pending", "replace", "apply", "save"]),
            ("bad-read", ["pending", "replace", "apply", "save", "read"]),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                state = app._IBConfigWriteState(task, "admin", "cumulus", "20261119-041125", True,
                    endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE",
                    identity_verified=case != "identity-unverified")
                calls = []

                def context(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout, local):
                    self.assertIs(device, target)
                    self.assertEqual(endpoint, neighbor)
                    self.assertEqual(("cumulus", "", "admin", "PUBLIC-MODEL-VALUE", 10, False),
                                     (eth_user, ethernet_password, ib_user, credential, timeout, local))

                def pending(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout,
                            command, *, local, allow_password_change):
                    context(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout, local)
                    self.assertIs(allow_password_change, False)
                    self.assertEqual(["nv", "config", "diff", "-o", "commands"], command)
                    calls.append("pending")
                    return app.SessionResult("PUBLIC pre-existing value\n" if case == "pending" else "", 0)

                def stage(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout,
                          command, *, local, strict, policy=None, **evidence):
                    context(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout, local)
                    self.assertIs(strict, False)
                    self.assertIsNone(policy)
                    if command == expected_replace:
                        calls.append("replace")
                        if case != "missing-backup":
                            state.backup_state = "VERIFIED"
                            state.backup_receipt = {"path": "/devices/PUBLIC/current_20261119-041125.yaml",
                                                    "bytes": 137}
                        sibling = "/devices/OTHER" if case == "bad-receipt" else "/devices/PUBLIC"
                        return app.SessionResult("path=" + sibling + "/initial-setup-replace.yaml\n"
                                                 "sha256=" + digest + "\n", 0)
                    if command == ["nv", "config", "apply", "-y"]:
                        calls.append("apply")
                    elif command == ["nv", "config", "save"]:
                        calls.append("save")
                        if case == "save-failure":
                            raise app.SetupError("PUBLIC save failed")
                    elif command == ["nv", "config", "show", "-o", "commands"]:
                        calls.append("read")
                        return app.SessionResult("" if case == "bad-read" else readback, 0)
                    else:
                        return self.deny()
                    return app.SessionResult("", 0)

                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "run_on_ib", pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    def invoke():
                        return app.run_replace_stage(state, data, authority, timeout=10,
                                                     authorized=case != "not-authorized", strict=False)

                    if case == "ready":
                        self.assertEqual(readback, invoke())
                    else:
                        with self.assertRaises(app.SetupError):
                            invoke()
                self.assertEqual(expected, calls)
        self.assertEqual([], self.effects)

    def test_sync_replace_cleanup_requires_current_attribution_and_preserves_the_failure(self):
        app = self.app
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = app.Target(self.target().ib, jump, "swp1", "eth0")
        endpoint = app.Neighbor("fe80::11", "public0", MACS[0], "oob")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        data = selected.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        replace_argv = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                        base64.b64encode(data).decode("ascii"), digest]
        receipt = "path=/devices/PUBLIC/initial-setup-replace.yaml\nsha256=" + digest + "\n"
        cases = (
            ("replace", "replace", ("replace", 7), ["pending", "replace", "detach"], "FAILED_DETACHED"),
            ("apply", "apply", ("apply", 7), ["pending", "replace", "apply", "detach"], "FAILED_DETACHED"),
            ("detach-error", "apply", ("apply", 7), ["pending", "replace", "apply", "detach"],
             "FAILED_DETACH_FAILED"),
            ("save", "save", ("save", 7), ["pending", "replace", "apply", "save"], None),
            ("unknown", "apply", None, ["pending", "replace", "apply"], None),
            ("wrong-stage", "apply", ("replace", 7), ["pending", "replace", "apply"], None),
            ("wrong-type", "apply", ("apply", True), ["pending", "replace", "apply"], None),
            ("bare-result", "apply", None, ["pending", "replace", "apply"], None),
            ("input-changed", "apply", ("apply", 7), ["pending", "replace", "apply"], None),
            ("cancelled", "apply", ("apply", 7), ["pending", "replace", "apply"], None),
        )
        for case, failed_phase, fact, expected_calls, outcome in cases:
            with self.subTest(case=case):
                selected.write_bytes(data)
                authority = app.RuntimeInputAuthority((self.project / "01-global.yaml", selected))
                state = app._IBConfigWriteState(task, "admin", "cumulus", "20261119-041125", True,
                    endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
                    backup_state="VERIFIED",
                    backup_receipt={"path": "/devices/PUBLIC/current_20261119-041125.yaml", "bytes": 137})
                calls, stop = [], [False]
                failure = app.SetupError("PUBLIC original stage failure")
                if fact is not None:
                    failure._replace_sync_failure = fact

                def pending(*args, **kwargs):
                    self.assertEqual(["nv", "config", "diff", "-o", "commands"], args[-1])
                    calls.append("pending")
                    return app.SessionResult("", 0)

                def stage(device, neighbor, eth_user, ethernet_password, ib_user, credential, timeout,
                          command, *, local, strict, policy=None, **evidence):
                    self.assertIs(device, target)
                    self.assertIs(neighbor, endpoint)
                    self.assertEqual((False, False, None), (local, strict, policy))
                    phase = ("replace" if command == replace_argv else {
                        ("nv", "config", "apply", "-y"): "apply", ("nv", "config", "save"): "save",
                        ("nv", "config", "detach"): "detach",
                    }.get(tuple(command)))
                    self.assertIsNotNone(phase, "no readback or other action after primary failure")
                    calls.append(phase)
                    if phase == "detach":
                        self.assertEqual({}, evidence)
                        if case == "detach-error":
                            raise app.SetupError("PUBLIC cleanup result not confirmed")
                        return app.SessionResult("", 0)
                    self.assertEqual({"_replace_sync_failure_task": state}, evidence)
                    if phase == failed_phase:
                        if case == "bare-result":
                            return app.SessionResult("PUBLIC unqualified result", 7)
                        if case == "input-changed":
                            selected.write_bytes(data + b"\n# PUBLIC input changed\n")
                        if case == "cancelled":
                            stop[0] = True
                        raise failure
                    return app.SessionResult(receipt if phase == "replace" else "", 0)

                expected_class = {"input-changed": app.ProjectInputChanged, "cancelled": app.BatchStopped
                                  }.get(case, app.SetupError)
                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "_WORKER_STOP", SimpleNamespace(is_set=lambda: stop[0])), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app, "run_on_ib", pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "worker_request", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    with self.assertRaises(expected_class) as caught:
                        app.run_replace_stage(state, data, authority, timeout=10, authorized=True, strict=False)
                    if case not in {"input-changed", "cancelled", "bare-result"}:
                        self.assertIs(failure, caught.exception)
                        self.assertEqual("PUBLIC original stage failure", str(caught.exception))
                    self.assertEqual(outcome, getattr(caught.exception, "_replace_cleanup_outcome", None))
                self.assertEqual(expected_calls, calls)
        self.assertEqual([], self.effects)

    def test_strict_cleanup_preserves_only_late_typed_veto_from_existing_write_gate(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, "public0")
        paths = (
            (app.Target(ib, jump, "swp1", "eth0"),
             app.Neighbor("fe80::11", "public0", MACS[0], "oob"), "cumulus"),
            (app.Target(ib, None, "", "eth0", route=route),
             app.DirectEndpoint("fe80::ff:fe00:11", "public0"), ""),
        )
        selected = self.release / "EXAMPLE-IB001.yaml"
        data = selected.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        replace_argv = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                        base64.b64encode(data).decode("ascii"), digest]
        receipt = "path=/devices/PUBLIC/initial-setup-replace.yaml\nsha256=" + digest + "\n"
        detach = ["nv", "config", "detach"]
        events_cleanup = ["inputs", "pending", "replace", "apply", "inputs", "cleanup", "backup", "permit"]
        events_legacy = ["cleanup", "backup", "permit"]
        real_stage, real_run = app._stage_ib_command, app.run_on_ib
        for target, endpoint, eth_user in paths:
            for case, error_type, cleanup in (
                ("stopped", app.BatchStopped, True),
                ("changed", app.ProjectInputChanged, True),
                ("unknown", app.SetupError, True),
                ("legacy-stopped", app.BatchStopped, False),
                ("legacy-changed", app.ProjectInputChanged, False),
            ):
                with self.subTest(path=type(endpoint).__name__, case=case):
                    events = []
                    typed_veto = error_type("PUBLIC write gate veto")
                    primary = app.SetupError("PUBLIC confirmed apply failure")
                    primary._replace_sync_failure = ("apply", 7)
                    authority = app.RuntimeInputAuthority((self.project / "01-global.yaml", selected))
                    assert_inputs = authority.assert_unchanged
                    policy = SimpleNamespace(assert_unchanged=self.deny)
                    state = app._IBConfigWriteState(app.PreparedIBTask(target, endpoint, "", False),
                        "admin", eth_user, "20261119-041125", True, endpoint=endpoint,
                        current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
                        backup_state="VERIFIED",
                        backup_receipt={"path": "/devices/PUBLIC/current_20261119-041125.yaml", "bytes": 137})

                    def inputs():
                        events.append("inputs")
                        assert_inputs()

                    def run_model(*args, **options):
                        if args[-1] == ["nv", "config", "diff", "-o", "commands"]:
                            events.append("pending")
                            return app.SessionResult("", 0)
                        self.assertEqual(detach, args[-1])
                        self.assertEqual({"local": False, "allow_password_change": False}, options)
                        events.append("cleanup")
                        return real_run(*args, **options)

                    def stage_model(*args, **options):
                        command = args[-1]
                        if command == replace_argv:
                            events.append("replace")
                            return app.SessionResult(receipt, 0)
                        if command == ["nv", "config", "apply", "-y"]:
                            events.append("apply")
                            raise primary
                        self.assertEqual(detach, command)
                        return real_stage(*args, **options)

                    def veto(category):
                        self.assertEqual("nvue", category)
                        events.append("permit")
                        raise typed_veto

                    with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                            mock.patch.object(app, "_WORKER_STOP", None), \
                            mock.patch.object(app, "_WORKER_CONNECTION", None), \
                            mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                            mock.patch.object(app, "_TASK_DEADLINE", None), \
                            mock.patch.object(app, "_AUTHORIZED_FAILURE_NOTE", []), \
                            mock.patch.object(authority, "assert_unchanged", side_effect=inputs), \
                            mock.patch.object(app, "_ib_project_value", return_value="PUBLIC-POLICY"), \
                            mock.patch.object(app, "run_on_ib", run_model), \
                            mock.patch.object(app, "_stage_ib_command", stage_model), \
                            mock.patch.object(app, "direct_ssh_command", return_value=["PUBLIC never run"]), \
                            mock.patch.object(app, "nested_ssh_command", return_value=["PUBLIC never run"]), \
                            mock.patch.object(app, "_ensure_ib_config_backup",
                                              side_effect=lambda *_a, **_k: events.append("backup")), \
                            mock.patch.object(app, "obtain_write_permit", side_effect=veto), \
                            mock.patch.object(app, "interactive_run", self.deny), \
                            mock.patch.object(app, "confirm_first_device_change", self.deny):
                        expected = error_type if cleanup else app.SetupError
                        with self.assertRaises(expected) as caught:
                            if cleanup:
                                app.run_replace_stage(state, data, authority, timeout=10,
                                                      authorized=True, strict=True, policy=policy)
                            else:
                                real_stage(target, endpoint, eth_user, "", "admin", "PUBLIC-MODEL-VALUE",
                                           10, detach, local=False, strict=True, policy=policy)
                        if not cleanup:
                            self.assertIs(type(caught.exception), app.SetupError)
                            self.assertEqual("management IB operation failed; device state is UNKNOWN",
                                             str(caught.exception))
                            self.assertIsNone(caught.exception.__context__)
                        elif error_type is app.SetupError:
                            self.assertIs(primary, caught.exception)
                            self.assertEqual("FAILED_DETACH_FAILED", primary._replace_cleanup_outcome)
                        else:
                            self.assertIs(typed_veto, caught.exception)
                            self.assertIsNone(getattr(primary, "_replace_cleanup_outcome", None))
                    self.assertEqual(events_cleanup if cleanup else events_legacy, events)
        self.assertEqual([], self.effects)

    def test_replace_restoration_requires_qualified_stage_results_before_continuing(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        profile = {"dns": ["203.0.113.53"], "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}
        present_services = ("nv set system dns server 203.0.113.53\n"
                            "nv set system date-time timezone Etc/UTC\n")
        before = "nv set system config auto-save state disabled\n" + present_services
        after = ("nv set system config auto-save state enabled\n"
                 "nv set system ntp server 203.0.113.54\n") + present_services
        pending = ("nv", "config", "diff", "-o", "commands")
        setter = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
        ntp = ("nv", "set", "system", "ntp", "server", "203.0.113.54")
        apply = ("nv", "config", "apply", "-y")
        save = ("nv", "config", "save")
        read = ("nv", "config", "show", "-o", "commands")
        operations = (setter, ntp, apply, save, read)
        uncertain = app.SessionResult("", 0)
        uncertain.cleanup_uncertain = True
        for case, fail_at, result, expected in (
            ("verified", None, None, [pending, setter, ntp, apply, save, read]),
            ("setter-nonzero", setter, app.SessionResult("", 7), [pending, setter]),
            ("apply-auth-rejected", apply, app.SessionResult("", 0, ib_authentication_rejected=True),
             [pending, setter, ntp, apply]),
            ("save-uncertain", save, uncertain, [pending, setter, ntp, apply, save]),
            ("readback-requires-password-change", read, app.SessionResult(after, 0, password_change_required=True),
             [pending, setter, ntp, apply, save, read]),
            ("readback-bool-status", read, app.SessionResult(after, False),
             [pending, setter, ntp, apply, save, read]),
        ):
            with self.subTest(case=case):
                observed = []

                def read_pending(*args, **options):
                    self.assertEqual(pending, tuple(args[-1]))
                    self.assertEqual({"local": False, "allow_password_change": False}, options)
                    observed.append(pending)
                    return app.SessionResult("", 0)

                def stage(*args, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10), args[:-1])
                    self.assertEqual({"local": False, "strict": False, "policy": None}, options)
                    argv = tuple(args[-1])
                    self.assertIn(argv, operations)
                    observed.append(argv)
                    if argv == fail_at:
                        return result
                    return app.SessionResult(after if argv == read else "", 0)

                with mock.patch.object(app, "run_on_ib", read_pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny):
                    def invoke():
                        return app._restore_replace_services(target, endpoint, "", "", "admin",
                            "PUBLIC-MODEL-VALUE", 10, profile, before, local=False, authorized=True)

                    if fail_at is None:
                        self.assertEqual((True, False), invoke())
                    else:
                        with self.assertRaisesRegex(app.IBConfigurationStageUncertain,
                                                    "services were not fully verified"):
                            invoke()
                self.assertEqual(expected, observed)
        self.assertEqual([], self.effects)

    def test_replace_restoration_requires_fresh_disabled_ztp_before_continuing(self):
        app = self.app
        target = self.target()
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        profile = {"dns": ["203.0.113.53"], "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}
        unchanged = ("nv set system dns server 203.0.113.53\n"
                     "nv set system date-time timezone Etc/UTC\n")
        before = "nv set system config auto-save state disabled\n" + unchanged
        after = ("nv set system config auto-save state enabled\n"
                 "nv set system ntp server 203.0.113.54\n") + unchanged
        pending = ("nv", "config", "diff", "-o", "commands")
        auto = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
        ntp = ("nv", "set", "system", "ntp", "server", "203.0.113.54")
        apply = ("nv", "config", "apply", "-y")
        save = ("nv", "config", "save")
        read = ("nv", "config", "show", "-o", "commands")
        ztp = ("nv", "show", "system", "ztp")
        restored = [pending, auto, ntp, apply, save, read]
        disabled = "service disabled\nstate disabled\n"
        fresh = app.SessionResult(disabled, 0)
        cases = (
            ("verified", before, fresh, [*restored, ztp], (True, False, disabled)),
            ("already-complete", after, fresh, [pending, ztp], (True, True, disabled)),
            ("pending", before, fresh, [pending], None),
            ("restore-readback-incomplete", before, fresh, restored, None),
            ("ztp-enabled", before, app.SessionResult("service enabled\n", 0), [*restored, ztp], None),
            ("ztp-missing", before, app.SessionResult("", 0), [*restored, ztp], None),
            ("ztp-conflicting", before, app.SessionResult("service disabled\nstate enabled\n", 0),
             [*restored, ztp], None),
            ("ztp-unqualified", before, app.SessionResult(disabled, 0, password_change_required=True),
             [*restored, ztp], None),
            ("no-authorization", before, fresh, [], None),
        )
        for case, readback, status, calls, outcome in cases:
            with self.subTest(case=case):
                observed = []
                context = (target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10)
                state = app._IBConfigWriteState(task, "admin", "", "20261119-053440", True,
                    endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
                    backup_state="VERIFIED",
                    backup_receipt={"path": "/devices/PUBLIC/current_20261119-053440.yaml", "bytes": 137})

                def read_pending(*args, **options):
                    self.assertEqual(context, args[:-1])
                    self.assertEqual(pending, tuple(args[-1]))
                    self.assertEqual({"local": False, "allow_password_change": False}, options)
                    observed.append(pending)
                    return app.SessionResult("PUBLIC pre-existing work" if case == "pending" else "", 0)

                def stage(*args, **options):
                    self.assertEqual(context, args[:-1])
                    self.assertEqual({"local": False, "strict": False, "policy": None}, options)
                    argv = tuple(args[-1])
                    self.assertIn(argv, (auto, ntp, apply, save, read, ztp))
                    observed.append(argv)
                    if argv == ztp:
                        return status
                    return app.SessionResult((before if case == "restore-readback-incomplete" else after)
                                             if argv == read else "", 0)

                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_WORKER_STOP", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app, "run_on_ib", read_pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "run_key_stage", self.deny), \
                        mock.patch.object(app, "run_management_direct_checks", self.deny):
                    def invoke():
                        return app._restore_replace_services_and_verify_ztp(
                            state, profile, readback, timeout=10, authorized=case != "no-authorization",
                            strict=False)

                    if outcome is None:
                        with self.assertRaises(app.SetupError):
                            invoke()
                    else:
                        self.assertEqual(outcome, invoke())
                self.assertEqual(calls, observed)
        self.assertEqual([], self.effects)

    def test_replace_consumes_only_the_original_admitted_host_file(self):
        app = self.app
        target = self.target()
        task = app.PreparedIBTask(target, app.DirectEndpoint("203.0.113.11"), "", False)
        pinned = b"- set:\n    system:\n      hostname: EXAMPLE-IB001\n"
        foreign = b"- set:\n    system:\n      hostname: EXAMPLE-IB002\n"
        for case in ("admitted", "missing-authority", "unbound", "alias-only", "alias-selection",
                     "default-file", "other-host", "different-release", "wrong-digest",
                     "changed-host", "changed-shared", "retargeted-leaf", "large", "cancelled"):
            with self.subTest(case=case):
                publish = self.root / ("public-publish-" + case)
                publish.mkdir()
                latest = self.root / ("public-latest-" + case)
                latest.symlink_to(publish, target_is_directory=True)
                host = publish / "EXAMPLE-IB001.yaml"
                other = publish / "EXAMPLE-IB002.yaml"
                default = publish / "default_ib.yaml"
                alias = publish / "aabbccddeeff.yaml"
                outside = self.root / "elsewhere" / "EXAMPLE-IB001.yaml"
                outside.parent.mkdir(exist_ok=True)
                body = b"X" * 98305 if case == "large" else pinned
                host.write_bytes(body)
                other.write_bytes(foreign)
                default.write_bytes(pinned)
                outside.write_bytes(pinned)
                alias.symlink_to(host.name)
                shared = self.root / ("public-bound-global-" + case)
                shared.write_bytes(b"PUBLIC shared original\n")
                entries = [shared, latest / other.name, latest / default.name, outside]
                if case not in {"unbound", "alias-only"}:
                    entries.append(latest / host.name)
                if case in {"alias-only", "alias-selection"}:
                    entries.append(latest / alias.name)
                authority = app.RuntimeInputAuthority(entries)
                chosen, selected_bytes = {
                    "other-host": (other, foreign), "default-file": (default, pinned),
                    "alias-selection": (alias, pinned), "different-release": (outside, pinned),
                }.get(case, (host, body))
                digest = hashlib.sha256(selected_bytes).hexdigest()
                args = SimpleNamespace(config_mode="replace", apply=True, _replace_release=latest,
                    _replace_selected={"example-ib001": {"verdict": "WOULD_REPLACE", "file": str(chosen),
                        "sha256": "0" * 64 if case == "wrong-digest" else digest, "reason": ""}},
                    _replace_runtime_authority=None if case == "missing-authority" else authority)
                if case == "changed-host":
                    host.write_bytes(b"PUBLIC replacement changed\n")
                elif case == "changed-shared":
                    shared.write_bytes(b"PUBLIC shared input changed\n")
                elif case == "retargeted-leaf":
                    host.unlink()
                    host.symlink_to(outside)
                stop = SimpleNamespace(is_set=lambda: case == "cancelled")
                with mock.patch.object(app, "_WORKER_STOP", stop), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app.RuntimeInputAuthority, "__init__", self.deny), \
                        mock.patch.object(app, "run_on_ib", self.deny), \
                        mock.patch.object(app, "_stage_ib_command", self.deny), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "worker_request", self.deny):
                    def consume():
                        return app._read_admitted_replace_yaml(task, args)

                    if case == "admitted":
                        self.assertEqual(pinned, consume())
                        self.assertIs(authority, args._replace_runtime_authority)
                    else:
                        expected = (app.ProjectInputChanged if case in {
                            "changed-host", "changed-shared", "retargeted-leaf"} else
                            app.BatchStopped if case == "cancelled" else app.SetupError)
                        with self.assertRaises(expected) as error:
                            consume()
                        self.assertIs(expected, type(error.exception))
        self.assertEqual([], self.effects)

    def test_replace_opt_in_rehash_accepts_only_stable_regular_descriptor_metadata(self):
        app = self.app
        path = self.root / "public-rehash.yaml"
        body = b"PUBLIC snapshot original\n"
        path.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        for case, expected in (
                ("legacy", ["legacy-hash"]),
                ("unchanged", []),
                ("stable", ["open", "read", "read", "close"]),
                ("not-regular", ["open", "close"]),
                ("opened-identity-mismatch", ["open", "close"]),
                ("metadata-changed-on-read", ["open", "read", "read", "close"]),
                ("content-changed", ["open", "read", "read", "close"])):
            with self.subTest(case=case):
                authority = app.RuntimeInputAuthority([path])
                entry = authority.entries[0]
                old = entry[2]
                current = old if case == "unchanged" else (*old[:3], old[3] + 10, old[4] + 10)
                events, stat_calls = [], []
                chunks = [b"x" * len(body) if case == "content-changed" else body, b""]

                def opened(file, flags):
                    self.assertEqual(path, file)
                    required = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                    self.assertEqual(required, flags & required)
                    events.append("open")
                    return 349

                def metadata(descriptor):
                    self.assertEqual(349, descriptor)
                    stat_calls.append(descriptor)
                    values = current
                    if case == "opened-identity-mismatch" or (case == "metadata-changed-on-read" and
                                                              len(stat_calls) > 1):
                        values = (current[0], current[1] + 1, *current[2:])
                    mode = 0 if case == "not-regular" else app.stat.S_IFREG
                    return SimpleNamespace(st_mode=mode, st_dev=values[0], st_ino=values[1],
                        st_size=values[2], st_mtime_ns=values[3], st_ctime_ns=values[4])

                def read(descriptor, bound):
                    self.assertEqual(349, descriptor)
                    self.assertGreater(bound, 0)
                    events.append("read")
                    return chunks.pop(0)

                def close(descriptor):
                    self.assertEqual(349, descriptor)
                    events.append("close")

                def legacy_hash(file):
                    self.assertEqual(path, file)
                    events.append("legacy-hash")
                    return digest

                with mock.patch.object(authority, "signature", return_value=current), \
                        mock.patch.object(app, "_file_sha256", legacy_hash if case == "legacy" else self.deny), \
                        mock.patch.object(app, "os", Facade(app.os, open=opened, fstat=metadata,
                                                           read=read, close=close)), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "run_on_ib", self.deny):
                    if case == "legacy":
                        authority.assert_unchanged()
                    elif case in {"unchanged", "stable"}:
                        authority.assert_unchanged(_stable_file_refresh=True)
                    else:
                        with self.assertRaises(app.ProjectInputChanged) as rejected:
                            authority.assert_unchanged(_stable_file_refresh=True)
                        self.assertIs(type(rejected.exception), app.ProjectInputChanged)
                self.assertEqual(expected, events)
                self.assertEqual(current if case in {"legacy", "unchanged", "stable"} else old, entry[2])
                self.assertEqual(digest, entry[3])
        self.assertEqual([], self.effects)

    def test_deferred_ipv4_replace_requires_same_stamp_receipt_and_fresh_device_read(self):
        app = self.app
        ib = self.target().ib
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        data = selected.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        stamp = "20261119-060440"
        replace_argv = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                        base64.b64encode(data).decode("ascii"), digest]
        launch = ["sh", "-c", EXPECTED_D7_LAUNCH_SCRIPT, "--", stamp]
        completion = ["sh", "-c", EXPECTED_D7_READ_RC_SCRIPT, "--", stamp]
        address = "2: eth0: <UP> mtu 1500\n    link/ether 02:00:00:00:00:11\n    inet 203.0.113.11/24\n"
        readback = "nv set system hostname EXAMPLE-IB001\n"
        same = ["pending", "replace", "launch", "receipt"]
        for case, expected in (
                ("success", [*same, "identity", "route", "read"]),
                ("pending-once", [*same, "wait10", "receipt", "identity", "route", "read"]),
                ("bad-stamp", []), ("no-authorization", []), ("pending-config", ["pending"]),
                ("wrong-backup-receipt", ["pending", "replace"]),
                ("unconfirmed-replace", ["pending", "replace"]),
                ("changed-before-launch", ["pending", "replace"]),
                ("wrong-launch-endpoint", ["pending", "replace", "launch"]),
                ("auth-launch", ["pending", "replace", "launch"]),
                ("failed-apply", same), ("failed-save", same),
                ("wrong-gateway", [*same, "identity", "route"]),
                ("wrong-hostname-readback", [*same, "identity", "route", "read"])):
            with self.subTest(case=case):
                selected.write_bytes(data)
                authority = app.RuntimeInputAuthority((self.project / "01-global.yaml", selected))
                state = app._IBConfigWriteState(task, "admin", "", "invalid" if case == "bad-stamp" else stamp,
                    True, endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
                    backup_state="VERIFIED",
                    backup_receipt={"path": f"/devices/PUBLIC/current_{stamp}.yaml", "bytes": 137})
                calls = []

                def pending(*args, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10), args[:-1])
                    self.assertEqual(["nv", "config", "diff", "-o", "commands"], args[-1])
                    self.assertEqual({"local": False, "allow_password_change": False}, options)
                    calls.append("pending")
                    return app.SessionResult("PUBLIC pending" if case == "pending-config" else "", 0)

                def stage(*args, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10), args[:-1])
                    command = args[-1]
                    if command == replace_argv:
                        request = options.pop("_replace_sync_failure_task", None)
                        self.assertIs(type(request), app._InitialIPv4ReplaceRequest)
                        self.assertIs(request.state, state)
                        self.assertIs(request.authority, authority)
                        self.assertIs(request.endpoint, endpoint)
                        self.assertEqual(stamp, request.stamp)
                    self.assertEqual({"local": False, "strict": False, "policy": None}, options)
                    if command == replace_argv:
                        calls.append("replace")
                        if case == "unconfirmed-replace":
                            raise app.SetupError("PUBLIC device result unknown")
                        if case == "changed-before-launch":
                            selected.write_bytes(data + b"\n# PUBLIC changed\n")
                        folder = "/devices/OTHER" if case == "wrong-backup-receipt" else "/devices/PUBLIC"
                        answer = app.SessionResult(f"path={folder}/initial-setup-replace.yaml\nsha256={digest}\n", 0)
                    elif command == launch:
                        calls.append("launch")
                        answer = app.SessionResult("", 0, ib_authentication_rejected=case == "auth-launch")
                    elif command == completion:
                        calls.append("receipt")
                        body = {"failed-apply": "rc=7\nfailed_operation=apply\n",
                                "failed-save": "rc=7\nfailed_operation=save\n"}.get(case,
                                    "rc=\nfailed_operation=pending\n" if case == "pending-once"
                                    and calls.count("receipt") == 1 else "rc=0\nfailed_operation=none\n")
                        answer = app.SessionResult(body, 0)
                    elif command == ["ip", "addr", "show", "eth0"]:
                        calls.append("identity")
                        answer = app.SessionResult(address, 0)
                    elif command == ["ip", "route"]:
                        calls.append("route")
                        gateway = "203.0.113.2" if case == "wrong-gateway" else "203.0.113.1"
                        answer = app.SessionResult(f"default via {gateway} dev eth0\n", 0)
                    elif command == ["nv", "config", "show", "-o", "commands"]:
                        calls.append("read")
                        answer = app.SessionResult("nv set system hostname EXAMPLE-IB002\n"
                                                   if case == "wrong-hostname-readback" else readback, 0)
                    else:
                        return self.deny()
                    answer._direct_endpoint = (app.DirectEndpoint("203.0.113.12")
                        if case == "wrong-launch-endpoint" and command == launch else endpoint)
                    return answer

                def wait(delay):
                    self.assertEqual(10, delay)
                    calls.append("wait10")

                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "_TASK_DEADLINE", 1000), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_WORKER_STOP", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "time", Facade(app.time, monotonic=lambda: 100, sleep=wait)), \
                        mock.patch.object(app, "run_on_ib", pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "_restore_replace_services_and_verify_ztp", self.deny), \
                        mock.patch.object(app, "run_key_stage", self.deny):
                    def invoke():
                        return app._run_replace_deferred_stage(state, data, authority, timeout=10,
                            authorized=case != "no-authorization", strict=False)

                    if case in {"success", "pending-once"}:
                        self.assertEqual(readback, invoke())
                    else:
                        error_type = app.ProjectInputChanged if case == "changed-before-launch" else app.SetupError
                        with self.assertRaises(error_type) as error:
                            invoke()
                        self.assertIs(type(error.exception), error_type)
                        self.assertIsNone(getattr(error.exception, "_replace_cleanup_outcome", None))
                self.assertEqual(expected, calls)
        self.assertEqual([], self.effects)

    def test_admitted_replace_dispatches_only_the_verified_path_before_restore(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        transit = app.Target(ib, jump, "swp1", "eth0")
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, "public0")
        direct = app.Target(ib, None, "", "eth0", route=route)
        nested = app.Neighbor("fe80::11", "public0", MACS[0], "oob")
        ll = app.DirectEndpoint("fe80::ff:fe00:11", "public0")
        ipv4 = app.DirectEndpoint("203.0.113.11")
        config = self.root / "public-dispatch-global.yaml"
        profile = {"dns": ["203.0.113.53"], "ntp": ["203.0.113.54"], "timezone": "Etc/UTC"}
        selected = b"PUBLIC original task input"
        fresh = {"sync": "PUBLIC fresh sync readback", "deferred": "PUBLIC fresh IPv4 readback"}
        status = (True, False, "service disabled\n")
        cases = (
            ("nested", transit, nested, nested, ["select", "sync", "restore"], None),
            ("link-local", direct, ll, ll, ["select", "sync", "restore"], None),
            ("direct-ipv4", direct, ipv4, ipv4, ["select", "deferred", "restore"], None),
            ("identity-transition", direct, ll, ipv4, ["select", "deferred", "restore"], None),
            ("foreign-ipv4", direct, ipv4, app.DirectEndpoint("203.0.113.12"), [], app.SetupError),
            ("wrong-endpoint-type", transit, nested, ll, [], app.SetupError),
            ("unverified", direct, ll, ll, [], app.SetupError),
            ("foreign-state", direct, ll, ll, [], app.SetupError),
            ("unauthorized", direct, ll, ll, [], app.SetupError),
            ("bad-original-input", direct, ll, ll, ["select"], app.ProjectInputChanged),
            ("sync-failed", direct, ll, ll, ["select", "sync"], app.SetupError),
            ("deferred-failed", direct, ipv4, ipv4, ["select", "deferred"], app.SetupError),
            ("input-changed-after-base", direct, ipv4, ipv4, ["select", "deferred"], app.ProjectInputChanged),
            ("cancelled-after-base", direct, ll, ll, ["select", "sync"], app.BatchStopped),
            ("restore-failed", direct, ll, ll, ["select", "sync", "restore"], app.SetupError),
        )
        for case, target, initial, actual, expected, error_type in cases:
            with self.subTest(case=case):
                config.write_bytes(b"PUBLIC original pinned input\n")
                authority = app.RuntimeInputAuthority((config,))
                args = SimpleNamespace(config_mode="replace", apply=True, _replace_runtime_authority=authority)
                task = app.PreparedIBTask(target, initial, "", False)
                state = app._IBConfigWriteState(task, "admin", "cumulus" if target is transit else "",
                    "20261119-061440", True, endpoint=actual, current_password="PUBLIC-MODEL-VALUE",
                    identity_verified=case != "unverified")
                calls, stop = [], [False]
                strict = case == "identity-transition"
                policy = SimpleNamespace(assert_unchanged=self.deny) if strict else None
                options = {"timeout": 10, "authorized": True, "strict": strict, "policy": policy}

                def select(new_task, original_args):
                    self.assertIs(task, new_task)
                    self.assertIs(args, original_args)
                    calls.append("select")
                    if case == "bad-original-input":
                        raise app.ProjectInputChanged("PUBLIC selected input changed")
                    return selected

                def base(mode, new_state, data, original_authority, **kwargs):
                    self.assertIs(state, new_state)
                    self.assertIs(selected, data)
                    self.assertIs(authority, original_authority)
                    self.assertEqual(options, kwargs)
                    calls.append(mode)
                    if case == mode + "-failed":
                        raise app.SetupError("PUBLIC base failed")
                    if case == "input-changed-after-base":
                        config.write_bytes(b"PUBLIC original input changed\n")
                    if case == "cancelled-after-base":
                        stop[0] = True
                    return fresh[mode]

                def restore(new_state, new_profile, body, **kwargs):
                    self.assertIs(state, new_state)
                    self.assertIs(profile, new_profile)
                    self.assertEqual(options, kwargs)
                    self.assertEqual(fresh[calls[-1]], body)
                    calls.append("restore")
                    if case == "restore-failed":
                        raise app.SetupError("PUBLIC fresh ZTP not verified")
                    return status

                with mock.patch.object(app, "_TASK_IB_CONFIG", object() if case == "foreign-state" else state), \
                        mock.patch.object(app, "_WORKER_STOP", SimpleNamespace(is_set=lambda: stop[0])), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app.RuntimeInputAuthority, "__init__", self.deny), \
                        mock.patch.object(app, "_read_admitted_replace_yaml", select), \
                        mock.patch.object(app, "run_replace_stage", lambda *a, **k: base("sync", *a, **k)), \
                        mock.patch.object(app, "_run_replace_deferred_stage", lambda *a, **k: base("deferred", *a, **k)), \
                        mock.patch.object(app, "_restore_replace_services_and_verify_ztp", restore), \
                        mock.patch.object(app, "_stage_ib_command", self.deny), \
                        mock.patch.object(app, "run_on_ib", self.deny), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "run_key_stage", self.deny), \
                        mock.patch.object(app, "run_management_direct_checks", self.deny):
                    def invoke():
                        return app._run_admitted_replace_to_ztp(state, args, profile, timeout=10,
                            authorized=case != "unauthorized", strict=strict, policy=policy)

                    if error_type is None:
                        self.assertIs(status, invoke())
                    else:
                        with self.assertRaises(error_type) as error:
                            invoke()
                        self.assertIs(type(error.exception), error_type)
                self.assertEqual(expected, calls)
                self.assertIs(initial, task.neighbor)
                self.assertIs(actual, state.endpoint)
        self.assertEqual([], self.effects)

    def test_deferred_apply_failure_requires_fresh_identity_for_one_cleanup(self):
        app = self.app
        ib = self.target().ib
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        selected = self.release / "EXAMPLE-IB001.yaml"
        common = self.project / "01-global.yaml"
        initial_common = common.read_bytes()
        data = selected.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        stamp = "20261119-062510"
        task = app.PreparedIBTask(target, endpoint, "", False)
        replace_argv = ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                        base64.b64encode(data).decode("ascii"), digest]
        launch = ["sh", "-c", EXPECTED_D7_LAUNCH_SCRIPT, "--", stamp]
        rc_read = ["sh", "-c", EXPECTED_D7_READ_RC_SCRIPT, "--", stamp]
        before = ["pending", "replace", "launch", "receipt"]
        identity = [*before, "identity", "route"]
        cleanup = [*identity, "detach"]
        failed_apply = "deferred configuration apply failed (rc=7)"
        cases = (
            ("confirmed", cleanup, "FAILED_DETACHED", app.SetupError, failed_apply),
            ("no-gateway-is-allowed", cleanup, "FAILED_DETACHED", app.SetupError, failed_apply),
            ("detach-nonzero", cleanup, "FAILED_DETACH_FAILED", app.SetupError, failed_apply),
            ("detach-other-endpoint", cleanup, "FAILED_DETACH_FAILED", app.SetupError, failed_apply),
            ("late-permit-stop", cleanup, None, app.BatchStopped, "PUBLIC original gate stopped"),
            ("identity-mismatch", identity, None, app.SetupError, failed_apply),
            ("route-mismatch", identity, None, app.SetupError, failed_apply),
            ("auth-identity", [*before, "identity"], None, app.SetupError, failed_apply),
            ("input-change-before-identity", before, None, app.ProjectInputChanged, "input bytes changed"),
            ("input-change-after-identity", identity, None, app.ProjectInputChanged, "input bytes changed"),
            ("cancel-after-identity", identity, None, app.BatchStopped, "coordinator stopped"),
            ("same-rc-save", before, None, app.SetupError, "deferred configuration save failed (rc=7)"),
            ("malformed", before, None, app.SetupError, "deferred configuration result is unverified"),
            ("uncertain-receipt", before, None, app.SetupError, "unverified"),
            ("unknown-replace", ["pending", "replace"], None, app.SetupError, "PUBLIC unknown replace"),
        )
        for case, expected, outcome, error_type, message in cases:
            with self.subTest(case=case):
                common.write_bytes(initial_common)
                authority = app.RuntimeInputAuthority((common, selected))
                args = SimpleNamespace(config_mode="replace", apply=True, _replace_release=self.release,
                    _replace_runtime_authority=authority, _replace_selected={"example-ib001": {
                        "verdict": "WOULD_REPLACE", "file": str(selected), "sha256": digest, "reason": ""}})
                state = app._IBConfigWriteState(task, "admin", "", stamp, True, endpoint=endpoint,
                    current_password="PUBLIC-MODEL-VALUE", identity_verified=True, backup_state="VERIFIED",
                    backup_receipt={"path": f"/devices/PUBLIC/current_{stamp}.yaml", "bytes": 137})
                calls, stop = [], [False]

                def pending(*args, **options):
                    self.assertEqual(["nv", "config", "diff", "-o", "commands"], args[-1])
                    self.assertEqual({"local": False, "allow_password_change": False}, options)
                    calls.append("pending")
                    return app.SessionResult("", 0)

                def stage(*arguments, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10), arguments[:-1])
                    command = arguments[-1]
                    if command == replace_argv:
                        request = options.pop("_replace_sync_failure_task", None)
                        self.assertIs(type(request), app._InitialIPv4ReplaceRequest)
                        self.assertIs(request.state, state)
                        self.assertIs(request.authority, authority)
                        self.assertIs(request.endpoint, endpoint)
                        self.assertEqual(stamp, request.stamp)
                    self.assertEqual({"local": False, "strict": False, "policy": None}, options)
                    if command == replace_argv:
                        calls.append("replace")
                        if case == "unknown-replace":
                            raise app.SetupError("PUBLIC unknown replace")
                        answer = app.SessionResult("path=/devices/PUBLIC/initial-setup-replace.yaml\n"
                                                   f"sha256={digest}\n", 0)
                    elif command == launch:
                        calls.append("launch")
                        answer = app.SessionResult("", 0)
                    elif command == rc_read:
                        calls.append("receipt")
                        if case == "input-change-before-identity":
                            common.write_bytes(initial_common + b"\n# PUBLIC changed\n")
                        body = {"same-rc-save": "rc=7\nfailed_operation=save\n",
                                "malformed": "rc=7\nfailed_operation=none\n"}.get(
                                    case, "rc=7\nfailed_operation=apply\n")
                        answer = app.SessionResult(body, 0)
                        if case == "uncertain-receipt":
                            answer.cleanup_uncertain = True
                    elif command == ["ip", "addr", "show", "eth0"]:
                        calls.append("identity")
                        mac = "02:00:00:00:00:12" if case == "identity-mismatch" else "02:00:00:00:00:11"
                        answer = app.SessionResult("2: eth0: <UP> mtu 1500\n"
                            f"    link/ether {mac}\n    inet 203.0.113.11/24\n", 0,
                            ib_authentication_rejected=case == "auth-identity")
                    elif command == ["ip", "route"]:
                        calls.append("route")
                        if case == "input-change-after-identity":
                            common.write_bytes(initial_common + b"\n# PUBLIC changed\n")
                        if case == "cancel-after-identity":
                            stop[0] = True
                        gateway = "203.0.113.2" if case == "route-mismatch" else "203.0.113.1"
                        answer = app.SessionResult("" if case == "no-gateway-is-allowed"
                                                   else f"default via {gateway} dev eth0\n", 0)
                    elif command == ["nv", "config", "detach"]:
                        calls.append("detach")
                        if case == "late-permit-stop":
                            raise app.BatchStopped("PUBLIC original gate stopped")
                        answer = app.SessionResult("", 3 if case == "detach-nonzero" else 0)
                    else:
                        return self.deny()
                    answer._direct_endpoint = (app.DirectEndpoint("203.0.113.12")
                        if case == "detach-other-endpoint" and command == ["nv", "config", "detach"] else endpoint)
                    return answer

                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "_TASK_DEADLINE", 1000), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_WORKER_STOP", SimpleNamespace(is_set=lambda: stop[0])), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "time", Facade(app.time, monotonic=lambda: 100, sleep=self.deny)), \
                        mock.patch.object(app, "run_on_ib", pending), \
                        mock.patch.object(app, "_stage_ib_command", stage), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "_restore_replace_services_and_verify_ztp", self.deny), \
                        mock.patch.object(app, "run_key_stage", self.deny), \
                        mock.patch.object(app, "run_management_direct_checks", self.deny):
                    with self.assertRaises(error_type) as error:
                        app._run_admitted_replace_to_ztp(state, args, None, timeout=10, authorized=True, strict=False)
                    self.assertIs(type(error.exception), error_type)
                    self.assertIn(message, str(error.exception))
                    self.assertEqual(outcome, getattr(error.exception, "_replace_cleanup_outcome", None))
                self.assertEqual(expected, calls)
                self.assertEqual(data, selected.read_bytes())
        self.assertEqual([], self.effects)

    def test_strict_deferred_cleanup_identity_reads_preserve_only_scoped_late_stop(self):
        app = self.app
        ib = self.target().ib
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        address = ["ip", "addr", "show", "eth0"]
        routes = ["ip", "route"]
        stamp = "20261119-063510"
        prior = self.root / "public-bound-failure.yml"
        prior.write_bytes(b"PUBLIC admitted inputs\n")
        for case, scope, failure_at, error_type, after_policy in (
                ("read-cancelled", True, address, app.BatchStopped, False),
                ("read-input-changed", True, address, app.ProjectInputChanged, False),
                ("route-cancelled", True, routes, app.BatchStopped, False),
                ("route-input-changed", True, routes, app.ProjectInputChanged, False),
                ("unscoped-address", False, address, app.BatchStopped, False),
                ("unscoped-route", False, routes, app.ProjectInputChanged, False),
                ("uncertain-transport", True, address, app.SetupError, False),
                ("post-scope-policy", True, address, app.BatchStopped, True)):
            with self.subTest(case=case):
                authority = app.RuntimeInputAuthority([prior])
                task = app.PreparedIBTask(target, endpoint, "", False)
                state = app._IBConfigWriteState(task, "admin", "", stamp, True,
                    endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE", identity_verified=True,
                    backup_state="VERIFIED", backup_receipt={"path": "/devices/PUBLIC/verified.yaml", "bytes": 137})
                primary = app.SetupError("PUBLIC prior stage failure")
                primary._replace_deferred_apply_failure = app._DeferredReplaceApplyFailure(
                    state, authority, endpoint, stamp, 7)
                veto = error_type("PUBLIC original typed stop")
                commands = []

                def read(device, point, jump_user, jump_password, ib_user, selected_credential, timeout,
                         command, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", "PUBLIC-MODEL-VALUE", 10),
                                     (device, point, jump_user, jump_password, ib_user, selected_credential, timeout))
                    self.assertEqual({"local": False, "allow_password_change": False}, options)
                    self.assertIn(command, (address, routes), "no cleanup write or extra action")
                    commands.append(list(command))
                    if command == failure_at and not after_policy:
                        raise veto
                    result = app.SessionResult("2: eth0: <UP> mtu 1500\n"
                        "    link/ether 02:00:00:00:00:11\n    inet 203.0.113.11/24\n", 0)
                    result._direct_endpoint = endpoint
                    return result

                def unchanged():
                    if after_policy:
                        raise veto

                policy = SimpleNamespace(assert_unchanged=unchanged)
                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "_WORKER_STOP", None), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app, "_AUTHORIZED_FAILURE_NOTE", []), \
                        mock.patch.object(app, "_ib_project_value", return_value="PUBLIC-POLICY"), \
                        mock.patch.object(app, "run_on_ib", read), \
                        mock.patch.object(app, "obtain_write_permit", self.deny), \
                        mock.patch.object(app, "confirm_first_device_change", self.deny), \
                        mock.patch.object(app, "interactive_run", self.deny):
                    def cleanup():
                        return app._try_cleanup_deferred_apply_failure(
                            state, authority, primary, timeout=10, strict=True, policy=policy)

                    if not scope:
                        with self.assertRaises(app.SetupError) as error:
                            app._read_direct_ipv4_command(target, endpoint, "admin", "PUBLIC-MODEL-VALUE",
                                10, failure_at, strict=True, policy=policy, details={})
                        self.assertIs(type(error.exception), app.SetupError)
                        self.assertEqual("management IB operation failed; device state is UNKNOWN",
                                         str(error.exception))
                        self.assertIsNone(error.exception.__context__)
                    elif after_policy or error_type is app.SetupError:
                        self.assertIsNone(cleanup())
                    else:
                        with self.assertRaises(error_type) as error:
                            cleanup()
                        self.assertIs(veto, error.exception)
                self.assertEqual([address, routes] if scope and failure_at == routes else [failure_at],
                                 commands)
                self.assertEqual("PUBLIC prior stage failure", str(primary))
                self.assertIsNone(getattr(primary, "_replace_cleanup_outcome", None))
        self.assertEqual([], self.effects)

    def test_initial_ipv4_replace_cleans_only_the_current_verified_device_failure(self):
        app = self.app
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(self.target().ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        data = selected.read_bytes()
        common = self.project / "01-global.yaml"
        original = common.read_bytes()
        digest = "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368"
        stamp = "20261119-071640"
        nonce = "51515151515151515151515151515151"
        stages = {
            "pending": ["nv", "config", "diff", "-o", "commands"],
            "replace": ["sh", "-c", EXPECTED_REPLACE_SCRIPT, "--",
                        base64.b64encode(data).decode("ascii"), digest],
            "address": ["ip", "addr", "show", "eth0"],
            "route": ["ip", "route"],
            "detach": ["nv", "config", "detach"],
        }
        vectors = {
            shlex.join(["sh", "-c", 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                        + shlex.join(command) + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                        + '__=%s\\n" "$task_rc"; exit "$task_rc"']): label
            for label, command in stages.items()
        }
        pre = ["pending", "replace"]
        identity = pre + ["address", "route"]
        detached = identity + ["detach"]
        receipt = "rc=7\nfailed_operation=replace\n"
        for strict in (False, True):
            for name, body, seen, outcome in (
                    ("confirmed", receipt, detached, "FAILED_DETACHED"),
                    ("cleanup-failed", receipt, detached, "FAILED_DETACH_FAILED"),
                    ("identity-mismatch", receipt, identity, None),
                    ("wrong-frame", receipt, pre, None),
                    ("uncertain", receipt, pre, None),
                    ("prepare-failure", "IB configuration replace failed\n", pre, None),
                    ("same-rc-other-action", "rc=7\nfailed_operation=apply\n", pre, None),
                    ("bare-rc", "", pre, None)):
                with self.subTest(strict=strict, case=name):
                    authority = app.RuntimeInputAuthority((common, selected))
                    args = SimpleNamespace(config_mode="replace", apply=True, _replace_release=self.release,
                        _replace_runtime_authority=authority, _replace_selected={"example-ib001": {
                            "verdict": "WOULD_REPLACE", "file": str(selected), "sha256": digest, "reason": ""}})
                    state = app._IBConfigWriteState(task, "admin", "", stamp, True, endpoint=endpoint,
                        current_password="PUBLIC-MODEL-VALUE", identity_verified=True, backup_state="VERIFIED",
                        backup_receipt={"path": f"/devices/PUBLIC/current_{stamp}.yaml", "bytes": 137})
                    calls, permits, backups = [], [], []

                    def captured(argv, responder, timeout):
                        self.assertEqual(["ssh", "-4", "-tt"], argv[:3])
                        self.assertEqual("admin@203.0.113.11", argv[-2])
                        self.assertEqual("admin@203.0.113.11", responder.ib_destination)
                        self.assertEqual(60, timeout)
                        self.assertIn(argv[-1], vectors, "no launch, later read or fallback")
                        label = vectors[argv[-1]]
                        calls.append(label)
                        rc, content, frame_nonce = 0, "", nonce
                        if label == "replace":
                            rc, content = 1, body
                            if name == "wrong-frame":
                                frame_nonce = "61616161616161616161616161616161"
                        elif label == "address":
                            mac = MACS[1] if name == "identity-mismatch" else MACS[0]
                            content = f"2: eth0: <UP> mtu 1500\n    link/ether {mac}\n    inet 203.0.113.11/24\n"
                        elif label == "route":
                            content = "default via 203.0.113.1 dev eth0\n"
                        elif label == "detach" and name == "cleanup-failed":
                            rc = 3
                        answer = app.SessionResult(
                            f"__HTTP_IB_BEGIN_{frame_nonce}__\n{content}\n__HTTP_IB_END_{frame_nonce}__={rc}\n", rc)
                        if label == "replace" and name == "uncertain":
                            answer.cleanup_uncertain = True
                        return answer

                    with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                            mock.patch.object(app, "_TASK_DEADLINE", 1000), \
                            mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                            mock.patch.object(app, "_WORKER_CONNECTION", None), \
                            mock.patch.object(app, "_WORKER_STOP", None), \
                            mock.patch.object(app, "time", Facade(app.time, monotonic=lambda: 100, sleep=self.deny)), \
                            mock.patch.object(app, "os", Facade(app.os, urandom=lambda size: b"\x51" * size)), \
                            mock.patch.object(app, "_ib_project_value", return_value="PUBLIC-POLICY"), \
                            mock.patch.object(app, "_ensure_ib_config_backup", side_effect=lambda *a, **k: backups.append(1)), \
                            mock.patch.object(app, "obtain_write_permit", side_effect=permits.append), \
                            mock.patch.object(app, "interactive_run", side_effect=captured), \
                            mock.patch.object(app, "_AUTHORIZED_FAILURE_NOTE", []), \
                            mock.patch.object(app, "_direct_ipv4_after_network", self.deny), \
                            mock.patch.object(app, "confirm_first_device_change", self.deny), \
                            mock.patch.object(app, "_restore_replace_services_and_verify_ztp", self.deny):
                        with self.assertRaises(app.SetupError) as caught:
                            app._run_admitted_replace_to_ztp(state, args, None, timeout=10, authorized=True,
                                strict=strict, policy=SimpleNamespace(assert_unchanged=lambda: None) if strict else None)
                    error = caught.exception
                    self.assertIs(type(error), app.SetupError)
                    expected = "management IB operation failed" if strict else "direct IB command failed"
                    self.assertEqual(expected + "; device state is UNKNOWN", str(error))
                    self.assertEqual(outcome, getattr(error, "_replace_cleanup_outcome", None))
                    self.assertEqual(seen, calls)
                    self.assertEqual(["nvue"] * seen.count("detach") + ["nvue"], permits)
                    self.assertEqual(1 + seen.count("detach"), len(backups))
                    self.assertEqual(original, common.read_bytes())
                    self.assertEqual(data, selected.read_bytes())
        self.assertEqual([], self.effects)

    def test_initial_ipv4_cleanup_rejects_conflicting_or_mismatched_evidence(self):
        app = self.app
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(self.target().ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        authority = app.RuntimeInputAuthority([self.project / "01-global.yaml"])
        stamp = "20261119-071640"
        state = app._IBConfigWriteState(task, "admin", "", stamp, True, endpoint=endpoint,
            current_password="PUBLIC-MODEL-VALUE", identity_verified=True, backup_state="VERIFIED")
        request = app._InitialIPv4ReplaceRequest(state, authority, endpoint, stamp)
        for name, candidate, rc, dual in (
                ("dual", request, 7, True),
                ("wrong-state", app.replace(request, state=app.replace(state)), 7, False),
                ("wrong-authority", app.replace(request, authority=app.RuntimeInputAuthority(
                    [self.project / "01-global.yaml"])), 7, False),
                ("wrong-endpoint-object", app.replace(request, endpoint=app.DirectEndpoint("203.0.113.11")), 7, False),
                ("wrong-stamp", app.replace(request, stamp="20261119-071641"), 7, False),
                ("shell-not-executed", request, 126, False),
                ("not-typed", None, 7, False)):
            with self.subTest(case=name):
                primary = app.SetupError("PUBLIC original failure")
                primary._replace_initial_ipv4_failure = (("replace", rc) if candidate is None
                    else app._InitialIPv4ReplaceFailure(candidate, rc))
                if dual:
                    primary._replace_deferred_apply_failure = app._DeferredReplaceApplyFailure(
                        state, authority, endpoint, stamp, 7)
                with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                        mock.patch.object(app, "check_task_cancelled", self.deny), \
                        mock.patch.object(app, "_stage_ib_command", self.deny), \
                        mock.patch.object(app, "obtain_write_permit", self.deny):
                    app._try_cleanup_deferred_apply_failure(state, authority, primary,
                        timeout=10, strict=False, policy=None)
                self.assertNotIn("_replace_initial_ipv4_failure", primary.__dict__)
                self.assertNotIn("_replace_deferred_apply_failure", primary.__dict__)
                self.assertEqual("PUBLIC original failure", str(primary))
                self.assertIsNone(getattr(primary, "_replace_cleanup_outcome", None))
        self.assertEqual([], self.effects)

    def test_admitted_replace_finishes_fresh_ztp_keys_and_final_readiness_once(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        nested = app.Target(ib, jump, "swp1", "eth0")
        via_jump = app.Neighbor("fe80::11", "public0", MACS[0], "oob")
        direct = app.Target(ib, None, "", "eth0",
            route=app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None))
        via_ipv4 = app.DirectEndpoint("203.0.113.11")
        selected = self.release / "EXAMPLE-IB001.yaml"
        original = selected.read_bytes()
        profile = object()
        direct_ready = "nv set system hostname example-ib001\n"
        stage_result = (True, False, "service disabled\n")
        for target, endpoint, base_label in ((nested, via_jump, "sync"), (direct, via_ipv4, "deferred")):
            for case, tail, error_type in (
                    ("complete", ["ZTP", "KEY", "D4"], None),
                    ("no-keys", ["ZTP", "KEY-SKIP", "D4"], None),
                    ("base-failed", [], app.SetupError),
                    ("ztp-failed", ["ZTP"], app.SetupError),
                    ("stale-after-ztp", ["ZTP"], app.ProjectInputChanged),
                    ("stop-after-ztp", ["ZTP"], app.BatchStopped),
                    ("key-failed", ["ZTP", "KEY"], app.SetupError),
                    ("keys-not-authorized", ["ZTP", "KEY"], app.SetupError),
                    ("stale-after-key", ["ZTP", "KEY"], app.ProjectInputChanged),
                    ("readiness-failed", ["ZTP", "KEY", "D4"], app.SetupError),
                    ("stop-after-readiness", ["ZTP", "KEY", "D4"], app.BatchStopped)):
                with self.subTest(route=base_label, case=case):
                    selected.write_bytes(original)
                    authority = app.RuntimeInputAuthority([selected])
                    args = SimpleNamespace(config_mode="replace", apply=True, _replace_release=self.release,
                        _replace_runtime_authority=authority, _replace_selected={"example-ib001": {
                            "verdict": "WOULD_REPLACE", "file": str(selected),
                            "sha256": "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368",
                            "reason": ""}})
                    task = app.PreparedIBTask(target, endpoint, "", False)
                    state = app._IBConfigWriteState(task, "admin", "cumulus" if target is nested else "",
                        "20261119-073641", True, endpoint=endpoint, current_password="PUBLIC-MODEL-VALUE",
                        identity_verified=True, backup_state="VERIFIED")
                    calls, stop = [], [False]
                    strict = target is direct
                    policy = SimpleNamespace(assert_unchanged=self.deny) if strict else None
                    stage_options = {"timeout": 10, "authorized": True, "strict": strict, "policy": policy}
                    primary = app.SetupError("PUBLIC modeled stage failure")

                    def base(label, current, data, snapshot, **options):
                        self.assertIs(state, current)
                        self.assertIs(authority, snapshot)
                        self.assertEqual(original, data)
                        self.assertEqual(stage_options, options)
                        calls.append(label)
                        if case == "base-failed":
                            raise primary
                        return direct_ready

                    def restore(current, services, readback, **options):
                        self.assertIs(state, current)
                        self.assertIs(profile, services)
                        self.assertEqual(direct_ready, readback)
                        self.assertEqual(stage_options, options)
                        calls.append("ZTP")
                        if case == "ztp-failed":
                            raise primary
                        if case == "stale-after-ztp":
                            selected.write_bytes(original + b"\n# PUBLIC changed after ZTP\n")
                        if case == "stop-after-ztp":
                            stop[0] = True
                        return stage_result

                    def keys():
                        calls.append("KEY-SKIP" if case == "no-keys" else "KEY")
                        if case == "key-failed":
                            raise primary
                        if case == "stale-after-key":
                            selected.write_bytes(original + b"\n# PUBLIC changed after KEY\n")
                        return case != "keys-not-authorized"

                    def ready(readiness):
                        self.assertIs(type(readiness), app.ReadinessPolicy)
                        self.assertEqual((15, 10, 9), (readiness.first_delay, readiness.interval, readiness.attempts))
                        calls.append("D4")
                        if case == "readiness-failed":
                            raise primary
                        if case == "stop-after-readiness":
                            stop[0] = True
                        return direct_ready if strict else None

                    with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                            mock.patch.object(app, "_WORKER_STOP", SimpleNamespace(is_set=lambda: stop[0])), \
                            mock.patch.object(app, "_ACTIVE_COORDINATOR", None), \
                            mock.patch.object(app, "_WORKER_CONNECTION", None), \
                            mock.patch.object(app, "_TASK_DEADLINE", None), \
                            mock.patch.object(app, "run_replace_stage", lambda *a, **k: base("sync", *a, **k)), \
                            mock.patch.object(app, "_run_replace_deferred_stage", lambda *a, **k: base("deferred", *a, **k)), \
                            mock.patch.object(app, "_restore_replace_services_and_verify_ztp", restore), \
                            mock.patch.object(app, "_stage_ib_command", self.deny), \
                            mock.patch.object(app, "run_on_ib", self.deny), \
                            mock.patch.object(app, "obtain_write_permit", self.deny), \
                            mock.patch.object(app, "confirm_first_device_change", self.deny), \
                            mock.patch.object(app, "run_key_stage", self.deny), \
                            mock.patch.object(app, "run_management_direct_checks", self.deny):
                        def invoke():
                            finish = getattr(app, "_run_admitted_replace_through_readiness", None)
                            if finish is None:
                                # Behavior before the final phases were attached: only base through ZTP.
                                return app._run_admitted_replace_to_ztp(state, args, profile, **stage_options)
                            return finish(state, args, profile, key_stage=keys, verify_ready=ready, **stage_options)
                        if error_type is None:
                            observed = invoke()
                            self.assertEqual((stage_result, direct_ready if strict else None), observed)
                        else:
                            with self.assertRaises(error_type) as caught:
                                invoke()
                            self.assertIs(type(caught.exception), error_type)
                            if case in {"base-failed", "ztp-failed", "key-failed", "readiness-failed"}:
                                self.assertIs(primary, caught.exception)
                    self.assertEqual([base_label] + tail, calls)
        self.assertEqual([], self.effects)

    def test_replace_first_write_confirmation_prints_warning_once_in_parent(self):
        app = self.app
        ib = self.target().ib
        jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        via_jump = app.Target(ib, jump, "swp1", "eth0")
        direct = self.target()
        reason = "PUBLIC existing first operation reason"
        source = self.project / "01-global.yaml"
        original = source.read_bytes()
        for case, target, worker_request, mode, preauthorized, response, prompts, error_type in (
                ("replace-inline", via_jump, False, "replace", False, "yes", 1, None),
                ("replace-worker-direct", direct, True, "replace", False, "yes", 1, None),
                ("replace-denied", via_jump, True, "replace", False, "no", 1, app.BatchStopped),
                ("replace-eof", via_jump, False, "replace", False, "eof", 1, app.BatchStopped),
                ("replace-yes", direct, True, "replace", True, "unused", 0, None),
                ("replace-stale", direct, False, "replace", False, "unused", 0, app.ProjectInputChanged),
                ("patch-inline", via_jump, False, "patch", False, "yes", 1, None)):
            with self.subTest(case=case):
                source.write_bytes(original)
                authority = app.RuntimeInputAuthority([source])
                args = SimpleNamespace(apply=True, yes=preauthorized, config_mode=mode)
                task = app.PreparedIBTask(target, app.DirectEndpoint("203.0.113.11") if target is direct else
                    app.Neighbor("fe80::11", "public0", MACS[0], "oob"), "", False)
                coordinator = app.RuntimeCoordinator(args, None, "PUBLIC-MODEL-VALUE", [task], authority)
                transcript, seen = io.StringIO(), []
                if case == "replace-stale":
                    source.write_bytes(original + b"\n# PUBLIC stale authorization input\n")

                def answer(prompt):
                    self.assertEqual("Authorize this change and subsequent eligible IB devices? [y/N]: ", prompt)
                    seen.append(transcript.getvalue())
                    if response == "eof":
                        raise EOFError
                    return response

                with redirect_stdout(transcript), \
                        mock.patch.object(app, "REPORT_HANDLE", None), \
                        mock.patch.object(app, "_TASK_LOG_BUFFER", []), \
                        mock.patch.object(app, "_TASK_DEADLINE", None), \
                        mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator), \
                        mock.patch.object(app, "_WORKER_CONNECTION", None), \
                        mock.patch.object(app, "input", side_effect=answer, create=True), \
                        mock.patch.object(app, "interactive_run", self.deny), \
                        mock.patch.object(app, "obtain_write_permit", self.deny):
                    def invoke():
                        if worker_request:
                            return coordinator.request("authorize", reason, target)
                        return app.confirm_first_device_change(target, reason)
                    if error_type is None:
                        try:
                            self.assertIs(True, invoke())
                            self.assertIs(True, invoke())
                        except AttributeError:
                            self.fail("direct admission must reach the real parent confirmation")
                    else:
                        with self.assertRaises(error_type) as caught:
                            invoke()
                        self.assertIs(type(caught.exception), error_type)
                        if error_type is app.BatchStopped:
                            self.assertTrue(coordinator.stopped)
                            with self.assertRaises(app.BatchStopped):
                                invoke()
                self.assertEqual(prompts, len(seen))
                self.assertEqual(prompts if mode == "replace" else 0, transcript.getvalue().count(WARNING))
                if prompts:
                    expected_path = "direct" if target is direct else "EXAMPLE-JUMP01:swp1"
                    self.assertIn("FIRST DEVICE CHANGE: EXAMPLE-IB001 via " + expected_path, seen[0])
                    self.assertIn("Required action: " + reason, seen[0])
                    self.assertEqual(1 if mode == "replace" else 0, seen[0].count(WARNING))
                self.assertFalse(coordinator.writes_attempted)
        self.assertEqual([], self.effects)

    def test_replace_apply_admits_only_current_managed_input_before_inspection(self):
        app = self.app
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(self.target().ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        selected = self.release / "EXAMPLE-IB001.yaml"
        data = selected.read_bytes()
        policy_file = self.project / "01-global.yaml"
        # A syntactic PUBLIC placeholder, never checked against a password.
        policy_bytes = ("switches:\n  - ib:\n      system:\n        aaa:\n          user:\n"
                        "            admin:\n              password: '$6$PublicFixture$" + "A" * 86 + "'\n").encode("ascii")
        previous = object()
        for case in ("current", "missing-yaml", "missing-policy", "wrong-account", "no-coordinator",
                     "foreign-authority", "other-mode", "not-manager", "local", "stale-input",
                     "selection-not-bound"):
            with self.subTest(case=case):
                policy_file.write_bytes(policy_bytes)
                selected.write_bytes(data)
                actual_policy = app.ProjectPasswordPolicy(policy_file, "admin", interactive=False)
                if case == "wrong-account":
                    actual_policy.user = "PUBLIC-OTHER"
                if case == "missing-yaml":
                    selected.unlink()
                snapshot = app.RuntimeInputAuthority((policy_file,) if case == "missing-yaml"
                                                     else (policy_file, selected))
                selection = {
                    "verdict": "YAML_MISSING_OR_INVALID" if case == "missing-yaml" else "WOULD_REPLACE",
                    "file": str(selected), "sha256": "" if case == "missing-yaml" else hashlib.sha256(data).hexdigest(),
                    "reason": YAML_ERROR if case == "missing-yaml" else "",
                }
                if case == "selection-not-bound":
                    selection["sha256"] = "0" * 64
                args = SimpleNamespace(config_mode="replace", apply=True, yes=True, ib_user="admin",
                    eth_user="admin", execution_mode="ethernet" if case == "other-mode" else "management",
                    connect_timeout=10, run_stamp="20261119-075221",
                    _on_management_server=case not in {"not-manager", "local"},
                    _replace_selected={"example-ib001": selection}, _replace_release=self.release,
                    _replace_runtime_authority=snapshot)
                task = app.PreparedIBTask(target, endpoint, "", case == "local")
                policy = None if case == "missing-policy" else actual_policy
                parent_snapshot = (app.RuntimeInputAuthority((policy_file, selected))
                                   if case == "foreign-authority" else snapshot)
                coordinator = app.RuntimeCoordinator(args, policy, "PUBLIC-INITIAL-MODEL", [task], parent_snapshot)
                seen = []
                if case == "stale-input":
                    selected.write_bytes(data + b"\n# PUBLIC stale task input\n")

                def stop_at_inspection(device, point, outer_user, outer, ib_user, initial, timeout,
                                       task_policy, **options):
                    self.assertIs(target, device)
                    self.assertIs(endpoint, point)
                    self.assertEqual(("", "", "admin", "PUBLIC-INITIAL-MODEL", 10),
                                     (outer_user, outer, ib_user, initial, timeout))
                    self.assertIs(policy, task_policy)
                    self.assertEqual({"apply": True, "authorized": True, "local": False,
                                      "strict": False, "_management_private_key": None}, options)
                    seen.append("inspect")
                    raise app.SetupError("PUBLIC inspection boundary")

                with ExitStack() as guards:
                    for key, value in (("_TASK_IB_CONFIG", previous), ("_WORKER_CONNECTION", None),
                                       ("_WORKER_STOP", None), ("_TASK_DEADLINE", None),
                                       ("_ACTIVE_COORDINATOR", None if case == "no-coordinator" else coordinator),
                                       ("_TASK_LOG_BUFFER", [])):
                        guards.enter_context(mock.patch.object(app, key, value))
                    guards.enter_context(mock.patch.object(app, "inspect_ib_device", stop_at_inspection))
                    guards.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "password", self.deny))
                    for boundary in ("interactive_run", "_stage_ib_command", "obtain_write_permit",
                                     "confirm_first_device_change", "_run_admitted_replace_through_readiness"):
                        guards.enter_context(mock.patch.object(app, boundary, self.deny))
                    result = app.execute_ib_task(task, args, policy, "PUBLIC-INITIAL-MODEL", None, [], None,
                                                 authorized=True)
                    self.assertIs(previous, app._TASK_IB_CONFIG)
                self.assertEqual(["inspect"] if case == "current" else [], seen)
                self.assertEqual("CHECK_ONLY" if case == "missing-yaml" else "FAILED", result["outcome"])
                self.assertIs(False, result["writes_attempted"])
                self.assertIs(False, coordinator.writes_attempted)
                self.assertIs(False, result["verified_complete"])
                self.assertEqual([], result["direct_rows"])
                if case == "current":
                    self.assertEqual("PUBLIC inspection boundary", result["reason"])
                    self.assertEqual("WOULD_REPLACE", result["replace"]["verdict"])
                elif case == "missing-yaml":
                    self.assertEqual(selection, result["replace"])
                    self.assertFalse(selected.exists())
                    self.assertEqual("NOT_REACHED", result["stage_status"]["authentication"])
                elif case == "stale-input":
                    self.assertIn("input bytes changed", result["batch_error"])
                    self.assertEqual(result["reason"], result["batch_error"])
                else:
                    self.assertTrue(result["reason"])
        self.assertEqual([], self.effects)

    def test_private_replace_execute_runs_owned_initial_backup_then_tail_without_replay(self):
        app = self.app
        route = app._import_tools("tools.login_path").Route(NAMES[0], "direct", "PUBLIC", None, None, None)
        target = app.Target(self.target().ib, None, "", "eth0", route=route)
        endpoint = app.DirectEndpoint("203.0.113.11")
        task = app.PreparedIBTask(target, endpoint, "", False)
        selected = self.release / "EXAMPLE-IB001.yaml"
        global_file = self.project / "01-global.yaml"
        global_file.write_text("switches:\n  - ib:\n      system:\n        aaa:\n          user:\n"
                               "            admin:\n              password: '$6$PublicFixture$" + "A" * 86 + "'\n",
                               encoding="ascii")
        policy = app.ProjectPasswordPolicy(global_file, "admin", interactive=False)
        authority = app.RuntimeInputAuthority((global_file, selected))
        stamp = "20261119-080011"
        nonce = "67676767676767676767676767676767"
        prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
        suffix = '; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce + '__=%s\\n" "$task_rc"; exit "$task_rc"'
        base = ("nv set system hostname example-ib001\n"
                "nv set interface eth0 ipv4 address 203.0.113.11/24\n"
                "nv set interface eth0 ipv4 gateway 203.0.113.1\n")
        auto = "nv set system config auto-save state enabled"
        ztp_save = "nv set system ztp config-save enabled"
        ready = base + auto + "\n" + ztp_save + "\n"
        ztp = "service disabled\nstatus aborted\n"
        backup_receipt = {"path": f"/devices/PUBLIC/current_{stamp}.yaml", "bytes": 137}
        inspect = ["INSPECT", "IP", "ROUTE", "ZTP"]
        initial = inspect + ["PROMPT", "PENDING", "BACKUP", "AUTO", "ZTP_SAVE", "APPLY", "SAVE", "READ", "ZTP"]
        for case, expected, verified in (
                ("complete", initial + ["REPLACE_COMPLETE", "KEY", "D4", "EXTRA"], True),
                ("initial-skip", inspect + ["PROMPT", "BACKUP", "REPLACE_COMPLETE", "KEY_SKIP", "D4", "EXTRA"], True),
                ("excluded-extra", initial + ["REPLACE_COMPLETE", "KEY", "D4", "EXTRA"], False),
                ("deny", inspect + ["PROMPT"], False),
                ("backup-failed", inspect + ["PROMPT", "PENDING", "BACKUP"], False),
                ("post-ztp-failed", initial + ["REPLACE_COMPLETE"], False),
                ("key-failed", initial + ["REPLACE_COMPLETE", "KEY"], False),
                ("d4-failed", initial + ["REPLACE_COMPLETE", "KEY", "D4"], False),
                ("d4-wrong-readback", initial + ["REPLACE_COMPLETE", "KEY", "D4"], False)):
            with self.subTest(case=case):
                args = SimpleNamespace(config_mode="replace", apply=True, yes=False, ib_user="admin", eth_user="admin",
                    execution_mode="management", connect_timeout=10, run_stamp=stamp, _on_management_server=True,
                    _replace_runtime_authority=authority, _replace_release=self.release, _replace_selected={
                        "example-ib001": {"verdict": "WOULD_REPLACE", "file": str(selected),
                        "sha256": "a596e8c95db198f49c2402dc80d4a4312f665519600ffce069cbf3476af23368", "reason": ""}})
                coordinator = app.RuntimeCoordinator(args, policy, "PUBLIC-INITIAL-MODEL", [task], authority)
                calls = []
                keys = [] if case == "initial-skip" else [{"name": "model.pub"}]
                publication = io.StringIO()

                def captured(argv, responder, timeout):
                    self.assertEqual(["ssh", "-4", "-tt"], argv[:3])
                    self.assertEqual("admin@203.0.113.11", argv[-2])
                    self.assertEqual("admin@203.0.113.11", responder.ib_destination)
                    self.assertEqual(60, timeout)
                    program = shlex.split(argv[-1])
                    self.assertEqual(["sh", "-c"], program[:2])
                    self.assertEqual(3, len(program))
                    self.assertTrue(program[2].startswith(prefix) and program[2].endswith(suffix))
                    command = tuple(shlex.split(program[2][len(prefix):-len(suffix)]))
                    effects = {
                        ("ip", "addr", "show", "eth0"): ("IP",
                            "2: eth0: <UP> mtu 1500\n    link/ether 02:00:00:00:00:11\n    inet 203.0.113.11/24\n"),
                        ("ip", "route"): ("ROUTE", "default via 203.0.113.1 dev eth0\n"),
                        ("nv", "show", "system", "ztp"): ("ZTP", ztp),
                        ("nv", "config", "diff", "-o", "commands"): ("PENDING", ""),
                        tuple(auto.split()): ("AUTO", ""), tuple(ztp_save.split()): ("ZTP_SAVE", ""),
                        ("nv", "config", "apply", "-y"): ("APPLY", ""), ("nv", "config", "save"): ("SAVE", ""),
                        ("nv", "config", "show", "-o", "commands"): ("READ", ready),
                    }
                    if (len(command) == 5 and command[:2] == ("sh", "-c") and command[3:] == ("--", stamp)
                            and hashlib.sha256(command[2].encode()).hexdigest()
                            == "7c1a6e279773a41477e0e7a061d8ecf828273157b785aca844361a14ff3344b6"):
                        label, output = "BACKUP", (f"path={backup_receipt['path']}\nbytes=137\n"
                                                   if case != "backup-failed" else "")
                    else:
                        self.assertIn(command, effects, "model refuses any unlisted external operation")
                        label, output = effects[command]
                    calls.append(label)
                    return app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\n{output}\n__HTTP_IB_END_{nonce}__=0\n", 0)

                def inspect_model(device, point, *_ignored, **options):
                    self.assertIs(target, device)
                    self.assertIs(endpoint, point)
                    self.assertIs(False, options["authorized"])
                    self.assertIs(True, options["apply"])
                    calls.append("INSPECT")
                    result = app.SessionResult(ready if case == "initial-skip" else base, 0)
                    result._direct_endpoint = endpoint
                    return result, "PUBLIC-VERIFIED-MODEL", False

                def ask_model(prompt):
                    self.assertIn(WARNING, publication.getvalue())
                    self.assertEqual("Authorize this change and subsequent eligible IB devices? [y/N]: ", prompt)
                    calls.append("PROMPT")
                    return "no" if case == "deny" else "yes"

                def replace_model(state, supplied_args, services, *, timeout, authorized, strict, policy):
                    self.assertIs(state, app._TASK_IB_CONFIG)
                    self.assertIs(endpoint, state.endpoint)
                    self.assertIs(args, supplied_args)
                    self.assertIsNone(services)
                    self.assertEqual((10, True, False), (timeout, authorized, strict))
                    self.assertIs(actual_policy, policy)
                    # Emulate the existing first replace write's original backup and permit boundaries.
                    app._ensure_ib_config_backup(target, endpoint, "", "", "admin", "PUBLIC-VERIFIED-MODEL", 10, local=False)
                    self.assertEqual(("VERIFIED", backup_receipt), (state.backup_state, state.backup_receipt))
                    app.obtain_write_permit("nvue")
                    calls.append("REPLACE_COMPLETE")
                    if case == "post-ztp-failed":
                        raise app.SetupError("PUBLIC post-restoration ZTP not verified")
                    return True, False, "service disabled\nstatus success\n"

                def key_model(device, point, outer_user, outer, ib_user, timeout, entries, **options):
                    self.assertEqual((target, endpoint, "", "", "admin", 10), (device, point, outer_user, outer, ib_user, timeout))
                    self.assertIs(keys, entries)
                    expected_keys = {"local", "apply", "authorized", "management_private_key", "details",
                                     "read_device_fingerprint", "operator_forced", "host_key_records", "ib_password"}
                    self.assertEqual(expected_keys, set(options))
                    self.assertEqual((False, True, True, None, False, "PUBLIC-VERIFIED-MODEL"),
                                     tuple(options[x] for x in ("local", "apply", "authorized", "management_private_key",
                                                               "operator_forced", "ib_password")))
                    calls.append("KEY" if keys else "KEY_SKIP")
                    if case == "key-failed":
                        raise app.SetupError("PUBLIC key stage failed")
                    if keys:
                        app.obtain_write_permit("public_key")
                        options["details"].update(content_action="UNCHANGED")
                    return True

                def d4_model(device, account, credential, timeout, **options):
                    self.assertEqual((target, "admin", "PUBLIC-VERIFIED-MODEL", 10), (device, account, credential, timeout))
                    self.assertIs(actual_policy, options["policy"])
                    self.assertIs(False, options["strict"])
                    self.assertIsNone(options.get("deferred_stamp"))
                    p = options["readiness_policy"]
                    self.assertEqual((15, 10, 9), (p.first_delay, p.interval, p.attempts))
                    options["details"].update(identity={"ok": True, "via_ipv4": True}, endpoint=endpoint)
                    calls.append("D4")
                    if case == "d4-failed":
                        raise app.SetupError("PUBLIC final readiness failed")
                    if case == "d4-wrong-readback":
                        return ready.replace("203.0.113.11/24", "203.0.113.12/24")
                    return ready

                def extra_model(targets, credentials, account, timeout, **options):
                    self.assertEqual(([target], {"example-ib001": "PUBLIC-VERIFIED-MODEL"}, "admin", 10),
                                     (targets, credentials, account, timeout))
                    self.assertIs(True, options["apply"])
                    self.assertIs(True, options["on_management_server"])
                    calls.append("EXTRA")
                    return [{"hostname": NAMES[0], "status": "FAIL" if case == "excluded-extra" else "PASS",
                             "interface": "eth0", "ip": "203.0.113.11", "detail": "PUBLIC summary probe"}]

                actual_policy = policy
                previous = object()
                with ExitStack() as guards:
                    guards.enter_context(redirect_stdout(publication))
                    for name, value in (("_TASK_IB_CONFIG", previous), ("_TASK_LOG_BUFFER", None), ("_TASK_DEADLINE", None),
                                        ("REPORT_HANDLE", None), ("_WORKER_CONNECTION", None), ("_WORKER_STOP", None),
                                        ("_ACTIVE_COORDINATOR", coordinator)):
                        guards.enter_context(mock.patch.object(app, name, value))
                    guards.enter_context(mock.patch.object(app, "os", Facade(app.os, urandom=lambda count: b"\x67" * count)))
                    guards.enter_context(mock.patch.object(app, "input", side_effect=ask_model, create=True))
                    guards.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "password", self.deny))
                    for name, effect in (("inspect_ib_device", inspect_model), ("interactive_run", captured),
                        ("_run_admitted_replace_to_ztp", replace_model), ("run_key_stage", key_model),
                        ("_wait_direct_ipv4_readback", d4_model), ("run_management_direct_checks", extra_model),
                        ("refresh_ib_host_key", self.deny), ("verify_ipv4_login", self.deny)):
                        guards.enter_context(mock.patch.object(app, name, side_effect=effect))
                    result = app.execute_ib_task(task, args, policy, "PUBLIC-INITIAL-MODEL", None, keys, None)
                    self.assertIs(previous, app._TASK_IB_CONFIG)
                self.assertEqual(expected, calls)
                self.assertEqual(verified, result["verified_complete"])
                completed = case in {"complete", "initial-skip", "excluded-extra"}
                self.assertEqual("REPLACED" if completed else "WOULD_REPLACE", result["replace"]["verdict"])
                self.assertEqual("CONFIGURED" if completed else "NOT_ATTEMPTED" if case == "deny" else "FAILED",
                                 result["outcome"])
                if completed:
                    self.assertEqual("success", result["ztp"]["status"])
                if case == "excluded-extra":
                    self.assertEqual("FAILED", result["stage_status"]["direct_ssh"])
                    self.assertEqual("FAILED_DIRECT_SSH_CHECK", result["attention_category"])
                self.assertEqual(case != "deny", coordinator.writes_attempted)
                self.assertEqual(None if case in {"backup-failed", "deny"} else backup_receipt, result["backup"])
        self.assertEqual([], self.effects)
