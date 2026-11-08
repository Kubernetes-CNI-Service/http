"""I-028 (v3.1.2 M3 WP-3): load starts the Switch collection worker on the management server.

Expectations come from issue I-028 (问题文档 I-028, owner 2026-11-03: 「采集worker的启动应该不依赖
ztp/dhcp/http服务……所以我觉得不需要设置任何条件。」) and its expected fix: the worker starts on
the management server outside --dry-run regardless of HTTP/DHCP/ZTP; the page control endpoint
(CGI, control auth) is still installed only with HTTP; the worker scope comes from the deployment
scope and a deployment scope of ``all`` asks once, as today; 12-ztp-monitor and the manual-ztp
worker keep their conditions.  The v3.1.2 guide decisions O4 (non-interactive ``all`` without a
scope: no worker, a WARN naming --prod/--air/--ztp-monitor-scope, load still succeeds; interactive:
ask even when the monitor is declined; no HTTP: start anyway) and the Docker freeze (supervisor
backend unchanged) complete the contract.

``SystemdLoadMainFixture`` is the reusable systemd ``main`` fixture announced by the guide for
WP-5 and WP-13: it runs the real ``11-load.py::main`` as a Linux management server (systemd backend
by default) with every heavy or host-mutating step replaced by a recorder.  Reuse it from another
test module by binding this module (G1) and mixing the fixture into a new TestCase::

    from test_cases import test_load_collection_worker_contract as M3

    class MyLoadTests(M3.SystemdLoadMainFixture, unittest.TestCase):
        def test_x(self):
            result = self.run_load_main(self.main_args(), self.main_inputs(http=True, dhcp=False),
                                        patches={"some_new_gate": mock.Mock()})

The mixin has no test methods, so mixing it in never collects these tests twice.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import itertools
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script(
    "load_collection_worker_contract_load", ROOT / "DAY0-Prepare/11-load.py",
)


class _FakeStdin:
    """Only the tty bit is observable; every read must go through a recorded prompt."""

    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        raise AssertionError("load read stdin outside a recorded prompt")

    def fileno(self) -> int:
        raise AssertionError("load selected on stdin outside a recorded prompt")


class _FakeProcess:
    pid = 4242

    def poll(self):
        return None


class SystemdLoadMainFixture:
    """Run the real ``11-load.py::main`` as a Linux management server with recorded side effects.

    Entry points:
    - ``main_args(**overrides)``: the parsed-argument namespace ``main`` reads (non-dry-run,
      management-server, ``--start-services``, ``--skip-infra``, deployment scope ``all``).
    - ``main_inputs(http=, dhcp=, ztp=)``: a minimal ``validate_inputs`` result.
    - ``run_load_main(args, inputs, backend=, tty=, monitor_answer=, scope_answers=, patches=)``:
      returns a namespace with ``rc``, ``stdout``, ``stderr``, ``events`` (ordered tuples),
      ``popen`` (argv lists), ``runs`` (command tuples), ``prompts``, ``root``, ``project``,
      ``mocks`` (name -> recorder).  ``patches`` adds or replaces module attributes, e.g. a later
      work package's root check; patch that function rather than ``os.geteuid`` (guide 2.2 #6).

    ``start_switch_collection_worker`` itself stays real; its own boundaries (``run``,
    ``_popen_subprocess``, control auth, Apache boundary and reload) are recorded, so a test sees
    what the worker start would install and launch.  ``HTTP_ROOT`` is a private temporary tree.
    """

    load_module = LOAD

    def main_args(self, **overrides) -> SimpleNamespace:
        values = dict(
            project="demo", host_role="management-server", dry_run=False,
            deployment_scope="all", switch_scope=None, mini=None,
            no_upgrade=True, p2p_file=None, skip_infra=True, skip_generate=False,
            skip_doca=False, download_doca=False, update_passwords=False,
            start_services=True, start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
        )
        values.update(overrides)
        return SimpleNamespace(**values)

    def main_inputs(self, *, http: bool, dhcp: bool, ztp: bool | None = None) -> SimpleNamespace:
        settings = SimpleNamespace(
            http_enabled=http, dhcp_enabled=dhcp,
            ztp_enabled=(http and dhcp) if ztp is None else ztp,
            http_address=None, http_port=80, http_package="apache2",
            http_listener_ips=("192.0.2.10",), service_ips=("192.0.2.10",),
            ztp_prefix="ztp", ztp_ips={}, boot_ips=(),
            schema_version=self.load_module.GLOBAL_SCHEMA_VERSION, versions={},
        )
        return SimpleNamespace(
            settings=settings, p2p_file=None, device_types=frozenset({"eth"}),
            pubkeys={}, source_identities={}, air_topology_policy=None,
            effective_devices_file=None, effective_devices_sha256=None,
        )

    def run_load_main(
        self, args: SimpleNamespace, inputs: SimpleNamespace, *,
        backend: str = "systemd", tty: bool = False, monitor_answer: bool = True,
        scope_answers: tuple[str, ...] = (), patches: dict | None = None,
    ) -> SimpleNamespace:
        load = self.load_module
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        project = root / "DAY0-Prepare" / str(args.project)
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text("# placeholder\n", encoding="utf-8")
        events: list[tuple] = []
        popen: list[list[str]] = []
        runs: list[tuple[str, ...]] = []
        prompts: list[str] = []
        answers = list(scope_answers)

        def forbidden_backend_command(command, **_kwargs):
            raise AssertionError(f"unexpected service command: {command}")

        runtime = (
            load.SystemdRuntimeBackend(command_runner=forbidden_backend_command)
            if backend == "systemd" else SimpleNamespace(name=backend)
        )

        def recorder(name, result=None):
            def record(*call_args, **call_kwargs):
                events.append((name,))
                return result
            return mock.Mock(side_effect=record)

        real_confirm = load.confirm_ztp_monitor_start

        def confirm_monitor():
            if not tty:
                return real_confirm()
            prompts.append("monitor")
            events.append(("prompt", "monitor"))
            return monitor_answer

        def scope_input(_question=""):
            prompts.append("scope")
            events.append(("prompt", "scope"))
            if not answers:
                raise AssertionError("unexpected extra scope question")
            return answers.pop(0)

        def record_run(command, **_kwargs):
            runs.append(tuple(command))
            events.append(("run", *command[:2]))

        def record_popen(command, **_kwargs):
            popen.append(list(command))
            events.append(("popen", Path(command[2]).name))
            return _FakeProcess()

        def make_candidate(target):
            candidate = Path(tempfile.mkdtemp(prefix=".load-dhcp-candidate-", dir=target))
            return candidate

        defaults = {
            "parse_args": mock.Mock(return_value=args),
            "runtime_os": mock.Mock(return_value="Linux"),
            "service_runtime_backend": mock.Mock(return_value=runtime),
            "acquire_deployment_lock": mock.Mock(return_value=97),
            "release_deployment_lock": mock.Mock(),
            "require_no_pending_dhcp_transaction": mock.Mock(),
            "sync_marker_present": mock.Mock(return_value=False),
            "HTTP_ROOT": root,
            "resolve_project": mock.Mock(return_value=project),
            "load_global": mock.Mock(
                return_value=SimpleNamespace(http_enabled=inputs.settings.http_enabled),
            ),
            "require_http_project_source_access": mock.Mock(),
            "stop_native_ztp_monitors": recorder("stop-native-monitor", ()),
            "ensure_management_key": mock.Mock(),
            "prepare_pubkeys": mock.Mock(),
            "ensure_previous_generation_frozen": mock.Mock(return_value=None),
            "initialize_from_template": mock.Mock(),
            "validate_inputs": mock.Mock(return_value=(inputs, {})),
            "validate_management_host": mock.Mock(return_value=True),
            "plan_local_dhcp_runtime": mock.Mock(return_value=SimpleNamespace(
                listener_names=("eno7",), listener_ifindexes=(17,),
                endpoint_ips=("192.0.2.10",),
            )),
            "supervisor_service_availability": mock.Mock(return_value=(
                inputs.settings.http_enabled, inputs.settings.dhcp_enabled,
            )),
            "confirm_ztp_monitor_start": mock.Mock(side_effect=confirm_monitor),
            "input": mock.Mock(side_effect=scope_input),
            "quiesce_services": recorder("quiesce"),
            "require_artifact_builder_services_inactive": recorder("builder-inactive"),
            "activate_project": recorder("activate"),
            "snapshot_ztp_prefix_publication": mock.Mock(),
            "configure_ztp_prefix_publication": mock.Mock(),
            "render_ztp_runtime": mock.Mock(),
            "_device_types_after_dhcp": mock.Mock(return_value=frozenset({"eth"})),
            "verify_monitor_authority": mock.Mock(),
            "snapshot_release_links": mock.Mock(return_value={}),
            "generate_configs": recorder("generate"),
            "retire_unselected_release_links": mock.Mock(),
            "_create_dhcp_candidate_dir": mock.Mock(side_effect=make_candidate),
            "_discard_dhcp_candidate_dir": mock.Mock(),
            "validate_and_publish_release": mock.Mock(return_value=None),
            "mount_and_test_dhcp": mock.Mock(),
            "publish_native_apache_listener_config": mock.Mock(),
            "preflight_services": mock.Mock(),
            "start_services": recorder("start-services"),
            "reset_completion_handoff_state": recorder("reset-handoff"),
            "start_ztp_monitor": recorder("monitor"),
            "start_manual_ztp_worker": recorder("manual"),
            "verify_control_auth": recorder("control-auth"),
            "verify_apache_publication_boundary": recorder("apache-boundary"),
            "_reload_apache_if_active": recorder("apache-reload"),
            "sudo_command": mock.Mock(side_effect=lambda *command: list(command)),
            "run": mock.Mock(side_effect=record_run),
            "_popen_subprocess": mock.Mock(side_effect=record_popen),
        }
        defaults.update(patches or {})
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            for name, value in defaults.items():
                stack.enter_context(mock.patch.object(load, name, value, create=(name == "input")))
            stack.enter_context(mock.patch.object(load.sys, "stdin", _FakeStdin(tty)))
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            rc = load.main([])
        return SimpleNamespace(
            rc=rc, stdout=stdout.getvalue(), stderr=stderr.getvalue(), events=events,
            popen=popen, runs=runs, prompts=prompts, root=root, project=project,
            mocks=defaults,
        )

    def worker_scopes(self, result: SimpleNamespace) -> list[str]:
        """The ``--scope`` values of every switch-collection worker launch."""
        scopes = []
        for argv in result.popen:
            if Path(argv[2]).name == "switch-collection-worker.py":
                scopes.extend(
                    argv[index + 1] for index, item in enumerate(argv) if item == "--scope"
                )
        return scopes

    def launched(self, result: SimpleNamespace) -> list[str]:
        return [event[1] for event in result.events if event[0] == "popen"]


class LoadCollectionWorkerStartTests(SystemdLoadMainFixture, unittest.TestCase):
    """main() and start_switch_collection_worker() under the I-028 contract."""

    def _assert_no_endpoint(self, result: SimpleNamespace) -> None:
        names = {event[0] for event in result.events}
        self.assertNotIn("control-auth", names)
        self.assertNotIn("apache-boundary", names)
        self.assertNotIn("apache-reload", names)
        for command in result.runs:
            self.assertNotIn(str(LOAD.SWITCH_COLLECTION_CONTROL_DEST), command)
            self.assertNotIn(str(LOAD.SWITCH_COLLECTION_CONTROL_DEST.parent), command)

    def test_no_http_no_dhcp_prod_starts_worker_without_endpoint(self) -> None:
        # I-028 owner 2026-11-03「不需要设置任何条件」; expected fix 1, 2, 4.
        result = self.run_load_main(
            self.main_args(deployment_scope="prod"),
            self.main_inputs(http=False, dhcp=False),
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["switch-collection-worker.py"], self.launched(result))
        self.assertEqual(["prod"], self.worker_scopes(result))
        self.assertNotIn(("monitor",), result.events)
        self.assertNotIn(("manual",), result.events)
        self._assert_no_endpoint(result)
        self.assertEqual([], result.prompts)

    def test_http_only_starts_worker_and_installs_endpoint(self) -> None:
        # I-028 expected fix 2: the control endpoint still comes with HTTP.
        result = self.run_load_main(
            self.main_args(deployment_scope="prod"),
            self.main_inputs(http=True, dhcp=False),
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["switch-collection-worker.py"], self.launched(result))
        self.assertEqual(["prod"], self.worker_scopes(result))
        self.assertNotIn(("monitor",), result.events)
        self.assertNotIn(("manual",), result.events)
        cgi = (
            "install", "-m", "0755", str(LOAD.SWITCH_COLLECTION_CONTROL_SOURCE),
            str(LOAD.SWITCH_COLLECTION_CONTROL_DEST),
        )
        self.assertIn(cgi, result.runs)
        request = [command for command in result.runs if command[-1].endswith(
            "monitor/status/switch-collection.request")]
        self.assertEqual(1, len(request))
        self.assertEqual(
            ("install", "-m", "0664", "-o", "root", "-g", "www-data"), request[0][:7],
        )
        order = [event[0] for event in result.events]
        self.assertLess(order.index("control-auth"), order.index("run"))
        self.assertIn("apache-boundary", order)
        self.assertLess(order.index("apache-reload"), order.index("popen"))

    def test_http_dhcp_monitor_declined_still_starts_worker(self) -> None:
        # I-028 expected fix 1 and 4: the worker no longer depends on the monitor answer.
        result = self.run_load_main(
            self.main_args(deployment_scope="prod"),
            self.main_inputs(http=True, dhcp=True),
            tty=True, monitor_answer=False,
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["switch-collection-worker.py"], self.launched(result))
        self.assertEqual(["prod"], self.worker_scopes(result))
        self.assertNotIn(("monitor",), result.events)
        self.assertNotIn(("manual",), result.events)
        self.assertEqual(["monitor"], result.prompts)

    def test_all_scope_tty_monitor_declined_asks_once_for_worker(self) -> None:
        # O4 ②: interactive, monitor declined, deployment scope all -> ask (once).
        result = self.run_load_main(
            self.main_args(),
            self.main_inputs(http=True, dhcp=True),
            tty=True, monitor_answer=False, scope_answers=("prod",),
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["monitor", "scope"], result.prompts)
        self.assertEqual(["prod"], self.worker_scopes(result))
        self.assertNotIn(("monitor",), result.events)
        self.assertNotIn(("manual",), result.events)

    def test_all_scope_tty_asks_once_shared_by_monitor_and_worker(self) -> None:
        # I-028 expected fix 3: deployment scope all asks once, as today.
        result = self.run_load_main(
            self.main_args(),
            self.main_inputs(http=True, dhcp=True),
            tty=True, monitor_answer=True, scope_answers=("air",),
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["monitor", "scope"], result.prompts)
        monitor = result.mocks["start_ztp_monitor"]
        manual = result.mocks["start_manual_ztp_worker"]
        self.assertEqual("air", monitor.call_args.kwargs["scope"])
        self.assertEqual("air", manual.call_args.args[0])
        self.assertEqual(["air"], self.worker_scopes(result))
        order = [event[0] for event in result.events]
        # monitor -> switch -> manual keeps its relative order.
        self.assertLess(order.index("monitor"), order.index("popen"))
        self.assertLess(order.index("popen"), order.index("manual"))

    def test_all_scope_explicit_monitor_scope_needs_no_prompt(self) -> None:
        # I-028 expected fix 3: an explicit scope answers the question.
        result = self.run_load_main(
            self.main_args(ztp_monitor_scope="prod"),
            self.main_inputs(http=True, dhcp=True),
            tty=True, monitor_answer=False,
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertNotIn("scope", result.prompts)
        self.assertEqual(["prod"], self.worker_scopes(result))

    def test_all_scope_non_tty_without_scope_warns_and_skips_worker(self) -> None:
        # O4 ①: no worker, a WARN naming the remedy parameters, load still succeeds.
        for http, dhcp in ((False, False), (True, True)):
            with self.subTest(http=http, dhcp=dhcp):
                result = self.run_load_main(
                    self.main_args(), self.main_inputs(http=http, dhcp=dhcp), tty=False,
                )
                self.assertEqual(0, result.rc, result.stderr)
                self.assertEqual([], result.popen)
                self.assertEqual([], result.prompts)
                warning = [
                    line for line in result.stdout.splitlines()
                    if line.startswith("[WARN]") and "--ztp-monitor-scope" in line
                ]
                self.assertEqual(1, len(warning), result.stdout)
                for remedy in ("--prod", "--air", "--ztp-monitor-scope"):
                    self.assertIn(remedy, warning[0])

    def test_dry_run_starts_nothing(self) -> None:
        # I-028 expected fix 5: only outside --dry-run; a dry run neither starts nor asks.
        result = self.run_load_main(
            self.main_args(dry_run=True, deployment_scope="prod"),
            self.main_inputs(http=False, dhcp=False), tty=True,
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual([], result.popen)
        self.assertEqual([], result.runs)
        self.assertEqual([], result.prompts)
        self.assertIn("[DRY] 后台启动独立 Switch 收集 worker", result.stdout)
        self.assertIn("--scope prod", result.stdout)
        self.assertNotIn("[DRY] 安装 Switch 收集控制端点", result.stdout)

        result = self.run_load_main(
            self.main_args(dry_run=True),
            self.main_inputs(http=True, dhcp=True), tty=True,
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual([], result.popen)
        self.assertEqual([], result.prompts)
        self.assertNotIn("[DRY] 后台启动独立 Switch 收集 worker", result.stdout)

    def test_workstation_role_starts_nothing(self) -> None:
        # I-028 expected fix 5: only on the management server.
        result = self.run_load_main(
            self.main_args(host_role="workstation", deployment_scope="prod",
                           start_services=False),
            self.main_inputs(http=True, dhcp=True), tty=True,
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual([], result.popen)
        self.assertEqual([], result.prompts)
        self.assertNotIn("[DRY] 后台启动独立 Switch 收集 worker", result.stdout)

    def test_worker_scope_failure_precedes_quiesce_activate_generate(self) -> None:
        # Same contract as test_load_release_transaction
        # ::test_monitor_scope_failure_precedes_quiesce_activation_and_generation.
        scope = mock.Mock(side_effect=LOAD.LoadError("worker scope required before mutation"))
        result = self.run_load_main(
            self.main_args(),
            self.main_inputs(http=True, dhcp=False),
            tty=True, patches={"resolve_ztp_monitor_scope": scope},
        )
        self.assertEqual(1, result.rc)
        scope.assert_called_once()
        self.assertIn("worker scope required before mutation", result.stderr)
        for step in ("quiesce", "activate", "generate", "popen"):
            self.assertNotIn(step, [event[0] for event in result.events])

    def test_monitor_requested_without_http_or_dhcp_starts_only_the_collection_worker(self) -> None:
        # I-028 expected fix 4: 12-ztp-monitor and manual-ztp keep their conditions (HTTP and
        # DHCP and the monitor); only the Switch collection worker is freed, endpoint with HTTP.
        for http, dhcp in ((True, False), (False, True)):
            with self.subTest(http=http, dhcp=dhcp):
                result = self.run_load_main(
                    self.main_args(deployment_scope="prod", start_ztp_monitor=True),
                    self.main_inputs(http=http, dhcp=dhcp),
                )
                self.assertEqual(0, result.rc, result.stderr)
                result.mocks["start_ztp_monitor"].assert_not_called()
                result.mocks["start_manual_ztp_worker"].assert_not_called()
                self.assertEqual(["prod"], self.worker_scopes(result))
                names = [event[0] for event in result.events]
                self.assertEqual(http, "control-auth" in names)
                self.assertEqual(http, "apache-reload" in names)

    def test_monitor_and_manual_ztp_gates_are_unchanged(self) -> None:
        # I-028 expected fix 4 / guide WP-3「monitor、manual-ztp 的条件不变」: before I-028 both
        # started only on a management server with HTTP and DHCP and the monitor accepted.  The
        # path condition of each call in main() must still be exactly that, for every truth value.
        tree = ast.parse((LOAD.HERE / "11-load.py").read_text(encoding="utf-8"))
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        parents = {child: node for node in ast.walk(main) for child in ast.iter_child_nodes(node)}
        names = ("local_services_supported", "http_service_available",
                 "dhcp_service_available", "should_monitor")
        for callee in ("start_ztp_monitor", "start_manual_ztp_worker"):
            with self.subTest(callee=callee):
                calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == callee]
                self.assertEqual(1, len(calls))
                path, node = [], calls[0]
                while node in parents:
                    parent = parents[node]
                    if isinstance(parent, ast.If) and node is not parent.test:
                        path.append((parent.test, node in parent.body))
                    node = parent
                for values in itertools.product((False, True), repeat=len(names)):
                    scope = dict(zip(names, values))
                    reached = all(
                        bool(eval(compile(ast.Expression(body=test), callee, "eval"), {}, scope))
                        == taken
                        for test, taken in path
                    )
                    self.assertEqual(all(values), reached, scope)

    def test_supervisor_dhcp_only_unchanged(self) -> None:
        # Docker is frozen (开发计划 :112): supervisor keeps today's rule.
        for http, dhcp in ((False, True), (True, False)):
            with self.subTest(http=http, dhcp=dhcp):
                result = self.run_load_main(
                    self.main_args(deployment_scope="prod", start_ztp_monitor=True),
                    self.main_inputs(http=http, dhcp=dhcp),
                    backend="supervisor",
                )
                self.assertEqual(0, result.rc, result.stderr)
                self.assertEqual([], result.popen)
                self.assertNotIn(("monitor",), result.events)
                self.assertNotIn(("manual",), result.events)

    def test_start_function_without_endpoint_skips_auth_apache_and_cgi(self) -> None:
        # I-028 expected fix 2; O4 ③: the idle request file is still written for manual triggers.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "monitor/status"
            status.mkdir(parents=True)
            log = status / "switch-collection.log"
            log.write_text("earlier\n", encoding="utf-8")
            runs: list[tuple[str, ...]] = []
            launched: list[list[str]] = []
            forbidden = mock.Mock(side_effect=AssertionError("endpoint step without HTTP"))
            with mock.patch.object(LOAD, "HTTP_ROOT", root), \
                    mock.patch.object(LOAD, "verify_control_auth", forbidden), \
                    mock.patch.object(LOAD, "verify_apache_publication_boundary", forbidden), \
                    mock.patch.object(LOAD, "_reload_apache_if_active", forbidden), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *c: list(c)), \
                    mock.patch.object(LOAD, "run", side_effect=lambda c, **_k: runs.append(tuple(c))), \
                    mock.patch.object(
                        LOAD, "_popen_subprocess",
                        side_effect=lambda c, **_k: launched.append(list(c)) or _FakeProcess(),
                    ), \
                    redirect_stdout(io.StringIO()):
                LOAD.start_switch_collection_worker(
                    "prod",
                    runtime_backend=LOAD.SystemdRuntimeBackend(
                        command_runner=mock.Mock(side_effect=AssertionError("systemctl")),
                    ),
                    control_endpoint=False,
                )
            forbidden.assert_not_called()
            self.assertEqual(1, len(launched))
            self.assertEqual(["--scope", "prod"], launched[0][-2:])
            self.assertEqual("4242\n", (status / "switch-collection.pid").read_text())
            lines = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual("earlier", lines[0])
            self.assertIn("load.py starting:", lines[-1])
            self.assertEqual(1, len(runs))
            self.assertEqual(
                ("install", "-m", "0664", "-o", "root", "-g", "www-data"), runs[0][:7],
            )
            self.assertEqual(str(status / "switch-collection.request"), runs[0][-1])


if __name__ == "__main__":
    unittest.main()
