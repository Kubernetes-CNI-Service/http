"""Exact DATA inverse of the v3.1.6 NS1 layer in tools/ztp_service_runtime.py (test support only).

R-034 / P052 (v3.1.6 guide WP-NS1) changed ``_read_native_monitor_process`` and added
``_native_monitor_argv_prefix_excludes``.  The feedback-recovery proof in
``test_monitor_writer_quiesce_workflow._source_bound_feedback_recovery_path`` is bound to the
reviewed runtime AST (sha256 6daae46cd55ac6fb6f85705be2d4b1bf455ef068ef7631365514af1d1959cde5).
http dev 2026-11-25 21:0x (NS1 pending point 1): that pin is not re-pinned; this layer restores the
exact reviewed source on a private copy first and the caller compares the unchanged pin.

The table below is generated from git by the landing agent's ``gen_ns1_layer.py``; it is data, not
derived from the implementation under test.  Missing, truncated, duplicated, reordered or changed
layer parts refuse (``None``); changes outside the layer survive the inverse and fail the pin.
This module defines no test case (G1: each TestCase is collected only by its defining module).
"""

from __future__ import annotations

import ast
import copy
import hashlib

# BEGIN GENERATED NS1 RUNTIME LAYER
# Generated from the diff 263364e28a24b15622ec177443902abf11466852:tools/ztp_service_runtime.py
# -> e95a8576b3444f3992da0144701e6a7f7cac024a:tools/ztp_service_runtime.py
# by gen_ns1_layer.py; never edit by hand.  previous sha256 174907928839f92a3e00792fa5245dacd46421b214678372a22ed6694098748f;
# candidate sha256 e821c9e119d602bbd13cfd0782b618178a3962ec767572f2a7f0708087526d08.
# Byte hunks (context=3, 3): [previous offset, previous length, candidate offset,
#  candidate length, previous sha256, candidate sha256]
#   [13558, 624, 13558, 2148, faf5682518457ba79c29f47a65e1292ab663817747fee6f36c447e06fe059d6d, 282912f334aa3ce5f95122c236fd9382f288e4115d43cd1441a7bd03453e90d0]
#   [14457, 354, 15981, 249, 8202b03aa7613a4fef71c5115b1b5ec6ea6cb43c2079e7cd5b754e2c50c86ddd, d77272748d9b8a1481b7db848f30009a481fd974a85251a06c50a4facffc0138]
#   [15661, 140, 17080, 1709, 4dfed71ff89b8eb55c80e5dadb5354d43ceea735a3084fe576383269c4d026fb, b1cd276a073d3386a6df032bdb043292e7bd154b0103d1d0313b0798f2f41506]
NS1_RUNTIME_PATH = 'tools/ztp_service_runtime.py'
NS1_RUNTIME_PREVIOUS_STATEMENTS = 73
NS1_RUNTIME_CANDIDATE_STATEMENTS = 74
# (kind, top-level function, previous statement index, candidate statement index,
#  previous source sha256, candidate source sha256, previous source, candidate source)
NS1_RUNTIME_REGIONS = (
    ('replace', '_read_native_monitor_process', 37, 37,
     'a1cb1eeeedbe3f3a0e144705f8e3eca5a17c04daa386ca5f1ba5f9a3be4d4fc6',
     'bf263388f1320f6c4e4150cca7126fc3d7650dd9fd6618c881b750174bd28e12',
     (
        'def _read_native_monitor_process(\n'
        '    pid: int,\n'
        '    proc_root: Path,\n'
        '    http_root: Path,\n'
        '    *,\n'
        '    referenced: bool,\n'
        ') -> Optional[_NativeMonitorProcess]:\n'
        '    process_path = proc_root / str(pid)\n'
        '    try:\n'
        '        process_status = process_path.stat()\n'
        '    except FileNotFoundError:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} is stale or unreadable"\n'
        '            )\n'
        '        return None\n'
        '    except OSError as exc:\n'
        '        raise RuntimeContractError(\n'
        '            f"cannot inspect Native Monitor PID {pid}: {exc}"\n'
        '        ) from exc\n'
        '    try:\n'
        '        content, _opened = _bounded_nofollow_read(\n'
        '            process_path / "cmdline",\n'
        '            _MAX_NATIVE_MONITOR_CMDLINE_BYTES,\n'
        '            f"process {pid} cmdline",\n'
        '        )\n'
        '    except RuntimeContractError:\n'
        '        if referenced:\n'
        '            raise\n'
        '        # An unreadable process cannot safely be excluded from the set of\n'
        '        # detached monitors, so a complete scan remains fail closed.\n'
        '        raise\n'
        '    if not content:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} has an empty cmdline"\n'
        '            )\n'
        '        return None\n'
        '    try:\n'
        '        cmdline = tuple(\n'
        '            token.decode("utf-8")\n'
        '            for token in content.rstrip(b"\\0").split(b"\\0")\n'
        '        )\n'
        '    except UnicodeDecodeError as exc:\n'
        '        raise RuntimeContractError(\n'
        '            f"Native Monitor PID {pid} cmdline is not UTF-8"\n'
        '        ) from exc\n'
        '    expected_script = (\n'
        '        http_root / "DAY0-Prepare/12-ztp-monitor.py"\n'
        '    ).resolve(strict=False)\n'
        '    project_token = _native_monitor_project_from_argv(cmdline, expected_script)\n'
        '    if project_token is None:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} cmdline identity does not match"\n'
        '            )\n'
        '        return None\n'
        '    project = Path(project_token)\n'
        '    expected_parent = http_root / "DAY0-Prepare"\n'
        '    try:\n'
        '        project = project.resolve(strict=True)\n'
        '    except OSError as exc:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} project identity is unreadable"\n'
        '            ) from exc\n'
        '        return None\n'
        '    if project.parent != expected_parent or project.name in {"", "template"}:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} project is outside direct project scope"\n'
        '            )\n'
        '        return None\n'
        '    return _NativeMonitorProcess(\n'
        '        pid=pid,\n'
        '        proc_device=process_status.st_dev,\n'
        '        proc_inode=process_status.st_ino,\n'
        '        cmdline=cmdline,\n'
        '    )\n'
     ),
     (
        'def _read_native_monitor_process(\n'
        '    pid: int,\n'
        '    proc_root: Path,\n'
        '    http_root: Path,\n'
        '    *,\n'
        '    referenced: bool,\n'
        ') -> Optional[_NativeMonitorProcess]:\n'
        '    process_path = proc_root / str(pid)\n'
        '    try:\n'
        '        process_status = process_path.stat()\n'
        '    except FileNotFoundError:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} is stale or unreadable"\n'
        '            )\n'
        '        return None\n'
        '    except OSError as exc:\n'
        '        raise RuntimeContractError(\n'
        '            f"cannot inspect Native Monitor PID {pid}: {exc}"\n'
        '        ) from exc\n'
        '    expected_script = (\n'
        '        http_root / "DAY0-Prepare/12-ztp-monitor.py"\n'
        '    ).resolve(strict=False)\n'
        '    cmdline_path = process_path / "cmdline"\n'
        '    if referenced:\n'
        '        content, _opened = _bounded_nofollow_read(\n'
        '            cmdline_path,\n'
        '            _MAX_NATIVE_MONITOR_CMDLINE_BYTES,\n'
        '            f"process {pid} cmdline",\n'
        '        )\n'
        '    else:\n'
        '        # R-034 / P052 (v3.1.6 guide WP-NS1): read in bounded chunks (a short\n'
        '        # read is not EOF) until EOF or 64 KiB + 1 bytes, and stop as soon as\n'
        '        # rejection A or B proves this is not the monitor.  An unreadable\n'
        '        # process cannot safely be excluded unless /proc/<pid> is gone.\n'
        '        flags = (\n'
        '            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)\n'
        '            | getattr(os, "O_NOFOLLOW", 0)\n'
        '        )\n'
        '        content = b""\n'
        '        try:\n'
        '            descriptor = os.open(os.fspath(cmdline_path), flags)\n'
        '            try:\n'
        '                while len(content) <= _MAX_NATIVE_MONITOR_CMDLINE_BYTES:\n'
        '                    chunk = os.read(descriptor, min(\n'
        '                        4096, _MAX_NATIVE_MONITOR_CMDLINE_BYTES + 1 - len(content),\n'
        '                    ))\n'
        '                    content += chunk\n'
        '                    if _native_monitor_argv_prefix_excludes(\n'
        '                        content, not chunk, expected_script,\n'
        '                    ):\n'
        '                        return None\n'
        '                    if not chunk:\n'
        '                        break\n'
        '            finally:\n'
        '                os.close(descriptor)\n'
        '        except OSError as exc:\n'
        '            if not process_path.exists():\n'
        '                return None\n'
        '            raise RuntimeContractError(\n'
        '                f"cannot read process {pid} cmdline {cmdline_path}: {exc}"\n'
        '            ) from exc\n'
        '        if len(content) > _MAX_NATIVE_MONITOR_CMDLINE_BYTES:\n'
        '            raise RuntimeContractError(\n'
        '                f"process {pid} cmdline exceeds "\n'
        '                f"{_MAX_NATIVE_MONITOR_CMDLINE_BYTES} bytes: {cmdline_path}"\n'
        '            )\n'
        '    if not content:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} has an empty cmdline"\n'
        '            )\n'
        '        return None\n'
        '    try:\n'
        '        cmdline = tuple(\n'
        '            token.decode("utf-8")\n'
        '            for token in content.rstrip(b"\\0").split(b"\\0")\n'
        '        )\n'
        '    except UnicodeDecodeError as exc:\n'
        '        raise RuntimeContractError(\n'
        '            f"Native Monitor PID {pid} cmdline is not UTF-8"\n'
        '        ) from exc\n'
        '    project_token = _native_monitor_project_from_argv(cmdline, expected_script)\n'
        '    if project_token is None:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} cmdline identity does not match"\n'
        '            )\n'
        '        return None\n'
        '    project = Path(project_token)\n'
        '    expected_parent = http_root / "DAY0-Prepare"\n'
        '    try:\n'
        '        project = project.resolve(strict=True)\n'
        '    except OSError as exc:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} project identity is unreadable"\n'
        '            ) from exc\n'
        '        return None\n'
        '    if project.parent != expected_parent or project.name in {"", "template"}:\n'
        '        if referenced:\n'
        '            raise RuntimeContractError(\n'
        '                f"Native Monitor PID {pid} project is outside direct project scope"\n'
        '            )\n'
        '        return None\n'
        '    return _NativeMonitorProcess(\n'
        '        pid=pid,\n'
        '        proc_device=process_status.st_dev,\n'
        '        proc_inode=process_status.st_ino,\n'
        '        cmdline=cmdline,\n'
        '    )\n'
     )),
    ('insert', '_native_monitor_argv_prefix_excludes', 38, 38,
     '',
     '329bf0dec0e21f42a0d1690f7eb1873908faa0f2421c2ac1038b6feca36758b5',
     '',
     (
        'def _native_monitor_argv_prefix_excludes(prefix, at_eof, expected_script):\n'
        '    """Return True when complete leading argv tokens prove "not the monitor".\n'
        '\n'
        '    R-034 / P052 (v3.1.6 guide WP-NS1 rules A and B): an unreferenced PID is\n'
        '    read in bounded chunks.  A complete argv0 that is not a supported Python\n'
        '    name (or is not UTF-8), or a complete script-slot token that is not the\n'
        '    expected script, excludes the process exactly as the complete grammar in\n'
        '    ``_native_monitor_project_from_argv`` would.  This never accepts a\n'
        '    process; every other prefix still needs the complete original judgement.\n'
        '    """\n'
        '    if not prefix:\n'
        '        return False\n'
        '    if at_eof:\n'
        '        tokens = prefix.rstrip(b"\\0").split(b"\\0")\n'
        '    else:\n'
        '        tokens = prefix.split(b"\\0")[:-1]\n'
        '    if not tokens:\n'
        '        return False\n'
        '    try:\n'
        '        executable_name = Path(tokens[0].decode("utf-8")).name\n'
        '    except UnicodeDecodeError:\n'
        '        return True\n'
        '    if not (\n'
        '        executable_name in {"python", "python3"}\n'
        '        or (\n'
        '            executable_name.startswith("python3.")\n'
        '            and executable_name[len("python3."):].isdigit()\n'
        '        )\n'
        '    ):\n'
        '        return True\n'
        '    script_index = 1\n'
        '    if len(tokens) > 1 and tokens[1] in {b"-u", b"-B"}:\n'
        '        script_index = 2\n'
        '    if script_index >= len(tokens):\n'
        '        return False\n'
        '    try:\n'
        '        token = tokens[script_index].decode("utf-8")\n'
        '    except UnicodeDecodeError:\n'
        '        return False\n'
        '    try:\n'
        '        return Path(token).resolve(strict=False) != expected_script\n'
        '    except (OSError, RuntimeError):\n'
        '        return True\n'
     )),
)
# END GENERATED NS1 RUNTIME LAYER


def restore_ns1_runtime_tree(tree, digest):
    """Return the reviewed pre-NS1 runtime module for ``tree``, or ``None`` to refuse.

    ``digest`` is the caller's reviewed-AST digest (``_reviewed_source_ast_sha256``); it decides
    whether one candidate definition is exactly the generated one.  A tree without the NS1 helper is
    returned unchanged (the unchanged pin then decides).  ``tree`` itself is never modified.
    """
    body = getattr(tree, "body", None)
    if type(body) is not list:
        return None
    inserted = {name for kind, name, *_rest in NS1_RUNTIME_REGIONS if kind == "insert"}
    if not any(getattr(node, "name", None) in inserted for node in body):
        return tree
    if len(body) != NS1_RUNTIME_CANDIDATE_STATEMENTS:
        return None
    wrap = lambda node: ast.Module(body=[node], type_ignores=[])  # noqa: E731
    for kind, name, _old_index, new_index, old_sha, new_sha, old_src, new_src in NS1_RUNTIME_REGIONS:
        if (hashlib.sha256(new_src.encode()).hexdigest() != new_sha
                or (kind == "replace") != bool(old_src)
                or (old_src and hashlib.sha256(old_src.encode()).hexdigest() != old_sha)):
            raise AssertionError("generated NS1 runtime layer table is corrupt")
        positions = [index for index, node in enumerate(body)
                     if isinstance(node, ast.FunctionDef) and node.name == name]
        if positions != [new_index]:
            return None
        expected = digest(wrap(ast.parse(new_src).body[0]))
        if expected is None or digest(wrap(body[new_index])) != expected:
            return None
    reviewed = copy.deepcopy(tree)
    for kind, _name, _old_index, new_index, *_rest, old_src, _new_src in reversed(NS1_RUNTIME_REGIONS):
        if kind == "replace":
            reviewed.body[new_index] = ast.parse(old_src).body[0]
        else:
            del reviewed.body[new_index]
    if len(reviewed.body) != NS1_RUNTIME_PREVIOUS_STATEMENTS:
        return None
    return reviewed
