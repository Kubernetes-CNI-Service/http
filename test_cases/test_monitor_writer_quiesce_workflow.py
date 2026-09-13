#!/usr/bin/env python3
"""Cross-script ordering contracts for Monitor-governed identity writers."""

from __future__ import annotations

import argparse
import ast
import copy
from contextlib import contextmanager
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import weakref

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if os.fspath(TOOLS) not in sys.path:
    sys.path.insert(0, os.fspath(TOOLS))
from deployment_lock import DeploymentLockError


def load_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def function_node(relative: str, function_name: str) -> ast.FunctionDef:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"missing function {function_name} in {relative}")


def first_call_line(function: ast.FunctionDef, name: str) -> int:
    matches = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        called = node.func
        if isinstance(called, ast.Name) and called.id == name:
            matches.append(node.lineno)
        elif isinstance(called, ast.Attribute) and called.attr == name:
            matches.append(node.lineno)
    if not matches:
        raise AssertionError(f"{function.name} does not call {name}")
    return min(matches)


def deployment_lock_scope(function: ast.FunctionDef) -> ast.With:
    for node in ast.walk(function):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            context = item.context_expr
            if not isinstance(context, ast.Call):
                continue
            called = context.func
            if ((isinstance(called, ast.Name) and called.id == "deployment_lock")
                    or (isinstance(called, ast.Attribute)
                        and called.attr == "deployment_lock")):
                return node
    raise AssertionError(f"{function.name} does not hold deployment_lock")


def call_names(node: ast.AST) -> set[str]:
    result = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            result.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            result.add(child.func.attr)
    return result


GOVERNED_AUTHORITY_NAMES = {
    "01-global.yaml", "02-devices_config.csv", "p2p-air.json",
    "current-release.json",
}
MUTATION_CALL_NAMES = {
    "replace", "rename", "copy", "copy2", "copyfile", "move",
    "copytree", "renames", "unlink", "symlink", "symlink_to",
    "link",
    "write_text", "write_bytes", "touch", "truncate",
}
_GOVERNED_SCRIPT_BASENAMES: set[str] | None = None
_GENERIC_MUTATION_SUMMARY_CACHE = weakref.WeakKeyDictionary()


def called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def production_functions(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _walk_local_scope(root: ast.AST):
    """Walk one function body without borrowing nested-function locals."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        children = list(ast.iter_child_nodes(node))
        if node is not root and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        ):
            continue
        stack.extend(reversed(children))


def _keyword_argument(call: ast.Call, *names: str) -> ast.AST | None:
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg in names),
        None,
    )


def _argument(
    call: ast.Call, index: int, *keyword_names: str,
) -> ast.AST | None:
    if index < len(call.args):
        return call.args[index]
    return _keyword_argument(call, *keyword_names)


def _static_integer(
    expression: ast.AST | None, constants: dict[str, int] | None = None,
) -> int | None:
    if isinstance(expression, ast.Name):
        return (constants or {}).get(expression.id)
    if isinstance(expression, ast.Constant) and isinstance(expression.value, int):
        return expression.value
    if (
        isinstance(expression, ast.Attribute)
        and isinstance(expression.value, ast.Name)
        and expression.value.id == "os"
        and expression.attr.startswith("O_")
    ):
        value = getattr(os, expression.attr, None)
        return value if isinstance(value, int) else None
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "getattr"
        and len(expression.args) >= 2
        and isinstance(expression.args[0], ast.Name)
        and expression.args[0].id == "os"
        and isinstance(expression.args[1], ast.Constant)
        and isinstance(expression.args[1].value, str)
        and expression.args[1].value.startswith("O_")
    ):
        fallback = _static_integer(
            expression.args[2] if len(expression.args) > 2 else None,
            constants,
        )
        value = getattr(os, expression.args[1].value, fallback)
        return value if isinstance(value, int) else None
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.BitOr):
        left = _static_integer(expression.left, constants)
        right = _static_integer(expression.right, constants)
        return None if left is None or right is None else left | right
    return None


def _function_static_integers(function: ast.AST) -> dict[str, int]:
    constants: dict[str, int] = {}
    conflicted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for assignment in (
            node for node in _walk_local_scope(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        ):
            if assignment.value is None:
                continue
            value = _static_integer(assignment.value, constants)
            if value is None:
                continue
            targets = (
                assignment.targets if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            for target in targets:
                for target_name in _assigned_names(target):
                    if target_name in conflicted:
                        continue
                    if target_name not in constants:
                        constants[target_name] = value
                        changed = True
                    elif constants[target_name] != value:
                        constants.pop(target_name)
                        conflicted.add(target_name)
                        changed = True
    return constants


def _mutation_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"os", "shutil"}:
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"os", "shutil"}:
            for alias in node.names:
                canonical = f"{node.module}.{alias.name}"
                if alias.name in MUTATION_CALL_NAMES or alias.name in {
                    "open", "remove", "write",
                }:
                    aliases[alias.asname or alias.name] = canonical
    module_assignments = [
        node for node in getattr(tree, "body", ())
        if isinstance(node, (ast.Assign, ast.AnnAssign))
    ]
    return _extend_mutation_aliases(module_assignments, aliases)


def _extend_mutation_aliases(
    nodes, seed: dict[str, str],
) -> dict[str, str]:
    aliases = dict(seed)
    assignments = [
        node for root in nodes for node in _walk_local_scope(root)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
    ]
    changed = True
    while changed:
        changed = False
        for node in assignments:
            value = node.value
            canonical = None
            if isinstance(value, ast.Name):
                canonical = aliases.get(value.id)
            elif (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
            ):
                module = aliases.get(value.value.id, value.value.id)
                if module in {"os", "shutil"} and (
                    value.attr in MUTATION_CALL_NAMES
                    or value.attr in {"open", "remove", "write"}
                ):
                    canonical = f"{module}.{value.attr}"
            if canonical is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for target_name in _assigned_names(target):
                    if aliases.get(target_name) != canonical:
                        aliases[target_name] = canonical
                        changed = True
    return aliases


def _mutation_destination(
    call: ast.Call, aliases: dict[str, str] | None = None,
    static_integers: dict[str, int] | None = None,
) -> ast.AST | None:
    aliases = aliases or {}
    name = called_name(call)
    if name is None:
        return None
    qualified = name
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        module = aliases.get(call.func.value.id, call.func.value.id)
        qualified = f"{module}.{name}"
    elif isinstance(call.func, ast.Name):
        qualified = aliases.get(call.func.id, call.func.id)

    if name == "open":
        if qualified == "os.open":
            path = _argument(call, 0, "path")
            flags_expression = _argument(call, 1, "flags")
            flags = _static_integer(flags_expression, static_integers)
            if flags_expression is None:
                return path
            if flags is None:
                return path
            access_mode = flags & getattr(os, "O_ACCMODE", 3)
            modifying = access_mode in {
                getattr(os, "O_WRONLY", 1), getattr(os, "O_RDWR", 2),
            } or any(
                flags & getattr(os, option, 0)
                for option in ("O_CREAT", "O_TRUNC", "O_APPEND")
            )
            return path if modifying else None
        is_method = isinstance(call.func, ast.Attribute)
        path = call.func.value if is_method else _argument(call, 0, "file")
        mode = _argument(call, 0 if is_method else 1, "mode")
        if mode is None:
            return None
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
            return path if any(flag in mode.value for flag in "wax+") else None
        return path

    if qualified in {"os.replace", "os.rename"}:
        return _argument(call, 1, "dst")
    if name in {"replace", "rename"} and isinstance(call.func, ast.Attribute):
        return _argument(call, 0, "target")
    if name in {"copy", "copy2", "copyfile", "copytree", "move"}:
        return _argument(call, 1, "dst")
    if name == "renames":
        return _argument(call, 1, "new")
    if name in {"symlink", "link"}:
        return _argument(call, 1, "dst", "dst_dir_fd")
    if qualified in {"os.remove", "os.unlink", "os.truncate"}:
        return _argument(call, 0, "path")
    if qualified == "os.write":
        return _argument(call, 0, "fd")
    if name not in MUTATION_CALL_NAMES:
        return None
    if isinstance(call.func, ast.Attribute):
        return call.func.value
    return call


def _function_parameters(function: ast.AST) -> list[str]:
    return [
        argument.arg for argument in (
            list(getattr(function.args, "posonlyargs", ()))
            + list(function.args.args) + list(function.args.kwonlyargs)
        )
    ]


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_assigned_names(item) for item in target.elts))
    return set()


def _call_argument(
    call: ast.Call, callee: ast.AST, parameter_index: int,
) -> ast.AST | None:
    parameters = _function_parameters(callee)
    if parameter_index >= len(parameters):
        return None
    method_offset = 0
    if (
        isinstance(call.func, ast.Attribute)
        and parameters
        and parameters[0] in {"self", "cls"}
    ):
        if parameter_index == 0:
            return call.func.value
        method_offset = 1
    positional_count = len(getattr(callee.args, "posonlyargs", ())) + len(
        callee.args.args
    )
    argument_index = parameter_index - method_offset
    if parameter_index < positional_count and argument_index < len(call.args):
        return call.args[argument_index]
    parameter_name = parameters[parameter_index]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == parameter_name),
        None,
    )


def generic_mutation_parameter_summaries(tree: ast.AST) -> dict[str, set[int]]:
    """Summarize which positional parameters can reach a mutation destination."""
    cached = _GENERIC_MUTATION_SUMMARY_CACHE.get(tree)
    if cached is not None:
        return cached
    functions = production_functions(tree)
    module_aliases = _mutation_aliases(tree)
    summaries: dict[str, set[int]] = {}
    symbolic_by_function: dict[str, dict[str, set[int]]] = {}
    calls_by_function: dict[str, list[ast.Call]] = {}
    for name, function in functions.items():
        aliases = _extend_mutation_aliases([function], module_aliases)
        parameters = _function_parameters(function)
        symbolic = {
            parameter: {index} for index, parameter in enumerate(parameters)
        }
        assignments = [
            node for node in _walk_local_scope(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and node.value is not None
        ]
        with_items = [
            item
            for statement in _walk_local_scope(function)
            if isinstance(statement, (ast.With, ast.AsyncWith))
            for item in statement.items if item.optional_vars is not None
        ]
        grew = True
        while grew:
            grew = False
            for assignment in assignments:
                sources = set().union(*(
                    symbolic.get(node.id, set())
                    for node in ast.walk(assignment.value)
                    if isinstance(node, ast.Name)
                ))
                targets = (
                    assignment.targets if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                for target in targets:
                    for target_name in _assigned_names(target):
                        before = len(symbolic.get(target_name, set()))
                        symbolic.setdefault(target_name, set()).update(sources)
                        grew |= len(symbolic[target_name]) != before
            for item in with_items:
                sources = set().union(*(
                    symbolic.get(node.id, set())
                    for node in ast.walk(item.context_expr)
                    if isinstance(node, ast.Name)
                ))
                for target_name in _assigned_names(item.optional_vars):
                    before = len(symbolic.get(target_name, set()))
                    symbolic.setdefault(target_name, set()).update(sources)
                    grew |= len(symbolic[target_name]) != before
        calls = [
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ]
        static_integers = _function_static_integers(function)
        direct = set()
        for call in calls:
            destination = _mutation_destination(call, aliases, static_integers)
            if destination is not None:
                direct.update(*(
                    symbolic.get(node.id, set())
                    for node in ast.walk(destination) if isinstance(node, ast.Name)
                ))
        symbolic_by_function[name] = symbolic
        calls_by_function[name] = calls
        summaries[name] = direct

    changed = True
    while changed:
        changed = False
        for name, function in functions.items():
            symbolic = symbolic_by_function[name]
            discovered = set()
            for call in calls_by_function[name]:
                callee = called_name(call)
                if (
                    callee == "write"
                    and isinstance(call.func, ast.Attribute)
                    and not (
                        isinstance(call.func.value, ast.Name)
                        and call.func.value.id in {"self", "cls"}
                    )
                ):
                    continue
                for parameter_index in summaries.get(callee, set()):
                    argument = _call_argument(
                        call, functions[callee], parameter_index,
                    )
                    if argument is None:
                        continue
                    discovered.update(*(
                        symbolic.get(node.id, set())
                        for node in ast.walk(argument)
                        if isinstance(node, ast.Name)
                    ))
            before = len(summaries[name])
            summaries[name].update(discovered)
            changed |= len(summaries[name]) != before
    _GENERIC_MUTATION_SUMMARY_CACHE[tree] = summaries
    return summaries


def governed_external_sink_calls(
    tree: ast.AST,
    repository_summaries: dict[str, tuple[list[str], set[int]]],
) -> set[tuple[str, str]]:
    """Find imported/generic sink calls receiving a governed destination."""
    local_functions = production_functions(tree)
    import_bindings = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                import_bindings[alias.asname or alias.name] = alias.name
    result = set()
    for function in local_functions.values():
        governed = set()
        changed = True
        while changed:
            changed = False
            for assignment in (
                node for node in _walk_local_scope(function)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            ):
                value = assignment.value
                if value is None:
                    continue
                spelling = ast.unparse(value)
                names = {
                    node.id for node in ast.walk(value) if isinstance(node, ast.Name)
                }
                transparent = isinstance(value, (ast.Name, ast.Attribute, ast.BinOp))
                if isinstance(value, ast.Call):
                    transparent = called_name(value) in {
                        "Path", "PurePath", "join", "realpath", "abspath",
                        "resolve", "with_name", "with_suffix",
                    }
                if not (
                    any(authority in spelling for authority in GOVERNED_AUTHORITY_NAMES)
                    or (transparent and names & governed)
                ):
                    continue
                targets = (
                    assignment.targets if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name) and target.id not in governed:
                        governed.add(target.id)
                        changed = True
        for call in (
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ):
            callee = called_name(call)
            definition_name = import_bindings.get(callee, callee)
            if callee in local_functions or definition_name not in repository_summaries:
                continue
            parameters, sink_indices = repository_summaries[definition_name]
            for parameter_index in sink_indices:
                argument = (
                    call.args[parameter_index]
                    if parameter_index < len(call.args)
                    else next((keyword.value for keyword in call.keywords
                               if keyword.arg == parameters[parameter_index]), None)
                )
                if argument is None:
                    continue
                spelling = ast.unparse(argument)
                names = {
                    node.id for node in ast.walk(argument)
                    if isinstance(node, ast.Name)
                }
                if (
                    any(authority in spelling for authority in GOVERNED_AUTHORITY_NAMES)
                    or names & governed
                ):
                    result.add((function.name, callee))
    return result


def _transparent_governed_expression(
    expression: ast.AST, governed: set[str], governed_returns: set[str],
) -> bool:
    path_calls = {
        "Path", "PurePath", "join", "realpath", "abspath", "resolve",
        "with_name", "with_suffix", "sorted", "list", "tuple", "set",
        "open",
    }
    if _has_governed_literal(expression) and (
        isinstance(expression, (ast.Constant, ast.BinOp, ast.List, ast.Tuple, ast.Set))
        or (
            isinstance(expression, ast.Call)
            and called_name(expression) in path_calls | governed_returns
        )
    ):
        return True
    names = {
        node.id for node in ast.walk(expression) if isinstance(node, ast.Name)
    }
    transparent = isinstance(
        expression,
        (
            ast.Name, ast.Attribute, ast.BinOp, ast.Subscript, ast.IfExp,
            ast.List, ast.Tuple, ast.Set, ast.Dict, ast.ListComp, ast.SetComp,
            ast.DictComp, ast.GeneratorExp,
        ),
    )
    if isinstance(expression, ast.Call):
        callee = called_name(expression)
        if callee in governed_returns:
            return True
        transparent = callee in path_calls or bool(
            callee and callee[:1].isupper() and names & governed
        )
    return transparent and bool(names & governed)


def _governed_locals(
    function: ast.AST, seed: set[str], governed_returns: set[str],
    *, aggregate_flows: bool = True,
) -> set[str]:
    governed = set(seed)
    changed = True
    while changed:
        changed = False
        for assignment in (
            node for node in _walk_local_scope(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ):
            value = assignment.value
            if value is None or not _transparent_governed_expression(
                value, governed, governed_returns,
            ):
                continue
            targets = (
                assignment.targets if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            for target in targets:
                for target_name in _assigned_names(target):
                    if target_name not in governed:
                        governed.add(target_name)
                        changed = True
        for statement in (
            node for node in _walk_local_scope(function)
            if isinstance(node, (ast.For, ast.AsyncFor))
        ):
            if not _transparent_governed_expression(
                statement.iter, governed, governed_returns,
            ):
                continue
            for target_name in _assigned_names(statement.target):
                if target_name not in governed:
                    governed.add(target_name)
                    changed = True
        if not aggregate_flows:
            continue
        for call in (
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ):
            if not (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.attr in {"append", "extend", "add", "update"}
                and any(
                    _transparent_governed_expression(
                        argument, governed, governed_returns,
                    )
                    for argument in call.args
                )
            ):
                continue
            receiver = call.func.value.id
            if receiver not in governed:
                governed.add(receiver)
                changed = True
        for statement in (
            node for node in _walk_local_scope(function)
            if isinstance(node, (ast.With, ast.AsyncWith))
        ):
            for item in statement.items:
                if item.optional_vars is None or not _transparent_governed_expression(
                    item.context_expr, governed, governed_returns,
                ):
                    continue
                for target_name in _assigned_names(item.optional_vars):
                    if target_name not in governed:
                        governed.add(target_name)
                        changed = True
    return governed


def _is_governed_destination(expression: ast.AST, governed: set[str]) -> bool:
    if _has_governed_literal(expression):
        return True
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
        # A governed basename copied under an unrelated staging/output root is
        # not itself a mutation of the live authority.  Earlier assignments
        # that bind the complete path remain tainted as one Name.
        names = {
            node.id for node in ast.walk(expression.left)
            if isinstance(node, ast.Name)
        }
        return bool(names & governed)
    names = {
        node.id for node in ast.walk(expression) if isinstance(node, ast.Name)
    }
    return bool(names & governed) and isinstance(
        expression, (ast.Name, ast.Attribute, ast.Subscript),
    )


def _has_governed_literal(expression: ast.AST) -> bool:
    accepted_relatives = {
        *GOVERNED_AUTHORITY_NAMES,
        "99-output-ztp/current-release.json",
        "config/isc-dhcp-server/p2p-air.json",
    }
    return any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and (
            node.value in accepted_relatives
            or (
                node.value.startswith("/")
                and any(
                    node.value.endswith("/" + authority)
                    for authority in GOVERNED_AUTHORITY_NAMES
                )
            )
        )
        for node in ast.walk(expression)
    )


def _governed_return_summaries(
    tree: ast.AST, module_governed: set[str],
) -> set[str]:
    """Find resolvers returning governed paths, including resolver chains."""
    functions = production_functions(tree)
    summaries: set[str] = set()

    changed = True
    while changed:
        changed = False
        for name, function in functions.items():
            governed = _governed_locals(function, module_governed, summaries)
            returns_governed = any(
                isinstance(node, ast.Return)
                and node.value is not None
                and _transparent_governed_expression(
                    node.value, governed, summaries,
                )
                for node in _walk_local_scope(function)
            )
            if returns_governed and name not in summaries:
                summaries.add(name)
                changed = True
    return summaries


def _delegated_governed_script_constants(tree: ast.AST) -> set[str]:
    """Bind a script-valued constant to a real governed writer target."""
    global _GOVERNED_SCRIPT_BASENAMES
    if _GOVERNED_SCRIPT_BASENAMES is None:
        _GOVERNED_SCRIPT_BASENAMES = set()
        for path in ROOT.rglob("*.py"):
            if "test_cases" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            if (
                any(authority in source for authority in GOVERNED_AUTHORITY_NAMES)
                and any(
                    primitive in source
                    for primitive in (".replace(", ".remove(", ".unlink(")
                )
            ):
                _GOVERNED_SCRIPT_BASENAMES.add(path.name)
    governed = set()
    for node in getattr(tree, "body", ()):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        script_names = {
            value.value for value in ast.walk(node.value)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.endswith(".py")
        }
        if not script_names:
            continue
        target_is_governed = any(
            Path(script_name).name in _GOVERNED_SCRIPT_BASENAMES
            for script_name in script_names
        )
        if not target_is_governed:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            governed.update(_assigned_names(target))
    return governed


def literal_governed_mutation_sinks(tree: ast.AST) -> set[str]:
    """Find sinks from their destination spelling, independent of quiesce calls."""
    result = set()
    module_aliases = _mutation_aliases(tree)
    delegated_script_constants = _delegated_governed_script_constants(tree)
    module_governed: set[str] = set()
    string_values = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    has_literal_authority = any(
        authority in value
        for authority in GOVERNED_AUTHORITY_NAMES
        for value in string_values
    )
    has_source_manifest_authority = any(
        "source manifest authority" in value for value in string_values
    )
    if not delegated_script_constants and not has_literal_authority \
            and not has_source_manifest_authority:
        return result
    for node in getattr(tree, "body", ()):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            if _has_governed_literal(value):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                module_governed.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
    governed_returns = _governed_return_summaries(tree, module_governed)
    governed_by_function = {}
    semantic_governed_by_function = {}
    functions = production_functions(tree)
    for function in functions.values():
        aliases = _extend_mutation_aliases([function], module_aliases)
        governed = _governed_locals(
            function, module_governed, governed_returns,
        )
        static_integers = _function_static_integers(function)
        delegated_governed = _governed_locals(
            function, delegated_script_constants, set(),
        ) if delegated_script_constants else set()
        governed_by_function[function.name] = governed
        semantic_governed_by_function[function.name] = _governed_locals(
            function, module_governed, governed_returns,
            aggregate_flows=False,
        )
        for call in (
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ):
            destination = _mutation_destination(call, aliases, static_integers)
            if destination is None:
                continue
            if _is_governed_destination(destination, governed):
                result.add(function.name)
        # A subprocess runner that consumes a command assembled from a
        # mechanically resolved governed-writer script is itself the mutation
        # boundary, even though the filesystem syscall lives in that child.
        for call in (
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ):
            if called_name(call) not in {"run", "call", "check_call", "check_output"}:
                continue
            if not any(
                isinstance(node, ast.Constant)
                and node.value in {"-y", "--yes"}
                for node in _walk_local_scope(function)
            ):
                continue
            names = {
                node.id for argument in (*call.args, *(item.value for item in call.keywords))
                for node in ast.walk(argument) if isinstance(node, ast.Name)
            }
            if names & delegated_governed:
                result.add(function.name)
    summaries = generic_mutation_parameter_summaries(tree)
    for function in functions.values():
        governed = semantic_governed_by_function[function.name]
        for call in (
            node for node in _walk_local_scope(function)
            if isinstance(node, ast.Call)
        ):
            callee = called_name(call)
            for parameter_index in summaries.get(callee, set()):
                argument = _call_argument(call, functions[callee], parameter_index)
                if argument is None:
                    continue
                if _is_governed_destination(argument, governed):
                    result.add(function.name)
                    result.add(callee)
    # A validated deployment archive is an authority for the complete source
    # tree, not one fixed filename.  Discover that boundary from its source-
    # manifest vocabulary, archive API shape, and an http_root parameter that
    # mechanically reaches a mutation; no quiesce/entry table participates.
    if has_source_manifest_authority:
        for name, function in functions.items():
            parameters = _function_parameters(function)
            if (
                name.startswith("run_locked_archive")
                and "http_root" in parameters
                and parameters.index("http_root") in summaries.get(name, set())
            ):
                result.add(name)
    return result


def local_call_graph(tree: ast.AST) -> dict[str, set[str]]:
    functions = production_functions(tree)
    return {
        name: {
            called_name(call) for call in ast.walk(function)
            if isinstance(call, ast.Call) and called_name(call) in functions
        }
        for name, function in functions.items()
    }


def transitive_sink_callers(tree: ast.AST, sinks: set[str]) -> set[str]:
    graph = local_call_graph(tree)
    reached = set(sinks)
    changed = True
    while changed:
        changed = False
        for caller, callees in graph.items():
            if caller not in reached and callees & reached:
                reached.add(caller)
                changed = True
    return reached


def _suppress_aliases(
    tree: ast.AST, function: ast.AST | None = None,
) -> set[str]:
    aliases = {"contextlib.suppress"}
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.ImportFrom) and node.module == "contextlib":
            for alias in node.names:
                if alias.name == "suppress":
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if not (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "contextlib"
                and value.attr == "suppress"
            ):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            aliases.update(
                target.id for target in targets if isinstance(target, ast.Name)
            )
    if function is None:
        return aliases
    assignments = [
        node for node in _walk_local_scope(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
    ]
    changed = True
    while changed:
        changed = False
        for node in assignments:
            if ast.unparse(node.value) not in aliases:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for target_name in _assigned_names(target):
                    if target_name not in aliases:
                        aliases.add(target_name)
                        changed = True
    return aliases


def _terminal_parameter_indices(
    call: ast.Call, function: ast.AST,
    summaries: dict[str, set[int]], functions: dict[str, ast.AST],
) -> set[int]:
    parameters = _function_parameters(function)
    by_name = {name: index for index, name in enumerate(parameters)}
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "error"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in by_name
    ):
        return {by_name[call.func.value.id]}
    callee = called_name(call)
    if callee not in summaries or callee not in functions:
        return set()
    result = set()
    for callee_index in summaries[callee]:
        argument = _call_argument(call, functions[callee], callee_index)
        if isinstance(argument, ast.Name) and argument.id in by_name:
            result.add(by_name[argument.id])
    return result


def _block_terminal_parameter_indices(
    statements, function: ast.AST,
    summaries: dict[str, set[int]], functions: dict[str, ast.AST],
) -> set[int]:
    for statement in statements:
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Call,
        ):
            indices = _terminal_parameter_indices(
                statement.value, function, summaries, functions,
            )
            if indices:
                return indices
        if isinstance(statement, ast.If) and statement.orelse:
            body = _block_terminal_parameter_indices(
                statement.body, function, summaries, functions,
            )
            alternate = _block_terminal_parameter_indices(
                statement.orelse, function, summaries, functions,
            )
            common = body & alternate
            if common:
                return common
    return set()


def _argparse_terminal_functions(tree: ast.AST) -> dict[str, set[int]]:
    functions = production_functions(tree)
    terminal: dict[str, set[int]] = {}
    changed = True
    while changed:
        changed = False
        for name, function in functions.items():
            if name in terminal or any(
                isinstance(node, ast.Return)
                for node in _walk_local_scope(function)
            ):
                continue
            indices = _block_terminal_parameter_indices(
                function.body, function, terminal, functions,
            )
            if indices:
                terminal[name] = indices
                changed = True
    return terminal


def _terminal_call_is_bound(
    call: ast.Call, trusted_receivers: set[str],
    summaries: dict[str, set[int]], functions: dict[str, ast.AST],
) -> bool:
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "error"
        and isinstance(call.func.value, ast.Name)
    ):
        return call.func.value.id in trusted_receivers
    callee = called_name(call)
    if callee not in summaries or callee not in functions:
        return False
    return any(
        isinstance(argument := _call_argument(
            call, functions[callee], parameter_index,
        ), ast.Name)
        and argument.id in trusted_receivers
        for parameter_index in summaries[callee]
    )


def _block_guarantees_bound_terminal(
    statements, trusted_receivers: set[str],
    summaries: dict[str, set[int]], functions: dict[str, ast.AST],
) -> bool:
    for statement in statements:
        if isinstance(statement, ast.Raise):
            return True
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and _terminal_call_is_bound(
                statement.value, trusted_receivers, summaries, functions,
            )
        ):
            return True
        if isinstance(statement, ast.If) and statement.orelse:
            if (
                _block_guarantees_bound_terminal(
                    statement.body, trusted_receivers, summaries, functions,
                )
                and _block_guarantees_bound_terminal(
                    statement.orelse, trusted_receivers, summaries, functions,
                )
            ):
                return True
    return False


def _handler_guarantees_terminal(
    handler: ast.ExceptHandler, terminal_functions: dict[str, set[int]],
    functions: dict[str, ast.AST], trusted_receivers: set[str],
) -> bool:
    if any(isinstance(node, ast.Return) for node in _walk_local_scope(handler)):
        return False
    return _block_guarantees_bound_terminal(
        handler.body, trusted_receivers, terminal_functions, functions,
    )


def structural_calls(
    node: ast.AST, suppress_aliases: set[str] | None = None,
    dominated_sink_names: set[str] | None = None,
    terminal_functions: dict[str, set[int]] | None = None,
    functions: dict[str, ast.AST] | None = None,
    trusted_receivers: set[str] | None = None,
) -> list[ast.Call]:
    """Return calls in AST statement order; lineno is deliberately ignored."""
    result = []

    def static_boolean(expression):
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value, (type(None), bool, int, float, complex, str, bytes),
        ):
            return bool(expression.value)
        if isinstance(expression, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            return bool(expression.elts if hasattr(expression, "elts") else expression.keys)
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            value = static_boolean(expression.operand)
            return None if value is None else not value
        if isinstance(expression, ast.BoolOp):
            values = [static_boolean(value) for value in expression.values]
            if isinstance(expression.op, ast.And):
                return False if False in values else True if all(
                    value is True for value in values
                ) else None
            return True if True in values else False if all(
                value is False for value in values
            ) else None
        if isinstance(expression, ast.Compare) and len(expression.ops) == 1:
            left = expression.left
            right = expression.comparators[0]
            if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
                operator = expression.ops[0]
                if isinstance(operator, (ast.Is, ast.Eq)):
                    return left.value == right.value
                if isinstance(operator, (ast.IsNot, ast.NotEq)):
                    return left.value != right.value
        return None

    class StructuralVisitor(ast.NodeVisitor):
        def __init__(self):
            self.suppress_conditional_stops = 0

        def _visit_nondominating(self, statements):
            self.suppress_conditional_stops += 1
            try:
                for statement in statements:
                    self.visit(statement)
            finally:
                self.suppress_conditional_stops -= 1

        def visit_If(self, conditional):
            value = static_boolean(conditional.test)
            if value is not None:
                branch = conditional.body if value else conditional.orelse
                for statement in branch:
                    self.visit(statement)
                return
            guard = ast.unparse(conditional.test)
            if guard == "lock_already_held":
                self.visit(conditional.test)
                for statement in conditional.orelse:
                    self.visit(statement)
                return
            recognized_live_guard = guard in {
                "not _DRY_RUN",
                "not dry_run",
                "backend.name == 'systemd' and (not dry_run) and "
                "(not native_monitor_already_quiesced)",
                "local_services_supported and "
                "runtime_backend_instance.name == 'systemd' and "
                "(not args.dry_run)",
                "_prepared_inputs is None and _global_writeback is None",
            }
            self.visit(conditional.test)
            if recognized_live_guard:
                for statement in conditional.body:
                    self.visit(statement)
            else:
                self._visit_nondominating(conditional.body)
            self._visit_nondominating(conditional.orelse)

        def visit_While(self, loop):
            value = static_boolean(loop.test)
            if value is False:
                for statement in loop.orelse:
                    self.visit(statement)
                return
            self.visit(loop.test)
            self._visit_nondominating(loop.body)
            self._visit_nondominating(loop.orelse)

        def visit_For(self, loop):
            self.visit(loop.target)
            self.visit(loop.iter)
            self._visit_nondominating(loop.body)
            self._visit_nondominating(loop.orelse)

        visit_AsyncFor = visit_For

        def visit_With(self, statement):
            suppressed = False
            for item in statement.items:
                context = item.context_expr
                self.visit(context)
                if isinstance(context, ast.Call):
                    spelling = ast.unparse(context.func)
                    if spelling in (suppress_aliases or set()):
                        suppressed = True
                if item.optional_vars is not None:
                    self.visit(item.optional_vars)
            if suppressed:
                self._visit_nondominating(statement.body)
            else:
                for child in statement.body:
                    self.visit(child)

        visit_AsyncWith = visit_With

        def visit_Try(self, statement):
            # A stop in try dominates later writes only when every handler
            # necessarily re-raises.  Swallowed exceptions make it conditional.
            reraises = bool(statement.handlers) and all(
                _handler_guarantees_terminal(
                    handler, terminal_functions or {}, functions or {},
                    trusted_receivers or set(),
                )
                for handler in statement.handlers
            )
            body_reaches_sink = any(
                isinstance(child, ast.Call)
                and called_name(child) in (dominated_sink_names or set())
                for body_statement in statement.body
                for child in ast.walk(body_statement)
            )
            if statement.handlers and not reraises and not body_reaches_sink:
                self._visit_nondominating(statement.body)
            else:
                for child in statement.body:
                    self.visit(child)
            for handler in statement.handlers:
                self.visit(handler)
            self._visit_nondominating(statement.orelse)
            for child in statement.finalbody:
                self.visit(child)

        visit_TryStar = visit_Try

        def visit_ExceptHandler(self, handler):
            if handler.type is not None:
                self.visit(handler.type)
            self._visit_nondominating(handler.body)

        def visit_Call(self, call):
            if self.suppress_conditional_stops and called_name(call) in {
                "stop_native_ztp_monitors", "stop_monitor",
                "quiesce_for_source_update",
            }:
                return
            result.append(call)
            self.generic_visit(call)

    StructuralVisitor().visit(node)
    return result


def assert_quiesce_structurally_precedes_reachable_sink(
    testcase: unittest.TestCase, tree: ast.AST, entry_name: str,
    known_sinks: set[str], stop_names: set[str] | None = None,
) -> None:
    functions = production_functions(tree)
    reachable = transitive_sink_callers(tree, known_sinks)
    function = functions[entry_name]
    accepted_stops = stop_names or {"stop_native_ztp_monitors"}
    try_types = (ast.Try,) + tuple(
        node_type for node_type in (getattr(ast, "TryStar", None),)
        if node_type is not None
    )
    terminal_functions = _argparse_terminal_functions(tree)

    def block_has_call(statements, names):
        return any(
            isinstance(child, ast.Call) and called_name(child) in names
            for statement in statements
            for child in _walk_local_scope(statement)
        )

    def reject_swallowed_stop_before_later_sink(statements):
        block_has_swallowed_stop = False
        for index, statement in enumerate(statements):
            statement_has_swallowed_stop = False
            if isinstance(statement, try_types) and statement.handlers:
                reraises = all(
                    _handler_guarantees_terminal(
                        handler, terminal_functions, functions, {"parser"},
                    )
                    for handler in statement.handlers
                )
                statement_has_swallowed_stop = (
                    not reraises
                    and block_has_call(statement.body, accepted_stops)
                )
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                continue
            for attribute in ("body", "orelse", "finalbody"):
                child_block = getattr(statement, attribute, None)
                if child_block:
                    statement_has_swallowed_stop |= (
                        reject_swallowed_stop_before_later_sink(child_block)
                    )
            for handler in getattr(statement, "handlers", ()):
                statement_has_swallowed_stop |= (
                    reject_swallowed_stop_before_later_sink(handler.body)
                )
            for case in getattr(statement, "cases", ()):
                statement_has_swallowed_stop |= (
                    reject_swallowed_stop_before_later_sink(case.body)
                )
            if statement_has_swallowed_stop and block_has_call(
                statements[index + 1:], reachable,
            ):
                testcase.fail(
                    f"{entry_name} can reach a governed sink after "
                    "swallowing a quiesce failure"
                )
            block_has_swallowed_stop |= statement_has_swallowed_stop
        return block_has_swallowed_stop

    reject_swallowed_stop_before_later_sink(function.body)
    calls = structural_calls(
        function, _suppress_aliases(tree, function), reachable,
        terminal_functions, functions, {"parser"},
    )
    stop_positions = [
        index for index, call in enumerate(calls)
        if called_name(call) in accepted_stops
    ]
    testcase.assertTrue(stop_positions, f"{entry_name} has no direct quiesce")
    first_stop = min(stop_positions)
    sink_positions = [
        index for index, call in enumerate(calls)
        if called_name(call) in reachable
    ]
    if sink_positions:
        testcase.assertTrue(
            all(position < min(sink_positions) for position in stop_positions),
            f"{entry_name} contains a post-mutation quiesce that can mask "
            "a dead/non-dominating earlier stop",
        )
    pre_stop_sinks = [
        called_name(call) for call in calls[:first_stop]
        if called_name(call) in reachable
    ]
    testcase.assertEqual(
        [], pre_stop_sinks,
        f"{entry_name} reaches governed mutation before quiesce",
    )


class MonitorWriterQuiesceWorkflowTests(unittest.TestCase):
    @staticmethod
    def dhcp_main_patches(module, *, events=None):
        record = {
            "type": "eth", "iface": "eth0", "hostname": "leaf01",
            "ip": "192.0.2.10", "mac": "02:11:22:33:44:55",
            "mac_norm": "02:11:22:33:44:55",
        }
        return (
            mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]),
            mock.patch.object(module.os.path, "isfile", return_value=True),
            mock.patch.object(module, "load_project_global", return_value=("ztp", 2)),
            mock.patch.object(module, "load_subnet_csv", return_value=[{}]),
            mock.patch.object(module, "load_csv", return_value=[record]),
            mock.patch.object(module, "load_p2p_air_json", return_value=[]),
            mock.patch.object(module, "inherit_air_records_from_production", return_value=[]),
            mock.patch.object(module, "exclude_all_air_records", side_effect=lambda records: (records, 0)),
            mock.patch.object(module, "merge_air_records", side_effect=lambda records, _air: (records, [])),
            mock.patch.object(module, "records_for_release_scope", return_value=[record]),
            mock.patch.object(module, "validate", return_value=([record], [])),
            mock.patch.object(module, "validate_records_against_subnets", return_value=[]),
            mock.patch.object(module, "plan_dhcp_assignments", return_value=[]),
            mock.patch.object(module, "_confirm", return_value=True),
        )

    @staticmethod
    def enter_all(patches):
        stack = __import__("contextlib").ExitStack()
        for patcher in patches:
            stack.enter_context(patcher)
        return stack

    def test_setup_stops_monitor_inside_lock_before_activation_write(self) -> None:
        setup = load_module("mwq_setup", "DAY0-Prepare/01-a-setup.py")
        events = []
        args = argparse.Namespace(
            project="customer", create=False, auto_yes=True,
            confirm_project_switch=False, force=False, strict=False,
            dry_run=False, csv_dir=None, p2p_file=None,
            status=False, list_projects=False,
        )

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "http"
            day0 = http_root / "DAY0-Prepare"
            (day0 / "customer").mkdir(parents=True)
            with mock.patch.object(setup, "HERE", os.fspath(day0)), \
                 mock.patch.object(setup, "HTTP_BASE", os.fspath(http_root)), \
                 mock.patch.object(setup, "_parse_args", return_value=args), \
                 mock.patch.object(setup, "deployment_lock", fake_lock), \
                 mock.patch.object(
                     setup, "stop_native_ztp_monitors",
                     side_effect=lambda *_a, **_k: events.append("monitor-stop"),
                     create=True,
                 ), \
                 mock.patch.object(
                     setup, "setup",
                     side_effect=lambda _project: events.append("activation-write"),
                 ):
                self.assertEqual(0, setup.main([]))

        self.assertEqual(
            ["lock-enter", "monitor-stop", "activation-write", "lock-exit"],
            events,
        )

    def test_unsetup_stops_monitor_inside_lock_before_manifest_or_link_delete(self) -> None:
        unsetup = load_module("mwq_unsetup", "DAY0-Prepare/02-unsetup.py")
        events = []
        args = argparse.Namespace(project=None, yes=True, dry_run=False)

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "http"
            managed = http_root / "ztp/config/cumulus/latest_yaml"
            target = http_root / "DAY0-Prepare/customer/99-output-eth"
            managed.parent.mkdir(parents=True)
            target.mkdir(parents=True)
            managed.symlink_to(target)

            def stop_before_delete(*_args, **_kwargs):
                self.assertTrue(managed.is_symlink())
                events.append("monitor-stop")

            with mock.patch.object(unsetup, "HTTP_BASE", os.fspath(http_root)), \
                 mock.patch.object(unsetup, "ZTP", os.fspath(http_root / "ztp")), \
                 mock.patch.object(
                     unsetup, "MANIFEST_FILE", os.fspath(http_root / "ztp/.setup_manifest"),
                 ), \
                 mock.patch.object(unsetup, "_parse_args", return_value=args), \
                 mock.patch.object(unsetup, "deployment_lock", fake_lock), \
                 mock.patch.object(
                     unsetup, "stop_native_ztp_monitors",
                     side_effect=stop_before_delete, create=True,
                 ), \
                 mock.patch.object(
                     unsetup, "_known_ztp_project_links", return_value=[os.fspath(managed)],
                 ), \
                 mock.patch.object(unsetup, "_known_workspace_links", return_value=[]):
                self.assertEqual(0, unsetup.main([]))
            self.assertFalse(managed.exists())
            self.assertFalse(managed.is_symlink())

        self.assertEqual(["lock-enter", "monitor-stop", "lock-exit"], events)

    def test_setup_stop_failure_performs_zero_activation_writes(self) -> None:
        setup = load_module("mwq_setup_fail", "DAY0-Prepare/01-a-setup.py")
        args = argparse.Namespace(
            project="customer", create=False, auto_yes=True,
            confirm_project_switch=False, force=False, strict=False,
            dry_run=False, csv_dir=None, p2p_file=None,
            status=False, list_projects=False,
        )
        writer = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "http"
            day0 = http_root / "DAY0-Prepare"
            (day0 / "customer").mkdir(parents=True)
            with mock.patch.object(setup, "HERE", os.fspath(day0)), \
                 mock.patch.object(setup, "HTTP_BASE", os.fspath(http_root)), \
                 mock.patch.object(setup, "_parse_args", return_value=args), \
                 mock.patch.object(setup, "deployment_lock", mock.MagicMock()), \
                 mock.patch.object(setup, "setup", writer), \
                 mock.patch.object(
                     setup, "stop_native_ztp_monitors",
                     side_effect=setup.RuntimeContractError("fixture stop failure"),
                     create=True,
                 ):
                self.assertEqual(1, setup.main([]))
        writer.assert_not_called()

    def test_unsetup_stop_failure_preserves_real_managed_link(self) -> None:
        unsetup = load_module("mwq_unsetup_fail", "DAY0-Prepare/02-unsetup.py")
        args = argparse.Namespace(project=None, yes=True, dry_run=False)
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "http"
            managed = http_root / "ztp/config/cumulus/latest_yaml"
            target = http_root / "DAY0-Prepare/customer/99-output-eth"
            managed.parent.mkdir(parents=True)
            target.mkdir(parents=True)
            managed.symlink_to(target)
            with mock.patch.object(unsetup, "HTTP_BASE", os.fspath(http_root)), \
                 mock.patch.object(unsetup, "ZTP", os.fspath(http_root / "ztp")), \
                 mock.patch.object(
                     unsetup, "MANIFEST_FILE", os.fspath(http_root / "ztp/.setup_manifest"),
                 ), \
                 mock.patch.object(unsetup, "_parse_args", return_value=args), \
                 mock.patch.object(unsetup, "deployment_lock", mock.MagicMock()), \
                 mock.patch.object(
                     unsetup, "_known_ztp_project_links", return_value=[os.fspath(managed)],
                 ), \
                 mock.patch.object(unsetup, "_known_workspace_links", return_value=[]), \
                 mock.patch.object(
                     unsetup, "stop_native_ztp_monitors",
                     side_effect=unsetup.RuntimeContractError("fixture stop failure"),
                     create=True,
                 ):
                self.assertEqual(1, unsetup.main([]))
            self.assertTrue(managed.is_symlink())

    def test_native_load_stops_monitor_before_systemd_services(self) -> None:
        load = load_module("mwq_load", "DAY0-Prepare/11-load.py")
        events = []
        backend = SimpleNamespace(name="systemd")
        with mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
             mock.patch.object(load.shutil, "which", return_value="/bin/systemctl"), \
             mock.patch.object(load, "active_managed_services", return_value=("apache2",)), \
             mock.patch.object(load, "sudo_command", return_value=["systemctl", "stop", "apache2"]), \
             mock.patch.object(
                 load, "stop_native_ztp_monitors",
                 side_effect=lambda *_a, **_k: events.append("monitor-stop"),
                 create=True,
             ), \
             mock.patch.object(
                 load, "run", side_effect=lambda *_a, **_k: events.append("service-stop"),
             ):
            load.quiesce_services(runtime_backend=backend)

        self.assertEqual(["monitor-stop", "service-stop"], events)

    def test_native_load_service_quiesce_reuses_earlier_monitor_stop(self) -> None:
        load = load_module("mwq_load_reuse", "DAY0-Prepare/11-load.py")
        backend = SimpleNamespace(name="systemd")
        native_stop = mock.Mock()
        service_stop = mock.Mock()
        with mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
             mock.patch.object(load.shutil, "which", return_value="/bin/systemctl"), \
             mock.patch.object(load, "active_managed_services", return_value=("apache2",)), \
             mock.patch.object(load, "sudo_command", return_value=["systemctl", "stop", "apache2"]), \
             mock.patch.object(load, "stop_native_ztp_monitors", native_stop), \
             mock.patch.object(load, "run", service_stop):
            load.quiesce_services(
                runtime_backend=backend,
                native_monitor_already_quiesced=True,
            )
        native_stop.assert_not_called()
        service_stop.assert_called_once()

    def test_supervisor_load_does_not_double_stop_native_monitor(self) -> None:
        load = load_module("mwq_load_supervisor", "DAY0-Prepare/11-load.py")
        backend = SimpleNamespace(name="supervisor")
        native_stop = mock.Mock()
        with mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
             mock.patch.object(load, "active_managed_services", return_value=()), \
             mock.patch.object(load, "stop_native_ztp_monitors", native_stop, create=True):
            load.quiesce_services(runtime_backend=backend)
        native_stop.assert_not_called()

    def test_native_load_stop_failure_precedes_all_service_actions(self) -> None:
        load = load_module("mwq_load_fail", "DAY0-Prepare/11-load.py")
        backend = SimpleNamespace(name="systemd")
        active = mock.Mock(return_value=("apache2",))
        service_stop = mock.Mock()
        with mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
             mock.patch.object(load, "active_managed_services", active), \
             mock.patch.object(load, "run", service_stop), \
             mock.patch.object(
                 load, "stop_native_ztp_monitors",
                 side_effect=load.RuntimeContractError("fixture stop failure"),
                 create=True,
             ):
            with self.assertRaises(load.RuntimeContractError):
                load.quiesce_services(runtime_backend=backend)
        active.assert_not_called()
        service_stop.assert_not_called()

    def test_load_passes_its_inherited_lock_to_both_locking_generators(self) -> None:
        load = load_module("mwq_load_child_lock", "DAY0-Prepare/11-load.py")
        calls = []

        def capture(command, **kwargs):
            calls.append((tuple(command), kwargs))

        with mock.patch.object(load, "run", side_effect=capture), \
             mock.patch.object(load, "_device_types_after_dhcp", return_value=frozenset()):
            load.generate_configs(
                frozenset(), install_dhcp=False,
                deployment_lock_descriptor=73,
                switch_scope="eth",
            )

        locking_children = {
            Path(command[1]).name: kwargs.get("inherited_lock_descriptor")
            for command, kwargs in calls
            if len(command) > 1 and Path(command[1]).name in {
                "b-xlsx_to_dot.py", "c1-generate_dhcp.py",
            }
        }
        self.assertEqual(
            {"b-xlsx_to_dot.py": 73, "c1-generate_dhcp.py": 73},
            locking_children,
        )

        main = function_node("DAY0-Prepare/11-load.py", "main")
        generate_calls = [
            node for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "generate_configs"
        ]
        self.assertTrue(generate_calls)
        for call in generate_calls:
            self.assertIn(
                "deployment_lock_descriptor",
                {keyword.arg for keyword in call.keywords},
            )

    def test_read_only_help_and_dry_run_paths_do_not_stop_monitor(self) -> None:
        setup = load_module("mwq_setup_readonly", "DAY0-Prepare/01-a-setup.py")
        unsetup = load_module("mwq_unsetup_dry", "DAY0-Prepare/02-unsetup.py")
        load = load_module("mwq_load_dry", "DAY0-Prepare/11-load.py")
        dhcp = load_module(
            "mwq_dhcp_help", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )
        p2p = load_module(
            "mwq_p2p_help", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )
        for module in (setup, unsetup, load, dhcp, p2p):
            setattr(module, "stop_native_ztp_monitors", mock.Mock())

        status_args = argparse.Namespace(
            status=True, list_projects=False, project=None, create=False,
            auto_yes=False, confirm_project_switch=False, force=False,
            strict=False, dry_run=False, csv_dir=None, p2p_file=None,
        )
        with mock.patch.object(setup, "_parse_args", return_value=status_args), \
             mock.patch.object(setup, "_print_active_status"):
            self.assertEqual(0, setup.main([]))

        dry_unsetup_args = argparse.Namespace(project=None, yes=True, dry_run=True)
        with mock.patch.object(unsetup, "_parse_args", return_value=dry_unsetup_args), \
             mock.patch.object(unsetup, "deployment_lock", mock.MagicMock()), \
             mock.patch.object(unsetup, "_main_locked", return_value=0):
            self.assertEqual(0, unsetup.main([]))

        dry_setup_args = argparse.Namespace(
            status=False, list_projects=False, project="customer", create=False,
            auto_yes=True, confirm_project_switch=False, force=False,
            strict=False, dry_run=True, csv_dir=None, p2p_file=None,
        )
        with tempfile.TemporaryDirectory() as temporary:
            day0 = Path(temporary) / "DAY0-Prepare"
            (day0 / "customer").mkdir(parents=True)
            with mock.patch.object(setup, "HERE", os.fspath(day0)), \
                 mock.patch.object(setup, "_parse_args", return_value=dry_setup_args), \
                 mock.patch.object(setup, "deployment_lock", mock.MagicMock()), \
                 mock.patch.object(setup, "setup"):
                self.assertEqual(0, setup.main([]))

        backend = SimpleNamespace(name="systemd")
        with mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
             mock.patch.object(load.shutil, "which", return_value=None):
            load.quiesce_services(dry_run=True, runtime_backend=backend)

        with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "--help"]):
            dhcp.main()
        with mock.patch.object(sys, "argv", ["b-xlsx_to_dot.py", "--help"]):
            p2p.main()

        for module in (setup, unsetup, load, dhcp, p2p):
            module.stop_native_ztp_monitors.assert_not_called()

    def test_password_writer_quiesces_inside_its_lock_and_load_reuses_parent_stop(self) -> None:
        password = load_module("mwq_password", "tools/password-update.py")
        events = []
        global_file = ROOT / "DAY0-Prepare/customer/01-global.yaml"

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        update_result = SimpleNamespace(path=global_file)
        common = (
            mock.patch.object(password, "resolve_global_file", return_value=global_file),
            mock.patch.object(
                password, "_read_regular_snapshot",
                return_value=SimpleNamespace(data=b"global fixture"),
            ),
            mock.patch.object(password, "locate_password_targets"),
            mock.patch.object(password, "validate_hash_backend"),
            mock.patch.object(
                password, "_passwords_for_sections",
                return_value={"eth": "fixture-secret"},
            ),
            mock.patch.object(
                password, "_hashes_for_sections",
                return_value={"eth": "$6$fixture"},
            ),
            mock.patch.object(password, "deployment_lock", fake_lock),
            mock.patch.object(
                password, "stop_native_ztp_monitors",
                side_effect=lambda *_a, **_k: events.append("monitor-stop") or (),
                create=True,
            ),
            mock.patch.object(
                password, "update_global_file",
                side_effect=lambda *_a, **_k: events.append("global-write") or update_result,
            ),
        )
        with self.enter_all(common):
            password.rotate_project_passwords(
                "customer", platform="cumulus", root=ROOT,
                day0=ROOT / "DAY0-Prepare", reader=lambda _prompt: "unused",
            )
            self.assertEqual(
                ["lock-enter", "monitor-stop", "global-write", "lock-exit"],
                events,
            )
            events.clear()
            password.rotate_project_passwords(
                "customer", platform="cumulus", root=ROOT,
                day0=ROOT / "DAY0-Prepare", lock_already_held=True,
                reader=lambda _prompt: "unused",
            )
            self.assertEqual(["global-write"], events)
            events.clear()
            password.rotate_project_passwords(
                "customer", platform="cumulus", root=ROOT,
                day0=ROOT / "DAY0-Prepare", dry_run=True,
                reader=lambda _prompt: "unused",
            )
            self.assertEqual(["lock-enter", "global-write", "lock-exit"], events)

    def test_password_writer_stop_failure_performs_zero_global_write(self) -> None:
        password = load_module("mwq_password_fail", "tools/password-update.py")
        global_file = ROOT / "DAY0-Prepare/customer/01-global.yaml"
        update = mock.Mock()

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            yield

        patches = (
            mock.patch.object(password, "resolve_global_file", return_value=global_file),
            mock.patch.object(
                password, "_read_regular_snapshot",
                return_value=SimpleNamespace(data=b"global fixture"),
            ),
            mock.patch.object(password, "locate_password_targets"),
            mock.patch.object(password, "validate_hash_backend"),
            mock.patch.object(
                password, "_passwords_for_sections",
                return_value={"eth": "fixture-secret"},
            ),
            mock.patch.object(
                password, "_hashes_for_sections",
                return_value={"eth": "$6$fixture"},
            ),
            mock.patch.object(password, "deployment_lock", fake_lock),
            mock.patch.object(
                password, "stop_native_ztp_monitors",
                side_effect=RuntimeError("fixture stop failure"), create=True,
            ),
            mock.patch.object(password, "update_global_file", update),
        )
        with self.enter_all(patches):
            with self.assertRaisesRegex(RuntimeError, "fixture stop failure"):
                password.rotate_project_passwords(
                    "customer", platform="cumulus", root=ROOT,
                    day0=ROOT / "DAY0-Prepare", reader=lambda _prompt: "unused",
                )
        update.assert_not_called()

    def test_load_quiesces_native_monitor_once_before_template_and_password_writes(self) -> None:
        load = load_module("mwq_load_password_order", "DAY0-Prepare/11-load.py")
        events = []
        backend = SimpleNamespace(name="systemd")
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "customer"
            project.mkdir()
            (project / "01-global.yaml").write_text("fixture\n", encoding="utf-8")

            def event(name, result=None):
                return lambda *_a, **_k: events.append(name) or result

            with mock.patch.object(load, "preflight_password_update_backend"), \
                 mock.patch.object(load, "acquire_deployment_lock", return_value=93), \
                 mock.patch.object(load, "release_deployment_lock"), \
                 mock.patch.object(load, "runtime_os", return_value="Linux"), \
                 mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
                 mock.patch.object(load, "service_runtime_backend", return_value=backend), \
                 mock.patch.object(load, "validate_runtime_options"), \
                 mock.patch.object(load, "resolve_project", return_value=project), \
                 mock.patch.object(load, "sync_marker_present", return_value=False), \
                 mock.patch.object(
                     load, "stop_native_ztp_monitors", side_effect=event("monitor-stop"),
                 ) as stop, mock.patch.object(
                     load, "initialize_from_template", side_effect=event("template-write"),
                 ), mock.patch.object(
                     load, "prompt_password_update_selection", return_value=("all", True),
                 ), mock.patch.object(
                     load, "update_passwords_before_load", side_effect=event("password-write"),
                 ), mock.patch.object(
                     load, "validate_inputs",
                     side_effect=lambda *_a, **_k: (
                         events.append("validate"),
                         (_ for _ in ()).throw(load.LoadError("fixture stop")),
                     )[-1],
                 ):
                self.assertEqual(1, load.main([str(project), "--update-passwords"]))

        self.assertEqual(
            ["monitor-stop", "template-write", "password-write", "validate"],
            events,
        )
        stop.assert_called_once_with(load.HTTP_ROOT)
        main = function_node("DAY0-Prepare/11-load.py", "main")
        self.assertLess(
            first_call_line(main, "stop_native_ztp_monitors"),
            first_call_line(main, "initialize_from_template"),
        )
        self.assertLess(
            first_call_line(main, "stop_native_ztp_monitors"),
            first_call_line(main, "update_passwords_before_load"),
        )

    def test_load_early_native_stop_failure_performs_zero_identity_write(self) -> None:
        load = load_module("mwq_load_password_fail", "DAY0-Prepare/11-load.py")
        backend = SimpleNamespace(name="systemd")
        template_write = mock.Mock()
        password_write = mock.Mock()
        validate = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "customer"
            project.mkdir()
            (project / "01-global.yaml").write_text("fixture\n", encoding="utf-8")
            with mock.patch.object(load, "preflight_password_update_backend"), \
                 mock.patch.object(load, "acquire_deployment_lock", return_value=94), \
                 mock.patch.object(load, "release_deployment_lock"), \
                 mock.patch.object(load, "runtime_os", return_value="Linux"), \
                 mock.patch.object(load, "supports_local_ztp_services", return_value=True), \
                 mock.patch.object(load, "service_runtime_backend", return_value=backend), \
                 mock.patch.object(load, "validate_runtime_options"), \
                 mock.patch.object(load, "resolve_project", return_value=project), \
                 mock.patch.object(load, "sync_marker_present", return_value=False), \
                 mock.patch.object(
                     load, "stop_native_ztp_monitors",
                     side_effect=load.RuntimeContractError("fixture stop failure"),
                 ), mock.patch.object(
                     load, "initialize_from_template", template_write,
                 ), mock.patch.object(
                     load, "update_passwords_before_load", password_write,
                 ), mock.patch.object(load, "validate_inputs", validate):
                self.assertEqual(1, load.main([str(project), "--update-passwords"]))
        template_write.assert_not_called()
        password_write.assert_not_called()
        validate.assert_not_called()

    def test_feedback_writer_quiesces_inside_lock_before_recovery_mutation(self) -> None:
        feedback = load_module("mwq_feedback", "ztp/optimize/feedback.py")
        events = []
        plan = SimpleNamespace(http_base=ROOT)

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield 91
            finally:
                events.append("lock-exit")

        with mock.patch.object(feedback, "discover_sample_inputs", return_value=plan), \
             mock.patch.object(
                 feedback, "_revalidate_sample_plan",
                 side_effect=lambda *_a: events.append("plan-revalidate"),
             ), mock.patch.object(feedback, "deployment_lock", fake_lock), \
             mock.patch.object(
                 feedback, "stop_native_ztp_monitors",
                 side_effect=lambda *_a, **_k: events.append("monitor-stop") or (),
                 create=True,
             ), mock.patch.object(
                 feedback, "find_global_config", return_value=ROOT / "global.yaml",
             ), mock.patch.object(
                 feedback, "recover_global_writeback_state",
                 side_effect=lambda *_a, **_k: events.append("state-mutation"),
             ):
            self.assertEqual(0, feedback.main([
                "--recover-global-writeback-state",
                "--global-config", os.fspath(ROOT / "global.yaml"),
            ]))
        self.assertEqual(
            [
                "lock-enter", "plan-revalidate", "monitor-stop",
                "state-mutation", "lock-exit",
            ],
            events,
        )

    def test_feedback_stop_failure_performs_zero_recovery_mutation(self) -> None:
        feedback = load_module("mwq_feedback_fail", "ztp/optimize/feedback.py")
        plan = SimpleNamespace(http_base=ROOT)
        recovery = mock.Mock()

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            yield 92

        with mock.patch.object(feedback, "discover_sample_inputs", return_value=plan), \
             mock.patch.object(feedback, "_revalidate_sample_plan"), \
             mock.patch.object(feedback, "deployment_lock", fake_lock), \
             mock.patch.object(
                 feedback, "stop_native_ztp_monitors",
                 side_effect=RuntimeError("fixture stop failure"), create=True,
             ), mock.patch.object(feedback, "find_global_config"), \
             mock.patch.object(feedback, "recover_global_writeback_state", recovery), \
             mock.patch.object(feedback, "_bounded_parser_error", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                feedback.main([
                    "--recover-global-writeback-state",
                    "--global-config", os.fspath(ROOT / "global.yaml"),
                ])
        recovery.assert_not_called()

    def test_each_direct_writer_quiesce_call_survives_ast_mutation_oracle(self) -> None:
        contracts = (
            ("DAY0-Prepare/01-a-setup.py", "_main_locked", "setup"),
            ("DAY0-Prepare/02-unsetup.py", "main", "_main_locked"),
            ("DAY0-Prepare/11-load.py", "quiesce_services", "run"),
            ("DAY0-Prepare/11-load.py", "main", "initialize_from_template"),
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                "main", "write_dhcpd_conf",
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                "main", "makedirs",
            ),
            ("tools/password-update.py", "rotate_project_passwords", "update_global_file"),
            ("ztp/optimize/feedback.py", "main", "recover_global_writeback_state"),
            (
                "tools/deployment_prewrite_guard.py",
                "quiesce_for_source_update", "write_deployment_owner",
            ),
        )

        class RemoveQuiesce(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                called = node.func
                if isinstance(called, ast.Name) and called.id == "stop_native_ztp_monitors":
                    called.id = "mutated_quiesce_removed"
                elif (
                    isinstance(called, ast.Attribute)
                    and called.attr == "stop_native_ztp_monitors"
                ):
                    called.attr = "mutated_quiesce_removed"
                return node

        for relative, function_name, first_writer in contracts:
            with self.subTest(script=relative, function=function_name):
                def assert_contract(tree):
                    function = next(
                        node for node in tree.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == function_name
                    )
                    self.assertIn("stop_native_ztp_monitors", call_names(function))
                    self.assertIn(first_writer, call_names(function))

                original = ast.parse(
                    (ROOT / relative).read_text(encoding="utf-8")
                )
                assert_contract(original)
                mutated = RemoveQuiesce().visit(copy.deepcopy(original))
                with self.assertRaises(
                    AssertionError,
                    msg="mutation oracle accepted a deleted/replaced quiesce call",
                ):
                    assert_contract(mutated)

    def test_no_quiesce_caller_escapes_the_sink_derived_contract_set(self) -> None:
        """Supplement W-1 by rejecting unknown wrappers; this is not discovery."""
        expected = {
            "DAY0-Prepare/01-a-setup.py": {"_main_locked"},
            "DAY0-Prepare/02-unsetup.py": {"main"},
            "DAY0-Prepare/11-load.py": {
                "main", "quiesce_services", "stop_other_ztp_monitors",
            },
            "DAY0-Prepare/13-unload.py": {"stop_monitor"},
            "tools/deployment_prewrite_guard.py": {"quiesce_for_source_update"},
            "tools/password-update.py": {"rotate_project_passwords"},
            "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py": {"main"},
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py": {"main"},
            "ztp/optimize/feedback.py": {"main"},
        }
        discovered = {}
        for source in ROOT.rglob("*.py"):
            relative = source.relative_to(ROOT)
            if relative.parts[0] in {"test_cases", ".git"}:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
            callers = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and "stop_native_ztp_monitors" in call_names(node)
            }
            if callers:
                discovered[relative.as_posix()] = callers
        self.assertEqual(expected, discovered)

    def test_standalone_generators_quiesce_before_their_first_output_write(self) -> None:
        cases = (
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                "write_dhcpd_conf",
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                "makedirs",
            ),
        )
        for relative, first_writer in cases:
            with self.subTest(script=relative):
                main = function_node(relative, "main")
                self.assertLess(
                    first_call_line(main, "stop_native_ztp_monitors"),
                    first_call_line(main, first_writer),
                )
        dhcp_main = function_node(
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py", "main",
        )
        self.assertLess(
            first_call_line(dhcp_main, "stop_native_ztp_monitors"),
            first_call_line(dhcp_main, "append_air_records_to_csv"),
        )
        p2p_main = function_node(
            "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py", "main",
        )
        for writer in ("generate_air_dot", "generate_air_json"):
            self.assertLess(
                first_call_line(p2p_main, "stop_native_ztp_monitors"),
                first_call_line(p2p_main, writer),
            )

    def test_dhcp_generator_stop_failure_performs_zero_candidate_or_csv_writes(self) -> None:
        dhcp = load_module(
            "mwq_dhcp_fail", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )
        writers = {
            "write_dhcpd_conf": mock.Mock(),
            "write_hosts": mock.Mock(),
            "write_release_manifest": mock.Mock(),
            "append_air_records_to_csv": mock.Mock(return_value=(0, 0, 0)),
        }
        stop_observed = False
        events = []

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        patches = self.dhcp_main_patches(dhcp) + (
            mock.patch.object(dhcp, "deployment_lock", fake_lock, create=True),
            mock.patch.object(
                dhcp, "stop_native_ztp_monitors",
                side_effect=lambda *_a, **_k: (
                    events.append("monitor-stop"),
                    (_ for _ in ()).throw(
                        dhcp.RuntimeContractError("fixture stop failure")
                    ),
                )[-1], create=True,
            ),
            mock.patch.multiple(dhcp, **writers),
        )
        with self.enter_all(patches):
            try:
                dhcp.main()
            except RuntimeError as exc:
                self.assertIn("fixture stop failure", str(exc))
                stop_observed = True
            except SystemExit as exc:
                self.assertEqual(1, exc.code)
                stop_observed = True
        self.assertTrue(stop_observed, "generator did not fail at Monitor quiesce")
        self.assertEqual(["lock-enter", "monitor-stop", "lock-exit"], events)
        for writer in writers.values():
            writer.assert_not_called()

    def test_dhcp_generator_holds_lock_from_stop_through_active_csv_mutation(self) -> None:
        dhcp = load_module(
            "mwq_dhcp_lock", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )
        events = []

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        def event(name, result=None):
            return lambda *_a, **_k: events.append(name) or result

        patches = self.dhcp_main_patches(dhcp) + (
            mock.patch.object(dhcp, "deployment_lock", fake_lock, create=True),
            mock.patch.object(
                dhcp, "stop_native_ztp_monitors", side_effect=event("monitor-stop", ()),
                create=True,
            ),
            mock.patch.object(dhcp, "write_dhcpd_conf", side_effect=event("dhcp-conf")),
            mock.patch.object(dhcp, "write_hosts", side_effect=event("hosts")),
            mock.patch.object(dhcp, "write_release_manifest", side_effect=event("manifest")),
            mock.patch.object(dhcp, "_candidate_mode", side_effect=event("candidate-mode")),
            mock.patch.object(
                dhcp, "_publish_dhcp_candidates", side_effect=event("publish"),
            ),
            mock.patch.object(
                dhcp, "append_air_records_to_csv",
                side_effect=event("active-csv", (0, 0, 0)),
            ),
        )
        with self.enter_all(patches):
            dhcp.main()
        self.assertEqual("lock-enter", events[0])
        self.assertEqual("monitor-stop", events[1])
        self.assertIn("active-csv", events)
        self.assertEqual("lock-exit", events[-1])
        self.assertLess(events.index("monitor-stop"), events.index("dhcp-conf"))
        self.assertLess(events.index("dhcp-conf"), events.index("active-csv"))

    def test_standalone_generator_lock_failure_performs_zero_mutation(self) -> None:
        dhcp = load_module(
            "mwq_dhcp_lock_fail", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )
        p2p = load_module(
            "mwq_p2p_lock_fail", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )
        dhcp_writer = mock.Mock()
        dhcp_hosts = mock.Mock()
        dhcp_manifest = mock.Mock()
        dhcp_csv = mock.Mock(return_value=(0, 0, 0))
        patches = self.dhcp_main_patches(dhcp) + (
            mock.patch.object(
                dhcp, "deployment_lock",
                side_effect=DeploymentLockError("fixture lock failure"), create=True,
            ),
            mock.patch.object(dhcp, "write_dhcpd_conf", dhcp_writer),
            mock.patch.object(dhcp, "write_hosts", dhcp_hosts),
            mock.patch.object(dhcp, "write_release_manifest", dhcp_manifest),
            mock.patch.object(dhcp, "append_air_records_to_csv", dhcp_csv),
        )
        with self.enter_all(patches):
            with self.assertRaises(SystemExit) as raised:
                dhcp.main()
        self.assertEqual(1, raised.exception.code)
        dhcp_writer.assert_not_called()
        dhcp_hosts.assert_not_called()
        dhcp_manifest.assert_not_called()
        dhcp_csv.assert_not_called()

        makedirs = mock.Mock()
        parsed = (
            os.fspath(ROOT / "ztp/config/cumulus/template/P2P/default-air.json"),
            None, None, None, "all",
        )
        with mock.patch.object(sys, "argv", ["b-xlsx_to_dot.py", "-y"]), \
             mock.patch.object(p2p, "_parse_cli_args", return_value=parsed), \
             mock.patch.object(p2p, "_missing_required_files", return_value=[]), \
             mock.patch.object(p2p, "deployment_lock", side_effect=DeploymentLockError("fixture lock failure"), create=True), \
             mock.patch.object(p2p.os, "makedirs", makedirs):
            with self.assertRaises(SystemExit) as raised:
                p2p.main()
        self.assertEqual(1, raised.exception.code)
        makedirs.assert_not_called()

    def test_p2p_generator_stop_failure_precedes_project_and_air_mutations(self) -> None:
        p2p = load_module(
            "mwq_p2p_fail", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )
        makedirs = mock.Mock()
        air_dot = mock.Mock()
        air_json = mock.Mock()
        extraction = mock.Mock(return_value=[])
        parsed = (
            os.fspath(ROOT / "ztp/config/cumulus/template/P2P/default-air.json"),
            None, None, None, "all",
        )
        events = []

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        with mock.patch.object(sys, "argv", ["b-xlsx_to_dot.py", "-y"]), \
             mock.patch.object(p2p, "_parse_cli_args", return_value=parsed), \
             mock.patch.object(p2p, "_missing_required_files", return_value=[]), \
             mock.patch.object(p2p.os, "makedirs", makedirs), \
             mock.patch.object(p2p, "_extract_xlsx_rows", extraction), \
             mock.patch.object(p2p, "generate_air_dot", air_dot), \
             mock.patch.object(p2p, "generate_air_json", air_json), \
             mock.patch.object(p2p, "deployment_lock", fake_lock, create=True), \
             mock.patch.object(
                 p2p, "stop_native_ztp_monitors",
                 side_effect=lambda *_a, **_k: (
                     events.append("monitor-stop"),
                     (_ for _ in ()).throw(
                         p2p.RuntimeContractError("fixture stop failure")
                     ),
                 )[-1], create=True,
             ):
            with self.assertRaises(SystemExit) as raised:
                p2p.main()
        self.assertEqual(1, raised.exception.code)
        self.assertEqual(["lock-enter", "monitor-stop", "lock-exit"], events)
        makedirs.assert_not_called()
        extraction.assert_not_called()
        air_dot.assert_not_called()
        air_json.assert_not_called()

    def test_p2p_generator_holds_lock_from_stop_through_air_mutations(self) -> None:
        p2p = load_module(
            "mwq_p2p_lock", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )
        events = []

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        parsed = (
            os.fspath(ROOT / "ztp/config/cumulus/template/P2P/default-air.json"),
            None, None, None, "all",
        )
        source_rows = [{
            "fields": ("leaf01", "1", "leaf02", "2"),
            "sheet": "TAN", "row": 3,
        }]
        description = {"empty_endpoints": []}
        opened = mock.mock_open()
        patches = (
            mock.patch.object(sys, "argv", ["b-xlsx_to_dot.py", "-y"]),
            mock.patch.object(p2p, "_parse_cli_args", return_value=parsed),
            mock.patch.object(p2p, "_missing_required_files", return_value=[]),
            mock.patch.object(p2p, "deployment_lock", fake_lock, create=True),
             mock.patch.object(
                 p2p, "stop_native_ztp_monitors",
                 side_effect=lambda *_a, **_k: events.append("monitor-stop") or (),
                 create=True,
             ),
             mock.patch.object(
                 p2p.os, "makedirs",
                 side_effect=lambda *_a, **_k: events.append("mkdir"),
             ),
            mock.patch.object(p2p, "_source_workbook_stem", return_value="fabric"),
            mock.patch.object(p2p, "_extract_xlsx_rows", return_value=source_rows),
            mock.patch.object(p2p, "load_inventory", return_value=({}, [])),
            mock.patch.object(p2p, "load_port_map", return_value=({}, {})),
            mock.patch.object(p2p, "_classify_p2p_endpoint", return_value="real"),
            mock.patch.object(p2p, "_validate_dot_token"),
            mock.patch.object(p2p, "_is_eth_sw", return_value=False),
            mock.patch.object(p2p, "infer_splitter_profiles", return_value=({}, [])),
            mock.patch.object(p2p, "_placeholder_device", return_value=True),
            mock.patch.object(p2p, "_validate_air_topology_policy", return_value=set()),
            mock.patch.object(p2p, "_find_duplicate_or_conflicting_links", return_value=([], [])),
            mock.patch.object(p2p, "_resolved_physical_links", return_value=([], [])),
            mock.patch.object(p2p, "_lldpq_header", return_value=""),
            mock.patch("builtins.open", opened),
            mock.patch.object(p2p, "_build_description_intent_document", return_value=description),
             mock.patch.object(
                 p2p, "_write_description_intent",
                 side_effect=lambda *_a, **_k: events.append("description") or "intent.json",
             ),
            mock.patch.object(p2p, "_complete_splitter_interface_inventory", return_value={}),
            mock.patch.object(p2p, "_configured_bond_member_inventory", return_value={}),
            mock.patch.object(p2p, "_merge_port_inventories", return_value={}),
            mock.patch.object(p2p, "_timed_input", return_value="5.11.1"),
            mock.patch.object(p2p, "_validate_air_os_version", return_value="5.11.1"),
             mock.patch.object(
                 p2p, "generate_air_dot",
                 side_effect=lambda *_a, **_k: events.append("air-dot"),
             ),
             mock.patch.object(
                 p2p, "generate_air_json",
                 side_effect=lambda *_a, **_k: events.append("air-json"),
             ),
        )
        with self.enter_all(patches):
            p2p.main()
        self.assertEqual("lock-enter", events[0])
        self.assertEqual("monitor-stop", events[1])
        self.assertIn("description", events)
        self.assertIn("air-dot", events)
        self.assertIn("air-json", events)
        self.assertEqual("lock-exit", events[-1])
        self.assertLess(events.index("monitor-stop"), events.index("mkdir"))
        self.assertLess(events.index("mkdir"), events.index("air-dot"))
        self.assertLess(events.index("air-dot"), events.index("air-json"))

    def test_generator_lock_scope_contains_stop_and_every_identity_mutation(self) -> None:
        cases = (
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                {
                    "stop_native_ztp_monitors", "write_dhcpd_conf",
                    "write_hosts", "write_release_manifest",
                    "append_air_records_to_csv",
                },
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                {
                    "stop_native_ztp_monitors", "makedirs",
                    "_write_description_intent", "generate_air_dot",
                    "generate_air_json",
                },
            ),
        )
        for relative, expected_calls in cases:
            with self.subTest(script=relative):
                scope = deployment_lock_scope(function_node(relative, "main"))
                self.assertTrue(expected_calls.issubset(call_names(scope)))

    def test_native_guard_quiesces_before_writer_ready_or_overlay(self) -> None:
        guard = load_module(
            "mwq_guard", "tools/deployment_prewrite_guard.py",
        )
        stop = mock.Mock(return_value=())
        with mock.patch.object(
            guard, "stop_native_ztp_monitors", stop, create=True,
        ):
            changed = guard.quiesce_for_source_update(
                ROOT, native_requested=True,
                which=lambda _name: None,
            )
        self.assertFalse(changed)
        stop.assert_called_once_with(ROOT)

    def test_native_guard_stop_failure_performs_zero_state_or_source_writes(self) -> None:
        guard = load_module(
            "mwq_guard_fail", "tools/deployment_prewrite_guard.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "state"
            state_root.mkdir()
            owner = mock.Mock()
            marker = mock.Mock()
            with mock.patch.object(
                guard, "stop_native_ztp_monitors",
                side_effect=guard.GuardError("fixture stop failure"), create=True,
            ), mock.patch.object(guard, "write_deployment_owner", owner), \
                 mock.patch.object(guard, "write_rebuild_required", marker):
                with self.assertRaises(guard.GuardError):
                    guard.quiesce_for_source_update(
                        ROOT, state_root=state_root,
                        native_requested=True, which=lambda _name: None,
                    )
            owner.assert_not_called()
            marker.assert_not_called()

    def test_guard_archive_and_sync_holder_forward_native_runtime(self) -> None:
        for function_name in ("run_locked_archive", "run_lock_holder"):
            with self.subTest(function=function_name):
                function = function_node(
                    "tools/deployment_prewrite_guard.py", function_name,
                )
                calls = [
                    node for node in ast.walk(function)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "quiesce_for_source_update"
                ]
                self.assertTrue(calls)
                for call in calls:
                    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
                    self.assertIn("native_requested", keywords)
                    self.assertIsInstance(keywords["native_requested"], ast.Compare)

    def test_executed_guard_holder_quiesces_inside_lock_before_writer_ready(self) -> None:
        guard = load_module(
            "mwq_guard_holder_order", "tools/deployment_prewrite_guard.py",
        )
        events = []

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        def quiesce(*_args, **kwargs):
            self.assertTrue(kwargs["native_requested"])
            events.append("monitor-stop")
            return False

        with mock.patch.object(guard, "safe_lock", fake_lock), \
             mock.patch.object(guard, "quiesce_for_source_update", side_effect=quiesce), \
             mock.patch.object(sys, "stdin", io.StringIO(guard.PREWRITE_REQUEST + "\n")):
            self.assertEqual(
                0,
                guard.run_lock_holder(
                    ROOT / ".deployment.lock", ROOT, runtime="native",
                ),
            )
        self.assertEqual(["lock-enter", "monitor-stop", "lock-exit"], events)

    def test_executed_guard_archive_quiesces_before_overlay_under_same_lock(self) -> None:
        guard = load_module(
            "mwq_guard_archive_order", "tools/deployment_prewrite_guard.py",
        )
        events = []
        bootstrap = mock.Mock()

        @contextmanager
        def fake_lock(*_args, **_kwargs):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        def quiesce(*_args, **kwargs):
            self.assertTrue(kwargs["native_requested"])
            events.append("monitor-stop")
            return False

        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            with mock.patch.object(
                guard, "_extract_archive_staging", return_value=(staging, ()),
            ), mock.patch.object(guard, "_live_capacity_authority", return_value=object()), \
                 mock.patch.object(guard, "ensure_deployment_root", return_value=bootstrap), \
                 mock.patch.object(guard, "_recheck_live_capacity_after_root_creation"), \
                 mock.patch.object(guard, "safe_lock", fake_lock), \
                 mock.patch.object(guard, "quiesce_for_source_update", side_effect=quiesce), \
                 mock.patch.object(guard, "_write_sync_marker", side_effect=lambda *_a: events.append("marker")), \
                 mock.patch.object(guard, "_apply_prepared_archive_overlay", side_effect=lambda *_a, **_k: events.append("overlay")), \
                 mock.patch.object(guard, "finalize_source_update", side_effect=lambda *_a, **_k: events.append("finalize")), \
                 mock.patch.object(guard, "_safe_unlink"), \
                 mock.patch.object(guard, "_close_live_capacity_authority"), \
                 mock.patch.object(guard, "_remove_archive_staging"):
                self.assertEqual(
                    0,
                    guard.run_locked_archive(
                        ROOT / ".deployment.lock", ROOT,
                        Path(temporary) / "payload.tar", "a" * 64, "b" * 64,
                        runtime="native",
                    ),
                )
        self.assertEqual(
            [
                "lock-enter", "monitor-stop", "marker", "overlay",
                "finalize", "lock-exit",
            ],
            events,
        )

    def test_monitor_cycle_governed_authority_reads_are_exact(self) -> None:
        """Derive the governed set from monitor_once's real per-cycle call graph."""
        monitor = ast.parse(
            (ROOT / "DAY0-Prepare/12-ztp-monitor.py").read_text(encoding="utf-8")
        )
        functions = {
            node.name: node for node in monitor.body
            if isinstance(node, ast.FunctionDef)
        }
        cycle = functions["monitor_once"]
        cycle_calls = call_names(cycle)
        self.assertTrue({
            "load_release_identity", "project_timezone", "read_devices",
        }.issubset(cycle_calls))

        def string_literals(function_name):
            return {
                node.value for node in ast.walk(functions[function_name])
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }

        governed = set()
        if "99-output-ztp/current-release.json" in string_literals(
            "load_release_identity"
        ):
            governed.add("project/99-output-ztp/current-release.json")
        if "01-global.yaml" in string_literals("project_timezone"):
            governed.add("project/01-global.yaml")
        cycle_text = ast.unparse(cycle)
        if 'project / "02-devices_config.csv"' in cycle_text or \
                "project / '02-devices_config.csv'" in cycle_text:
            governed.add("project/02-devices_config.csv")
        if "ACTIVE_AIR_JSON" in cycle_text:
            governed.add("runtime/p2p-air.json")
        self.assertEqual({
            "project/99-output-ztp/current-release.json",
            "project/01-global.yaml",
            "project/02-devices_config.csv",
            "runtime/p2p-air.json",
        }, governed)

        # These calls consume observations or publish reports; their paths are
        # not identity/config authorities and must not narrow or widen W-1.
        self.assertTrue({
            "collect_dhcp", "read_tail", "write_report",
        }.issubset(cycle_calls))

        all_functions = production_functions(monitor)
        graph = local_call_graph(monitor)
        reachable = {"monitor_once"}
        changed = True
        while changed:
            changed = False
            for caller in tuple(reachable):
                for callee in graph.get(caller, set()):
                    if callee not in reachable:
                        reachable.add(callee)
                        changed = True
        filesystem_readers = {
            name for name in reachable
            if call_names(all_functions[name]) & {
                "open", "read_text", "read_bytes", "readline", "readlines",
            }
        }
        self.assertEqual({
            # Governed identity/config authority readers.
            "_read_bounded_regular_text", "project_timezone", "read_devices",
            # Explicit observations / previous output; never source identity.
            "_previous_report", "_snapshot_state_from_dir",
            "latest_manual_trigger_markers", "read_tail",
            # Atomic report publication output (open is write-mode here).
            "write_report",
        }, filesystem_readers)
        self.assertEqual(
            ["load_release_identity"],
            sorted(name for name in reachable
                   if "_read_bounded_regular_text" in graph.get(name, set())),
        )
        self.assertEqual(1, sum(
            called_name(call) == "read_devices"
            for call in structural_calls(cycle)
        ))

    def test_all_native_monitor_stop_entrypoints_bind_to_canonical_authority(self) -> None:
        """No legacy stop implementation may retain independent PID authority."""
        canonical = function_node(
            "tools/ztp_service_runtime.py", "stop_native_ztp_monitors",
        )
        self.assertIn("_read_native_monitor_process", call_names(canonical))

        embedded = function_node(
            "tools/deployment_prewrite_guard.py", "stop_native_ztp_monitors",
        )
        self.assertIn("_native_monitor_process", call_names(embedded))

        load_stop = function_node(
            "DAY0-Prepare/11-load.py", "stop_other_ztp_monitors",
        )
        unload_stop = function_node("DAY0-Prepare/13-unload.py", "stop_monitor")
        self.assertIn("stop_native_ztp_monitors", call_names(load_stop))
        self.assertIn("stop_native_ztp_monitors", call_names(unload_stop))

    def test_governed_writers_are_derived_from_real_mutation_sinks(self) -> None:
        """W-1 walks from governed mutations, never from existing stop callers."""
        # Each row names a real production mutation sink and the supported
        # entry that can reach it.  QUIESCE rows form the W-2 contract set;
        # DELEGATED rows are already enclosed by that entry, and EXEMPT is
        # justified by an independent no-overwrite behavior test below.
        sinks = (
            ("DAY0-Prepare/01-a-setup.py", "_make_exact_link", "replace", "binding", "QUIESCE"),
            ("DAY0-Prepare/02-unsetup.py", "_main_locked", "remove", "binding", "QUIESCE"),
            ("DAY0-Prepare/11-load.py", "commit_prepared_release", "replace", "release", "QUIESCE"),
            ("DAY0-Prepare/13-unload.py", "remove_project_links", "run", "binding", "QUIESCE"),
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                "append_air_records_to_csv", "replace", "inventory", "QUIESCE",
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                "generate_air_json", "replace", "air-json", "QUIESCE",
            ),
            ("tools/password-update.py", "update_global_file", "_atomic_replace", "global", "QUIESCE"),
            ("ztp/optimize/feedback.py", "write_global_yaml", "stage", "global", "QUIESCE"),
            (
                "tools/deployment_prewrite_guard.py", "_promote_staged_member",
                "replace", "all", "QUIESCE",
            ),
            ("infra/docker/hostctl.py", "transactional_load", "run_child", "all", "DOCKER-QUIESCE"),
            ("infra/docker/hostctl.py", "transactional_unload", "run_child", "binding", "DOCKER-QUIESCE"),
            ("tools/import-from-download.py", "merge_entry", "copy2", "all", "EXEMPT-MERGE-NEW"),
        )
        for relative, function_name, primitive, _authority, _classification in sinks:
            with self.subTest(script=relative, sink=function_name):
                function = function_node(relative, function_name)
                self.assertIn(primitive, call_names(function))

        native_entries = {
            "DAY0-Prepare/01-a-setup.py": ("_main_locked", None),
            "DAY0-Prepare/02-unsetup.py": ("main", None),
            "DAY0-Prepare/11-load.py": ("main", None),
            "DAY0-Prepare/13-unload.py": ("main", {"stop_monitor"}),
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py": ("main", None),
            "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py": ("main", None),
            "tools/password-update.py": ("rotate_project_passwords", None),
            "ztp/optimize/feedback.py": ("main", None),
            "tools/deployment_prewrite_guard.py": (
                "run_locked_archive", {"quiesce_for_source_update"},
            ),
        }
        production_trees = {}
        repository_summaries = {}
        for source in ROOT.rglob("*.py"):
            relative_path = source.relative_to(ROOT)
            if relative_path.parts[0] in {"test_cases", ".git"}:
                continue
            tree = ast.parse(
                source.read_text(encoding="utf-8"), filename=str(relative_path),
            )
            production_trees[relative_path.as_posix()] = tree
            functions = production_functions(tree)
            for name, indices in generic_mutation_parameter_summaries(tree).items():
                if not indices:
                    continue
                parameters = _function_parameters(functions[name])
                if name in repository_summaries:
                    previous_parameters, previous_indices = repository_summaries[name]
                    if previous_parameters == parameters:
                        previous_indices.update(indices)
                    else:
                        previous_indices.update(range(len(previous_parameters)))
                else:
                    repository_summaries[name] = (parameters, set(indices))

        for relative, tree in production_trees.items():
            relative_path = Path(relative)
            discovered = literal_governed_mutation_sinks(tree)
            external_hits = governed_external_sink_calls(
                tree, repository_summaries,
            )
            if not discovered and not external_hits:
                continue
            self.assertIn(
                relative, native_entries,
                f"unclassified governed mutation sink in {relative_path}: "
                f"local={discovered}, imported={external_hits}",
            )
            entry, stop_names = native_entries[relative]
            graph = local_call_graph(tree)
            forward = {entry}
            changed = True
            while changed:
                changed = False
                for caller in tuple(forward):
                    for callee in graph.get(caller, set()):
                        if callee not in forward:
                            forward.add(callee)
                            changed = True
            self.assertEqual(
                set(), (discovered | {caller for caller, _callee in external_hits}) - forward,
                f"governed sink is not owned by supported entry {relative}:{entry}",
            )
            assert_quiesce_structurally_precedes_reachable_sink(
                self, tree, entry,
                discovered | {callee for _caller, callee in external_hits},
                stop_names=stop_names,
            )

        self.assertEqual(
            {
                "DAY0-Prepare/01-a-setup.py",
                "DAY0-Prepare/02-unsetup.py",
                "DAY0-Prepare/11-load.py",
                "DAY0-Prepare/13-unload.py",
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                "tools/password-update.py",
                "ztp/optimize/feedback.py",
                "tools/deployment_prewrite_guard.py",
            },
            {relative for relative, *_rest, classification in sinks
             if classification == "QUIESCE"},
        )

    def test_import_merge_new_exemption_never_overwrites_governed_authority(self) -> None:
        importer = load_module(
            "mwq_import_merge_new", "tools/import-from-download.py",
        )
        authorities = (
            "01-global.yaml", "02-devices_config.csv", "p2p-air.json",
            "99-output-ztp/current-release.json",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "review"
            destination = root / "active"
            report = {
                "added": [], "identical": [], "conflicts": [], "errors": [],
            }
            for name in authorities:
                source_path = source / name
                destination_path = destination / name
                source_path.parent.mkdir(parents=True, exist_ok=True)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_bytes(b"archive")
                destination_path.write_bytes(b"active-authority")
                importer.merge_entry(
                    source_path, destination_path, name, report, {}, name,
                )
                self.assertEqual(b"active-authority", destination_path.read_bytes())
            self.assertEqual(list(authorities), report["conflicts"])

    def test_load_and_unload_native_stop_delegate_runtime_fail_closed(self) -> None:
        load = load_module("mwq_load_stop_delegate", "DAY0-Prepare/11-load.py")
        unload = load_module("mwq_unload_stop_delegate", "DAY0-Prepare/13-unload.py")
        project = ROOT / "DAY0-Prepare/customer"
        with mock.patch.object(
            load, "stop_native_ztp_monitors", return_value=(41, 42),
        ) as stop:
            self.assertEqual([41, 42], load.stop_other_ztp_monitors(project))
            stop.assert_called_once_with(load.HTTP_ROOT)

        runtime_error = unload.RuntimeContractError("unsafe PID authority")
        with mock.patch.object(
            unload, "stop_native_ztp_monitors", side_effect=runtime_error,
            create=True,
        ) as stop:
            with self.assertRaises(unload.UnloadError):
                unload.stop_monitor(
                    project, dry_run=False,
                    runtime_backend=SimpleNamespace(name="native"),
                )
            stop.assert_called_once_with(unload.HTTP_ROOT)

    def test_governed_resolver_return_taint_reaches_realistic_writer_sink(self) -> None:
        """A governed path returned by a resolver remains governed at its caller."""
        tree = ast.parse(
            "DAY0 = Path('/srv/http/DAY0-Prepare')\n"
            "def resolve_inventory_file(project):\n"
            "    return (DAY0 / project / '02-devices_config.csv').resolve(strict=True)\n"
            "def resolve_inventory_alias(project):\n"
            "    return resolve_inventory_file(project)\n"
            "def _atomic_commit(destination, payload):\n"
            "    with open(destination, 'wb') as stream:\n"
            "        stream.write(payload)\n"
            "def rewrite_inventory(project, payload):\n"
            "    target = resolve_inventory_alias(project)\n"
            "    _atomic_commit(target, payload)\n"
        )

        self.assertEqual(
            {"_atomic_commit", "rewrite_inventory"},
            literal_governed_mutation_sinks(tree),
        )

        short_direct = ast.parse(
            "BASE = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
            "def publish_direct():\n"
            "    p = BASE\n"
            "    p.write_text('updated', encoding='utf-8')\n"
        )
        with self.subTest(flow="short-local-name"):
            self.assertEqual(
                {"publish_direct"},
                literal_governed_mutation_sinks(short_direct),
            )

        short_resolver = ast.parse(
            "BASE = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
            "def resolve_short():\n"
            "    x = BASE\n"
            "    return x\n"
            "def publish_short():\n"
            "    y = resolve_short()\n"
            "    y.write_text('updated', encoding='utf-8')\n"
        )
        with self.subTest(flow="resolver-short-local-names"):
            self.assertEqual(
                {"publish_short"},
                literal_governed_mutation_sinks(short_resolver),
            )

        descriptor_flow = ast.parse(
            "AUTHORITY = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
            "def read_only():\n"
            "    p = AUTHORITY\n"
            "    fd = os.open(p, os.O_RDONLY)\n"
            "    return os.read(fd, 1)\n"
            "def write_through_read_descriptor(payload):\n"
            "    p = AUTHORITY\n"
            "    fd = os.open(p, os.O_RDONLY)\n"
            "    os.write(fd, payload)\n"
        )
        with self.subTest(flow="read-open-then-write-descriptor"):
            self.assertEqual(
                {"write_through_read_descriptor"},
                literal_governed_mutation_sinks(descriptor_flow),
            )

        short_generic = ast.parse(
            "BASE = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
            "def commit(z):\n"
            "    z.write_text('updated', encoding='utf-8')\n"
            "def publish():\n"
            "    p = BASE\n"
            "    commit(p)\n"
        )
        with self.subTest(flow="cross-local-generic-short-names"):
            self.assertEqual(
                {"commit", "publish"},
                literal_governed_mutation_sinks(short_generic),
            )

        loop_generic = ast.parse(
            "BASE = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
            "def commit(z):\n"
            "    z.write_text('updated', encoding='utf-8')\n"
            "def publish():\n"
            "    for p in (BASE,):\n"
            "        commit(p)\n"
            "def observe_only():\n"
            "    items = []\n"
            "    items.append(BASE)\n"
            "    return len(items)\n"
        )
        with self.subTest(flow="loop-target-cross-local-generic"):
            self.assertEqual(
                {"commit", "publish"},
                literal_governed_mutation_sinks(loop_generic),
            )

    def test_mutation_destination_covers_supported_file_mutation_apis(self) -> None:
        """Every supported write API identifies its actual destination expression."""
        cases = (
            ("open(destination, mode='w')", "destination"),
            ("open(file=destination, mode='a')", "destination"),
            ("open(destination, mode)", "destination"),
            ("destination.open('wb')", "destination"),
            ("destination.open(mode='x')", "destination"),
            ("destination.open(mode)", "destination"),
            (
                "os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC)",
                "destination",
            ),
            (
                "os.open(path=destination, flags=os.O_RDWR | os.O_CLOEXEC)",
                "destination",
            ),
            ("os.open(destination, flags)", "destination"),
            ("os.write(descriptor, payload)", "descriptor"),
            ("os.write(fd=descriptor, data=payload)", "descriptor"),
            ("source.replace(destination)", "destination"),
            ("source.replace(target=destination)", "destination"),
            ("source.rename(destination)", "destination"),
            ("source.rename(target=destination)", "destination"),
            ("os.replace(src=source, dst=destination)", "destination"),
            ("os.replace(source, dst=destination)", "destination"),
            ("os.rename(src=source, dst=destination)", "destination"),
            ("shutil.copytree(source, destination)", "destination"),
            ("shutil.copytree(src=source, dst=destination)", "destination"),
            ("shutil.copy(source, destination)", "destination"),
            ("shutil.copy(src=source, dst=destination)", "destination"),
            ("shutil.copy(source, dst=destination)", "destination"),
            ("shutil.copy2(source, destination)", "destination"),
            ("shutil.copy2(src=source, dst=destination)", "destination"),
            ("shutil.copyfile(source, destination)", "destination"),
            ("shutil.copyfile(src=source, dst=destination)", "destination"),
            ("shutil.move(source, destination)", "destination"),
            ("shutil.move(src=source, dst=destination)", "destination"),
            ("os.renames(source, destination)", "destination"),
            ("os.renames(old=source, new=destination)", "destination"),
            ("os.truncate(destination, 0)", "destination"),
            ("os.truncate(path=destination, length=0)", "destination"),
            ("os.remove(path=destination)", "destination"),
            ("os.unlink(path=destination)", "destination"),
            ("os.link(src=source, dst=destination)", "destination"),
            ("os.symlink(src=source, dst=destination)", "destination"),
            (
                "os.open(destination, os.O_RDONLY | os.O_CREAT | os.O_CLOEXEC)",
                "destination",
            ),
            ("os.open(destination, os.O_RDONLY | os.O_CLOEXEC)", None),
            (
                "os.open(path=destination, flags=os.O_RDONLY | os.O_CLOEXEC)",
                None,
            ),
            ("open(destination, 'rb')", None),
            ("open(file=destination, mode='r')", None),
            ("open(destination)", None),
            ("destination.open('rb')", None),
            ("destination.open(mode='r')", None),
            ("destination.open()", None),
        )
        for expression, expected in cases:
            with self.subTest(expression=expression):
                call = ast.parse(expression, mode="eval").body
                self.assertIsInstance(call, ast.Call)
                destination = _mutation_destination(call)
                self.assertEqual(
                    expected,
                    None if destination is None else ast.unparse(destination),
                )

    def test_mutation_function_aliases_preserve_governed_destination_taint(self) -> None:
        """Imported and assigned aliases cannot disguise a mutation primitive."""
        modules = (
            (
                "imported-alias",
                "from os import replace as commit\n"
                "def publish(temporary):\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    commit(temporary, destination)\n",
            ),
            (
                "assigned-alias",
                "commit = os.replace\n"
                "def publish(temporary):\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    commit(temporary, destination)\n",
            ),
            (
                "module-import-alias",
                "import os as operating_system\n"
                "def publish():\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    operating_system.remove(destination)\n",
            ),
            (
                "imported-remove-alias",
                "from os import remove as erase\n"
                "def publish():\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    erase(destination)\n",
            ),
            (
                "function-local-alias",
                "def publish(temporary):\n"
                "    commit = os.replace\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    commit(temporary, destination)\n",
            ),
            (
                "function-local-two-hop-alias",
                "def publish(temporary):\n"
                "    commit = os.replace\n"
                "    publish_mutation = commit\n"
                "    destination = Path('/srv/http/DAY0-Prepare/customer/01-global.yaml')\n"
                "    publish_mutation(temporary, destination)\n",
            ),
        )
        for name, source in modules:
            with self.subTest(alias=name):
                self.assertEqual(
                    {"publish"},
                    literal_governed_mutation_sinks(ast.parse(source)),
                )

    def test_all_nine_declared_native_writers_are_mechanically_discovered(self) -> None:
        """Hand-maintained entry tables may classify discovery, never replace it."""
        writers = (
            "DAY0-Prepare/01-a-setup.py",
            "DAY0-Prepare/02-unsetup.py",
            "DAY0-Prepare/11-load.py",
            "DAY0-Prepare/13-unload.py",
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
            "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
            "tools/password-update.py",
            "ztp/optimize/feedback.py",
            "tools/deployment_prewrite_guard.py",
        )
        # A future intrinsically undiscoverable writer must be listed here
        # with a literal, operator-reviewable reason rather than disappearing
        # behind the hand-maintained entry table.
        discovery_exceptions: dict[str, str] = {}
        mechanically_discovered = set()
        for relative in writers:
            tree = ast.parse(
                (ROOT / relative).read_text(encoding="utf-8"),
                filename=relative,
            )
            if literal_governed_mutation_sinks(tree):
                mechanically_discovered.add(relative)
                continue
            with self.subTest(writer=relative):
                self.assertIn(
                    relative,
                    discovery_exceptions,
                    "declared writer escaped mechanical discovery without a "
                    "literal exception reason",
                )
                self.assertGreaterEqual(
                    len(discovery_exceptions[relative].strip()), 24,
                )
        self.assertEqual(
            len(writers) - len(discovery_exceptions),
            len(mechanically_discovered),
            f"mechanical governed-writer discovery regressed: "
            f"{len(mechanically_discovered)}/{len(writers)}",
        )

    def test_quiesce_oracle_rejects_swallowed_and_suppressed_stop_failures(self) -> None:
        """A stop whose failure is swallowed cannot dominate a later mutation."""
        bodies = (
            (
                "try-swallowed",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "    except Exception:\n"
                "        pass\n",
            ),
            (
                "contextlib-suppress",
                "    with contextlib.suppress(Exception):\n"
                "        stop_native_ztp_monitors()\n",
            ),
            (
                "imported-suppress-alias",
                "    with silence(Exception):\n"
                "        stop_native_ztp_monitors()\n",
            ),
            (
                "assigned-suppress-alias",
                "    with silence(Exception):\n"
                "        stop_native_ztp_monitors()\n",
            ),
            (
                "bare-except-return",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "    except:\n"
                "        return\n",
            ),
            (
                "base-exception-return",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "    except BaseException:\n"
                "        return\n",
            ),
            (
                "local-assigned-suppress-alias",
                "    silence = contextlib.suppress\n"
                "    with silence(Exception):\n"
                "        stop_native_ztp_monitors()\n",
            ),
            (
                "try-inner-and-post-write-swallowed",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "        write_authority()\n"
                "    except Exception:\n"
                "        pass\n",
            ),
            (
                "nested-live-guard-try-inner-and-post-write-swallowed",
                "    if not dry_run:\n"
                "        try:\n"
                "            stop_native_ztp_monitors()\n"
                "            write_authority()\n"
                "        except Exception:\n"
                "            pass\n"
                "        write_authority()\n",
            ),
            (
                "nested-live-guard-swallowed-with-ancestor-successor",
                "    if not dry_run:\n"
                "        try:\n"
                "            stop_native_ztp_monitors()\n"
                "            write_authority()\n"
                "        except Exception:\n"
                "            pass\n"
                "    write_authority()\n",
            ),
            (
                "logger-error-helper-does-not-terminate",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "        write_authority()\n"
                "    except Exception:\n"
                "        report_error()\n",
            ),
            (
                "parser-error-helper-with-early-return-does-not-terminate",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "        write_authority()\n"
                "    except Exception:\n"
                "        maybe_parser_error(parser, skip)\n",
            ),
            (
                "parser-error-helper-receiver-is-not-argparse-parser",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "        write_authority()\n"
                "    except Exception:\n"
                "        fatal(logger)\n",
            ),
            (
                "renamed-parser-error-helper-receiver-is-logger",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "        write_authority()\n"
                "    except Exception:\n"
                "        renamed_fatal(logger)\n",
            ),
        )
        for name, body in bodies:
            with self.subTest(guard=name):
                imports = (
                    "from contextlib import suppress as silence\n"
                    if name == "imported-suppress-alias"
                    else "silence = contextlib.suppress\n"
                    if name == "assigned-suppress-alias" else ""
                )
                support = (
                    "def report_error():\n"
                    "    logger.error('failed')\n"
                    if name == "logger-error-helper-does-not-terminate"
                    else "def maybe_parser_error(parser, skip):\n"
                    "    if skip:\n"
                    "        return\n"
                    "    parser.error('fatal')\n"
                    if name == "parser-error-helper-with-early-return-does-not-terminate"
                    else "def fatal(parser):\n"
                    "    parser.error('fatal')\n"
                    if name == "parser-error-helper-receiver-is-not-argparse-parser"
                    else "def renamed_fatal(receiver):\n"
                    "    receiver.error('fatal')\n"
                    if name == "renamed-parser-error-helper-receiver-is-logger"
                    else ""
                )
                tree = ast.parse(
                    imports
                    + support
                    + "def write_authority():\n"
                    "    pass\n"
                    "def main():\n"
                    + body
                    + "    write_authority()\n"
                )
                with self.assertRaises(
                    AssertionError,
                    msg=f"quiesce oracle accepted {name} stop failure suppression",
                ):
                    assert_quiesce_structurally_precedes_reachable_sink(
                        self, tree, "main", {"write_authority"},
                    )

        propagating_bodies = (
            (
                "except-reraises",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "    except Exception:\n"
                "        raise\n",
            ),
            (
                "try-finally-propagates",
                "    try:\n"
                "        stop_native_ztp_monitors()\n"
                "    finally:\n"
                "        record_attempt()\n",
            ),
        )
        for name, body in propagating_bodies:
            with self.subTest(allowed_guard=name):
                tree = ast.parse(
                    "def write_authority():\n"
                    "    pass\n"
                    "def record_attempt():\n"
                    "    pass\n"
                    "def main():\n"
                    + body
                    + "    write_authority()\n"
                )
                assert_quiesce_structurally_precedes_reachable_sink(
                    self, tree, "main", {"write_authority"},
                )

        parser_terminal_bodies = (
            (
                "direct-argparse-error",
                "",
                "        parser.error('fatal')\n",
            ),
            (
                "bounded-argparse-error-helper",
                "def _bounded_parser_error(parser):\n"
                "    parser.error('fatal')\n",
                "        _bounded_parser_error(parser)\n",
            ),
            (
                "two-hop-argparse-error-helper",
                "def fatal2(parser):\n"
                "    parser.error('fatal')\n"
                "def fatal1(parser):\n"
                "    fatal2(parser)\n",
                "        fatal1(parser)\n",
            ),
            (
                "renamed-argparse-error-helper-positional",
                "def renamed_fatal(receiver):\n"
                "    receiver.error('fatal')\n",
                "        renamed_fatal(parser)\n",
            ),
            (
                "renamed-argparse-error-helper-keyword",
                "def renamed_fatal(receiver):\n"
                "    receiver.error('fatal')\n",
                "        renamed_fatal(receiver=parser)\n",
            ),
            (
                "renamed-two-hop-kwonly-argparse-error-helper",
                "def final_fatal(*, sink):\n"
                "    sink.error('fatal')\n"
                "def forward_fatal(receiver):\n"
                "    final_fatal(sink=receiver)\n",
                "        forward_fatal(parser)\n",
            ),
        )
        for name, support, handler_body in parser_terminal_bodies:
            with self.subTest(allowed_guard=name):
                tree = ast.parse(
                    support
                    + "def write_authority():\n"
                    "    pass\n"
                    "def main(parser):\n"
                    "    try:\n"
                    "        stop_native_ztp_monitors()\n"
                    "    except Exception:\n"
                    + handler_body
                    + "    write_authority()\n"
                )
                assert_quiesce_structurally_precedes_reachable_sink(
                    self, tree, "main", {"write_authority"},
                )

    def test_writer_quiesce_oracle_rejects_order_reversal_mutation(self) -> None:
        """W-2 is order-sensitive, not merely a coexistence/name check."""
        contracts = (
            ("DAY0-Prepare/01-a-setup.py", "_main_locked", "setup"),
            ("DAY0-Prepare/02-unsetup.py", "main", "_main_locked"),
            ("DAY0-Prepare/11-load.py", "quiesce_services", "run"),
            ("DAY0-Prepare/11-load.py", "main", "initialize_from_template"),
            ("DAY0-Prepare/13-unload.py", "main", "remove_project_links"),
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
                "main", "append_air_records_to_csv",
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
                "main", "generate_air_json",
            ),
            ("tools/password-update.py", "rotate_project_passwords", "update_global_file"),
            ("ztp/optimize/feedback.py", "main", "recover_global_writeback_state"),
            (
                "tools/deployment_prewrite_guard.py",
                "quiesce_for_source_update", "write_deployment_owner",
            ),
        )

        def call_lines(function, name):
            result = []
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func
                called_name = called.id if isinstance(called, ast.Name) else (
                    called.attr if isinstance(called, ast.Attribute) else None
                )
                if called_name == name:
                    result.append(node.lineno)
            if not result:
                raise AssertionError(f"{function.name} does not call {name}")
            return sorted(result)

        def assert_order(function):
            stop_name = (
                "stop_monitor"
                if relative == "DAY0-Prepare/13-unload.py"
                else "stop_native_ztp_monitors"
            )
            self.assertLess(
                first_call_line(function, stop_name),
                # password-update's inherited-lock branch deliberately reuses
                # the parent's quiescence; its standalone branch is the last
                # update_global_file call and owns the direct stop.
                max(call_lines(function, writer))
                if relative == "tools/password-update.py"
                else first_call_line(function, writer),
            )

        for relative, function_name, writer in contracts:
            with self.subTest(script=relative, function=function_name):
                original = function_node(relative, function_name)
                assert_order(original)
                mutated = copy.deepcopy(original)
                writer_line = (
                    max(call_lines(mutated, writer))
                    if relative == "tools/password-update.py"
                    else first_call_line(mutated, writer)
                )
                stop_name = (
                    "stop_monitor"
                    if relative == "DAY0-Prepare/13-unload.py"
                    else "stop_native_ztp_monitors"
                )
                for node in ast.walk(mutated):
                    if not isinstance(node, ast.Call):
                        continue
                    called = node.func
                    name = called.id if isinstance(called, ast.Name) else (
                        called.attr if isinstance(called, ast.Attribute) else None
                    )
                    if name == stop_name:
                        node.lineno = writer_line + 1
                with self.assertRaises(
                    AssertionError,
                    msg="order oracle accepted quiesce moved after first mutation",
                ):
                    assert_order(mutated)

    def test_reverse_sink_closure_rejects_covert_writer_and_real_reordering(self) -> None:
        """Hostile additions and actual AST statement moves must trip one oracle."""
        source = ROOT / "DAY0-Prepare/01-a-setup.py"
        original = ast.parse(source.read_text(encoding="utf-8"))
        known_sinks = {"_make_exact_link"} | literal_governed_mutation_sinks(original)
        assert_quiesce_structurally_precedes_reachable_sink(
            self, original, "_main_locked", known_sinks,
        )

        mutated = copy.deepcopy(original)
        covert = ast.parse(
            "def covert_writer(destination, temporary):\n"
            "    authority = Path(destination).parent / '01-global.yaml'\n"
            "    alias = authority\n"
            "    os.replace(temporary, alias)\n"
        ).body[0]
        mutated.body.append(covert)
        discovered = literal_governed_mutation_sinks(mutated)
        self.assertIn("covert_writer", discovered)

        injected = ast.Expr(value=ast.Call(
            func=ast.Name(id="covert_writer", ctx=ast.Load()),
            args=[],
            keywords=[
                ast.keyword(
                    arg="destination",
                    value=ast.BinOp(
                        left=ast.Name(id="proj_dir", ctx=ast.Load()),
                        op=ast.Div(), right=ast.Constant(value="01-global.yaml"),
                    ),
                ),
                ast.keyword(arg="temporary", value=ast.Constant(value="temporary")),
            ],
        ))

        def insert_before_real_stop(node):
            for _field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for index, child in enumerate(value):
                        if isinstance(child, ast.stmt) and any(
                            called_name(call) == "stop_native_ztp_monitors"
                            for call in structural_calls(child)
                        ):
                            value.insert(index, injected)
                            return True
                        if isinstance(child, ast.AST) and insert_before_real_stop(child):
                            return True
                elif isinstance(value, ast.AST) and insert_before_real_stop(value):
                    return True
            return False

        entry = production_functions(mutated)["_main_locked"]
        self.assertTrue(insert_before_real_stop(entry))
        with self.assertRaises(
            AssertionError,
            msg="reverse closure accepted a real pre-stop covert writer statement",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, mutated, "_main_locked", known_sinks | discovered,
            )

        delegated_tree = ast.parse(
            "def delegated_writer(destination, *, temporary):\n"
            "    alias = destination\n"
            "    os.replace(temporary, alias)\n"
        )
        delegated_function = production_functions(delegated_tree)["delegated_writer"]
        repository_summaries = {
            "delegated_writer": (
                _function_parameters(delegated_function),
                generic_mutation_parameter_summaries(delegated_tree)[
                    "delegated_writer"
                ],
            ),
        }
        cross_module = copy.deepcopy(original)
        cross_module.body.insert(0, ast.ImportFrom(
            module="mwq_delegated_writer", level=0,
            names=[ast.alias(name="delegated_writer", asname="publish")],
        ))
        self.assertTrue(insert_before_real_stop(
            production_functions(cross_module)["_main_locked"]
        ))
        # Replace the just-inserted local call with the external helper name.
        entry_calls = structural_calls(
            production_functions(cross_module)["_main_locked"]
        )
        next(call for call in entry_calls if called_name(call) == "covert_writer").func.id = "publish"
        dead_fake_stop = ast.If(
            test=ast.Constant(value=0),
            body=[ast.Expr(value=ast.Call(
                func=ast.Name(id="stop_native_ztp_monitors", ctx=ast.Load()),
                args=[ast.Name(id="HTTP_BASE", ctx=ast.Load())], keywords=[],
            ))],
            orelse=[],
        )

        def insert_before_publish(node):
            for _field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for index, child in enumerate(value):
                        if isinstance(child, ast.stmt) and any(
                            called_name(call) == "publish"
                            for call in structural_calls(child)
                        ):
                            value.insert(index, dead_fake_stop)
                            return True
                        if isinstance(child, ast.AST) and insert_before_publish(child):
                            return True
                elif isinstance(value, ast.AST) and insert_before_publish(value):
                    return True
            return False

        self.assertTrue(insert_before_publish(
            production_functions(cross_module)["_main_locked"]
        ))
        hits = governed_external_sink_calls(cross_module, repository_summaries)
        self.assertIn(("_main_locked", "publish"), hits)
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted a pre-stop cross-module sink",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, cross_module, "_main_locked", {"publish"},
            )

        dead_only = copy.deepcopy(cross_module)

        def remove_live_stop(node):
            for _field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    kept = []
                    for child in value:
                        is_dead_fixture = (
                            isinstance(child, ast.If)
                            and ast.unparse(child.test) == "0"
                        )
                        contains_stop = isinstance(child, ast.stmt) and any(
                            called_name(call) == "stop_native_ztp_monitors"
                            for call in ast.walk(child) if isinstance(call, ast.Call)
                        )
                        if contains_stop and not is_dead_fixture:
                            continue
                        if isinstance(child, ast.AST):
                            remove_live_stop(child)
                        kept.append(child)
                    value[:] = kept
                elif isinstance(value, ast.AST):
                    remove_live_stop(value)

        remove_live_stop(production_functions(dead_only)["_main_locked"])
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted a dead-only conditional stop",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, dead_only, "_main_locked", {"publish"},
            )
        dead_while = ast.parse(
            "def _main_locked(proj_dir):\n"
            "    while False:\n"
            "        stop_native_ztp_monitors(HTTP_BASE)\n"
            "    publish(proj_dir / '01-global.yaml', temporary='temporary')\n"
        )
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted a dead-only while stop",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, dead_while, "_main_locked", {"publish"},
            )
        exception_only = ast.parse(
            "def _main_locked(proj_dir):\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        stop_native_ztp_monitors(HTTP_BASE)\n"
            "    publish(proj_dir / '01-global.yaml', temporary='temporary')\n"
        )
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted an exception-only stop",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, exception_only, "_main_locked", {"publish"},
            )
        inverted_dry_run = ast.parse(
            "def _main_locked(proj_dir):\n"
            "    if _DRY_RUN:\n"
            "        stop_native_ztp_monitors(HTTP_BASE)\n"
            "    publish(proj_dir / '01-global.yaml', temporary='temporary')\n"
        )
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted an inverted dry-run guard",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, inverted_dry_run, "_main_locked", {"publish"},
            )
        false_conjunct = ast.parse(
            "def _main_locked(proj_dir):\n"
            "    if not _DRY_RUN and NEVER_STOP:\n"
            "        stop_native_ztp_monitors(HTTP_BASE)\n"
            "    publish(proj_dir / '01-global.yaml', temporary='temporary')\n"
        )
        with self.assertRaises(
            AssertionError,
            msg="repository oracle accepted an extra false stop conjunct",
        ):
            assert_quiesce_structurally_precedes_reachable_sink(
                self, false_conjunct, "_main_locked", {"publish"},
            )

    def test_sink_reverse_closure_is_quiesced_at_each_supported_native_entry(self) -> None:
        contracts = (
            ("DAY0-Prepare/01-a-setup.py", "_main_locked", {"_make_exact_link"}, None),
            ("DAY0-Prepare/02-unsetup.py", "main", {"_main_locked"}, None),
            ("DAY0-Prepare/11-load.py", "main", {"commit_prepared_release"}, None),
            (
                "DAY0-Prepare/13-unload.py", "main", {"remove_project_links"},
                {"stop_monitor"},
            ),
            (
                "ztp/config/isc-dhcp-server/c1-generate_dhcp.py", "main",
                {"append_air_records_to_csv"}, None,
            ),
            (
                "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py", "main",
                {"generate_air_json"}, None,
            ),
            (
                "ztp/optimize/feedback.py", "main",
                {"write_global_yaml", "recover_global_writeback_state"}, None,
            ),
            (
                "tools/deployment_prewrite_guard.py", "run_locked_archive",
                {"_apply_prepared_archive_overlay"}, {"quiesce_for_source_update"},
            ),
        )
        for relative, entry, sinks, stop_names in contracts:
            with self.subTest(script=relative, entry=entry):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                assert_quiesce_structurally_precedes_reachable_sink(
                    self, tree, entry,
                    sinks | literal_governed_mutation_sinks(tree),
                    stop_names=stop_names,
                )

        password = function_node(
            "tools/password-update.py", "rotate_project_passwords",
        )
        locked = deployment_lock_scope(password)
        locked_calls = structural_calls(locked)
        self.assertLess(
            next(index for index, call in enumerate(locked_calls)
                 if called_name(call) == "stop_native_ztp_monitors"),
            next(index for index, call in enumerate(locked_calls)
                 if called_name(call) == "update_global_file"),
        )
        inherited = next(
            node for node in ast.walk(password)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "lock_already_held"
        )
        self.assertIn("update_global_file", call_names(inherited))


if __name__ == "__main__":
    unittest.main()
