#!/usr/bin/env python3
"""Native confirmation and real Docker-wrapper dispatch workflow contracts."""

from __future__ import annotations

import argparse
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.test_docker_destructive_confirmation import (
    CONTAINER_ID,
    EXPECTED_FACTS,
    mutation_events,
    run_dispatch,
)


ROOT = Path(__file__).resolve().parents[1]


def load_unload_module():
    path = ROOT / "DAY0-Prepare/13-unload.py"
    spec = importlib.util.spec_from_file_location("h28_native_unload", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = load_unload_module()


class DestructiveConfirmationWorkflowTests(unittest.TestCase):
    def test_native_and_docker_both_require_full_yes_and_cancel_eof(self):
        arguments = argparse.Namespace(
            yes=False, dry_run=False, clear_ztp_status=False,
            teardown_infra=False,
        )
        project = ROOT / "DAY0-Prepare/h28-project"
        for label, response, expected in (
            ("yes", "yes", True),
            ("no", "no", False),
            ("uppercase", "YES", False),
            ("space-padded", " yes ", False),
            ("eof", EOFError(), False),
        ):
            input_patch = (
                mock.patch("builtins.input", side_effect=response)
                if isinstance(response, BaseException)
                else mock.patch("builtins.input", return_value=response)
            )
            with self.subTest(label=label), input_patch, mock.patch(
                "sys.stdout", new=io.StringIO(),
            ):
                self.assertEqual(expected, NATIVE.confirm(arguments, project))
            with tempfile.TemporaryDirectory() as name:
                answer = None if label == "eof" else response + "\n"
                result, events = run_dispatch(
                    Path(name), "unload", answer=answer,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(expected, bool(mutation_events(events)), events)

    def test_real_unload_dispatch_reaches_only_fake_docker_after_confirmation(self):
        with tempfile.TemporaryDirectory() as name:
            result, events = run_dispatch(
                Path(name), "unload", "--yes", answer=None,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        mutations = mutation_events(events)
        self.assertEqual(
            [
                f"wait:recover {CONTAINER_ID}",
                f"docker:exec {CONTAINER_ID} /opt/http-ztp/hostctl.py unload",
            ],
            mutations,
        )
        first_mutation = events.index(mutations[0])
        for fact in EXPECTED_FACTS["unload"]:
            self.assertIn(fact, result.stdout)
            self.assertLess(events.index(f"say:{fact}"), first_mutation)


if __name__ == "__main__":
    unittest.main()
