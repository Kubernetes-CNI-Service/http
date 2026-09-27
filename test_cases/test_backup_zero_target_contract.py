"""Direct fail-closed contract for an empty YAML backup target set."""

from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class BackupZeroTargetDirectTests(unittest.TestCase):
    def test_empty_deduplicated_inventory_stops_before_private_staging(self):
        target = ROOT / "ztp/backup/yaml-collect.py"
        spec = importlib.util.spec_from_file_location("backup_zero_target_direct", target)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, "path", [str(target.parent), *sys.path]):
            spec.loader.exec_module(module)

        with mock.patch.object(module, "_parse_args", return_value=(True, "prod", False, None)), \
                mock.patch.object(module, "_inventory_paths", return_value=["inventory.csv"]), \
                mock.patch.object(module, "load_devices_csv", return_value=[]), \
                mock.patch.object(module, "_resolve_backup_passwords", return_value=(None, None, None)), \
                mock.patch.object(module, "_confirm", return_value=True), \
                mock.patch.object(
                    module, "_stage_private_backup_tree",
                    side_effect=AssertionError("staged empty backup"),
                ) as stage, redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                module.main()

        self.assertNotEqual(0, stopped.exception.code)
        stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
