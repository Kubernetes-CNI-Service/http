#!/usr/bin/env python3
"""Recover selected switches with a fixed family-specific NVUE action.

Cumulus uses factory-default reset; NVOS safely maps this recovery request to
``nv action run system ztp force`` and never receives a Cumulus reset command.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


implementation = Path(__file__).with_name("manual-ztp.py")
spec = importlib.util.spec_from_file_location("http_manual_ztp_impl", implementation)
if spec is None or spec.loader is None:
    raise SystemExit(f"cannot load {implementation}")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

if __name__ == "__main__":
    raise SystemExit(module.main(["--operation", "reset", *sys.argv[1:]]))
