"""Explicit profile authority inputs for tests unrelated to P2P inference.

Callers supply literal modes, never derive them from connected lane indices.
The real file consumer validates this independently constructed schema fixture.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import mock


def write_splitter_fixture(p2p, profiles):
    p2p = Path(p2p)
    p2p.mkdir(parents=True, exist_ok=True)
    output = p2p / "output-p2p"
    output.mkdir(exist_ok=True)
    payloads = {
        "workbook_sha256": (p2p / "p2p.xlsx", b"independent profile workbook fixture\n"),
        "inventory_sha256": (p2p / "01-inventory.log", b"[Eth-SW]\n*\n"),
        "port_mapping_sha256": (p2p / "02-port-mapping.log", b"explicit profile fixture\n"),
        "lldpq_sha256": (output / "p2p-lldpq.dot", b'graph "fixture" {}\n'),
    }
    hashes = {}
    for key, (path, data) in payloads.items():
        path.write_bytes(data)
        hashes[key] = hashlib.sha256(data).hexdigest()
    document = dict(schema_version=1, source_workbook="p2p.xlsx", profiles=[
        dict(device=host, parent=parent, profile=profile)
        for host, parents in profiles.items() for parent, profile in parents.items()
    ], **hashes)
    (output / "p2p-splitter-profiles.json").write_text(json.dumps(document))
    return dict(P2P_INPUT_DIR=str(p2p), P2P_OUTPUT_DIR=str(output))


@contextmanager
def splitter_fixture(module, profiles):
    with tempfile.TemporaryDirectory() as directory:
        with mock.patch.multiple(module, **write_splitter_fixture(Path(directory), profiles)):
            yield
