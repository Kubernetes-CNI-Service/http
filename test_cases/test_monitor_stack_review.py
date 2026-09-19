#!/usr/bin/env python3
"""Focused contracts for the monitor/GUI/worker and bring-up review."""

from __future__ import annotations

import ast
from contextlib import ExitStack
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
from datetime import datetime
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


CAPTURED_UNNAMED_INVENTORY = (
    "\n"
    "          HW Version     Model   Serial             State  Type  \n"
    "--------  -------------  ------  -----------------  -----  ------\n"
    "FAN1/1    N/A            N/A     N/A                ok     fan   \n"
    "FAN1/2    N/A            N/A     N/A                ok     fan   \n"
    "FAN2/1    N/A            N/A     N/A                ok     fan   \n"
    "FAN2/2    N/A            N/A     N/A                ok     fan   \n"
    "FAN3/1    N/A            N/A     N/A                ok     fan   \n"
    "FAN3/2    N/A            N/A     N/A                ok     fan   \n"
    "PSU1      N/A            N/A     N/A                ok     psu   \n"
    "PSU1/FAN  N/A            N/A     N/A                ok     fan   \n"
    "PSU2      N/A            N/A     N/A                ok     psu   \n"
    "PSU2/FAN  N/A            N/A     N/A                ok     fan   \n"
    "SWITCH    pc-i440fx-6.2  5.16.4  02:b7:b0:db:e9:20  ok     switch\n"
    "\n"
)
CAPTURED_UNNAMED_INVENTORY_SHA256 = (
    "0162f00c56b8d8c6bf56150192f2d8b4ddd2c5a3a7b06e6b86c0f19d74f052dc"
)
CAPTURED_UNNAMED_INVENTORY_EXPECTED = {
    "inventory_components": [
        {"name": "FAN1/1", "type": "fan", "state": "ok"},
        {"name": "FAN1/2", "type": "fan", "state": "ok"},
        {"name": "FAN2/1", "type": "fan", "state": "ok"},
        {"name": "FAN2/2", "type": "fan", "state": "ok"},
        {"name": "FAN3/1", "type": "fan", "state": "ok"},
        {"name": "FAN3/2", "type": "fan", "state": "ok"},
        {"name": "PSU1", "type": "psu", "state": "ok"},
        {"name": "PSU1/FAN", "type": "fan", "state": "ok"},
        {"name": "PSU2", "type": "psu", "state": "ok"},
        {"name": "PSU2/FAN", "type": "fan", "state": "ok"},
    ],
    "psu_ok": 2,
    "psu_fail": 0,
    "fan_ok": 8,
    "fan_fail": 0,
}
DEIDENTIFIED_INVENTORY_CORPUS_JSON = r"""
{
  "format": "monitor-inventory-deidentified-v2",
  "private_source_binding_sha256": "cf04b971b2a52b42340cef0fa5bb0392e1121c0dcf22462685a0309020154c34",
  "selection": {
    "count": 118,
    "excluded": "package-import mirrors are outside the root glob; no sampling",
    "glob": "DAY0-Prepare/**/99-output-monitor/**/*.info"
  },
  "profiles": [
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 8,
        "psu_fail": 0,
        "psu_ok": 2
      },
      "id": "P1",
      "section": "          HW Version     Model   Serial             State  Type  \n--------  -------------  ------  -----------------  -----  ------\nFAN1/1    N/A            N/A     N/A                ok     fan\nFAN1/2    N/A            N/A     N/A                ok     fan\nFAN2/1    N/A            N/A     N/A                ok     fan\nFAN2/2    N/A            N/A     N/A                ok     fan\nFAN3/1    N/A            N/A     N/A                ok     fan\nFAN3/2    N/A            N/A     N/A                ok     fan\nPSU1      N/A            N/A     N/A                ok     psu\nPSU1/FAN  N/A            N/A     N/A                ok     fan\nPSU2      N/A            N/A     N/A                ok     psu\nPSU2/FAN  N/A            N/A     N/A                ok     fan\nSWITCH    XXXXXXXXXXXXX  XXXXXX  XXXXXXXXXXXXXXXXX  ok     switch\n",
      "section_sha256": "971380d97a85a248c12b494a6df2efa8dfdfa47eff0e371f4948ed65f72fbe0a"
    },
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 6,
        "psu_fail": 0,
        "psu_ok": 2
      },
      "id": "P2",
      "section": "          HW Version  Model          Serial        State  Type  \n--------  ----------  -------------  ------------  -----  ------\nFAN1/1    N/A         N/A            N/A           ok     fan\nFAN2/1    N/A         N/A            N/A           ok     fan\nFAN3/1    N/A         N/A            N/A           ok     fan\nFAN4/1    N/A         N/A            N/A           ok     fan\nPSU1      XX          XXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU1/FAN  N/A         N/A            N/A           ok     fan\nPSU2      XX          XXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU2/FAN  N/A         N/A            N/A           ok     fan\nSWITCH    XX          XXXXXXXXXXXXX  XXXXXXXXXXXX  ok     switch\n",
      "section_sha256": "7db3d6751df4cefd4a87a933ee8c45b89b77eb2c3184244a7af087c5faa076f7"
    },
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 14,
        "psu_fail": 0,
        "psu_ok": 2
      },
      "id": "P3",
      "section": "          HW Version  Model          Serial                State  Type  \n--------  ----------  -------------  --------------------  -----  ------\nFAN1/1    N/A         N/A            N/A                   ok     fan\nFAN1/2    N/A         N/A            N/A                   ok     fan\nFAN2/1    N/A         N/A            N/A                   ok     fan\nFAN2/2    N/A         N/A            N/A                   ok     fan\nFAN3/1    N/A         N/A            N/A                   ok     fan\nFAN3/2    N/A         N/A            N/A                   ok     fan\nFAN4/1    N/A         N/A            N/A                   ok     fan\nFAN4/2    N/A         N/A            N/A                   ok     fan\nFAN5/1    N/A         N/A            N/A                   ok     fan\nFAN5/2    N/A         N/A            N/A                   ok     fan\nFAN6/1    N/A         N/A            N/A                   ok     fan\nFAN6/2    N/A         N/A            N/A                   ok     fan\nPSU1      XX          XXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU1/FAN  N/A         N/A            N/A                   ok     fan\nPSU2      XX          XXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU2/FAN  N/A         N/A            N/A                   ok     fan\nSWITCH    XX          XXXXXX         XXXXXXXXXXXXXXXXXXXX  ok     switch\n",
      "section_sha256": "c527d2759de7f1a48e51ef82db4f28b3e438623667e7a648304302611f7d5960"
    },
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 14,
        "psu_fail": 0,
        "psu_ok": 4
      },
      "id": "P4",
      "section": "          HW Version  Model               Serial                State  Type  \n--------  ----------  ------------------  --------------------  -----  ------\nFAN1/1    N/A         N/A                 N/A                   ok     fan\nFAN1/2    N/A         N/A                 N/A                   ok     fan\nFAN2/1    N/A         N/A                 N/A                   ok     fan\nFAN2/2    N/A         N/A                 N/A                   ok     fan\nFAN3/1    N/A         N/A                 N/A                   ok     fan\nFAN3/2    N/A         N/A                 N/A                   ok     fan\nFAN4/1    N/A         N/A                 N/A                   ok     fan\nFAN4/2    N/A         N/A                 N/A                   ok     fan\nFAN5/1    N/A         N/A                 N/A                   ok     fan\nFAN5/2    N/A         N/A                 N/A                   ok     fan\nPSU1      XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU1/FAN  N/A         N/A                 N/A                   ok     fan\nPSU2      XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU2/FAN  N/A         N/A                 N/A                   ok     fan\nPSU3      XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU3/FAN  N/A         N/A                 N/A                   ok     fan\nPSU4      XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX          ok     psu\nPSU4/FAN  N/A         N/A                 N/A                   ok     fan\nSWITCH    XX          XXXXXX              XXXXXXXXXXXXXXXXXXXX  ok     switch\n",
      "section_sha256": "263637a571be8fa67449047e9d4eeca1ba855ff0b95a139628cfc9540dfd6c6b"
    },
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 4,
        "psu_fail": 2,
        "psu_ok": 0
      },
      "id": "P5",
      "section": "        HW Version  Model          Serial        State  Type  \n------  ----------  -------------  ------------  -----  ------\nFAN1/1  N/A         N/A            N/A           ok     fan\nFAN2/1  N/A         N/A            N/A           ok     fan\nFAN3/1  N/A         N/A            N/A           ok     fan\nFAN4/1  N/A         N/A            N/A           ok     fan\nSWITCH  XX          XXXXXXXXXXXXX  XXXXXXXXXXXX  ok     switch\npsu1    N/A         N/A            N/A           n/a    psu\npsu2    N/A         N/A            N/A           n/a    psu\n",
      "section_sha256": "efa4795841e62605e546e3b0fc67ca470ac3ccbbe466d3de6450b8e47c80b1ff"
    },
    {
      "expected": {
        "fan_fail": 0,
        "fan_ok": 20,
        "psu_fail": 0,
        "psu_ok": 8
      },
      "id": "P6",
      "section": "         HW Version  Model               Serial        State  Type  \n-------  ----------  ------------------  ------------  -----  ------\nFAN1/1   N/A         N/A                 N/A           ok     fan\nFAN1/2   N/A         N/A                 N/A           ok     fan\nFAN2/1   N/A         N/A                 N/A           ok     fan\nFAN2/2   N/A         N/A                 N/A           ok     fan\nFAN3/1   N/A         N/A                 N/A           ok     fan\nFAN3/2   N/A         N/A                 N/A           ok     fan\nFAN4/1   N/A         N/A                 N/A           ok     fan\nFAN4/2   N/A         N/A                 N/A           ok     fan\nFAN5/1   N/A         N/A                 N/A           ok     fan\nFAN5/2   N/A         N/A                 N/A           ok     fan\nFAN6/1   N/A         N/A                 N/A           ok     fan\nFAN6/2   N/A         N/A                 N/A           ok     fan\nFAN7/1   N/A         N/A                 N/A           ok     fan\nFAN7/2   N/A         N/A                 N/A           ok     fan\nFAN8/1   N/A         N/A                 N/A           ok     fan\nFAN8/2   N/A         N/A                 N/A           ok     fan\nFAN9/1   N/A         N/A                 N/A           ok     fan\nFAN9/2   N/A         N/A                 N/A           ok     fan\nFAN10/1  N/A         N/A                 N/A           ok     fan\nFAN10/2  N/A         N/A                 N/A           ok     fan\nPSU1     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU2     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU3     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU4     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU5     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU6     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU7     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nPSU8     XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     psu\nSWITCH   XX          XXXXXXXXXXXXXXXXXX  XXXXXXXXXXXX  ok     switch\n",
      "section_sha256": "c3e595248bf2cef477ff2aecf870ecf671a8c1f122369dc358b6df49837569b7"
    }
  ],
  "records": [
    {
      "id": "ETH-001",
      "private_command_block_sha256": "73de4f0ca1cf7ad9ddaf208c4823384ca07ac3e61dca197f8ebe8f5c192eca3e",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-002",
      "private_command_block_sha256": "2966d12ec120d269f62e9b4baad5eb4538e5bf73e590b684e0334d9d411b0e60",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-003",
      "private_command_block_sha256": "cc307eae1a393b37d384585e4d1649dbfcfb808d3b5e4e77ba6f1bbc658612a3",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-004",
      "private_command_block_sha256": "698c3db0084758c355542a3b93fbcb0c700bf3cba78baaa9a26efbee6a5bd52d",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-005",
      "private_command_block_sha256": "8382d75dfab9fbfdeba49cef8e12f3c930a69de1075aa3e32e7eafd95c37d886",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-006",
      "private_command_block_sha256": "2129966c847cd21c995a8d7aa824f5d44e82d10e360bd121d09419719ef68ed7",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-007",
      "private_command_block_sha256": "9c16cd40760185556759cab57b65ee2621932123ed741d52d1ae6baee75d5882",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-008",
      "private_command_block_sha256": "f469d327cd98e6a74de298666cdcf11279a8bd89af0242cc962cb7a8b75dfcb1",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-009",
      "private_command_block_sha256": "86fc39b2453c6574070b57dbfb5ef6ead11813136f5daace68816dc15fd58deb",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-010",
      "private_command_block_sha256": "f3c0c9fa29e650c3368a4aad2e86643bd5f2d903082a67c3e1e91130bb8a8126",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-011",
      "private_command_block_sha256": "0af9d2840a90a57d68874acdadcbc02f53e1d94bd04abe3491de4578ac18a749",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-012",
      "private_command_block_sha256": "c0c428ce935ffb5009950ba9237997a09b4eaf42bfda65467d30d4ec0f9c6271",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-013",
      "private_command_block_sha256": "7db49c0afc764b29dd3ba568e96087b64f0cd9039b38fda820bdf0c6a2dd4a44",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-014",
      "private_command_block_sha256": "1532c9205358bb05559d502a622568a7e3b8b18dc4853ac4cfee80819eff4fbe",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-015",
      "private_command_block_sha256": "225193f4b31ba47e21fae5cb085ec0d777ea55448d3173b617ef44398a9c382c",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-016",
      "private_command_block_sha256": "7f6a54cbfb7bac788d06f66b4c7a77b456077a0a1546d4ff97fba00042ee5de0",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-017",
      "private_command_block_sha256": "39c013bdb339bcb5b3ee8295a72dbd6ae3874db927ab418ad32a9a3510c70fbc",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-018",
      "private_command_block_sha256": "982f09870221729baa4dbd93c3c9dd8ddae30ef938ecc844f214f3875876b07e",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-019",
      "private_command_block_sha256": "43f578742a3a5cdb297b2dc4ab6ad4952e6a44d1ed09196c102cf93563ed398e",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-020",
      "private_command_block_sha256": "5590dedaff347f37e54cd5f1aea37b64f5220400a1274ccc7aa9ce124f3ae5c5",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-021",
      "private_command_block_sha256": "b25dd3fa27bd6bbf68ceb4d3c4184c2e9e6e2f0b6fccc82bcb47f134919e4628",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-022",
      "private_command_block_sha256": "24457f94ab9d7156f995711ceb23544ad7abe401eaa19ffd17fd5972e6f9419a",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-023",
      "private_command_block_sha256": "faa49d32b0fc42cbceb8e31722bb26ac33754f3840b49d08265a42e5f358c6bf",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-024",
      "private_command_block_sha256": "ba3b62f02feb29df236c4096ba152fedf586ec4b53b6c440d9fcafc711fd3521",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-025",
      "private_command_block_sha256": "f9f2f6fd74d46384d6c016b4c722660ec3725b9ea0aeacc7c3e483a287b2fc06",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-026",
      "private_command_block_sha256": "597561efa35fc0641db94520f206904d08a8ea4b47fb025e5426137d5e3148ac",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-027",
      "private_command_block_sha256": "0d4610a4cd6031f5cc1a2e7bbc404a593237f47be21fdeecfedf0ba728fc39aa",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-028",
      "private_command_block_sha256": "ddf8e4c7a8c3461091c776cdc84609bb6fb1168621d5427e438054b2d343d128",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-029",
      "private_command_block_sha256": "789b70ae4da7ba76bf85c3b267e4b2b8db1cdeb3e43db4deb6b801836bdf63fd",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-030",
      "private_command_block_sha256": "a21df86c3108264a9649dae65edad8d0edd20fc692613240e0d9536561b59de5",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-031",
      "private_command_block_sha256": "43ff990d6a45777381d805f284ca6a80e696d5f31882a12f8482173a91e52a94",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-032",
      "private_command_block_sha256": "c907d8811aaaad14f04e207b275897cd9b507a46a8c11012a27d7dbeeb9a789f",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-033",
      "private_command_block_sha256": "4735b85fdf4d1d2e3479c2600e00c696dff19e7ad325691e4def3cb6a6f85a76",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-034",
      "private_command_block_sha256": "2703321b0b27dab1010b0181be07c94d9b73552bb79c651c3f1e5c2279b7b378",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-035",
      "private_command_block_sha256": "10ed99ce6b3d7347646525e650d1488f3f33bc3f2ed4fcc37472a7867b13aad9",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-036",
      "private_command_block_sha256": "d92d7af76c3ebf24e5d29f0b6664ee931bea28be81ec2bdedb5ed85427827a97",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-037",
      "private_command_block_sha256": "eff69a7827399746b0f19d52c22c24bf928fd677fb725153f320ac6d750ba703",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-038",
      "private_command_block_sha256": "0162f00c56b8d8c6bf56150192f2d8b4ddd2c5a3a7b06e6b86c0f19d74f052dc",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-039",
      "private_command_block_sha256": "9cec9aa2cb1b65ba80829b76cc5cce60be07270c9ecd232bb5b832594d3a83e7",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-040",
      "private_command_block_sha256": "bcfa3b59382fbc4966df28cda6668e9ccbe283bae5c68f07b8a2455b151d21bb",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-041",
      "private_command_block_sha256": "e17e0d66013da758105069c75ca7a9df70c867cce3bc39648e133a8f6e7a7ed6",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-042",
      "private_command_block_sha256": "247576c94770bc50e346b4c259f369179c79c3ee172228d87595e86af71aa25b",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-043",
      "private_command_block_sha256": "ffb69a472a19efe2db371cc24c560fe75ed9311ae217bb5408dc02a692f2c8c2",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-044",
      "private_command_block_sha256": "2086881c868ac2b8824fedfb467a35740dd994ba90c0c3a73afda0e81cb18f70",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-045",
      "private_command_block_sha256": "361e7f5a9060304967d3a096aaad1e6b36b3a4c7dc4040f799682936f454fcd6",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-046",
      "private_command_block_sha256": "2aa1bec7cddf4bd0e3a982fe5c900f8445e004f897e3d697ec3a6027b4c1da62",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-047",
      "private_command_block_sha256": "1667cef1ebb081a71f1cf2ad1c085074db4bbd34d70041b3e95ae87486bbe226",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-048",
      "private_command_block_sha256": "14bf7ec2fcbb36c88a01263fe5394e755d221ae2eb9fb5bb3449ac39b11c0d77",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-049",
      "private_command_block_sha256": "ddccf6efa7372beae9ebb5aedc62e482e2fce0bb9a05bbd3bdf5bb5ff32561fb",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-050",
      "private_command_block_sha256": "2e1058081e23ee86dac118f56266cdff8966642dd74e38f17bcb18433961907f",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-051",
      "private_command_block_sha256": "dad42908a37b04cb198349aa0a90905aa58a9139998ab1e4e4e6d6b151ff6235",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-052",
      "private_command_block_sha256": "eae2f9ad071eab1622203695d23e0ddbde317b57f3448a906f69052b3698a874",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-053",
      "private_command_block_sha256": "0acc93fc567bdbfaca940e0f9c37f5570c414b865cda16cf5dbc156de727de28",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-054",
      "private_command_block_sha256": "ec469df0c359aa17e8fd074f13e9aed34c2d7e43d91441d221162275f74b339e",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-055",
      "private_command_block_sha256": "5cf0155b5b25113745ea74f85e0a4c1c630063f851c1453532fbc0b8bd52486b",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-056",
      "private_command_block_sha256": "e2cf61d57271508488e59167d6d1765e4db32d4c023b59536e6b86f7ae4de31d",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-057",
      "private_command_block_sha256": "69de58ff8b86c541e6ae7f7bf8c9c811d25a53ad69c8160ec768d900e8bbb82f",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-058",
      "private_command_block_sha256": "10933a6a3790fd3be3525bee4e25eed27313a19130600440aa73669ca01fd7f7",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-059",
      "private_command_block_sha256": "962d902133847fc66aa36bf2c8b5560c8d0813bfa8a8ecfc664f4106bb901c07",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-060",
      "private_command_block_sha256": "118c7e2f3c010703b9842d7b9f8e10dc8d9df79a0bee88014e87372b2fb188d5",
      "profile": "P3",
      "scope": "ETH"
    },
    {
      "id": "ETH-061",
      "private_command_block_sha256": "87a32b5818a77d08fb81334c7b9b1628c64fd41bf302982e970333dafc94eaf3",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-062",
      "private_command_block_sha256": "053deb0f1ec1057ecb79ab645f4b2465c8783cf8d2bd5154b4379d56cc4b493b",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-063",
      "private_command_block_sha256": "cdff138efccc306a66608dcb873594a36015e20a46b380401db892fdb7d158b0",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-064",
      "private_command_block_sha256": "f0eca33534fbc4edca64f028b5ca4eecd675563adacfccfc7b59a8191e5db3b1",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-065",
      "private_command_block_sha256": "962d902133847fc66aa36bf2c8b5560c8d0813bfa8a8ecfc664f4106bb901c07",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-066",
      "private_command_block_sha256": "e2cf61d57271508488e59167d6d1765e4db32d4c023b59536e6b86f7ae4de31d",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-067",
      "private_command_block_sha256": "69de58ff8b86c541e6ae7f7bf8c9c811d25a53ad69c8160ec768d900e8bbb82f",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-068",
      "private_command_block_sha256": "10933a6a3790fd3be3525bee4e25eed27313a19130600440aa73669ca01fd7f7",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-069",
      "private_command_block_sha256": "962d902133847fc66aa36bf2c8b5560c8d0813bfa8a8ecfc664f4106bb901c07",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-070",
      "private_command_block_sha256": "118c7e2f3c010703b9842d7b9f8e10dc8d9df79a0bee88014e87372b2fb188d5",
      "profile": "P3",
      "scope": "ETH"
    },
    {
      "id": "ETH-071",
      "private_command_block_sha256": "87a32b5818a77d08fb81334c7b9b1628c64fd41bf302982e970333dafc94eaf3",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-072",
      "private_command_block_sha256": "053deb0f1ec1057ecb79ab645f4b2465c8783cf8d2bd5154b4379d56cc4b493b",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-073",
      "private_command_block_sha256": "cdff138efccc306a66608dcb873594a36015e20a46b380401db892fdb7d158b0",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-074",
      "private_command_block_sha256": "f0eca33534fbc4edca64f028b5ca4eecd675563adacfccfc7b59a8191e5db3b1",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-075",
      "private_command_block_sha256": "e2cf61d57271508488e59167d6d1765e4db32d4c023b59536e6b86f7ae4de31d",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-076",
      "private_command_block_sha256": "69de58ff8b86c541e6ae7f7bf8c9c811d25a53ad69c8160ec768d900e8bbb82f",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-077",
      "private_command_block_sha256": "10933a6a3790fd3be3525bee4e25eed27313a19130600440aa73669ca01fd7f7",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-078",
      "private_command_block_sha256": "962d902133847fc66aa36bf2c8b5560c8d0813bfa8a8ecfc664f4106bb901c07",
      "profile": "P2",
      "scope": "ETH"
    },
    {
      "id": "ETH-079",
      "private_command_block_sha256": "118c7e2f3c010703b9842d7b9f8e10dc8d9df79a0bee88014e87372b2fb188d5",
      "profile": "P3",
      "scope": "ETH"
    },
    {
      "id": "ETH-080",
      "private_command_block_sha256": "87a32b5818a77d08fb81334c7b9b1628c64fd41bf302982e970333dafc94eaf3",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-081",
      "private_command_block_sha256": "053deb0f1ec1057ecb79ab645f4b2465c8783cf8d2bd5154b4379d56cc4b493b",
      "profile": "P4",
      "scope": "ETH"
    },
    {
      "id": "ETH-082",
      "private_command_block_sha256": "cdff138efccc306a66608dcb873594a36015e20a46b380401db892fdb7d158b0",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-083",
      "private_command_block_sha256": "f0eca33534fbc4edca64f028b5ca4eecd675563adacfccfc7b59a8191e5db3b1",
      "profile": "P5",
      "scope": "ETH"
    },
    {
      "id": "ETH-084",
      "private_command_block_sha256": "1c8f87a8fe71ac01b54d9efd990fd8090f8fff2fe312bdfc59a80171779d5739",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-085",
      "private_command_block_sha256": "141aa2824596db95d57871699da27aaa2b6cb37783a56a6570ea6f4874c35689",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-086",
      "private_command_block_sha256": "e75c4fbf06920b3ec7108c60ab586a2b77da52d8be6059faa80439b2d11a2c09",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-087",
      "private_command_block_sha256": "be749391fdded79c93dac61807b5f502664df6eb7c5dcbc50c11671b6912f50d",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-088",
      "private_command_block_sha256": "8c75ccfffdc81100d52a6091d5233c4360267b7bc9e2449ea847026f46fa73cc",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-089",
      "private_command_block_sha256": "bf2de03192ae9d415596b64c095923d8b2421ce03ae6911e3f32b1a8a55494d3",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-090",
      "private_command_block_sha256": "e1e181fb076e94c9d358be42b388ffcfc5661a38d9b58c40e911fedb4a275569",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-091",
      "private_command_block_sha256": "ed8329eaa186296d3e4672022ffd86f5ae4ef47d8783e9e18b9a972f1f086d18",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-092",
      "private_command_block_sha256": "9daae87426be7e44a565fc88a6a568002f00be9d0e14cd2812bf22808a28c8ea",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-093",
      "private_command_block_sha256": "ee8726d8445864ac0b65f436f59887bf6f027b663efb77a60f927efbc2a2fa10",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "ETH-094",
      "private_command_block_sha256": "23642b0b742e0c480750852fd973ca4ce3b0776bf06d3d37002b34dc79dcaa1b",
      "profile": "P1",
      "scope": "ETH"
    },
    {
      "id": "IB-001",
      "private_command_block_sha256": "1734c8e5782e3066f501e7ebdd73a88b47c739446d204c40b973d8ef876fe0e8",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-002",
      "private_command_block_sha256": "6c3ce3977e6a867052da133468b047cc2f17fe2a14e6782ca736a945fb77b64a",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-003",
      "private_command_block_sha256": "34d02239ad490f00355501cef0100c3e275596c2fae1f3e333e583cf7d5638cb",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-004",
      "private_command_block_sha256": "a3144e4d729bdda16d0ae5b96448e60d4c5c1cf9d5261435c3fe5b5ff140901f",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-005",
      "private_command_block_sha256": "bcaa15cf41b693cfdd9f29aa9aa88e4eae42812a211299dd4ddc73257d6e8bd2",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-006",
      "private_command_block_sha256": "60b612725380ac1e8b85d90297670c721a2afaa4d9756c3065672befd2bd6bc5",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-007",
      "private_command_block_sha256": "9df2865da994aacf317319d7703bd800469e705e9c1b0f7751d333480f1372dd",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-008",
      "private_command_block_sha256": "b20151933ec5329b4e7f508bedb461f0520face658129c7d734cd8ac8ff48bda",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-009",
      "private_command_block_sha256": "59d5d6ce13deb044b0b137af802bedadddb14f8466e7f533939b682124e024af",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-010",
      "private_command_block_sha256": "16446f21b47214565814c6ed8db7ce644748a7d77432e70c739a33dd06c8853e",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-011",
      "private_command_block_sha256": "3d24cba1b7291e839fad4b018812ed797858b0f94a04953829a10153b879495c",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-012",
      "private_command_block_sha256": "d25207749ac7f575bc664444abb650497e0c3fe6119cd82592f7e174a7e60090",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-013",
      "private_command_block_sha256": "dd593df325619212887542f8ed862eb63a497239730a2cf774c5d39cd80d49be",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-014",
      "private_command_block_sha256": "1e4f4cf329b1e5e2211d84221cde56b109dcf72d22899eec845b0c529b852046",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-015",
      "private_command_block_sha256": "e40768e948e3efe1a86bfb9fa8489a1fa4d672cabed3fabff2387ccc70289814",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-016",
      "private_command_block_sha256": "f125923074cc652b0fb1ea79d0d899ae694fdc66189dca8ff63ea9e6a8b03244",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-017",
      "private_command_block_sha256": "72935e5ccf40302e9fa2c653c0183cec2019309250c5e43cfd67dc02b9e12548",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-018",
      "private_command_block_sha256": "7fa13565707c8e14a46113c30313d3bc7f59269411de6050dbd84b9dc54f439f",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-019",
      "private_command_block_sha256": "019f34f307605e011912643debb86fbb71e37a7b1e65b7afd6653b273c01acb2",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-020",
      "private_command_block_sha256": "584fcfad4f23e962587a6637239488d2ca8f07e256d4410ab27fb4da2bf990cc",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-021",
      "private_command_block_sha256": "1c4bce621709c576bde3209b43d504124ac90bb8ef4050849d7fe201af763f23",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-022",
      "private_command_block_sha256": "1aed1a8474e07d8a44f00e4c7834682f870433f7149a04f1af7d156a00c4d885",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-023",
      "private_command_block_sha256": "f850c2a4ca5c63d2423ccf0e1b07f02bcf189dcdbb0cc135f33e87c8b9a0bb10",
      "profile": "P6",
      "scope": "IB"
    },
    {
      "id": "IB-024",
      "private_command_block_sha256": "f56a97dfec5fe2d7ca65f028e5dcf6d4d6aa5e3c3fd22ddbb9a0f0f3f6ae912d",
      "profile": "P6",
      "scope": "IB"
    }
  ],
  "redaction": {
    "preserved": [
      "header-and-separator-bytes",
      "component-name",
      "state",
      "type",
      "field-occupancy"
    ],
    "replaced": [
      "source-path",
      "hw-version-value",
      "model-value",
      "serial-value"
    ],
    "replacement": "non-N/A characters in ignored hardware fields become X; N/A and whitespace remain"
  }
}
"""[1:]
DEIDENTIFIED_INVENTORY_CORPUS_SHA256 = (
    "576dcdc936a63a939f902d53985b4ff5abc18c4b751cee084eccd525065f0507"
)
DEIDENTIFIED_INVENTORY_SOURCE_BINDING_SHA256 = (
    "cf04b971b2a52b42340cef0fa5bb0392e1121c0dcf22462685a0309020154c34"
)
DEIDENTIFIED_INVENTORY_PROFILE_COMPONENTS = {'P1': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN1/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU1', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU1/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU2', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU2/FAN', 'state': 'ok', 'type': 'fan'}],
 'P2': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU1', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU1/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU2', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU2/FAN', 'state': 'ok', 'type': 'fan'}],
 'P3': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN1/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN6/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN6/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU1', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU1/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU2', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU2/FAN', 'state': 'ok', 'type': 'fan'}],
 'P4': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN1/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU1', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU1/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU2', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU2/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU3', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU3/FAN', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU4', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU4/FAN', 'state': 'ok', 'type': 'fan'}],
 'P5': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'psu1', 'state': 'n/a', 'type': 'psu'},
        {'name': 'psu2', 'state': 'n/a', 'type': 'psu'}],
 'P6': [{'name': 'FAN1/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN1/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN2/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN3/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN4/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN5/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN6/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN6/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN7/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN7/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN8/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN8/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN9/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN9/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN10/1', 'state': 'ok', 'type': 'fan'},
        {'name': 'FAN10/2', 'state': 'ok', 'type': 'fan'},
        {'name': 'PSU1', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU2', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU3', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU4', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU5', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU6', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU7', 'state': 'ok', 'type': 'psu'},
        {'name': 'PSU8', 'state': 'ok', 'type': 'psu'}]}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(name)
    sys.path.insert(0, str(path.parent))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old
    return module


CONTROL_AUTH_SEMANTIC_API = load_module(
    "monitor_stack_control_auth_semantics", ROOT / "tools/control-auth.py",
)


REVIEWED_ENTRYPOINTS = {
    "DAY0-Prepare/12-ztp-monitor.py": "ZTP evidence correlation and rounds",
    "monitor/dot_to_html.py": "DOT topology conversion",
    "monitor/generate-monitor-html.py": "unified static monitor publication",
    "monitor/manual-ztp-control.cgi": "per-device control endpoint",
    "monitor/manual-ztp-worker.py": "preview/confirm/time-sync worker",
    "monitor/switch-collection-control.cgi": "switch collection endpoint",
    "monitor/switch-collection-worker.py": "switch collector worker",
    "monitor/switch_collection_gate.py": "cross-collector lock/cooldown",
    "monitor/ztp-monitor-control.cgi": "monitor pause/resume endpoint",
    "ethernet/monitor/cron.sh": "shared collection orchestrator",
    "ethernet/monitor/post-collect.py": "Ethernet closed-loop publisher",
    "ethernet/monitor/sw-info.sh": "atomic switch info snapshot",
    "ethernet/monitor/sw-link.sh": "atomic link snapshot",
    "infiniband/monitor/cron.sh": "IB shared orchestrator link",
    "infiniband/monitor/sw-info.sh": "IB shared info collector link",
    "infiniband/monitor/sw-link.sh": "IB shared link collector link",
    "nvlink/monitor/cron.sh": "NVLink shared orchestrator link",
    "nvlink/monitor/sw-info.sh": "NVLink shared info collector link",
    "nvlink/monitor/sw-link.sh": "NVLink shared link collector link",
    "infiniband/bringup/ndr/data-collect-IB.sh": "legacy MLNX-OS read-only collection",
    "infiniband/bringup/ndr/OS-CPLD-upgrade.sh": "guarded legacy destructive upgrade",
    "infiniband/bringup/xdr-initial-setup/initial-setup.py": "NVOS Day-0 setup",
    "infiniband/bringup/xdr-upgrade/upgrade.sh": "NVOS upgrade orchestration",
}


class EntrypointInventoryTests(unittest.TestCase):
    def test_review_inventory_exists_and_all_sources_parse(self):
        failures = []
        for relative in REVIEWED_ENTRYPOINTS:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            if path.suffix == ".sh":
                result = subprocess.run(
                    ["bash", "-n", str(path)], cwd=ROOT, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=10, check=False,
                )
                if result.returncode:
                    failures.append(f"{relative}: {result.stdout}")
            else:
                try:
                    compile(path.read_bytes(), str(path), "exec")
                except (SyntaxError, UnicodeError) as exc:
                    failures.append(f"{relative}: {exc}")
        self.assertEqual([], failures)

    def test_ib_and_nvlink_collectors_are_exact_shared_links(self):
        for domain in ("infiniband", "nvlink"):
            for name in ("cron.sh", "sw-info.sh", "sw-link.sh"):
                self.assertTrue((ROOT / domain / "monitor" / name).is_symlink())
                self.assertEqual(
                    (ROOT / "ethernet/monitor" / name).resolve(),
                    (ROOT / domain / "monitor" / name).resolve(),
                )


class UnknownAndTransitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module(
            "monitor_stack_ztp", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )

    def test_supervisor_service_and_dhcp_evidence_uses_shared_backend_only(self):
        calls = []

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                calls.append(("active", service))
                return service == "apache2"

            @staticmethod
            def is_enabled(_service):
                return None

            @staticmethod
            def read_log(service):
                calls.append(("log", service))
                return "DHCPACK on 192.0.2.20 to 02:00:00:00:00:20\n"

        with mock.patch.object(
            self.monitor, "run_command",
            side_effect=AssertionError(
                "supervisor monitor path must not invoke systemctl/journalctl"
            ),
        ):
            state = self.monitor.service_state("apache2", runtime_backend=Backend())
            dhcp_text, dhcp_error = self.monitor.collect_dhcp(
                60, runtime_backend=Backend(),
            )

        self.assertEqual("active", state["active"])
        self.assertEqual("not-applicable", state["enabled"])
        self.assertEqual("", state["error"])
        self.assertIn("DHCPACK", dhcp_text)
        self.assertEqual("", dhcp_error)
        self.assertEqual(
            [("active", "apache2"), ("log", "isc-dhcp-server")], calls,
        )

    def test_true_unknown_retains_audit_ip_but_has_no_ssh_identity(self):
        item = {
            "mac": "02:00:00:00:00:99", "mac_plain": "020000000099",
            "platform": "unknown", "lease_state": "active",
            "ip": "192.0.2.99", "last_seen": "2026-08-31T10:00:00+00:00",
            "fingerprints": {"option60": "unrecognized"},
        }
        with mock.patch.object(
            self.monitor, "unknown_dhcp_devices", return_value=[item],
        ):
            rows = self.monitor.runtime_unknown_devices(
                Path("unused.csv"), "", scope="prod", dhcp_leases=None,
            )
        self.assertEqual(1, len(rows))
        device = rows[0]
        self.assertEqual("192.0.2.99", device["ip"])
        self.assertEqual([], device["ssh_ips"])
        self.assertEqual({}, device["ssh_interfaces"])
        self.assertEqual({}, device["candidate_identity"])
        self.assertFalse(device["ssh_collect_enabled"])
        self.assertEqual([], self.monitor.devices_for_switch_collection([device], {}))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            self.monitor, "run_command",
            side_effect=AssertionError("unknown device attempted SSH"),
        ):
            result = self.monitor.collect_switch(
                device, 1, None, Path(directory) / "known_hosts",
            )
        self.assertEqual("ssh_disabled", result["kind"])
        self.assertEqual([], result["attempts"])

    def test_recognized_pending_nvos_keeps_mac_bound_candidate(self):
        item = {
            "mac": "02:00:00:00:00:42", "mac_plain": "020000000042",
            "platform": "nvos", "product": "QM9700", "serial": "S42",
            "lease_state": "observed", "ip": "192.0.2.42",
            "last_seen": "2026-08-31T10:00:00+00:00", "fingerprints": {},
        }
        with mock.patch.object(
            self.monitor, "unknown_dhcp_devices", return_value=[item],
        ):
            device = self.monitor.runtime_unknown_devices(
                Path("unused.csv"), "", scope="prod", dhcp_leases=None,
            )[0]
        self.assertEqual(["192.0.2.42"], device["ssh_ips"])
        self.assertEqual(
            {"192.0.2.42": ("dhcp", "020000000042")},
            device["candidate_identity"],
        )
        self.assertTrue(device["ssh_collect_enabled"])
        issue = next(
            value for value in device["issues"]
            if value["code"] == "ZTP_MANAGED_IDENTITY_PENDING"
        )["message"]
        self.assertIn("Native/systemd", issue)
        self.assertIn("DAY0-Prepare/11-load.py", issue)
        self.assertIn("Docker/Supervisor", issue)
        self.assertIn("infra/docker/deploy.sh deploy", issue)
        self.assertIn("deploy-preloaded <IMAGE_ID>", issue)
        self.assertIn("source write 后不得 load", issue)

    def test_oob_air_row_inherits_production_same_subnet_svi_fallback(self):
        csv_text = (
            "hostname,type,template,eth0_ip,netmask,eth0_mac,vlan_id,svi_ip,netmask\n"
            "AIR-EXAMPLE-OOB-Leaf01,air,oob,192.0.2.34,25,02:00:00:00:00:aa,,,\n"
            "EXAMPLE-OOB-Leaf01,eth,oob,192.0.2.34,25,02:00:00:00:00:bb,100,192.0.2.3,25\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "devices.csv"
            inventory.write_text(csv_text, encoding="utf-8")
            with mock.patch.object(
                self.monitor, "static_air_lease_fallbacks", return_value=[],
            ), mock.patch.object(
                self.monitor, "dynamic_air_devices", return_value=[],
            ):
                devices = {
                    item["hostname"]: item
                    for item in self.monitor.read_devices(inventory, "all")
                }
        air = devices["AIR-EXAMPLE-OOB-Leaf01"]
        self.assertEqual(["192.0.2.34", "192.0.2.3"], air["ssh_ips"])
        self.assertEqual("vlan100", air["ssh_interfaces"]["192.0.2.3"])
        self.assertEqual(
            ("eth0", "0200000000aa"),
            air["candidate_identity"]["192.0.2.3"],
        )


class MonitorEvidenceAndModeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module(
            "monitor_evidence_mode_contract",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )

    def test_tail_exact_boundary_and_truncation_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            complete = b"first\nsecond\n"
            path.write_bytes(complete)

            exact = self.monitor.read_tail(path, max_bytes=len(complete))
            self.assertEqual(complete.decode(), exact.text)
            self.assertEqual("", exact.error)
            self.assertFalse(exact.truncated)
            self.assertEqual(len(complete), exact.source_bytes)
            self.assertEqual(len(complete), exact.read_bytes)
            self.assertEqual(0, exact.dropped_bytes)

            payload = b"discarded-line\nkept-one\nkept-two\n"
            path.write_bytes(payload)
            limited = self.monitor.read_tail(path, max_bytes=14)
            self.assertEqual("kept-two\n", limited.text)
            self.assertEqual("", limited.error)
            self.assertTrue(limited.truncated)
            self.assertEqual(len(payload), limited.source_bytes)
            self.assertLessEqual(limited.read_bytes, 20)
            self.assertEqual(
                len(payload) - len(limited.text.encode()),
                limited.dropped_bytes,
            )

    def test_report_names_release_and_incomplete_evidence_window(self):
        report = {
            "project": "2026-12-example",
            "release_id": "0123456789abcdefabcd",
            "release_generated_at": "2026-09-06T12:00:00+08:00",
            "generated_at": "2026-09-06T12:10:00+08:00",
            "since_minutes": 10080,
            "evidence_window": {
                "earliest_observed_at": "2026-09-05T23:59:00+08:00",
                "incomplete": True,
                "sources": {
                    "apache": {
                        "truncated": True,
                        "source_bytes": 30000000,
                        "read_bytes": 20971520,
                        "dropped_bytes": 9028480,
                    },
                    "dhcp": {"truncated": False},
                },
            },
            "services": {},
            "devices": [],
            "unmatched_interactions": [],
            "collection_errors": [],
        }
        rendered = self.monitor.render_markdown(report)
        self.assertIn("Release ID：0123456789abcdefabcd", rendered)
        self.assertIn("Release 生成时间：2026-09-06T12:00:00+08:00", rendered)
        self.assertIn("实际最早证据：2026-09-05T23:59:00+08:00", rendered)
        self.assertIn("证据不完整", rendered)
        self.assertIn("apache", rendered)
        self.assertIn("20.0 MiB", rendered)

    def _make_active_fixture(self, root: Path):
        root = root.resolve()
        day0 = root / "DAY0-Prepare"
        active = day0 / "active-project"
        inactive = day0 / "inactive-project"
        for project in (active, inactive):
            (project / "99-output-ztp").mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type,template\nEXAMPLE-Leaf01,eth,oob-leaf\n",
                encoding="utf-8",
            )
        ztp = root / "ztp"
        runtime = ztp / "config/isc-dhcp-server"
        runtime.mkdir(parents=True)
        inventory = runtime / "02-devices_config.csv"
        inventory.symlink_to(os.path.relpath(
            active / "02-devices_config.csv", inventory.parent,
        ))
        status_link = ztp / "status"
        status_link.symlink_to(os.path.relpath(
            active / "99-output-ztp", status_link.parent,
        ))
        manifest = ztp / ".setup_manifest"
        manifest.write_text(
            f"# setup manifest — proj: {active.resolve()}\n"
            f"{inventory}\n{status_link}\n",
            encoding="utf-8",
        )
        return day0, active, inactive, inventory, status_link, manifest

    def test_live_monitor_requires_exact_active_project_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            day0, active, inactive, inventory, status_link, manifest = (
                self._make_active_fixture(root)
            )
            with mock.patch.multiple(
                self.monitor,
                HERE=day0,
                HTTP_ROOT=root,
                ACTIVE_INVENTORY=inventory,
                ZTP_STATUS_DIR=status_link,
                SETUP_MANIFEST=manifest,
            ):
                self.monitor.require_active_project(active)
                with self.assertRaisesRegex(ValueError, "active-project"):
                    self.monitor.require_active_project(inactive)

                inventory.unlink()
                inventory.symlink_to(os.path.relpath(
                    inactive / "02-devices_config.csv", inventory.parent,
                ))
                with self.assertRaisesRegex(ValueError, "活动项目身份"):
                    self.monitor.require_active_project(active)

    def test_offline_mode_requires_all_explicit_inputs_and_no_live_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "02-devices_config.csv").write_text(
                "hostname,type,template\nEXAMPLE-Leaf01,eth,oob-leaf\n",
                encoding="utf-8",
            )
            apache = root / "apache.log"
            dhcp = root / "dhcp.log"
            leases = root / "dhcpd.leases"
            air = root / "air.json"
            for path, content in (
                (apache, ""), (dhcp, ""), (leases, ""),
                (air, '{"content":{"nodes":{}}}\n'),
            ):
                path.write_text(content, encoding="utf-8")
            output = root / "offline-output"
            args = self.monitor.parser().parse_args([
                str(project), "--offline", "--no-ssh",
                "--apache-log", str(apache),
                "--dhcp-log", str(dhcp),
                "--dhcp-leases", str(leases),
                "--air-json", str(air),
                "--output-dir", str(output),
            ])
            self.monitor.validate_monitor_mode(args, project)
            self.assertTrue(args.offline)

            missing = self.monitor.parser().parse_args([
                str(project), "--offline", "--no-ssh",
                "--output-dir", str(output),
            ])
            with self.assertRaisesRegex(ValueError, "显式指定"):
                self.monitor.validate_monitor_mode(missing, project)

            live_action = self.monitor.parser().parse_args([
                str(project), "--offline", "--no-ssh", "--watch", "5",
                "--apache-log", str(apache), "--dhcp-log", str(dhcp),
                "--dhcp-leases", str(leases), "--air-json", str(air),
                "--output-dir", str(output),
            ])
            with self.assertRaisesRegex(ValueError, "一次性分析"):
                self.monitor.validate_monitor_mode(live_action, project)

    def test_release_identity_is_bounded_and_project_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "sample"
            release_dir = project / "99-output-ztp"
            release_dir.mkdir(parents=True)
            release = release_dir / "current-release.json"
            release.write_text(json.dumps({
                "schema_version": 1,
                "project": "sample",
                "release_id": "0123456789abcdefabcd",
                "generated_at": "2026-09-06T12:00:00+08:00",
                "validation": "passed",
            }) + "\n", encoding="utf-8")
            self.assertEqual(
                {
                    "release_id": "0123456789abcdefabcd",
                    "generated_at": "2026-09-06T12:00:00+08:00",
                },
                self.monitor.load_release_identity(project),
            )
            payload = json.loads(release.read_text(encoding="utf-8"))
            payload["project"] = "other"
            release.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "项目身份"):
                self.monitor.load_release_identity(project)

    def test_collect_on_complete_is_canonical_and_old_name_is_deprecated_alias(self):
        canonical = self.monitor.parser().parse_args([
            "project", "--collect-on-complete",
        ])
        legacy = self.monitor.parser().parse_args([
            "project", "--exit-on-complete",
        ])
        self.assertTrue(canonical.collect_on_complete)
        self.assertTrue(legacy.collect_on_complete)
        help_text = self.monitor.parser().format_help()
        self.assertIn("--collect-on-complete", help_text)
        self.assertIn("--exit-on-complete", help_text)
        self.assertIn("废弃别名", help_text)
        self.assertIn("USER_MANUAL.md", help_text)

    def test_stall_warning_requires_last_evidence_and_never_marks_failure(self):
        observed = "2026-09-06T10:00:00+08:00"
        now = datetime.fromisoformat("2026-09-06T12:15:00+08:00")
        device = {
            "hostname": "EXAMPLE-Leaf01", "ip": "192.0.2.10",
            "issues": [],
            "stages": {
                name: self.monitor.stage(
                    "running" if name == "bootstrap" else "pending",
                    timestamp=observed if name == "bootstrap" else "",
                )
                for name in self.monitor.STAGE_NAMES
            },
        }

        self.monitor.annotate_progress_stall(
            device, now=now, threshold_minutes=60,
        )
        self.monitor.finalize_device(device)

        issue = next(
            item for item in device["issues"]
            if item["code"] == "PROGRESS_STALLED"
        )
        self.assertEqual("warning", issue["severity"])
        self.assertEqual("2026-09-06T02:00:00+00:00", issue["last_evidence_at"])
        self.assertEqual(135, issue["elapsed_minutes"])
        self.assertNotEqual("failed", device["overall"])

        no_evidence = {
            "hostname": "EXAMPLE-Leaf02", "issues": [],
            "stages": {
                name: self.monitor.stage() for name in self.monitor.STAGE_NAMES
            },
        }
        self.monitor.annotate_progress_stall(
            no_evidence, now=now, threshold_minutes=60,
        )
        self.assertEqual([], no_evidence["issues"])

    def test_every_monitor_issue_has_terminal_remediation(self):
        known_codes = {
            "AIR_BASELINE_CONFIG_USED", "CONSOLE_INITIAL_PASSWORD_REQUIRED",
            "DEFAULT_CONFIG_USED", "DHCP_LEASE_NOT_ACTIVE",
            "DHCP_PLATFORM_UNKNOWN", "DHCP_TRANSITION_IP_CONFLICT",
            "HOSTNAME_TRANSITION", "MAC_CONFIG_NOT_FOUND",
            "MANAGEMENT_VIA_ZTP_TRANSIT", "SSH_HOST_KEY_CHANGED",
            "STALE_ZTP_LOG_AFTER_REBOOT", "STATIC_PROMOTION_PENDING",
            "YAML_APPLY_FAILED", "ZTP_LOG_NOT_FOUND",
            "ZTP_LOG_POINTER_INVALID", "dynamic_address_conflict",
            "HOSTNAME_NOT_OBTAINED", "HOSTNAME_MISMATCH",
            "MANAGEMENT_MAC_MISMATCH", "ZTP_TRANSIT_HOLDER_MAC_MISMATCH",
            "NETWORK_ERROR", "SSH_TIMEOUT", "SSH_UNREACHABLE",
            "SSH_AUTH_FAILED", "PROGRESS_STALLED",
            "ZTP_MANAGED_IDENTITY_PENDING", "UNMANAGED_DHCP_DEVICE",
            "SSH_DISABLED", "SSH_FAILED", "AUTHENTICATION_FAILED",
            "UNREACHABLE", "COLLECTOR_ERROR",
        }
        self.assertTrue(known_codes.issubset(self.monitor.ISSUE_REMEDIATIONS))
        for code in known_codes:
            with self.subTest(code=code):
                self.assertTrue(self.monitor.issue_remediation(code).strip())

        report = {
            "project": "example", "generated_at": "now",
            "release_id": "0123456789abcdefabcd",
            "release_generated_at": "then", "since_minutes": 60,
            "services": {}, "unmatched_interactions": [],
            "collection_errors": [],
            "devices": [{
                "hostname": "EXAMPLE-Leaf01", "type": "eth",
                "ip": "192.0.2.10", "progress": {"percent": 50},
                "overall": "warning",
                "stages": {
                    name: self.monitor.stage() for name in self.monitor.STAGE_NAMES
                },
                "issues": [{
                    "code": "PROGRESS_STALLED", "severity": "warning",
                    "message": "two hours without new evidence",
                }],
            }],
        }
        rendered = self.monitor.render_markdown(report)
        self.assertIn("下一步：", rendered)
        self.assertIn("PROGRESS_STALLED", rendered)

    def test_release_regeneration_remediations_route_each_runtime(self):
        for code in (
            "AIR_BASELINE_CONFIG_USED",
            "DEFAULT_CONFIG_USED",
            "MAC_CONFIG_NOT_FOUND",
            "STATIC_PROMOTION_PENDING",
            "YAML_APPLY_FAILED",
            "ZTP_MANAGED_IDENTITY_PENDING",
            "UNMANAGED_DHCP_DEVICE",
            "SSH_DISABLED",
        ):
            with self.subTest(code=code):
                guidance = self.monitor.issue_remediation(code)
                self.assertIn("source write", guidance)
                self.assertIn("Native/systemd", guidance)
                self.assertIn("DAY0-Prepare/11-load.py", guidance)
                self.assertIn("Docker/Supervisor", guidance)
                self.assertIn("infra/docker/deploy.sh deploy", guidance)
                self.assertIn("deploy-preloaded <IMAGE_ID>", guidance)
                self.assertIn("没有 source write", guidance)
                self.assertIn("infra/docker/deploy.sh load", guidance)

    def test_embedded_controls_do_not_prescribe_an_ambiguous_load_command(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("需运行 load", source)
        self.assertIn("需按当前后端恢复", source)


class InventoryComponentAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor_html = load_module(
            "review_generate_monitor_inventory_components",
            ROOT / "monitor/generate-monitor-html.py",
        )

    def test_inventory_type_column_is_the_only_component_authority(self):
        inventory = """\
Component       HW Version  Model   Serial  State  Type
--------------- ----------- ------- ------- ------ ------
PSU1/FAN        A3          M1      S1      fail   fan
PSU             A3          M2      S2      ok     psu
FAN             A3          M3      S3      ok     fan
PSU2            A3          M4      S4      ok     fan
FAN3            A3          M5      S5      fail   psu
psuLower        A3          M6      S6      fail   PSU
fanLower        A3          M7      S7      ok     FaN
PSU4            A3          M8      S8      fail   module
FAN5            A3          M9      S9      fail
FANok7          A3          ok      S10     fail   fan
"""
        expected = {
            "inventory_components": [
                {"name": "PSU1/FAN", "type": "fan", "state": "fail"},
                {"name": "PSU", "type": "psu", "state": "ok"},
                {"name": "FAN", "type": "fan", "state": "ok"},
                {"name": "PSU2", "type": "fan", "state": "ok"},
                {"name": "FAN3", "type": "psu", "state": "fail"},
                {"name": "psuLower", "type": "psu", "state": "fail"},
                {"name": "fanLower", "type": "fan", "state": "ok"},
                {"name": "FANok7", "type": "fan", "state": "fail"},
            ],
            "psu_ok": 1,
            "psu_fail": 2,
            "fan_ok": 3,
            "fan_fail": 2,
        }

        parsed = self.monitor_html.parse_inventory(inventory)

        self.assertEqual(expected, parsed)
        derived = {
            "psu_ok": 0, "psu_fail": 0,
            "fan_ok": 0, "fan_fail": 0,
        }
        for component in parsed["inventory_components"]:
            state = "ok" if component["state"] == "ok" else "fail"
            derived[f'{component["type"]}_{state}'] += 1
        self.assertEqual(
            {key: expected[key] for key in derived},
            derived,
            "summary counts must be derived from the retained typed components",
        )

    def test_captured_unnamed_component_column_flows_through_both_parsers(self):
        self.assertEqual(
            CAPTURED_UNNAMED_INVENTORY_SHA256,
            hashlib.sha256(CAPTURED_UNNAMED_INVENTORY.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            CAPTURED_UNNAMED_INVENTORY_EXPECTED,
            self.monitor_html.parse_inventory(CAPTURED_UNNAMED_INVENTORY),
        )
        framed = (
            "Switch Type: ETH (VX)\n"
            "####################################################\n"
            "# Execute Command: nv show platform inventory\n"
            "####################################################\n"
            f"{CAPTURED_UNNAMED_INVENTORY[1:]}"
        )
        parsed = self.monitor_html.parse_info_file("captured-air", framed)
        self.assertEqual(
            CAPTURED_UNNAMED_INVENTORY_EXPECTED,
            {key: parsed[key] for key in CAPTURED_UNNAMED_INVENTORY_EXPECTED},
        )

    def test_unnamed_component_schema_is_exact_and_fails_closed(self):
        valid = """\
HW Version Model Serial State Type
-- ------- ----- ------ ----- ----
A1 V1 M1 S1 ok fan
P1 V2 M2 S2 fail psu
"""
        expected = {
            "inventory_components": [
                {"name": "A1", "type": "fan", "state": "ok"},
                {"name": "P1", "type": "psu", "state": "fail"},
            ],
            "psu_ok": 0,
            "psu_fail": 1,
            "fan_ok": 1,
            "fan_fail": 0,
        }
        self.assertEqual(expected, self.monitor_html.parse_inventory(valid))
        explicit = """\
Component HW Version Model Serial State Type
A1 V1 M1 S1 ok fan
P1 V2 M2 S2 fail psu
"""
        self.assertEqual(
            self.monitor_html.parse_inventory(explicit),
            self.monitor_html.parse_inventory(valid),
        )
        self.assertEqual(
            {
                "inventory_components": [
                    {"name": "A1", "type": "fan", "state": "ok"},
                ],
                "psu_ok": 0, "psu_fail": 0, "fan_ok": 1, "fan_fail": 0,
            },
            self.monitor_html.parse_inventory(
                "Component HW Version Model Serial State Type\n"
                "A1 EXTRA V1 M1 S1 ok fan\n"
            ),
        )
        self.assertEqual(
            {"inventory_components": [], "psu_ok": 0, "psu_fail": 0,
             "fan_ok": 0, "fan_fail": 0},
            self.monitor_html.parse_inventory(
                "HW Version Model Serial State Type\n"
                "-- ------- ----- ------ ----- ----\n"
                "A1 EXTRA V1 M1 S1 ok fan\n"
            ),
        )
        for header in (
            "Version Model Serial State Type",
            "HW Version Model Serial Type State",
            "HW Version Model Serial State State Type",
            "prose about HW Version Model Serial State Type values",
        ):
            with self.subTest(header=header):
                self.assertEqual(
                    {"inventory_components": [], "psu_ok": 0, "psu_fail": 0,
                     "fan_ok": 0, "fan_fail": 0},
                    self.monitor_html.parse_inventory(
                        f"{header}\nA1 V1 M1 S1 ok fan\n"
                    ),
                )

    def test_inventory_compact_rows_use_complete_state_and_type_fields(self):
        inventory = """\
Component HW-Version Model Serial State Type
PSU9 A3 M9 S9 fail psu
FAN9\tA3\tM10\tS10\tOK\tfan
PSU_SHORT fail psu
FAN_NO_TYPE A3 M11 S11 fail
"""
        expected = {
            "inventory_components": [
                {"name": "PSU9", "type": "psu", "state": "fail"},
                {"name": "FAN9", "type": "fan", "state": "ok"},
            ],
            "psu_ok": 0,
            "psu_fail": 1,
            "fan_ok": 1,
            "fan_fail": 0,
        }

        self.assertEqual(expected, self.monitor_html.parse_inventory(inventory))

    def test_info_parser_and_html_show_named_failed_fan_component(self):
        content = """\
Switch Type: ETH (SN5600)
####
# Execute Command: nv show platform inventory
####
Component       HW Version  Model   Serial  State  Type
--------------- ----------- ------- ------- ------ ------
PSU1            A3          M1      S1      ok     psu
PSU1/FAN        A3          M2      S2      fail   fan
FAN&<>"7        A3          M3      S3      fail   fan
FANupper        A3          M4      S4      OK     fan
"""
        expected = {
            "inventory_components": [
                {"name": "PSU1", "type": "psu", "state": "ok"},
                {"name": "PSU1/FAN", "type": "fan", "state": "fail"},
                {"name": 'FAN&<>"7', "type": "fan", "state": "fail"},
                {"name": "FANupper", "type": "fan", "state": "ok"},
            ],
            "psu_ok": 1,
            "psu_fail": 0,
            "fan_ok": 1,
            "fan_fail": 2,
        }

        parsed = self.monitor_html.parse_info_file("leaf01", content)

        observed = {key: parsed.get(key) for key in expected}
        rendered = self.monitor_html.render_sw_list_row(parsed)
        violations = []
        if observed != expected:
            violations.append(f"structured inventory mismatch: {observed!r}")
        for fragment in (
            "PSU1/FAN (fail)", 'FAN&amp;&lt;&gt;&quot;7 (fail)',
            "1/3", "(2↓)",
        ):
            if fragment not in rendered:
                violations.append(f"HTML omitted {fragment!r}")
        if 'FAN&<>"7 (fail)' in rendered:
            violations.append("HTML exposed a raw component name")
        self.assertEqual([], violations)


class ControlPlaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manual_cgi = load_module(
            "review_manual_cgi", ROOT / "monitor/manual-ztp-control.cgi"
        )
        cls.switch_cgi = load_module(
            "review_switch_cgi", ROOT / "monitor/switch-collection-control.cgi"
        )
        cls.ztp_cgi = load_module(
            "review_ztp_cgi", ROOT / "monitor/ztp-monitor-control.cgi"
        )
        cls.monitor_html = load_module(
            "review_generate_monitor_html_auth",
            ROOT / "monitor/generate-monitor-html.py",
        )
        cls.manual_worker = load_module(
            "review_manual_worker", ROOT / "monitor/manual-ztp-worker.py"
        )
        cls.manual = load_module(
            "review_manual_time_sync", ROOT / "ztp/manual-ztp.py"
        )
        cls.monitor = load_module(
            "review_monitor_time_sync", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        cls.switch_worker = load_module(
            "review_switch_worker", ROOT / "monitor/switch-collection-worker.py"
        )
        cls.yaml_backup = load_module(
            "review_yaml_backup", ROOT / "ztp/backup/yaml-collect.py"
        )

    @staticmethod
    def _control_endpoints(manual_cgi, switch_cgi, ztp_cgi):
        return (
            (
                manual_cgi,
                "/monitor/control/manual-ztp",
                "/cgi-bin/manual-ztp-control",
                ("process_state", "status_with_queue", "enqueue_request"),
            ),
            (
                switch_cgi,
                "/monitor/control/switch-collection",
                "/cgi-bin/switch-collection-control",
                (
                    "process_state", "collection_status", "yaml_backup_status",
                    "continuous_collection_status", "continuous_backup_status",
                    "request_action", "write_request", "send_memory_request",
                    "send_yaml_backup_request",
                ),
            ),
            (
                ztp_cgi,
                "/monitor/control/ztp-monitor",
                "/cgi-bin/ztp-monitor-control",
                (
                    "control_auth_status", "process_state", "control_state",
                    "write_control",
                ),
            ),
        )

    def test_all_control_cgis_reject_invalid_auth_and_route_before_state_access(self):
        invalid_overrides = (
            ("missing auth flag", {"CONTROL_REQUIRE_AUTH": None}),
            ("false auth flag", {"CONTROL_REQUIRE_AUTH": "0"}),
            ("junk auth flag", {"CONTROL_REQUIRE_AUTH": "true"}),
            ("missing auth type", {"AUTH_TYPE": None}),
            ("wrong auth type", {"AUTH_TYPE": "Digest"}),
            ("missing user", {"REMOTE_USER": None}),
            ("unknown user", {"REMOTE_USER": "operator"}),
            ("path info", {"PATH_INFO": "/extra"}),
        )
        endpoints = self._control_endpoints(
            self.manual_cgi, self.switch_cgi, self.ztp_cgi,
        )
        for endpoint, canonical, _legacy, protected_helpers in endpoints:
            route_overrides = (
                ("trailing route", {"SCRIPT_NAME": canonical + "/tail"}),
                ("mis-cased route", {"SCRIPT_NAME": canonical.upper()}),
                (
                    "wrong route",
                    {"SCRIPT_NAME": "/monitor/control/not-this-endpoint"},
                ),
            )
            for method in ("GET", "POST"):
                for label, overrides in invalid_overrides + route_overrides:
                    with self.subTest(
                        endpoint=endpoint.__name__, method=method, case=label,
                    ):
                        environment = {
                            "REQUEST_METHOD": method,
                            "CONTROL_REQUIRE_AUTH": "1",
                            "AUTH_TYPE": "Basic",
                            "REMOTE_USER": "nvis",
                            "PATH_INFO": "",
                            "SCRIPT_NAME": canonical,
                        }
                        for name, value in overrides.items():
                            if value is None:
                                environment.pop(name, None)
                            else:
                                environment[name] = value
                        with mock.patch.dict(os.environ, environment, clear=True), \
                                ExitStack() as stack:
                            response = stack.enter_context(
                                mock.patch.object(endpoint, "respond")
                            )
                            for helper in protected_helpers:
                                stack.enter_context(mock.patch.object(
                                    endpoint, helper,
                                    side_effect=AssertionError(
                                        f"{helper} ran before the control guard"
                                    ),
                                ))
                            endpoint.main()
                        response.assert_called_once_with(
                            {"error": "forbidden"}, "403 Forbidden",
                        )

    def test_control_cgis_accept_only_exact_users_and_own_exact_routes(self):
        endpoints = self._control_endpoints(
            self.manual_cgi, self.switch_cgi, self.ztp_cgi,
        )
        for endpoint, canonical, legacy, _protected_helpers in endpoints:
            for user in ("nvis", "cumulus"):
                for route in (canonical, legacy):
                    with self.subTest(
                        endpoint=endpoint.__name__, user=user, route=route,
                    ), mock.patch.dict(os.environ, {
                        "CONTROL_REQUIRE_AUTH": "1",
                        "AUTH_TYPE": "Basic",
                        "REMOTE_USER": user,
                        "PATH_INFO": "",
                        "SCRIPT_NAME": route,
                    }, clear=True):
                        self.assertEqual((True, ""), endpoint.control_request_guard())

    def test_control_auth_guard_is_the_first_main_logic(self):
        for relative in (
            "monitor/manual-ztp-control.cgi",
            "monitor/switch-collection-control.cgi",
            "monitor/ztp-monitor-control.cgi",
        ):
            with self.subTest(relative=relative):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                main_node = next(
                    node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "main"
                )
                first = main_node.body[0]
                self.assertIsInstance(first, ast.Assign)
                self.assertIsInstance(first.value, ast.Call)
                self.assertIsInstance(first.value.func, ast.Name)
                self.assertEqual("control_request_guard", first.value.func.id)

    def test_generated_monitor_uses_canonical_authenticated_control_urls(self):
        stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
        html = self.monitor_html.build_html(
            {}, "", 0, "", "", 0, {}, "",
            "", "", stats, None, 0,
            "", "", stats, None, 0,
            "", "", 0, "",
            "", "", stats, None, 0,
            {}, {}, {}, {},
            {
                "available": False, "counts": {},
                "environment_updates": {}, "devices": [],
            },
        )
        for declaration in (
            "const ZTP_CONTROL_URL = '/monitor/control/ztp-monitor';",
            "const SWITCH_COLLECTION_URL = '/monitor/control/switch-collection';",
            "const MANUAL_ZTP_URL = '/monitor/control/manual-ztp';",
        ):
            self.assertIn(declaration, html)
        for legacy in (
            "/cgi-bin/ztp-monitor-control",
            "/cgi-bin/switch-collection-control",
            "/cgi-bin/manual-ztp-control",
        ):
            self.assertNotIn(legacy, html)
        fetch_lines = [
            index for index, line in enumerate(html.splitlines())
            if "fetch(" in line
        ]
        self.assertTrue(fetch_lines)
        lines = html.splitlines()
        for index in fetch_lines:
            with self.subTest(fetch_line=lines[index].strip()):
                self.assertIn(
                    "credentials: 'same-origin'",
                    "\n".join(lines[index:index + 7]),
                )

    def test_ztp_control_auth_status_failure_precedes_state_and_actions(self):
        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(
                    self.ztp_cgi, "control_auth_status",
                    side_effect=self.ztp_cgi.ControlAuthStatusError(
                        "helper-authority"
                    ),
                ), mock.patch.object(
                    self.ztp_cgi, "process_state",
                    side_effect=AssertionError("state read after auth failure"),
                ), mock.patch.object(
                    self.ztp_cgi, "write_control",
                    side_effect=AssertionError("action after auth failure"),
                ), mock.patch.object(self.ztp_cgi, "respond") as response, \
                mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
            self.ztp_cgi.main()

        response.assert_called_once_with(
            {"error": "control authentication state unavailable"},
            "503 Service Unavailable",
        )
        self.assertEqual(
            "monitor-control-auth: helper-authority\n", stderr.getvalue(),
        )

    def test_ztp_control_get_and_post_preserve_exact_factory_status(self):
        base_environment = {
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "cumulus",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
        }
        response = mock.Mock()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ, {**base_environment, "REQUEST_METHOD": "GET"}, clear=True,
        ), mock.patch.object(
            self.ztp_cgi, "control_auth_status", return_value=True,
        ), mock.patch.object(
            self.ztp_cgi, "process_state", return_value=(True, 123),
        ), mock.patch.object(
            self.ztp_cgi, "control_state", return_value="running",
        ), mock.patch.object(self.ztp_cgi, "respond", response), \
                mock.patch.object(sys, "stderr", stderr):
            self.ztp_cgi.main()
        response.assert_called_once_with({
            "state": "running",
            "process_alive": True,
            "control_auth": {"factory_records_active": True},
        })
        self.assertEqual("", stderr.getvalue())

        response.reset_mock()
        body = "action=stop"
        post_environment = {
            **base_environment,
            "REQUEST_METHOD": "POST",
            "HTTP_X_REQUESTED_WITH": "ZTPMonitorControl",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        with mock.patch.dict(os.environ, post_environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(
                    self.ztp_cgi, "control_auth_status", return_value=False,
                ), mock.patch.object(
                    self.ztp_cgi, "process_state", return_value=(True, 123),
                ), mock.patch.object(
                    self.ztp_cgi, "control_state", return_value="paused",
                ), mock.patch.object(self.ztp_cgi, "write_control") as write, \
                mock.patch.object(self.ztp_cgi, "respond", response), \
                mock.patch.object(sys, "stderr", stderr):
            self.ztp_cgi.main()
        write.assert_called_once_with("paused")
        response.assert_called_once_with({
            "state": "paused",
            "process_alive": True,
            "message": "ZTP monitoring paused",
            "control_auth": {"factory_records_active": False},
        })
        self.assertEqual("", stderr.getvalue())

    def test_ztp_status_response_is_bounded_json_and_never_cacheable(self):
        class CapturedOutput:
            def __init__(self):
                self.headers = io.StringIO()
                self.buffer = io.BytesIO()

            def write(self, value):
                return self.headers.write(value)

            def flush(self):
                return None

        output = CapturedOutput()
        payload = {
            "state": "running",
            "process_alive": True,
            "control_auth": {"factory_records_active": True},
        }
        with mock.patch.object(sys, "stdout", output):
            self.ztp_cgi.respond(payload)
        headers = output.headers.getvalue()
        body = output.buffer.getvalue()
        self.assertIn("Cache-Control: no-store\r\n", headers)
        self.assertIn(f"Content-Length: {len(body)}\r\n", headers)
        self.assertLessEqual(len(body), self.ztp_cgi.CONTROL_AUTH_OUTPUT_LIMIT)
        self.assertEqual(payload, json.loads(body.decode("utf-8")))

    @staticmethod
    def _private_cache_root(parent: Path) -> Path:
        root = parent / "cache-root"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        cache = root / "monitor-auth"
        cache.mkdir(mode=0o700)
        cache.chmod(0o700)
        lock = root / "status.lock"
        lock.write_bytes(b"")
        lock.chmod(0o660)
        return root

    @staticmethod
    def _shared_cache_payload(factory_records_active, helper_sha256):
        return CONTROL_AUTH_SEMANTIC_API.build_monitor_authority_cache(
            factory_records_active,
            expected_helper_sha256=helper_sha256,
        )

    @staticmethod
    def _shared_breaker_payload(state):
        return CONTROL_AUTH_SEMANTIC_API.build_monitor_authority_breaker(
            contaminant_dev=state["contaminant_dev"],
            contaminant_ino=state["contaminant_ino"],
            failure_count=state["failure_count"],
        )

    def _cached_factory_status(self, root, refresher, **overrides):
        options = {
            "cache_root": root,
            "authority_boundary": root.parent,
            "cache_parent_uid": os.geteuid(),
            "cache_parent_gid": os.getegid(),
            "cache_euid": os.geteuid(),
            "cache_egid": os.getegid(),
            "expected_helper_sha256": "a" * 64,
            "refresher": refresher,
            "semantic_api": CONTROL_AUTH_SEMANTIC_API,
        }
        options.update(overrides)
        return self.ztp_cgi._cached_control_auth_status(**options)

    def _cache_paths(self, root):
        cache_dir = root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
        return (
            cache_dir,
            root / self.ztp_cgi.CONTROL_AUTH_CACHE_LOCK_NAME,
            cache_dir / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME,
        )

    def _seed_stale_cache_contaminant(self, root):
        self.assertFalse(self._cached_factory_status(root, lambda: False))
        _cache_dir, _lock_file, cache_file = self._cache_paths(root)
        stale_ns = time.time_ns() - self.ztp_cgi.CONTROL_AUTH_CACHE_TTL_NS - 1
        os.utime(cache_file, ns=(stale_ns, stale_ns))
        return cache_file

    def _trip_same_contaminant_breaker(self, root):
        cache_file = self._seed_stale_cache_contaminant(root)
        real_unlink = os.unlink
        refreshes = []

        def leave_existing_final(_source, _destination, *args, **kwargs):
            return None

        def refuse_only_final(path, *args, **kwargs):
            if path == self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME:
                raise PermissionError("deterministic unremovable contaminant")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(
            self.ztp_cgi.os, "replace", side_effect=leave_existing_final,
        ), mock.patch.object(
            self.ztp_cgi.os, "unlink", side_effect=refuse_only_final,
        ):
            for attempt in range(3):
                with self.subTest(publication_attempt=attempt + 1), \
                        self.assertRaises(
                            self.ztp_cgi.ControlAuthStatusError
                        ) as raised:
                    self._cached_factory_status(
                        root, lambda: refreshes.append(attempt) or True,
                    )
                self.assertEqual("cache-authority", raised.exception.category)
        self.assertEqual([0, 1, 2], refreshes)
        return cache_file

    def test_control_auth_cache_uses_held_mtime_only_and_exact_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            refreshes = []

            self.assertTrue(self._cached_factory_status(
                root, lambda: refreshes.append(True) or True,
            ))
            self.assertEqual([True], refreshes)
            cache_file = (
                root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
                / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            )
            payload = json.loads(cache_file.read_text(encoding="ascii"))
            self.assertEqual(
                {"schema_version", "factory_records_active", "helper_sha256"},
                set(payload),
            )
            self.assertNotIn("monotonic", cache_file.read_text(encoding="ascii"))
            cache_dir = cache_file.parent
            lock_file = root / self.ztp_cgi.CONTROL_AUTH_CACHE_LOCK_NAME
            self.assertEqual(0o700, stat.S_IMODE(cache_dir.stat().st_mode))
            self.assertEqual(0o660, stat.S_IMODE(lock_file.stat().st_mode))
            self.assertEqual(1, lock_file.stat().st_nlink)
            self.assertEqual(0o600, stat.S_IMODE(cache_file.stat().st_mode))
            self.assertEqual(1, cache_file.stat().st_nlink)
            self.assertEqual([], list(cache_dir.glob("*.tmp")))
            cache_mtime = cache_file.stat().st_mtime_ns

            at_boundary = lambda: cache_mtime + self.ztp_cgi.CONTROL_AUTH_CACHE_TTL_NS
            self.assertTrue(self._cached_factory_status(
                root, lambda: refreshes.append(False) or False,
                clock_ns=at_boundary,
            ))
            self.assertEqual([True], refreshes)

            beyond_boundary = lambda: (
                cache_mtime + self.ztp_cgi.CONTROL_AUTH_CACHE_TTL_NS + 1
            )
            self.assertFalse(self._cached_factory_status(
                root, lambda: refreshes.append(False) or False,
                clock_ns=beyond_boundary,
            ))
            self.assertEqual([True, False], refreshes)

    def test_cache_hits_take_shared_lock_and_refresh_publication_takes_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            real_flock = self.ztp_cgi.fcntl.flock
            operations = []

            def record_lock(descriptor, operation):
                operations.append(operation)
                return real_flock(descriptor, operation)

            with mock.patch.object(
                self.ztp_cgi.fcntl, "flock", side_effect=record_lock,
            ):
                self.assertTrue(self._cached_factory_status(root, lambda: True))
            self.assertEqual(
                [
                    self.ztp_cgi.fcntl.LOCK_SH,
                    self.ztp_cgi.fcntl.LOCK_UN,
                    self.ztp_cgi.fcntl.LOCK_EX,
                    self.ztp_cgi.fcntl.LOCK_UN,
                ],
                operations,
            )

            operations.clear()
            refresh = mock.Mock(side_effect=AssertionError("fresh hit refreshed"))
            with mock.patch.object(
                self.ztp_cgi.fcntl, "flock", side_effect=record_lock,
            ):
                self.assertTrue(self._cached_factory_status(root, refresh))
            self.assertEqual(
                [self.ztp_cgi.fcntl.LOCK_SH, self.ztp_cgi.fcntl.LOCK_UN],
                operations,
            )
            refresh.assert_not_called()

    def test_candidate_name_poison_is_removed_before_one_recovery_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            real_replace = os.replace
            real_unlink = os.unlink
            poisoned = []

            def replace_held_candidate_with_poison(
                source, destination, *, src_dir_fd, dst_dir_fd,
            ):
                self.assertEqual(src_dir_fd, dst_dir_fd)
                real_unlink(source, dir_fd=src_dir_fd)
                descriptor = os.open(
                    source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                    dir_fd=src_dir_fd,
                )
                try:
                    data = self._shared_cache_payload(False, "a" * 64)
                    self.ztp_cgi._write_all(descriptor, data)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                poisoned.append(True)
                return real_replace(
                    source, destination,
                    src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                )

            first_refresh = mock.Mock(return_value=True)
            with mock.patch.object(
                self.ztp_cgi.os, "replace",
                side_effect=replace_held_candidate_with_poison,
            ), self.assertRaises(
                self.ztp_cgi.ControlAuthStatusError
            ) as raised:
                self._cached_factory_status(root, first_refresh)
            self.assertEqual("cache-authority", raised.exception.category)
            self.assertEqual([True], poisoned)
            first_refresh.assert_called_once_with()

            recovery = mock.Mock(return_value=True)
            self.assertTrue(self._cached_factory_status(root, recovery))
            recovery.assert_called_once_with()
            _cache_dir, _lock_file, cache_file = self._cache_paths(root)
            self.assertTrue(json.loads(
                cache_file.read_text(encoding="ascii")
            )["factory_records_active"])

    def test_same_size_candidate_mutation_is_rejected_and_not_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            real_replace = os.replace
            intended = self._shared_cache_payload(True, "a" * 64)
            poisoned = self._shared_cache_payload(True, "b" * 64)
            self.assertEqual(len(intended), len(poisoned))

            def mutate_same_inode_before_replace(
                source, destination, *, src_dir_fd, dst_dir_fd,
            ):
                descriptor = os.open(
                    source, os.O_WRONLY | os.O_NOFOLLOW,
                    dir_fd=src_dir_fd,
                )
                try:
                    os.ftruncate(descriptor, 0)
                    self.ztp_cgi._write_all(descriptor, poisoned)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                return real_replace(
                    source, destination,
                    src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                )

            with mock.patch.object(
                self.ztp_cgi.os, "replace",
                side_effect=mutate_same_inode_before_replace,
            ), self.assertRaises(
                self.ztp_cgi.ControlAuthStatusError
            ) as raised:
                self._cached_factory_status(root, lambda: True)
            self.assertEqual("cache-authority", raised.exception.category)

            recovery = mock.Mock(return_value=True)
            self.assertTrue(self._cached_factory_status(root, recovery))
            recovery.assert_called_once_with()

    def test_cache_directory_rebind_never_returns_rebound_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            cache_dir = root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
            held_name = root / "held-cache-directory"
            rebound = root / "rebound-cache-directory"
            rebound.mkdir(mode=0o700)
            cache = rebound / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            cache.write_bytes(self._shared_cache_payload(False, "a" * 64))
            cache.chmod(0o600)
            real_replace = os.replace

            def rebind_directory_after_publish(
                source, destination, *, src_dir_fd, dst_dir_fd,
            ):
                result = real_replace(
                    source, destination,
                    src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                )
                real_replace(cache_dir, held_name)
                real_replace(rebound, cache_dir)
                return result

            try:
                with mock.patch.object(
                    self.ztp_cgi.os, "replace",
                    side_effect=rebind_directory_after_publish,
                ), self.assertRaises(
                    self.ztp_cgi.ControlAuthStatusError
                ) as raised:
                    self._cached_factory_status(root, lambda: True)
                self.assertEqual("cache-authority", raised.exception.category)
            finally:
                if cache_dir.exists() and held_name.exists():
                    real_replace(cache_dir, rebound)
                    real_replace(held_name, cache_dir)

    def test_publication_breaker_is_three_attempts_per_contaminant_identity(self):
        """The N=3 bound is per dev+ino; cycling requires cache-owner authority."""
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            cache_file = self._trip_same_contaminant_breaker(root)
            blocked_refresh = mock.Mock(
                side_effect=AssertionError("breaker spawned a fourth helper")
            )
            with self.assertRaises(
                self.ztp_cgi.ControlAuthStatusError
            ) as raised:
                self._cached_factory_status(root, blocked_refresh)
            self.assertEqual("cache-authority", raised.exception.category)
            blocked_refresh.assert_not_called()

            _cache_dir, lock_file, _cache_file = self._cache_paths(root)
            breaker = json.loads(lock_file.read_text(encoding="ascii"))
            metadata = os.stat(cache_file, follow_symlinks=False)
            self.assertEqual({
                "schema_version": 1,
                "contaminant_dev": metadata.st_dev,
                "contaminant_ino": metadata.st_ino,
                "failure_count": 3,
            }, breaker)

    def test_non_rebindable_anchor_blocks_directory_d1_to_d2_across_requests(self):
        """0555 models www-data's no-write class on the root-owned 0755 anchor."""
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self.assertTrue(self._cached_factory_status(root, lambda: True))
            cache_dir, _lock, _cache = self._cache_paths(root)
            held = root / "held-d1"
            attacker = root / "attacker-d2"
            attacker.mkdir(mode=0o700)
            poisoned = attacker / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            poisoned.write_bytes(self._shared_cache_payload(False, "a" * 64))
            poisoned.chmod(0o600)

            root.chmod(0o555)
            try:
                with self.assertRaises(PermissionError):
                    os.replace(cache_dir, held)
            finally:
                root.chmod(0o755)

            refresh = mock.Mock(side_effect=AssertionError("D2 became a cache hit"))
            self.assertTrue(self._cached_factory_status(root, refresh))
            refresh.assert_not_called()
            self.assertFalse(held.exists())
            self.assertTrue(attacker.exists())

    def test_non_rebindable_anchor_blocks_lock_l1_to_l2_across_requests(self):
        """A later CGI process must reopen the same privileged fixed lock name."""
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self.assertTrue(self._cached_factory_status(root, lambda: True))
            _cache_dir, lock, _cache = self._cache_paths(root)
            original = (lock.stat().st_dev, lock.stat().st_ino)

            root.chmod(0o555)
            try:
                with self.assertRaises(PermissionError):
                    lock.unlink()
            finally:
                root.chmod(0o755)

            refresh = mock.Mock(side_effect=AssertionError("L2 erased breaker authority"))
            self.assertTrue(self._cached_factory_status(root, refresh))
            refresh.assert_not_called()
            self.assertEqual(original, (lock.stat().st_dev, lock.stat().st_ino))

    def test_publication_breaker_bound_persists_across_cgi_processes(self):
        """Three attempts are allowed per identity, including across CGI processes."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self._private_cache_root(parent)
            self._seed_stale_cache_contaminant(root)
            marker = parent / "refreshes"
            probe = parent / "breaker-probe.py"
            probe.write_text(
                """import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import sys

loader = SourceFileLoader("breaker_probe_cgi", sys.argv[1])
spec = importlib.util.spec_from_loader("breaker_probe_cgi", loader)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
helper_spec = importlib.util.spec_from_file_location("breaker_probe_helper", sys.argv[4])
helper = importlib.util.module_from_spec(helper_spec)
sys.modules[helper_spec.name] = helper
helper_spec.loader.exec_module(helper)
root = Path(sys.argv[2])
marker = Path(sys.argv[3])
real_unlink = os.unlink

def leave_existing_final(_source, _destination, *args, **kwargs):
    return None

def refuse_only_final(path, *args, **kwargs):
    if path == module.CONTROL_AUTH_CACHE_FILE_NAME:
        raise PermissionError("deterministic unremovable contaminant")
    return real_unlink(path, *args, **kwargs)

def refresh():
    with marker.open("a", encoding="ascii") as stream:
        stream.write(str(os.getpid()) + "\\n")
        stream.flush()
        os.fsync(stream.fileno())
    return True

module.os.replace = leave_existing_final
module.os.unlink = refuse_only_final
try:
    module._cached_control_auth_status(
        cache_root=root,
        authority_boundary=root.parent,
        cache_parent_uid=os.geteuid(),
        cache_parent_gid=os.getegid(),
        cache_euid=os.geteuid(),
        cache_egid=os.getegid(),
        expected_helper_sha256="a" * 64,
        refresher=refresh,
        semantic_api=helper,
    )
except module.ControlAuthStatusError as exc:
    print(exc.category)
    raise SystemExit(0 if exc.category == "cache-authority" else 2)
raise SystemExit(3)
""",
                encoding="utf-8",
            )
            argv = [
                sys.executable, "-B", str(probe),
                str(ROOT / "monitor/ztp-monitor-control.cgi"),
                str(root), str(marker), str(ROOT / "tools/control-auth.py"),
            ]
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            results = [subprocess.run(
                argv, cwd=ROOT, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=15,
            ) for _ in range(4)]
            self.assertEqual([0] * 4, [item.returncode for item in results])
            self.assertEqual(
                ["cache-authority\n"] * 4,
                [item.stdout for item in results],
            )
            self.assertEqual([""] * 4, [item.stderr for item in results])
            self.assertEqual(
                3, len(marker.read_text(encoding="ascii").splitlines()),
            )

    def test_replace_refusal_counts_the_persistent_contaminant_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self._seed_stale_cache_contaminant(root)
            refreshes = []
            with mock.patch.object(
                self.ztp_cgi.os, "replace",
                side_effect=PermissionError("unreplaceable final"),
            ):
                for attempt in range(3):
                    with self.assertRaises(
                        self.ztp_cgi.ControlAuthStatusError
                    ) as raised:
                        self._cached_factory_status(
                            root, lambda: refreshes.append(attempt) or True,
                        )
                    self.assertEqual("cache-authority", raised.exception.category)
                blocked = mock.Mock(
                    side_effect=AssertionError("replace refusal spawned again")
                )
                with self.assertRaises(
                    self.ztp_cgi.ControlAuthStatusError
                ) as raised:
                    self._cached_factory_status(root, blocked)
                self.assertEqual("cache-authority", raised.exception.category)
                blocked.assert_not_called()
            self.assertEqual([0, 1, 2], refreshes)

    def test_breaker_identity_absence_or_change_allows_one_locked_recovery(self):
        for recovery_case in ("absent", "changed"):
            with self.subTest(recovery_case=recovery_case), \
                    tempfile.TemporaryDirectory() as directory:
                root = self._private_cache_root(Path(directory))
                cache_file = self._trip_same_contaminant_breaker(root)
                if recovery_case == "absent":
                    cache_file.unlink()
                else:
                    replacement = cache_file.with_name("new-contaminant")
                    replacement.write_bytes(
                        self._shared_cache_payload(False, "a" * 64)
                    )
                    replacement.chmod(0o600)
                    os.replace(replacement, cache_file)

                refresh = mock.Mock(return_value=True)
                self.assertTrue(self._cached_factory_status(root, refresh))
                refresh.assert_called_once_with()
                _cache_dir, lock_file, _cache_file = self._cache_paths(root)
                self.assertEqual(b"", lock_file.read_bytes())

    def test_breaker_uses_old_held_lock_fd_after_name_unlink_and_recreate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            root_fd, directory_fd, lock_fd = self.ztp_cgi._open_cache_handles(
                root, os.geteuid(), os.geteuid(), os.getegid(),
                authority_boundary=root.parent,
                parent_gid=os.getegid(),
            )
            lock_path = (
                root / self.ztp_cgi.CONTROL_AUTH_CACHE_LOCK_NAME
            )
            old_identity = (
                os.fstat(lock_fd).st_dev, os.fstat(lock_fd).st_ino,
            )
            old_state = {
                "schema_version": 1,
                "contaminant_dev": 101,
                "contaminant_ino": 202,
                "failure_count": 2,
            }
            updated_old_state = {**old_state, "failure_count": 3}
            replacement_state = {
                "schema_version": 1,
                "contaminant_dev": 303,
                "contaminant_ino": 404,
                "failure_count": 3,
            }
            try:
                self.ztp_cgi._write_cache_breaker(
                    lock_fd, old_state,
                    required_uid=os.geteuid(), required_gid=os.getegid(),
                    semantic_api=CONTROL_AUTH_SEMANTIC_API,
                )
                lock_path.unlink()
                replacement_bytes = self._shared_breaker_payload(
                    replacement_state
                )
                lock_path.write_bytes(replacement_bytes)
                lock_path.chmod(0o600)
                self.assertNotEqual(
                    old_identity,
                    (lock_path.stat().st_dev, lock_path.stat().st_ino),
                )
                with mock.patch.object(
                    self.ztp_cgi.os, "open",
                    side_effect=AssertionError("breaker reopened the lock name"),
                ):
                    self.ztp_cgi._write_cache_breaker(
                        lock_fd, updated_old_state,
                        required_uid=os.geteuid(), required_gid=os.getegid(),
                        semantic_api=CONTROL_AUTH_SEMANTIC_API,
                    )
                    self.assertEqual(
                        updated_old_state,
                        self.ztp_cgi._read_cache_breaker(
                            lock_fd, required_uid=os.geteuid(),
                            required_gid=os.getegid(),
                            semantic_api=CONTROL_AUTH_SEMANTIC_API,
                        ),
                    )
                self.assertEqual(replacement_bytes, lock_path.read_bytes())
            finally:
                for descriptor in (lock_fd, directory_fd, root_fd):
                    os.close(descriptor)

    def test_invalid_or_partial_breaker_fails_before_helper_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self.assertTrue(self._cached_factory_status(root, lambda: True))
            _cache_dir, lock_path, _cache_file = self._cache_paths(root)
            malformed_states = (
                b'{"schema_version":1',
                b'{"contaminant_dev":1,"contaminant_ino":2,'
                b'"failure_count":0,"schema_version":1}\n',
            )
            for data in malformed_states:
                with self.subTest(data=data):
                    lock_path.write_bytes(data)
                    lock_path.chmod(0o600)
                    refresh = mock.Mock(
                        side_effect=AssertionError("invalid breaker spawned helper")
                    )
                    with self.assertRaises(
                        self.ztp_cgi.ControlAuthStatusError
                    ) as raised:
                        self._cached_factory_status(root, refresh)
                    self.assertEqual("cache-authority", raised.exception.category)
                    refresh.assert_not_called()

    def test_stale_former_monotonic_payload_and_future_mtime_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self.assertTrue(self._cached_factory_status(root, lambda: True))
            cache_file = (
                root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
                / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            )
            misleading = {
                "schema_version": 1,
                "factory_records_active": False,
                "helper_sha256": "a" * 64,
                "refreshed_monotonic_ns": time.monotonic_ns(),
            }
            cache_file.write_text(
                json.dumps(misleading, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            cache_file.chmod(0o600)
            old_ns = time.time_ns() - self.ztp_cgi.CONTROL_AUTH_CACHE_TTL_NS - 1
            os.utime(cache_file, ns=(old_ns, old_ns))
            refreshes = []
            self.assertTrue(self._cached_factory_status(
                root, lambda: refreshes.append("stale") or True,
            ))
            self.assertEqual(["stale"], refreshes)
            self.assertNotIn("monotonic", cache_file.read_text(encoding="ascii"))

            future_ns = time.time_ns() + 5_000_000_000
            os.utime(cache_file, ns=(future_ns, future_ns))
            self.assertFalse(self._cached_factory_status(
                root, lambda: refreshes.append("future") or False,
            ))
            self.assertEqual(["stale", "future"], refreshes)

    def test_cache_timestamp_change_during_held_read_forces_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            self.assertTrue(self._cached_factory_status(root, lambda: True))
            cache_file = (
                root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
                / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            )
            cache_identity = (
                cache_file.stat().st_dev, cache_file.stat().st_ino,
            )
            real_read_all = self.ztp_cgi._read_all

            def change_timestamp(descriptor, size, category):
                data = real_read_all(descriptor, size, category)
                metadata = os.fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) == cache_identity:
                    changed = max(time.time_ns(), metadata.st_mtime_ns + 1)
                    os.utime(cache_file, ns=(changed, changed))
                return data

            refreshes = []
            with mock.patch.object(
                self.ztp_cgi, "_read_all", side_effect=change_timestamp,
            ):
                self.assertFalse(self._cached_factory_status(
                    root, lambda: refreshes.append(False) or False,
                ))
            self.assertEqual([False], refreshes)

    def test_cache_root_and_fresh_schema_are_fail_closed_authorities(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            unsafe_root = parent / "unsafe-authority"
            unsafe_root.mkdir(mode=0o777)
            unsafe_root.chmod(0o777)
            refresh = mock.Mock(return_value=True)
            with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                self._cached_factory_status(unsafe_root, refresh)
            self.assertEqual("cache-authority", raised.exception.category)
            refresh.assert_not_called()

            real_root = self._private_cache_root(parent)
            alias = parent / "cache-alias"
            alias.symlink_to(real_root, target_is_directory=True)
            with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                self._cached_factory_status(alias, refresh)
            self.assertEqual("cache-authority", raised.exception.category)
            refresh.assert_not_called()

            self.assertTrue(self._cached_factory_status(real_root, lambda: True))
            cache_file = (
                real_root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
                / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
            )
            cache_file.write_text(
                '{"factory_records_active":1,"helper_sha256":"'
                + "a" * 64 + '","schema_version":1}\n',
                encoding="ascii",
            )
            cache_file.chmod(0o600)
            with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                self._cached_factory_status(real_root, refresh)
            self.assertEqual("cache-authority", raised.exception.category)
            refresh.assert_not_called()

    def test_cgi_never_creates_or_repairs_missing_authority_objects(self):
        for missing in ("root", "lock", "cache-directory"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = self._private_cache_root(parent)
                _cache_dir, lock, _cache = self._cache_paths(root)
                if missing == "root":
                    shutil.rmtree(root)
                elif missing == "lock":
                    lock.unlink()
                else:
                    shutil.rmtree(root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME)
                before = sorted(str(path.relative_to(parent)) for path in parent.rglob("*"))
                refresh = mock.Mock(side_effect=AssertionError("missing authority spawned helper"))
                with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                    self._cached_factory_status(root, refresh)
                self.assertEqual("cache-authority", raised.exception.category)
                refresh.assert_not_called()
                self.assertEqual(
                    before,
                    sorted(str(path.relative_to(parent)) for path in parent.rglob("*")),
                )

    def test_fixed_anchor_lock_and_leaf_unsafe_shapes_fail_before_refresh(self):
        cases = (
            "root-owner", "root-group", "root-mode", "root-symlink",
            "lock-owner", "lock-group", "lock-mode", "lock-symlink",
            "lock-hardlink", "lock-fifo", "cache-owner", "cache-group",
            "cache-mode", "cache-symlink", "writable-parent",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = self._private_cache_root(parent)
                cache_dir, lock, _cache = self._cache_paths(root)
                overrides = {}
                if case == "root-owner":
                    overrides["cache_parent_uid"] = os.geteuid() + 1
                elif case == "root-group":
                    overrides["cache_parent_gid"] = os.getegid() + 1
                elif case == "root-mode":
                    root.chmod(0o775)
                elif case == "root-symlink":
                    real = parent / "real-root"
                    root.rename(real)
                    root.symlink_to(real, target_is_directory=True)
                elif case == "lock-owner":
                    overrides["cache_parent_uid"] = os.geteuid() + 1
                elif case == "lock-group":
                    overrides["cache_egid"] = os.getegid() + 1
                elif case == "lock-mode":
                    lock.chmod(0o600)
                elif case == "lock-symlink":
                    lock.unlink()
                    lock.symlink_to(parent / "victim")
                elif case == "lock-hardlink":
                    os.link(lock, root / "other-lock")
                elif case == "lock-fifo":
                    lock.unlink()
                    os.mkfifo(lock, 0o660)
                elif case == "cache-owner":
                    overrides["cache_euid"] = os.geteuid() + 1
                elif case == "cache-group":
                    overrides["cache_egid"] = os.getegid() + 1
                elif case == "cache-mode":
                    cache_dir.chmod(0o755)
                elif case == "cache-symlink":
                    cache_dir.rmdir()
                    cache_dir.symlink_to(parent, target_is_directory=True)
                elif case == "writable-parent":
                    parent.chmod(0o777)
                refresh = mock.Mock(side_effect=AssertionError("unsafe authority spawned helper"))
                with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                    self._cached_factory_status(root, refresh, **overrides)
                self.assertEqual("cache-authority", raised.exception.category)
                refresh.assert_not_called()

    def test_cache_publication_io_fails_closed_and_never_sets_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._private_cache_root(Path(directory))
            with mock.patch.object(
                self.ztp_cgi.os, "fsync", side_effect=OSError("io canary"),
            ), self.assertRaises(
                self.ztp_cgi.ControlAuthStatusError
            ) as raised:
                self._cached_factory_status(root, lambda: True)
            self.assertEqual("cache-io", raised.exception.category)
        source = (ROOT / "monitor/ztp-monitor-control.cgi").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("os.utime", source)

    def test_control_auth_cache_is_cross_process_and_prevents_a_herd(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self._private_cache_root(parent)
            marker = parent / "refreshes"
            probe = parent / "probe.py"
            probe.write_text(
                """import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import sys
import time

loader = SourceFileLoader("cache_probe_cgi", sys.argv[1])
spec = importlib.util.spec_from_loader("cache_probe_cgi", loader)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
helper_spec = importlib.util.spec_from_file_location("cache_probe_helper", sys.argv[4])
helper = importlib.util.module_from_spec(helper_spec)
sys.modules[helper_spec.name] = helper
helper_spec.loader.exec_module(helper)
root = Path(sys.argv[2])
marker = Path(sys.argv[3])
value = sys.argv[5] == "true"

def refresh():
    with marker.open("a", encoding="ascii") as stream:
        stream.write(str(os.getpid()) + "\\n")
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(0.15)
    return value

result = module._cached_control_auth_status(
    cache_root=root,
    authority_boundary=root.parent,
    cache_parent_uid=os.geteuid(),
    cache_parent_gid=os.getegid(),
    cache_euid=os.geteuid(),
    cache_egid=os.getegid(),
    expected_helper_sha256="a" * 64,
    refresher=refresh,
    semantic_api=helper,
)
print("true" if result else "false")
""",
                encoding="utf-8",
            )
            argv = [
                sys.executable, "-B", str(probe),
                str(ROOT / "monitor/ztp-monitor-control.cgi"),
                str(root), str(marker), str(ROOT / "tools/control-auth.py"), "true",
            ]
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            processes = [subprocess.Popen(
                argv, cwd=ROOT, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) for _ in range(6)]
            results = [process.communicate(timeout=15) for process in processes]
            self.assertEqual(
                [0] * 6, [process.returncode for process in processes], results,
            )
            self.assertEqual(["true\n"] * 6, [stdout for stdout, _ in results])
            self.assertEqual([""] * 6, [stderr for _, stderr in results])
            self.assertEqual(1, len(marker.read_text(encoding="ascii").splitlines()))

            reader = subprocess.run(
                argv[:-1] + ["false"], cwd=ROOT, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=15,
            )
            self.assertEqual(0, reader.returncode, reader.stderr)
            self.assertEqual("true\n", reader.stdout)
            self.assertEqual(1, len(marker.read_text(encoding="ascii").splitlines()))

    def test_unsafe_cache_objects_fail_closed_without_refresh(self):
        cases = ("directory-mode", "lock-hardlink", "cache-symlink", "cache-large")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = self._private_cache_root(Path(directory))
                cache_dir = root / self.ztp_cgi.CONTROL_AUTH_CACHE_DIRECTORY_NAME
                if case == "directory-mode":
                    cache_dir.chmod(0o755)
                elif case == "lock-hardlink":
                    lock = root / self.ztp_cgi.CONTROL_AUTH_CACHE_LOCK_NAME
                    os.link(lock, root / "other-lock")
                elif case == "cache-symlink":
                    victim = cache_dir / "victim"
                    victim.write_text("victim", encoding="ascii")
                    (cache_dir / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME).symlink_to(
                        victim
                    )
                else:
                    cache = cache_dir / self.ztp_cgi.CONTROL_AUTH_CACHE_FILE_NAME
                    cache.write_bytes(
                        b"x" * (self.ztp_cgi.CONTROL_AUTH_CACHE_MAX_BYTES + 1)
                    )
                    cache.chmod(0o600)
                refresh = mock.Mock(return_value=True)
                with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                    self._cached_factory_status(root, refresh)
                self.assertEqual("cache-authority", raised.exception.category)
                refresh.assert_not_called()

    @staticmethod
    def _synthetic_status_helper(root: Path, body: str) -> tuple[Path, str]:
        helper_dir = root / "usr/local/lib/http-ztp"
        helper_dir.mkdir(parents=True)
        for directory in (
            root, root / "usr", root / "usr/local", root / "usr/local/lib",
            helper_dir,
        ):
            directory.chmod(0o755)
        helper = helper_dir / "control-auth.py"
        helper.write_text(body, encoding="utf-8")
        helper.chmod(0o755)
        return helper, hashlib.sha256(helper.read_bytes()).hexdigest()

    def _refresh_synthetic_helper(self, root, helper, digest, **overrides):
        options = {
            "helper_path": helper,
            "authority_root": root,
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "expected_helper_sha256": digest,
        }
        options.update(overrides)
        return self.ztp_cgi._refresh_control_auth_status(**options)

    def test_helper_refresh_uses_exact_process_contract_and_no_stdin_or_pyc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "authority"
            root.mkdir()
            evidence = Path(directory) / "evidence.json"
            source_canary = "HELD_SOURCE_BYTES_MUST_NOT_LEAVE_THE_INHERITED_FD"
            body = f"""#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys
SOURCE_CANARY = {source_canary!r}
evidence = Path({str(evidence)!r})
evidence.write_text(json.dumps({{
    "argv": sys.argv[1:],
    "cached": __cached__,
    "environment": dict(os.environ),
    "file": __file__,
    "name": __name__,
    "package": __package__,
    "stdin": len(sys.stdin.buffer.read()),
}}, sort_keys=True), encoding="utf-8")
print('{{"factory_records_active":true,"valid":true}}')
"""
            helper, digest = self._synthetic_status_helper(root, body)
            real_popen = self.ztp_cgi.subprocess.Popen
            launched = {}

            def capture_popen(command, **kwargs):
                launched["command"] = list(command)
                launched["kwargs"] = dict(kwargs)
                return real_popen(command, **kwargs)

            with mock.patch.object(
                self.ztp_cgi.subprocess, "Popen", side_effect=capture_popen,
            ):
                self.assertTrue(self._refresh_synthetic_helper(root, helper, digest))
            recorded = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(["status"], recorded["argv"])
            self.assertIsNone(recorded["cached"])
            self.assertEqual(str(self.ztp_cgi.CONTROL_AUTH_HELPER), recorded["file"])
            self.assertEqual("__main__", recorded["name"])
            self.assertIsNone(recorded["package"])
            self.assertEqual(0, recorded["stdin"])
            for key, value in self.ztp_cgi.CONTROL_AUTH_SAFE_ENV.items():
                self.assertEqual(value, recorded["environment"].get(key))
            self.assertNotIn("HTTP_AUTHORIZATION", recorded["environment"])
            self.assertFalse(any(root.rglob("*.pyc")))
            self.assertFalse(any(root.rglob("__pycache__")))
            self.assertEqual(Path("/usr/bin/python3"), self.ztp_cgi.CONTROL_AUTH_PYTHON)
            self.assertEqual(
                Path("/usr/local/lib/http-ztp/control-auth.py"),
                self.ztp_cgi.CONTROL_AUTH_HELPER,
            )
            command = launched["command"]
            kwargs = launched["kwargs"]
            self.assertEqual(
                ["/usr/bin/python3", "-I", "-B", "-c"], command[:4],
            )
            self.assertEqual(
                self.ztp_cgi.CONTROL_AUTH_HELD_LAUNCH_V1, command[4],
            )
            self.assertLessEqual(
                len(command[4].encode("utf-8")), 16384,
            )
            self.assertEqual(1, len(kwargs["pass_fds"]))
            self.assertEqual(str(kwargs["pass_fds"][0]), command[5])
            self.assertEqual(str(len(body.encode("utf-8"))), command[6])
            self.assertEqual(digest, command[7])
            self.assertEqual(str(self.ztp_cgi.CONTROL_AUTH_HELPER), command[8])
            self.assertIs(self.ztp_cgi.subprocess.DEVNULL, kwargs["stdin"])
            self.assertIs(self.ztp_cgi.subprocess.PIPE, kwargs["stdout"])
            self.assertIs(self.ztp_cgi.subprocess.PIPE, kwargs["stderr"])
            self.assertTrue(kwargs["close_fds"])
            self.assertEqual((int(command[5]),), kwargs["pass_fds"])
            launch_surface = repr(command) + repr(kwargs["env"])
            self.assertNotIn(source_canary, launch_surface)
            self.assertNotIn(body, launch_surface)

    def test_helper_parent_aba_executes_held_bytes_and_cannot_hide_warning(self):
        """An ABA can silence the credential warning while leaving every check green.

        That accepted false result is distinct from the declared last-window
        missed-detection residual: trusted A may run or the request may fail,
        but a pathname-exposed B must never execute or be accepted.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "authority"
            root.mkdir()
            evidence = Path(directory) / "executed.txt"
            trusted_body = (
                "#!/usr/bin/python3\nfrom pathlib import Path\n"
                f"Path({str(evidence)!r}).write_text('trusted', encoding='ascii')\n"
                "print('{\"factory_records_active\":true,\"valid\":true}')\n"
            )
            attacker_body = (
                "#!/usr/bin/python3\nfrom pathlib import Path\n"
                f"Path({str(evidence)!r}).write_text('attacker', encoding='ascii')\n"
                "print('{\"factory_records_active\":false,\"valid\":true}')\n"
            )
            helper, digest = self._synthetic_status_helper(root, trusted_body)
            canonical_parent = helper.parent
            held_parent = canonical_parent.with_name("http-ztp-held")
            attacker_parent = canonical_parent.with_name("http-ztp-attacker")
            attacker_parent.mkdir(mode=0o755)
            attacker = attacker_parent / helper.name
            attacker.write_text(attacker_body, encoding="utf-8")
            attacker.chmod(0o755)
            real_popen = self.ztp_cgi.subprocess.Popen

            def parent_aba_before_spawn(command, **kwargs):
                os.replace(canonical_parent, held_parent)
                os.replace(attacker_parent, canonical_parent)
                try:
                    process = real_popen(command, **kwargs)
                    deadline = time.monotonic() + 3
                    while not evidence.exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    return process
                finally:
                    os.replace(canonical_parent, attacker_parent)
                    os.replace(held_parent, canonical_parent)

            with mock.patch.object(
                self.ztp_cgi.subprocess, "Popen", side_effect=parent_aba_before_spawn,
            ):
                self.assertTrue(self._refresh_synthetic_helper(root, helper, digest))
            self.assertEqual("trusted", evidence.read_text(encoding="ascii"))

    def test_helper_refresh_rejects_authority_digest_and_rebind_races(self):
        valid = "#!/usr/bin/python3\nprint('{\"factory_records_active\":true,\"valid\":true}')\n"
        for case, expected_category in (
            ("mode", "helper-authority"),
            ("writable-parent", "helper-authority"),
            ("symlink-parent", "helper-authority"),
            ("hardlink", "helper-authority"),
            ("oversize", "helper-authority"),
            ("digest", "helper-digest"),
            ("rebind", "helper-rebind"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "authority"
                root.mkdir()
                body = valid
                if case == "rebind":
                    body = (
                        "#!/usr/bin/python3\nimport time\n"
                        "time.sleep(0.2)\n"
                        "print('{\"factory_records_active\":true,\"valid\":true}')\n"
                    )
                helper, digest = self._synthetic_status_helper(root, body)
                if case == "mode":
                    helper.chmod(0o775)
                if case == "writable-parent":
                    helper.parent.chmod(0o775)
                if case == "symlink-parent":
                    original_parent = helper.parent
                    real_parent = original_parent.with_name("http-ztp-real")
                    os.replace(original_parent, real_parent)
                    original_parent.symlink_to(real_parent, target_is_directory=True)
                    helper = original_parent / "control-auth.py"
                if case == "hardlink":
                    os.link(helper, helper.with_name("helper-hardlink"))
                if case == "oversize":
                    helper.write_bytes(
                        b"x" * (self.ztp_cgi.CONTROL_AUTH_HELPER_MAX_BYTES + 1)
                    )
                if case == "digest":
                    digest = "b" * 64
                replacement_thread = None
                if case == "rebind":
                    def replace():
                        time.sleep(0.05)
                        candidate = helper.with_name("replacement")
                        candidate.write_text(valid, encoding="utf-8")
                        candidate.chmod(0o755)
                        os.replace(candidate, helper)
                    replacement_thread = threading.Thread(target=replace)
                    replacement_thread.start()
                try:
                    with self.assertRaises(
                        self.ztp_cgi.ControlAuthStatusError
                    ) as raised:
                        self._refresh_synthetic_helper(root, helper, digest)
                    self.assertEqual(expected_category, raised.exception.category)
                finally:
                    if replacement_thread is not None:
                        replacement_thread.join(timeout=2)

    def test_helper_process_timeout_overflow_protocol_and_invalid_state(self):
        cases = (
            (
                "timeout",
                "#!/usr/bin/python3\nimport time\ntime.sleep(2)\n",
                "helper-timeout", {"timeout_seconds": 0.05},
            ),
            (
                "overflow",
                "#!/usr/bin/python3\nprint('x' * 2048)\n",
                "output-overflow", {},
            ),
            (
                "protocol", "#!/usr/bin/python3\nprint('{}')\n",
                "helper-protocol", {},
            ),
            (
                "invalid",
                "#!/usr/bin/python3\nimport sys\nprint('{\"factory_records_active\":false,\"valid\":false}')\nsys.exit(1)\n",
                "credential-state-invalid", {},
            ),
        )
        for label, body, category, overrides in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "authority"
                root.mkdir()
                helper, digest = self._synthetic_status_helper(root, body)
                with self.assertRaises(self.ztp_cgi.ControlAuthStatusError) as raised:
                    self._refresh_synthetic_helper(
                        root, helper, digest, **overrides,
                    )
                self.assertEqual(category, raised.exception.category)

    def test_monitor_status_pins_the_reviewed_helper_digest(self):
        expected = (
            "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
        )
        self.assertEqual(expected, self.ztp_cgi.CONTROL_AUTH_HELPER_SHA256)
        self.assertEqual(
            expected,
            hashlib.sha256((ROOT / "tools/control-auth.py").read_bytes()).hexdigest(),
        )

    def test_all_nine_status_failures_emit_one_safe_server_category(self):
        categories = (
            "cache-authority", "cache-io", "helper-authority",
            "helper-digest", "helper-rebind", "helper-timeout",
            "output-overflow", "helper-protocol", "credential-state-invalid",
        )
        environment = {
            "REQUEST_METHOD": "GET",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
        }
        canaries = (
            "/usr/local/lib", "$2y$", "nvidia", "cumulus", "deadbeef",
            self.ztp_cgi.CONTROL_AUTH_HELPER_SHA256,
            "subprocess-canary",
        )
        for category in categories:
            with self.subTest(category=category):
                response = mock.Mock()
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(
                            self.ztp_cgi, "control_auth_status",
                            side_effect=self.ztp_cgi.ControlAuthStatusError(category),
                        ), mock.patch.object(
                            self.ztp_cgi, "process_state",
                            side_effect=AssertionError("state read after failure"),
                        ), mock.patch.object(self.ztp_cgi, "respond", response), \
                        mock.patch.object(sys, "stderr", stderr):
                    self.ztp_cgi.main()
                response.assert_called_once_with(
                    {"error": "control authentication state unavailable"},
                    "503 Service Unavailable",
                )
                self.assertEqual(
                    f"monitor-control-auth: {category}\n", stderr.getvalue(),
                )
                combined = repr(response.call_args) + stderr.getvalue()
                for canary in canaries:
                    self.assertNotIn(canary, combined)

    def test_generated_monitor_renders_quiet_persistent_factory_warning(self):
        stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
        html = self.monitor_html.build_html(
            {}, "", 0, "", "", 0, {}, "",
            "", "", stats, None, 0,
            "", "", stats, None, 0,
            "", "", 0, "",
            "", "", stats, None, 0,
            {}, {}, {}, {},
            {
                "available": False, "counts": {},
                "environment_updates": {}, "devices": [],
            },
        )
        self.assertIn(
            'id="factory-credentials-warning" '
            'class="factory-credentials-warning hidden"',
            html,
        )
        self.assertIn("Monitor 仍在使用初始认证凭据，请尽快轮换。", html)
        self.assertIn("payload?.control_auth?.factory_records_active", html)
        self.assertIn(
            "warning.classList.toggle('hidden', factoryActive !== true);", html,
        )
        self.assertEqual(1, html.count('id="factory-credentials-warning"'))
        self.assertNotIn("window.prompt", html)

    def test_control_sources_do_not_embed_factory_password_literal(self):
        for relative in (
            "monitor/manual-ztp-control.cgi",
            "monitor/switch-collection-control.cgi",
            "monitor/ztp-monitor-control.cgi",
            "monitor/generate-monitor-html.py",
        ):
            with self.subTest(relative=relative):
                self.assertNotIn(
                    "nvidia", (ROOT / relative).read_text(encoding="utf-8").casefold()
                )

    def test_all_mutating_cgis_accept_only_exact_http_service_ipv4_origin(self):
        service_ip = "192.0.2.40"
        endpoints = (self.manual_cgi, self.switch_cgi, self.ztp_cgi)
        for endpoint in endpoints:
            for host in (service_ip, f"{service_ip}:80"):
                for origin in (f"http://{service_ip}", f"http://{service_ip}:80"):
                    for https in (None, "off"):
                        for fetch_site in (None, "same-origin"):
                            environment = {
                                "SERVER_ADDR": service_ip,
                                "SERVER_PORT": "80",
                                "REQUEST_SCHEME": "http",
                                "HTTP_HOST": host,
                                "HTTP_ORIGIN": origin,
                            }
                            if https is not None:
                                environment["HTTPS"] = https
                            if fetch_site is not None:
                                environment["HTTP_SEC_FETCH_SITE"] = fetch_site
                            with self.subTest(
                                endpoint=endpoint.__name__, host=host,
                                origin=origin, https=https,
                                fetch_site=fetch_site,
                            ), mock.patch.dict(os.environ, environment, clear=True):
                                self.assertEqual(
                                    (True, ""), endpoint.post_control_guard(),
                                )

            proxy_spoof = {
                "SERVER_ADDR": service_ip,
                "SERVER_PORT": "80",
                "REQUEST_SCHEME": "http",
                "HTTPS": "off",
                "HTTP_HOST": service_ip,
                "HTTP_ORIGIN": f"http://{service_ip}",
                "HTTP_X_FORWARDED_PROTO": "https",
                "HTTP_FORWARDED": (
                    "for=203.0.113.9;proto=https;host=attacker.example"
                ),
            }
            with self.subTest(
                endpoint=endpoint.__name__, case="untrusted proxy headers ignored",
            ), mock.patch.dict(os.environ, proxy_spoof, clear=True):
                self.assertEqual((True, ""), endpoint.post_control_guard())

    def test_all_mutating_cgis_reject_ambiguous_or_spoofed_origin_authority(self):
        service_ip = "192.0.2.40"
        base = {
            "SERVER_ADDR": service_ip,
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": service_ip,
            "HTTP_ORIGIN": f"http://{service_ip}",
            "HTTP_SEC_FETCH_SITE": "same-origin",
        }
        cases = (
            ("missing server address", {"SERVER_ADDR": None}),
            ("empty server address", {"SERVER_ADDR": ""}),
            ("malformed server address", {"SERVER_ADDR": "not-an-ip"}),
            ("padded server address", {"SERVER_ADDR": f" {service_ip}"}),
            ("missing server port", {"SERVER_PORT": None}),
            ("empty server port", {"SERVER_PORT": ""}),
            ("malformed server port", {"SERVER_PORT": "eighty"}),
            ("noncanonical server port", {"SERVER_PORT": "080"}),
            ("wrong server port 81", {"SERVER_PORT": "81"}),
            ("wrong server port 443", {"SERVER_PORT": "443"}),
            ("missing request scheme", {"REQUEST_SCHEME": None}),
            ("empty request scheme", {"REQUEST_SCHEME": ""}),
            ("https request scheme", {"REQUEST_SCHEME": "https"}),
            ("mis-cased request scheme", {"REQUEST_SCHEME": "HTTP"}),
            ("unknown request scheme", {"REQUEST_SCHEME": "gopher"}),
            ("empty TLS marker", {"HTTPS": ""}),
            ("tls enabled", {"HTTPS": "on"}),
            ("missing host", {"HTTP_HOST": None}),
            ("empty host", {"HTTP_HOST": ""}),
            ("scheme in host", {"HTTP_HOST": f"http://{service_ip}"}),
            ("non-numeric host port", {
                "HTTP_HOST": f"{service_ip}:http",
                "HTTP_ORIGIN": f"http://{service_ip}:http",
            }),
            ("duplicate-like host", {
                "HTTP_HOST": f"{service_ip}, {service_ip}",
                "HTTP_ORIGIN": f"http://{service_ip}, {service_ip}",
            }),
            ("hostname rebinding", {
                "HTTP_HOST": "monitor.example",
                "HTTP_ORIGIN": "http://monitor.example",
            }),
            ("other IPv4", {
                "HTTP_HOST": "192.0.2.41",
                "HTTP_ORIGIN": "http://192.0.2.41",
            }),
            ("host port 81", {
                "HTTP_HOST": f"{service_ip}:81",
                "HTTP_ORIGIN": f"http://{service_ip}:81",
            }),
            ("host port 443", {
                "HTTP_HOST": f"{service_ip}:443",
                "HTTP_ORIGIN": f"http://{service_ip}:443",
            }),
            ("isolated host port 81", {"HTTP_HOST": f"{service_ip}:81"}),
            ("isolated host port 080", {"HTTP_HOST": f"{service_ip}:080"}),
            ("isolated origin port 81", {
                "HTTP_ORIGIN": f"http://{service_ip}:81",
            }),
            ("isolated origin port 080", {
                "HTTP_ORIGIN": f"http://{service_ip}:080",
            }),
            ("origin userinfo", {"HTTP_ORIGIN": f"http://user@{service_ip}"}),
            ("missing origin", {"HTTP_ORIGIN": None}),
            ("empty origin", {"HTTP_ORIGIN": ""}),
            ("malformed origin", {"HTTP_ORIGIN": "not-an-origin"}),
            ("padded origin", {"HTTP_ORIGIN": f" http://{service_ip}"}),
            ("https origin", {"HTTP_ORIGIN": f"https://{service_ip}"}),
            ("origin path", {"HTTP_ORIGIN": f"http://{service_ip}/control"}),
            ("origin root path", {"HTTP_ORIGIN": f"http://{service_ip}/"}),
            ("origin query", {"HTTP_ORIGIN": f"http://{service_ip}?control=1"}),
            ("origin fragment", {"HTTP_ORIGIN": f"http://{service_ip}#control"}),
            ("IPv6 authority", {
                "SERVER_ADDR": "2001:db8::40",
                "HTTP_HOST": "[2001:db8::40]",
                "HTTP_ORIGIN": "http://[2001:db8::40]",
            }),
            ("leading-zero IPv4", {
                "SERVER_ADDR": "192.000.002.040",
                "HTTP_HOST": "192.000.002.040",
                "HTTP_ORIGIN": "http://192.000.002.040",
            }),
            ("integer IPv4", {
                "SERVER_ADDR": "3221226024",
                "HTTP_HOST": "3221226024",
                "HTTP_ORIGIN": "http://3221226024",
            }),
            ("spoofed forwarded proto", {
                "HTTP_ORIGIN": f"https://{service_ip}",
                "HTTP_X_FORWARDED_PROTO": "http",
            }),
            ("spoofed Forwarded", {
                "HTTP_ORIGIN": f"https://{service_ip}",
                "HTTP_FORWARDED": f"for=192.0.2.9;proto=http;host={service_ip}",
            }),
            ("cross-site fetch", {"HTTP_SEC_FETCH_SITE": "cross-site"}),
        )
        for endpoint in (self.manual_cgi, self.switch_cgi, self.ztp_cgi):
            for label, overrides in cases:
                environment = dict(base)
                for name, value in overrides.items():
                    if value is None:
                        environment.pop(name, None)
                    else:
                        environment[name] = value
                with self.subTest(
                    endpoint=endpoint.__name__, case=label,
                ), mock.patch.dict(os.environ, environment, clear=True):
                    self.assertFalse(endpoint.post_control_guard()[0])

    def test_post_origin_and_xrw_gates_run_before_state_stdin_or_actions(self):
        service_ip = "192.0.2.40"
        endpoint_cases = (
            (
                self.manual_cgi, "/monitor/control/manual-ztp",
                "ManualZTPControl", {
                    "process_state": (False, None),
                    "status_with_queue": {},
                    "enqueue_request": None,
                },
            ),
            (
                self.switch_cgi, "/monitor/control/switch-collection",
                "SwitchCollectionControl", {
                    "process_state": (False, None),
                    "collection_status": {},
                    "yaml_backup_status": {},
                    "continuous_collection_status": {},
                    "continuous_backup_status": {},
                    "request_action": None,
                    "write_request": None,
                    "send_memory_request": None,
                    "send_yaml_backup_request": None,
                },
            ),
            (
                self.ztp_cgi, "/monitor/control/ztp-monitor",
                "ZTPMonitorControl", {
                    "process_state": (False, None),
                    "control_state": "paused",
                    "write_control": None,
                },
            ),
        )

        class UnreadableInput:
            def read(self, *_args, **_kwargs):
                raise AssertionError("stdin read before POST authority completed")

        for endpoint, route, exact_xrw, protected in endpoint_cases:
            base = {
                "REQUEST_METHOD": "POST",
                "CONTROL_REQUIRE_AUTH": "1",
                "AUTH_TYPE": "Basic",
                "REMOTE_USER": "nvis",
                "PATH_INFO": "",
                "SCRIPT_NAME": route,
                "SERVER_ADDR": service_ip,
                "SERVER_PORT": "80",
                "REQUEST_SCHEME": "http",
                "HTTPS": "off",
                "HTTP_HOST": service_ip,
                "HTTP_ORIGIN": f"https://{service_ip}",
                "HTTP_SEC_FETCH_SITE": "same-origin",
                "HTTP_X_REQUESTED_WITH": exact_xrw,
                "CONTENT_LENGTH": "1",
            }
            real_origin_guard = endpoint.post_control_guard

            def run_request(environment, *, origin_expected):
                events = []

                def auth_guard():
                    events.append("auth")
                    return True, ""

                def origin_guard():
                    events.append("origin")
                    return real_origin_guard()

                with mock.patch.dict(os.environ, environment, clear=True), \
                        ExitStack() as stack:
                    response = stack.enter_context(mock.patch.object(endpoint, "respond"))
                    stack.enter_context(mock.patch.object(
                        endpoint, "control_request_guard", side_effect=auth_guard,
                    ))
                    stack.enter_context(mock.patch.object(
                        endpoint, "post_control_guard",
                        side_effect=(
                            origin_guard if origin_expected else
                            AssertionError("origin ran after invalid XRW")
                        ),
                    ))
                    if endpoint is self.ztp_cgi:
                        stack.enter_context(mock.patch.object(
                            endpoint, "control_auth_status",
                            side_effect=lambda: events.append("factory-auth") or False,
                        ))
                    for name, result in protected.items():
                        stack.enter_context(mock.patch.object(
                            endpoint, name,
                            side_effect=lambda *args, _name=name, _result=result, **kwargs: (
                                events.append(f"protected:{_name}") or _result
                            ),
                        ))
                    if hasattr(endpoint, "subprocess"):
                        stack.enter_context(mock.patch.object(
                            endpoint.subprocess, "Popen",
                            side_effect=lambda *_args, **_kwargs: events.append("subprocess"),
                        ))
                    stack.enter_context(mock.patch.object(sys, "stdin", UnreadableInput()))
                    endpoint.main()
                return events, response

            isolated_authority_failures = (
                ("https origin", {}),
                ("isolated host port 81", {
                    "HTTP_HOST": f"{service_ip}:81",
                    "HTTP_ORIGIN": f"http://{service_ip}",
                }),
                ("isolated host port 080", {
                    "HTTP_HOST": f"{service_ip}:080",
                    "HTTP_ORIGIN": f"http://{service_ip}",
                }),
                ("isolated origin port 81", {
                    "HTTP_ORIGIN": f"http://{service_ip}:81",
                }),
                ("isolated origin port 080", {
                    "HTTP_ORIGIN": f"http://{service_ip}:080",
                }),
            )
            for label, overrides in isolated_authority_failures:
                with self.subTest(endpoint=endpoint.__name__, case=label):
                    events, response = run_request(
                        {**base, **overrides}, origin_expected=True,
                    )
                    expected = ["auth"]
                    if endpoint is self.ztp_cgi:
                        expected.append("factory-auth")
                    expected.append("origin")
                    self.assertEqual(expected, events)
                    self.assertEqual("403 Forbidden", response.call_args.args[1])

            invalid_xrw = (
                None, "", exact_xrw.swapcase(), f"{exact_xrw}, {exact_xrw}",
            )
            for bad_xrw in invalid_xrw:
                environment = {**base, "HTTP_ORIGIN": f"http://{service_ip}"}
                if bad_xrw is None:
                    environment.pop("HTTP_X_REQUESTED_WITH", None)
                else:
                    environment["HTTP_X_REQUESTED_WITH"] = bad_xrw
                with self.subTest(
                    endpoint=endpoint.__name__, case="invalid XRW", value=bad_xrw,
                ):
                    events, response = run_request(environment, origin_expected=False)
                    expected = ["auth"]
                    if endpoint is self.ztp_cgi:
                        expected.append("factory-auth")
                    self.assertEqual(expected, events)
                    self.assertEqual("403 Forbidden", response.call_args.args[1])

    def test_yaml_backup_button_uses_password_modal_and_ten_minute_status(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        collect_at = source.index('id="switch-collect-button"')
        backup_at = source.index('id="yaml-backup-button"')
        self.assertLess(collect_at, backup_at)
        self.assertLess(backup_at - collect_at, 1400)
        self.assertIn('id="yaml-backup-password" type="password"', source)
        self.assertIn("action: 'yaml_backup'", source)
        self.assertIn("body.set('password', password)", source)
        self.assertIn("new URLSearchParams", source)
        self.assertIn("10 分钟冷却中", source)
        self.assertIn("refreshYamlBackupControl();", source)

    def test_collection_toolbar_exposes_four_independent_controls(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        expected_controls = (
            ('id="switch-collect-button"', "信息收集"),
            ('id="continuous-collection-button"', "持续收集"),
            ('id="yaml-backup-button"', "配置备份"),
            ('id="continuous-backup-button"', "持续备份"),
        )
        positions = []
        for marker, label in expected_controls:
            with self.subTest(marker=marker):
                position = source.index(marker)
                positions.append(position)
                self.assertIn(label, source[position:position + 300])
        self.assertEqual(sorted(positions), positions)
        self.assertIn('id="continuous-collection-interval"', source)
        self.assertIn('id="continuous-backup-interval"', source)
        self.assertNotIn("持续收集与备份", source)

    def test_four_controls_use_two_symmetric_non_interrupting_lanes(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        request = source.split(
            "async function requestSwitchCollection() {{", 1,
        )[1].split("\n}}\n\nfunction renderSwitchCollectionControl", 1)[0]
        self.assertIn("const action = 'collect';", request)
        self.assertNotIn("? 'stop' : 'collect'", request)

        running = source.split(
            "if (['queued', 'collecting'].includes(switchCollectionState)) {{", 1,
        )[1].split("}} else", 1)[0]
        self.assertIn("button.textContent = '信息收集中…';", running)
        self.assertIn("button.disabled = true;", running)
        self.assertNotIn("停止信息收集", source)

        self.assertEqual(4, source.count('class="monitor-control-item"'))
        for explanation in (
            "单次执行；开始后不可中断",
            "周期执行；停止只取消后续轮次",
        ):
            self.assertIn(explanation, source)
        self.assertIn("停止后续持续收集", source)
        self.assertIn("停止后续持续备份", source)
        self.assertEqual(
            2,
            source.count(
                "payload?.failed_count ? failedDeviceSummary(payload)"
            ),
        )

    def test_manual_collection_stop_is_not_an_operator_action(self):
        with mock.patch.object(self.switch_cgi, "write_request") as write_request:
            response = self._post_switch_action("action=stop")
        write_request.assert_not_called()
        self.assertEqual("400 Bad Request", response.call_args.args[1])
        self.assertIn("unsupported", response.call_args.args[0]["error"])

        with mock.patch.object(self.switch_cgi, "write_request") as write_request:
            response = self._post_switch_action(
                "action=collect", switch_state="collecting",
            )
        write_request.assert_not_called()
        self.assertEqual("409 Conflict", response.call_args.args[1])
        self.assertIn("already running", response.call_args.args[0]["error"])

    def test_worker_decodes_two_independent_continuous_request_schemas(self):
        collection = self.switch_worker.decode_yaml_backup_request(json.dumps({
            "action": "continuous_collection_start", "interval_minutes": 17,
        }).encode("utf-8"))
        backup = self.switch_worker.decode_yaml_backup_request(json.dumps({
            "action": "continuous_backup_start", "password": "sentinel",
            "interval_minutes": 23,
        }).encode("utf-8"))
        self.assertEqual({
            "action": "continuous_collection_start", "interval_minutes": 17,
        }, collection)
        self.assertEqual("sentinel", backup["password"])
        self.assertEqual(23, backup["interval_minutes"])
        for action in ("continuous_collection_stop", "continuous_backup_stop"):
            self.assertEqual(
                {"action": action},
                self.switch_worker.decode_yaml_backup_request(
                    json.dumps({"action": action}).encode("utf-8")
                ),
            )
        with self.assertRaises(ValueError):
            self.switch_worker.decode_yaml_backup_request(json.dumps({
                "action": "continuous_collection_start", "password": "*",
                "interval_minutes": 17,
            }).encode("utf-8"))

    def _post_switch_action(
        self, body, *, switch_state="idle", backup_state="idle",
        continuous_collection=False, continuous_backup=False,
    ):
        response = mock.Mock()
        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/switch-collection",
            "HTTP_X_REQUESTED_WITH": "SwitchCollectionControl",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        collection_schedule = {
            "state": "scheduled" if continuous_collection else "stopped",
            "enabled": continuous_collection,
        }
        backup_schedule = {
            "state": "scheduled" if continuous_backup else "stopped",
            "enabled": continuous_backup,
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(
                    self.switch_cgi, "process_state", return_value=(True, 321),
                ), mock.patch.object(
                    self.switch_cgi, "collection_status",
                    return_value={"state": switch_state},
                ), mock.patch.object(
                    self.switch_cgi, "yaml_backup_status",
                    return_value={"state": backup_state},
                ), mock.patch.object(
                    self.switch_cgi, "continuous_status",
                    return_value=collection_schedule,
                ), mock.patch.object(
                    self.switch_cgi, "continuous_collection_status",
                    return_value=collection_schedule, create=True,
                ), mock.patch.object(
                    self.switch_cgi, "continuous_backup_status",
                    return_value=backup_schedule, create=True,
                ), mock.patch.object(self.switch_cgi, "respond", response):
            self.switch_cgi.main()
        return response

    def test_manual_collection_and_backup_do_not_block_each_other(self):
        with mock.patch.object(self.switch_cgi, "write_request") as write_request, \
                mock.patch.object(self.switch_cgi, "send_memory_request"):
            collect_response = self._post_switch_action(
                "action=collect", backup_state="collecting",
            )
            write_request.assert_called_once_with("collect")
            self.assertEqual("queued", collect_response.call_args.args[0]["state"])

        with mock.patch.object(self.switch_cgi, "write_request"), \
                mock.patch.object(
                    self.switch_cgi, "send_memory_request",
                ) as send_memory_request:
            backup_response = self._post_switch_action(
                "action=yaml_backup&password=sentinel",
                switch_state="collecting",
            )
            send_memory_request.assert_called_once_with({
                "action": "yaml_backup", "password": "sentinel",
            })
            self.assertEqual("queued", backup_response.call_args.args[0]["state"])

    def test_each_continuous_mode_disables_only_its_manual_peer(self):
        with mock.patch.object(self.switch_cgi, "write_request") as write_request, \
                mock.patch.object(self.switch_cgi, "send_memory_request"):
            blocked_collection = self._post_switch_action(
                "action=collect", continuous_collection=True,
            )
            self.assertEqual("409 Conflict", blocked_collection.call_args.args[1])
            write_request.assert_not_called()

            allowed_collection = self._post_switch_action(
                "action=collect", continuous_backup=True,
            )
            self.assertEqual("queued", allowed_collection.call_args.args[0]["state"])

        with mock.patch.object(self.switch_cgi, "write_request"), \
                mock.patch.object(
                    self.switch_cgi, "send_memory_request",
                ) as send_memory_request:
            blocked_backup = self._post_switch_action(
                "action=yaml_backup&password=sentinel", continuous_backup=True,
            )
            self.assertEqual("409 Conflict", blocked_backup.call_args.args[1])

            allowed_backup = self._post_switch_action(
                "action=yaml_backup&password=sentinel", continuous_collection=True,
            )
            self.assertEqual("queued", allowed_backup.call_args.args[0]["state"])
            send_memory_request.assert_called_once_with({
                "action": "yaml_backup", "password": "sentinel",
            })

    def test_continuous_collection_and_backup_start_independently(self):
        with mock.patch.object(
            self.switch_cgi, "send_memory_request",
        ) as send_memory_request:
            collection_response = self._post_switch_action(
                "action=continuous_collection_start&interval_minutes=17",
                continuous_backup=True,
            )
            self.assertEqual("scheduled", collection_response.call_args.args[0]["state"])
            send_memory_request.assert_called_once_with({
                "action": "continuous_collection_start", "interval_minutes": 17,
            })

        with mock.patch.object(
            self.switch_cgi, "send_memory_request",
        ) as send_memory_request:
            backup_response = self._post_switch_action(
                "action=continuous_backup_start&password=sentinel&interval_minutes=23",
                continuous_collection=True,
            )
            self.assertEqual("scheduled", backup_response.call_args.args[0]["state"])
            send_memory_request.assert_called_once_with({
                "action": "continuous_backup_start", "password": "sentinel",
                "interval_minutes": 23,
            })

    def test_stopping_one_continuous_mode_does_not_emit_a_cross_channel_stop(self):
        for action in ("continuous_collection_stop", "continuous_backup_stop"):
            with self.subTest(action=action), mock.patch.object(
                self.switch_cgi, "send_memory_request",
            ) as send_memory_request, mock.patch.object(
                self.switch_cgi, "write_request",
            ) as write_request:
                response = self._post_switch_action(f"action={action}")
                send_memory_request.assert_called_once_with({"action": action})
                write_request.assert_not_called()
                self.assertEqual("stopping", response.call_args.args[0]["state"])

    def test_switch_status_refresh_defaults_off_and_continuous_modes_are_independent(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("enabled: tab !== 'eth'", source)
        self.assertIn('id="continuous-collection-interval"', source)
        self.assertIn('min="10"', source)
        self.assertIn('id="continuous-collection-button"', source)
        self.assertIn("continuousCollectionEnabled", source)
        self.assertIn("continuousCollectionStartPending", source)
        self.assertIn("continuousCollectionStartPending = true", source)
        self.assertIn("continuousBackupEnabled", source)
        self.assertIn("continuousBackupStartPending", source)
        self.assertIn("renderCollectionControls", source)
        self.assertIn("action: 'continuous_collection_start'", source)
        self.assertIn("action: 'continuous_collection_stop'", source)
        self.assertIn("action: 'continuous_backup_start'", source)
        self.assertIn("action: 'continuous_backup_stop'", source)
        self.assertIn("持续收集：等待收集冷却", source)
        self.assertIn("持续备份：等待备份冷却", source)
        self.assertNotIn("持续收集与备份", source)

    def test_yaml_backup_cgi_sends_password_only_to_memory_socket(self):
        body = "action=yaml_backup&password=sentinel"
        response = mock.Mock()
        sent = []

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def sendto(self, payload, address):
                sent.append((payload, address))
                return len(payload)

        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/switch-collection",
            "HTTP_X_REQUESTED_WITH": "SwitchCollectionControl",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(
                    self.switch_cgi, "process_state", return_value=(True, 321),
                ), mock.patch.object(
                    self.switch_cgi, "collection_status", return_value={"state": "idle"},
                ), mock.patch.object(
                    self.switch_cgi, "yaml_backup_status", return_value={"state": "idle"},
                ), mock.patch.object(
                    self.switch_cgi.socket, "socket", return_value=FakeSocket(),
                ), mock.patch.object(self.switch_cgi, "write_request") as write_request, \
                mock.patch.object(self.switch_cgi, "respond", response):
            self.switch_cgi.main()

        self.assertEqual(1, len(sent))
        payload = json.loads(sent[0][0].decode("utf-8"))
        self.assertEqual(
            {"action": "yaml_backup", "password": "sentinel"}, payload,
        )
        self.assertEqual(str(self.switch_cgi.YAML_BACKUP_SOCKET), sent[0][1])
        write_request.assert_not_called()
        response.assert_called_once()
        self.assertEqual("queued", response.call_args.args[0]["state"])

    def test_yaml_backup_http_to_worker_to_collector_keeps_secret_out_of_argv(self):
        secret = "sentinel"
        datagram = json.dumps({
            "action": "yaml_backup", "password": secret,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertEqual(
            {"action": "yaml_backup", "password": secret},
            self.switch_worker.decode_yaml_backup_request(datagram),
        )
        captured = {}

        class FakeGate:
            cooldown_seconds = 600

            def __init__(self, project, scope, **kwargs):
                captured.update(project=project, scope=scope, **kwargs)
                self.decision = SimpleNamespace(allowed=True, reason="allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def mark_success(self):
                return "2026-09-08T12:00:00+08:00"

        def fake_run(command, cwd, timeout, *, pass_fds=(), lane="collection"):
            self.assertNotIn(secret, command)
            self.assertEqual(1, len(pass_fds))
            self.assertEqual(str(pass_fds[0]), command[command.index("--password-fd") + 1])
            captured["password"] = os.read(pass_fds[0], 2048).decode("utf-8")
            captured["command"] = command
            captured["lane"] = lane
            result = {
                "schema_version": 1,
                "task": "yaml_backup",
                "state": "success",
                "planned": 1,
                "succeeded": 1,
                "failed_count": 0,
                "failed_devices": [],
            }
            return {
                "returncode": 0,
                "stdout": "[HTTP_ZTP_TASK_RESULT] " + json.dumps(result) + "\n",
                "stderr": "",
            }, False

        with mock.patch.object(self.switch_worker, "CollectionGate", FakeGate), \
                mock.patch.object(
                    self.switch_worker, "active_project_identity", return_value="/project",
                ), mock.patch.object(
                    self.switch_worker, "run_interruptible", side_effect=fake_run,
                ), mock.patch.object(self.switch_worker, "write_yaml_backup_status"):
            self.assertTrue(self.switch_worker.run_yaml_backup(secret, "prod", 60, 7))

        self.assertEqual(secret, captured["password"])
        self.assertEqual(("yaml-backup",), captured["collection_keys"])
        self.assertEqual(600, captured["cooldown_seconds"])
        self.assertEqual(7, captured["lock_wait_seconds"])
        self.assertEqual("backup", captured["lane"])
        self.assertEqual("prod", captured["command"][captured["command"].index("--type") + 1])

    def test_continuous_modes_run_one_job_each_and_keep_backup_password_in_memory(self):
        secret = "sentinel"
        collection_message = self.switch_worker.decode_yaml_backup_request(json.dumps({
            "action": "continuous_collection_start", "interval_minutes": 10,
        }).encode("utf-8"))
        backup_message = self.switch_worker.decode_yaml_backup_request(json.dumps({
            "action": "continuous_backup_start", "password": secret,
            "interval_minutes": 20,
        }).encode("utf-8"))
        collection_statuses = []
        backup_statuses = []
        with mock.patch.object(
            self.switch_worker, "write_continuous_status",
            side_effect=lambda state, **extra: collection_statuses.append((state, extra)),
        ), mock.patch.object(
            self.switch_worker, "write_continuous_backup_status",
            side_effect=lambda state, **extra: backup_statuses.append((state, extra)),
        ), mock.patch.object(
            self.switch_worker.time, "monotonic", return_value=100.0,
        ):
            self.switch_worker.configure_continuous_collection(collection_message)
            self.switch_worker.configure_continuous_backup(backup_message)
        self.assertTrue(self.switch_worker.continuous_collection_enabled())
        self.assertTrue(self.switch_worker.continuous_backup_enabled())
        self.assertNotIn(secret, json.dumps(backup_statuses, ensure_ascii=False))

        with mock.patch.object(
            self.switch_worker, "continuous_cooldown_wait", return_value={},
        ), mock.patch.object(
            self.switch_worker, "collect_safely", return_value=True,
        ) as collect, mock.patch.object(
            self.switch_worker, "run_yaml_backup_safely", return_value=True,
        ) as backup, mock.patch.object(
            self.switch_worker, "write_continuous_status",
        ), mock.patch.object(
            self.switch_worker, "write_continuous_backup_status",
        ), mock.patch.object(
            self.switch_worker.time, "monotonic", return_value=101.0,
        ):
            self.assertTrue(
                self.switch_worker.run_continuous_collection_cycle("prod", 60, 7)
            )
            collect.assert_called_once_with("prod", 60, 7)
            backup.assert_not_called()
            self.assertTrue(
                self.switch_worker.run_continuous_backup_cycle("prod", 60, 7)
            )
            backup.assert_called_once_with(secret, "prod", 60, 7)

        with mock.patch.object(self.switch_worker, "write_continuous_status"), \
                mock.patch.object(
                    self.switch_worker, "write_continuous_backup_status",
                ):
            self.switch_worker.stop_continuous_collection_mode("operator")
            self.switch_worker.stop_continuous_backup_mode("operator")
        self.assertFalse(self.switch_worker.continuous_collection_enabled())
        self.assertFalse(self.switch_worker.continuous_backup_enabled())

    def test_worker_rejects_manual_yaml_backup_only_during_continuous_backup(self):
        previous = self.switch_worker._CONTINUOUS_BACKUP_PASSWORD
        self.switch_worker._CONTINUOUS_BACKUP_PASSWORD = "sentinel"
        try:
            with mock.patch.object(
                self.switch_worker, "run_yaml_backup_safely",
            ) as backup, self.assertRaisesRegex(
                ValueError, "disabled during continuous backup",
            ):
                self.switch_worker.handle_memory_request(
                    {"action": "yaml_backup", "password": "sentinel"},
                    "prod", 60, 7,
                )
            backup.assert_not_called()
        finally:
            self.switch_worker._CONTINUOUS_BACKUP_PASSWORD = previous

    def test_continuous_cycles_use_independent_failure_boundaries(self):
        self.switch_worker._CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 600
        self.switch_worker._CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
        self.switch_worker._CONTINUOUS_BACKUP_PASSWORD = "sentinel"
        self.switch_worker._CONTINUOUS_BACKUP_INTERVAL_SECONDS = 1200
        self.switch_worker._CONTINUOUS_BACKUP_NEXT_RUN = 0.0
        collection_statuses = []
        backup_statuses = []
        with mock.patch.object(
            self.switch_worker, "collect_safely", return_value=False,
        ) as collect, mock.patch.object(
            self.switch_worker, "run_yaml_backup_safely", return_value=False,
        ) as backup, mock.patch.object(
            self.switch_worker, "write_continuous_status",
            side_effect=lambda state, **extra: collection_statuses.append((state, extra)),
        ), mock.patch.object(
            self.switch_worker, "write_continuous_backup_status",
            side_effect=lambda state, **extra: backup_statuses.append((state, extra)),
        ), mock.patch.object(
            self.switch_worker, "continuous_cooldown_wait", return_value={},
        ), mock.patch.object(
            self.switch_worker.time, "monotonic", return_value=100.0,
        ), mock.patch.object(
            self.switch_worker.time, "time", return_value=1_000.0,
        ):
            self.assertFalse(
                self.switch_worker.run_continuous_collection_cycle("prod", 60, 7),
            )
            backup.assert_not_called()
            self.assertFalse(
                self.switch_worker.run_continuous_backup_cycle("prod", 60, 7),
            )
        collect.assert_called_once_with("prod", 60, 7)
        backup.assert_called_once_with("sentinel", "prod", 60, 7)
        self.assertEqual("scheduled", collection_statuses[-1][0])
        self.assertEqual(False, collection_statuses[-1][1]["collection_ok"])
        self.assertEqual("scheduled", backup_statuses[-1][0])
        self.assertEqual(False, backup_statuses[-1][1]["backup_ok"])
        self.assertTrue(self.switch_worker.continuous_collection_enabled())
        self.assertTrue(self.switch_worker.continuous_backup_enabled())
        with mock.patch.object(self.switch_worker, "write_continuous_status"), \
                mock.patch.object(
                    self.switch_worker, "write_continuous_backup_status",
                ):
            self.switch_worker.stop_continuous_collection_mode("test cleanup")
            self.switch_worker.stop_continuous_backup_mode("test cleanup")

    def test_yaml_backup_status_rejects_unbounded_cooldown_metadata(self):
        status_file = mock.Mock()
        status_file.read_text.return_value = json.dumps({
            "state": "success", "next_allowed_epoch": 10 ** 1000,
        })
        with mock.patch.object(
            self.switch_cgi, "YAML_BACKUP_STATUS_FILE", status_file,
        ):
            payload = self.switch_cgi.yaml_backup_status()
        self.assertEqual("success", payload["state"])
        self.assertNotIn("remaining_seconds", payload)

    def test_continuous_intervals_are_bounded_and_old_combined_action_is_rejected(self):
        for interval in ("9", "0", "1441", "not-a-number"):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                self.switch_cgi.validate_continuous_interval(interval)
        response = self._post_switch_action(
            "action=continuous_start&password=sentinel&interval_minutes=10"
        )
        self.assertEqual("400 Bad Request", response.call_args.args[1])

    def test_worker_imports_interval_floor_and_keeps_timing_quantities_distinct(self):
        worker_source = (
            ROOT / "monitor/switch-collection-worker.py"
        ).read_text(encoding="utf-8")
        gate_source = (
            ROOT / "monitor/switch_collection_gate.py"
        ).read_text(encoding="utf-8")
        def authority_errors(source):
            tree = ast.parse(source)
            local_floor_assignments = []
            imported_floor = []
            guarded_imports = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(
                        isinstance(target, ast.Name)
                        and target.id == "MIN_CONTINUOUS_INTERVAL_MINUTES"
                        for target in targets
                    ):
                        local_floor_assignments.append(node)
                if isinstance(node, ast.ImportFrom) and node.module == "project_contract":
                    imported_floor.extend(alias.name for alias in node.names)
                if isinstance(node, ast.Try) and any(
                    isinstance(child, ast.ImportFrom)
                    and child.module == "project_contract"
                    for child in ast.walk(node)
                ):
                    guarded_imports.append(node)
            errors = []
            if local_floor_assignments:
                errors.append("worker has a local floor or fallback")
            if imported_floor != ["MIN_CONTINUOUS_INTERVAL_MINUTES"]:
                errors.append("worker lacks one exact canonical import")
            if guarded_imports:
                errors.append("canonical import is hidden behind a fallback")
            if 'HTTP_ROOT / "tools"' not in source:
                errors.append("worker lacks deterministic tools provenance")
            gate_position = source.find("from switch_collection_gate import")
            tools_position = source.find('TOOLS_ROOT = HTTP_ROOT / "tools"')
            contract_position = source.find(
                "from project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES"
            )
            if not 0 <= gate_position < tools_position < contract_position:
                errors.append("tools path can shadow the local collection gate")
            return errors

        self.assertEqual([], authority_errors(worker_source))
        self.assertTrue(authority_errors(worker_source.replace(
            "from project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES\n",
            "",
            1,
        )))
        self.assertTrue(authority_errors(
            worker_source + "\nMIN_CONTINUOUS_INTERVAL_MINUTES = 10\n",
        ))
        self.assertTrue(authority_errors(worker_source.replace(
            "from project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES\n",
            "try:\n"
            "    from project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES\n"
            "except ImportError:\n"
            "    MIN_CONTINUOUS_INTERVAL_MINUTES = 10\n",
            1,
        )))
        self.assertIn('HTTP_ROOT / "tools"', worker_source)
        self.assertIn("YAML_BACKUP_COOLDOWN_SECONDS = 10 * 60", worker_source)
        self.assertIn("COOLDOWN_SECONDS = 10 * 60", gate_source)
        self.assertNotIn(
            "MIN_CONTINUOUS_INTERVAL_MINUTES = 10", worker_source,
        )

    def test_worker_continuous_interval_boundaries_use_the_canonical_floor(self):
        test_value = "-".join(("fixed", "secret"))
        for action in (
            "continuous_collection_start", "continuous_backup_start",
        ):
            for interval in (10, 1440):
                with self.subTest(action=action, interval=interval):
                    encoded = {
                        "action": action,
                        "interval_minutes": interval,
                    }
                    if action == "continuous_backup_start":
                        encoded["password"] = test_value
                    decoded = self.switch_worker.decode_yaml_backup_request(
                        json.dumps(encoded).encode("utf-8"),
                    )
                    self.assertEqual(interval, decoded["interval_minutes"])
                    self.assertEqual(
                        interval,
                        self.switch_worker._validated_interval(
                            {"action": action, "interval_minutes": interval},
                            action,
                        ),
                    )
            for interval in (9, 1441, True, False, 10.0, "10", None):
                with self.subTest(action=action, interval=interval):
                    encoded = {
                        "action": action,
                        "interval_minutes": interval,
                    }
                    if action == "continuous_backup_start":
                        encoded["password"] = test_value
                    with self.assertRaises(ValueError):
                        self.switch_worker.decode_yaml_backup_request(
                            json.dumps(encoded).encode("utf-8"),
                        )
                    with self.assertRaises(ValueError):
                        self.switch_worker._validated_interval(
                            {"action": action, "interval_minutes": interval},
                            action,
                        )

    def test_worker_continuous_interval_conversion_is_exact_minutes_to_seconds(self):
        worker = self.switch_worker
        test_value = "-".join(("fixed", "secret"))
        with (
            mock.patch.object(worker, "write_continuous_status"),
            mock.patch.object(worker, "write_continuous_backup_status"),
            mock.patch.object(worker.time, "monotonic", return_value=42.0),
        ):
            worker.configure_continuous_collection({
                "action": "continuous_collection_start",
                "interval_minutes": 10,
            })
            worker.configure_continuous_backup({
                "action": "continuous_backup_start",
                "password": test_value,
                "interval_minutes": 1440,
            })
        self.assertEqual(10 * 60, worker._CONTINUOUS_COLLECTION_INTERVAL_SECONDS)
        self.assertEqual(1440 * 60, worker._CONTINUOUS_BACKUP_INTERVAL_SECONDS)
        worker.stop_continuous_collection_mode("test cleanup")
        worker.stop_continuous_backup_mode("test cleanup")

    def test_cgi_static_interval_pin_is_bidirectional_and_mutation_proven(self):
        # generate-monitor-html.py keeps non-authoritative UX hints; the CGI
        # static pin and worker admission remain the fail-closed authorities.
        contract_source = (ROOT / "tools/project_contract.py").read_text(
            encoding="utf-8",
        )
        cgi_source = (
            ROOT / "monitor/switch-collection-control.cgi"
        ).read_text(encoding="utf-8")

        def assigned_integers(source, predicate):
            result = []
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if (
                        isinstance(target, ast.Name) and predicate(target.id)
                        and isinstance(value, ast.Constant)
                        and type(value.value) is int
                    ):
                        result.append((target.id, value.value))
            return result

        def parity_errors(canonical, cgi):
            errors = []
            canonical_values = assigned_integers(
                canonical, lambda name: name == "MIN_CONTINUOUS_INTERVAL_MINUTES",
            )
            cgi_values = assigned_integers(
                cgi, lambda name: "CONTINUOUS_INTERVAL_MINUTES" in name,
            )
            cgi_ten_literals = [
                node for node in ast.walk(ast.parse(cgi))
                if isinstance(node, ast.Constant)
                and type(node.value) is int and node.value == 10
            ]
            if len(canonical_values) != 1:
                errors.append("canonical authority must be singular")
            if len(cgi_values) != 1:
                errors.append("CGI ten-minute source must remain singular")
            if len(cgi_ten_literals) != 1:
                errors.append("CGI has an independent ten-minute literal")
            minimums = [value for name, value in cgi_values if name.startswith("MIN_")]
            if len(minimums) != 1 or not canonical_values or minimums[0] != canonical_values[0][1]:
                errors.append("CGI minimum differs from canonical authority")
            if "from project_contract import" in cgi or "import project_contract" in cgi:
                errors.append("CGI must not gain a runtime authority import")
            return errors

        self.assertEqual([], parity_errors(contract_source, cgi_source))
        self.assertTrue(parity_errors(
            contract_source.replace(
                "MIN_CONTINUOUS_INTERVAL_MINUTES = 10",
                "MIN_CONTINUOUS_INTERVAL_MINUTES = 11",
                1,
            ),
            cgi_source,
        ))
        self.assertTrue(parity_errors(
            contract_source,
            cgi_source + "\nFLOOR = 10\n",
        ))

    def test_continuous_start_rejects_same_type_manual_work_only(self):
        with mock.patch.object(
            self.switch_cgi, "send_memory_request",
        ) as send_memory_request:
            blocked_collection = self._post_switch_action(
                "action=continuous_collection_start&interval_minutes=10",
                switch_state="collecting",
            )
            self.assertEqual("409 Conflict", blocked_collection.call_args.args[1])
            send_memory_request.assert_not_called()

            allowed_collection = self._post_switch_action(
                "action=continuous_collection_start&interval_minutes=10",
                backup_state="collecting",
            )
            self.assertEqual("scheduled", allowed_collection.call_args.args[0]["state"])

        with mock.patch.object(
            self.switch_cgi, "send_memory_request",
        ) as send_memory_request:
            blocked_backup = self._post_switch_action(
                "action=continuous_backup_start&password=sentinel&interval_minutes=10",
                backup_state="collecting",
            )
            self.assertEqual("409 Conflict", blocked_backup.call_args.args[1])
            send_memory_request.assert_not_called()

            allowed_backup = self._post_switch_action(
                "action=continuous_backup_start&password=sentinel&interval_minutes=10",
                switch_state="collecting",
            )
            self.assertEqual("scheduled", allowed_backup.call_args.args[0]["state"])

    def test_worker_rejects_continuous_start_when_same_lane_is_already_busy(self):
        collection_request = {
            "action": "continuous_collection_start", "interval_minutes": 10,
        }
        backup_request = {
            "action": "continuous_backup_start", "password": "sentinel",
            "interval_minutes": 10,
        }
        with mock.patch.object(
            self.switch_worker, "lane_busy",
            side_effect=lambda lane: lane in {"collection", "backup"},
        ), mock.patch.object(
            self.switch_worker, "write_continuous_status",
        ), mock.patch.object(
            self.switch_worker, "write_continuous_backup_status",
        ):
            with self.assertRaisesRegex(ValueError, "collection task is already running"):
                self.switch_worker.handle_memory_request(
                    collection_request, "prod", 60, 7,
                )
            with self.assertRaisesRegex(ValueError, "backup task is already running"):
                self.switch_worker.handle_memory_request(
                    backup_request, "prod", 60, 7,
                )
        self.assertFalse(self.switch_worker.continuous_collection_enabled())
        self.assertFalse(self.switch_worker.continuous_backup_enabled())

    def test_continuous_stop_cannot_be_overwritten_by_a_waiting_cycle(self):
        cases = (
            (
                "collection", "run_continuous_collection_cycle",
                "stop_continuous_collection_mode", "write_continuous_status",
            ),
            (
                "backup", "run_continuous_backup_cycle",
                "stop_continuous_backup_mode", "write_continuous_backup_status",
            ),
        )
        for lane, cycle_name, stop_name, status_name in cases:
            with self.subTest(lane=lane):
                worker = load_module(
                    f"review_switch_worker_stop_race_{lane}",
                    ROOT / "monitor/switch-collection-worker.py",
                )
                if lane == "collection":
                    worker._CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 600
                else:
                    worker._CONTINUOUS_BACKUP_PASSWORD = "*"
                    worker._CONTINUOUS_BACKUP_INTERVAL_SECONDS = 600
                reached = threading.Event()
                release = threading.Event()
                statuses = []

                def cooldown_wait(_scope, selected_lane):
                    self.assertEqual(lane, selected_lane)
                    reached.set()
                    self.assertTrue(release.wait(2))
                    return {
                        "remaining_seconds": 300,
                        "wait_reason": f"{lane} cooldown",
                        "next_allowed_at": "",
                    }

                with mock.patch.object(
                    worker, "continuous_cooldown_wait", side_effect=cooldown_wait,
                ), mock.patch.object(
                    worker, status_name,
                    side_effect=lambda state, **extra: statuses.append((state, extra)),
                ):
                    cycle = threading.Thread(
                        target=getattr(worker, cycle_name), args=("prod", 60, 7),
                    )
                    cycle.start()
                    self.assertTrue(reached.wait(2))
                    getattr(worker, stop_name)("operator")
                    release.set()
                    cycle.join(2)
                self.assertFalse(cycle.is_alive())
                self.assertEqual("stopped", statuses[-1][0])
                self.assertIs(False, statuses[-1][1]["enabled"])

    def test_continuous_stop_drains_the_current_same_type_task(self):
        cases = (
            (
                "collection", "run_continuous_collection_cycle",
                "stop_continuous_collection_mode", "write_continuous_status",
                "collect_safely", "continuous_collection_enabled",
            ),
            (
                "backup", "run_continuous_backup_cycle",
                "stop_continuous_backup_mode", "write_continuous_backup_status",
                "run_yaml_backup_safely", "continuous_backup_enabled",
            ),
        )
        for lane, cycle_name, stop_name, status_name, work_name, enabled_name in cases:
            with self.subTest(lane=lane):
                worker = load_module(
                    f"review_switch_worker_graceful_stop_{lane}",
                    ROOT / "monitor/switch-collection-worker.py",
                )
                if lane == "collection":
                    worker._CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 600
                else:
                    worker._CONTINUOUS_BACKUP_PASSWORD = "*"
                    worker._CONTINUOUS_BACKUP_INTERVAL_SECONDS = 600
                entered = threading.Event()
                release = threading.Event()
                statuses = []

                def current_work(*_args):
                    entered.set()
                    self.assertTrue(release.wait(2))
                    return True

                with mock.patch.object(
                    worker, "continuous_cooldown_wait", return_value={},
                ), mock.patch.object(
                    worker, work_name, side_effect=current_work,
                ), mock.patch.object(
                    worker, status_name,
                    side_effect=lambda state, **extra: statuses.append((state, extra)),
                ):
                    self.assertTrue(worker.start_lane_task(
                        lane, "continuous", getattr(worker, cycle_name),
                        "prod", 60, 7,
                    ))
                    self.assertTrue(entered.wait(2))
                    getattr(worker, stop_name)("operator")
                    self.assertTrue(worker.lane_busy(lane))
                    self.assertFalse(worker.lane_cancelled(lane))
                    self.assertTrue(getattr(worker, enabled_name)())
                    self.assertEqual("stopping", statuses[-1][0])
                    self.assertIs(True, statuses[-1][1]["enabled"])
                    release.set()
                    worker.join_lane_tasks(timeout=2)
                self.assertEqual("stopped", statuses[-1][0])
                self.assertIs(False, statuses[-1][1]["enabled"])
                self.assertFalse(getattr(worker, enabled_name)())

    def test_continuous_cycles_wait_only_for_their_own_manual_cooldown(self):
        project = "/project/current"
        collection_statuses = []
        backup_statuses = []
        with tempfile.TemporaryDirectory() as directory:
            status_dir = Path(directory)
            with self.switch_worker.CollectionGate(
                project, "prod",
                collection_keys=(
                    "prod-ethernet", "prod-infiniband", "prod-nvlink",
                ),
                status_dir=status_dir, clock=lambda: 1_000.0,
                lane="collection",
            ) as gate:
                self.assertTrue(gate.decision.allowed)
                gate.mark_success()
            with self.switch_worker.CollectionGate(
                project, "prod", collection_keys=("yaml-backup",),
                status_dir=status_dir, clock=lambda: 1_050.0, lane="backup",
            ) as gate:
                self.assertTrue(gate.decision.allowed)
                gate.mark_success()

            self.switch_worker._CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 600
            self.switch_worker._CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
            self.switch_worker._CONTINUOUS_BACKUP_PASSWORD = "sentinel"
            self.switch_worker._CONTINUOUS_BACKUP_INTERVAL_SECONDS = 1200
            self.switch_worker._CONTINUOUS_BACKUP_NEXT_RUN = 0.0
            with mock.patch.object(
                self.switch_worker, "STATUS_DIR", status_dir,
            ), mock.patch.object(
                self.switch_worker, "active_project_identity", return_value=project,
            ), mock.patch.object(
                self.switch_worker.time, "time", return_value=1_100.0,
            ), mock.patch.object(
                self.switch_worker.time, "monotonic", return_value=500.0,
            ), mock.patch.object(
                self.switch_worker, "write_continuous_status",
                side_effect=lambda state, **extra: collection_statuses.append((state, extra)),
            ), mock.patch.object(
                self.switch_worker, "write_continuous_backup_status",
                side_effect=lambda state, **extra: backup_statuses.append((state, extra)),
            ), mock.patch.object(
                self.switch_worker, "collect_safely",
                side_effect=AssertionError("collection ran during cooldown"),
            ), mock.patch.object(
                self.switch_worker, "run_yaml_backup_safely",
                side_effect=AssertionError("backup ran during cooldown"),
            ):
                self.assertTrue(
                    self.switch_worker.run_continuous_collection_cycle("prod", 60, 7)
                )
                self.assertTrue(
                    self.switch_worker.run_continuous_backup_cycle("prod", 60, 7)
                )

        self.assertEqual(500, collection_statuses[-1][1]["remaining_seconds"])
        self.assertEqual("collection cooldown", collection_statuses[-1][1]["wait_reason"])
        self.assertEqual(550, backup_statuses[-1][1]["remaining_seconds"])
        self.assertEqual("backup cooldown", backup_statuses[-1][1]["wait_reason"])
        with mock.patch.object(self.switch_worker, "write_continuous_status"), \
                mock.patch.object(
                    self.switch_worker, "write_continuous_backup_status",
                ):
            self.switch_worker.stop_continuous_collection_mode("test cleanup")
            self.switch_worker.stop_continuous_backup_mode("test cleanup")

    def test_worker_status_transitions_preserve_unexpired_cooldowns(self):
        with tempfile.TemporaryDirectory() as directory:
            status_dir = Path(directory)
            switch_status = status_dir / "switch.json"
            backup_status = status_dir / "backup.json"
            with mock.patch.object(
                self.switch_worker, "STATUS_DIR", status_dir,
            ), mock.patch.object(
                self.switch_worker, "STATUS_FILE", switch_status,
            ), mock.patch.object(
                self.switch_worker, "YAML_BACKUP_STATUS_FILE", backup_status,
            ), mock.patch.object(
                self.switch_worker.time, "time", return_value=1_000.0,
            ):
                self.switch_worker.write_status(
                    "success", next_allowed_epoch=1_500.0,
                    next_allowed_at="2026-09-09T12:10:00+08:00",
                    cooldown_seconds=600,
                )
                self.switch_worker.write_yaml_backup_status(
                    "success", next_allowed_epoch=1_550.0,
                    next_allowed_at="2026-09-09T12:10:50+08:00",
                    cooldown_seconds=600,
                )
                self.switch_worker.write_status("idle", stopped_at="now")
                self.switch_worker.write_yaml_backup_status("idle", stopped_at="now")

            switch_payload = json.loads(switch_status.read_text(encoding="utf-8"))
            backup_payload = json.loads(backup_status.read_text(encoding="utf-8"))
        self.assertEqual("idle", switch_payload["state"])
        self.assertEqual(1_500.0, switch_payload["next_allowed_epoch"])
        self.assertEqual("idle", backup_payload["state"])
        self.assertEqual(1_550.0, backup_payload["next_allowed_epoch"])

    def test_manual_collection_is_not_dispatched_during_post_continuous_cooldown(self):
        body = "action=collect"
        response = mock.Mock()
        write_request = mock.Mock()
        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/switch-collection",
            "HTTP_X_REQUESTED_WITH": "SwitchCollectionControl",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(
                    self.switch_cgi, "process_state", return_value=(True, 321),
                ), mock.patch.object(
                    self.switch_cgi, "collection_status", return_value={
                        "state": "success", "remaining_seconds": 300,
                        "next_allowed_at": "2026-09-09T12:10:00+08:00",
                    },
                ), mock.patch.object(
                    self.switch_cgi, "yaml_backup_status", return_value={
                        "state": "success", "remaining_seconds": 300,
                    },
                ), mock.patch.object(
                    self.switch_cgi, "continuous_status", return_value={
                        "state": "stopped", "enabled": False,
                    },
                ), mock.patch.object(
                    self.switch_cgi, "write_request", write_request,
                ), mock.patch.object(self.switch_cgi, "respond", response):
            self.switch_cgi.main()

        write_request.assert_not_called()
        self.assertIn("cooling down", response.call_args.args[0]["error"])
        self.assertEqual("409 Conflict", response.call_args.args[1])

    def test_memory_request_decoder_rejects_secret_and_schedule_ambiguity(self):
        invalid = [
            b'not-json',
            json.dumps({"action": "yaml_backup", "password": "x", "extra": 1}).encode(),
            json.dumps({"action": "yaml_backup", "password": "x\n"}).encode(),
            json.dumps({
                "action": "continuous_start", "password": "x",
                "interval_minutes": True,
            }).encode(),
            json.dumps({
                "action": "continuous_start", "password": "x",
                "interval_minutes": 9,
            }).encode(),
            json.dumps({
                "action": "continuous_start", "password": "x",
                "interval_minutes": 1441,
            }).encode(),
            b"x" * 2049,
        ]
        for payload in invalid:
            with self.subTest(payload=payload[:80]), self.assertRaises(ValueError):
                self.switch_worker.decode_yaml_backup_request(payload)

    @unittest.skipIf(
        sys.platform == "darwin",
        "the macOS workspace sandbox forbids filesystem AF_UNIX binds",
    )
    def test_yaml_backup_memory_socket_is_private_and_inode_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.sock"
            group = SimpleNamespace(gr_gid=os.getgid())
            with mock.patch.object(
                self.switch_worker.sys, "platform", "linux",
            ), mock.patch.object(
                self.switch_worker.os, "geteuid", return_value=0,
            ), mock.patch.object(
                self.switch_worker.os, "chown",
            ), mock.patch.object(
                self.switch_worker.grp, "getgrnam", return_value=group,
            ):
                endpoint, identity = self.switch_worker.open_memory_socket(path)
                metadata = os.lstat(path)
                self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
                self.assertEqual(0o660, stat.S_IMODE(metadata.st_mode))
                self.assertEqual(1, metadata.st_nlink)
                self.assertEqual((metadata.st_dev, metadata.st_ino), identity)

                replacement = Path(directory) / "replacement.sock"
                other = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    other.bind(str(replacement))
                    os.replace(replacement, path)
                    self.switch_worker.close_memory_socket(endpoint, identity, path)
                    self.assertTrue(path.exists())
                    self.assertTrue(stat.S_ISSOCK(os.lstat(path).st_mode))
                finally:
                    other.close()

    def test_ztp_start_when_process_is_missing_routes_runtime_recovery(self):
        response = mock.Mock()
        body = "action=start"
        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
            "HTTP_X_REQUESTED_WITH": "ZTPMonitorControl",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(
                    self.ztp_cgi, "process_state", return_value=(False, None),
                ), mock.patch.object(
                    self.ztp_cgi, "control_auth_status", return_value=True,
                ), mock.patch.object(self.ztp_cgi, "respond", response):
            self.ztp_cgi.main()

        response.assert_called_once()
        payload, status = response.call_args.args
        self.assertEqual("409 Conflict", status)
        self.assertEqual("stopped", payload["state"])
        self.assertFalse(payload["process_alive"])
        self.assertEqual(
            {"factory_records_active": True}, payload["control_auth"],
        )
        guidance = payload["error"]
        self.assertIn("按当前后端恢复", guidance)
        self.assertIn("Native/systemd", guidance)
        self.assertIn("DAY0-Prepare/11-load.py", guidance)
        self.assertIn("--start-ztp-monitor", guidance)
        self.assertIn("Docker/Supervisor", guidance)
        self.assertIn("infra/docker/deploy.sh deploy", guidance)
        self.assertIn("deploy-preloaded <IMAGE_ID>", guidance)
        self.assertIn("没有 source write", guidance)
        self.assertIn("infra/docker/deploy.sh load", guidance)

    def test_control_files_reject_hardlinks_before_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_text("original\n", encoding="utf-8")
            linked = root / "linked"
            os.link(victim, linked)
            with mock.patch.object(self.ztp_cgi, "CONTROL_FILE", linked):
                with self.assertRaises(OSError):
                    self.ztp_cgi.write_control("paused")
            self.assertEqual("original\n", victim.read_text(encoding="utf-8"))
            with mock.patch.object(self.switch_cgi, "REQUEST_FILE", linked):
                with self.assertRaises(OSError):
                    self.switch_cgi.write_request("collect")
            self.assertEqual("original\n", victim.read_text(encoding="utf-8"))

    def test_manual_queue_rejects_hardlink_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_text('{"requests": []}\n', encoding="utf-8")
            linked = root / "request.json"
            os.link(victim, linked)
            with mock.patch.object(self.manual_cgi, "REQUEST_FILE", linked):
                with self.assertRaises(OSError):
                    self.manual_cgi.enqueue_request("EXAMPLE-Leaf01")
            self.assertEqual('{"requests": []}\n', victim.read_text(encoding="utf-8"))
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (1024 * 1024 + 1))
            with mock.patch.object(self.manual_cgi, "REQUEST_FILE", oversized):
                with self.assertRaises(OSError):
                    self.manual_cgi.enqueue_request("EXAMPLE-Leaf01")

    def test_manual_queue_retains_busy_host_and_releases_other_host(self):
        payload = {"requests": [
            {"hostname": "EXAMPLE-LeafA", "action": "trigger", "phase": "preview"},
            {"hostname": "EXAMPLE-LeafB", "action": "trigger", "phase": "preview"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(self.manual_worker, "REQUEST_FILE", request):
                runnable = self.manual_worker.pop_requests({"example-leafa"})
            self.assertEqual(["EXAMPLE-LeafB"], [item["hostname"] for item in runnable])
            retained = json.loads(request.read_text(encoding="utf-8"))["requests"]
            self.assertEqual(["EXAMPLE-LeafA"], [item["hostname"] for item in retained])

    def test_switch_request_accepts_only_non_interrupting_manual_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request"
            request.write_text("stop\n", encoding="utf-8")
            with mock.patch.object(self.switch_worker, "REQUEST_FILE", request):
                self.assertEqual("", self.switch_worker.claim_request("collect"))
                self.assertEqual("stop\n", request.read_text(encoding="utf-8"))
                self.assertEqual("", self.switch_worker.claim_request("stop"))
                self.assertEqual("stop\n", request.read_text(encoding="utf-8"))
                request.write_text("collect\n", encoding="utf-8")
                self.assertEqual("collect", self.switch_worker.claim_request("collect"))
                self.assertEqual("idle\n", request.read_text(encoding="utf-8"))

    def test_worker_parses_bounded_partial_task_results(self):
        payload = {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "partial",
            "planned": 3,
            "succeeded": 2,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf03",
                "operation": "ssh_prepare",
                "reason": "unreachable",
            }],
        }
        output = "ordinary log\n[HTTP_ZTP_TASK_RESULT] " + json.dumps(payload) + "\n"
        self.assertEqual(
            payload,
            self.switch_worker.parse_task_result(output, "switch_collection"),
        )
        invalid = dict(payload, failed_count=2)
        with self.assertRaisesRegex(ValueError, "failed_count"):
            self.switch_worker.parse_task_result(
                "[HTTP_ZTP_TASK_RESULT] " + json.dumps(invalid),
                "switch_collection",
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.switch_worker.parse_task_result(output + output, "switch_collection")

    def test_worker_collection_workflow_completes_with_device_warnings(self):
        partial = {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "partial",
            "planned": 2,
            "succeeded": 1,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf02",
                "operation": "retrieve_info",
                "reason": "unreachable",
            }],
        }
        success = {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "success",
            "planned": 1,
            "succeeded": 1,
            "failed_count": 0,
            "failed_devices": [],
        }
        results = [
            ({"returncode": 0, "stdout": "[HTTP_ZTP_TASK_RESULT] "
              + json.dumps(partial) + "\n", "stderr": ""}, False),
            ({"returncode": 0, "stdout": "[HTTP_ZTP_TASK_RESULT] "
              + json.dumps(success) + "\n", "stderr": ""}, False),
        ]
        statuses = []

        class Gate:
            cooldown_seconds = 600
            decision = SimpleNamespace(allowed=True, reason="allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def mark_success(self):
                return "2026-09-10T10:00:00+08:00"

        commands = [
            ["bash", str(ROOT / "ethernet/monitor/cron.sh")],
            ["bash", str(ROOT / "infiniband/monitor/cron.sh")],
        ]
        with mock.patch.object(
            self.switch_worker, "active_project_identity", return_value="project-a",
        ), mock.patch.object(
            self.switch_worker, "CollectionGate", return_value=Gate(),
        ), mock.patch.object(
            self.switch_worker, "commands_for_scope", return_value=commands,
        ), mock.patch.object(
            self.switch_worker, "run_interruptible", side_effect=results,
        ), mock.patch.object(
            self.switch_worker.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ), mock.patch.object(
            self.switch_worker, "write_status",
            side_effect=lambda state, **extra: statuses.append((state, extra)),
        ):
            self.assertTrue(self.switch_worker.collect("prod", 60, 7))

        self.assertEqual("partial", statuses[-1][0])
        self.assertEqual(1, statuses[-1][1]["failed_count"])
        self.assertEqual("leaf02", statuses[-1][1]["failed_devices"][0]["hostname"])

    def test_worker_collection_keeps_a_successful_family_when_another_fails(self):
        failed = {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "failed",
            "planned": 2,
            "succeeded": 0,
            "failed_count": 2,
            "failed_devices": [
                {
                    "hostname": "leaf01",
                    "operation": "ssh_prepare",
                    "reason": "unreachable",
                },
                {
                    "hostname": "leaf02",
                    "operation": "ssh_prepare",
                    "reason": "unreachable",
                },
            ],
        }
        success = {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "success",
            "planned": 1,
            "succeeded": 1,
            "failed_count": 0,
            "failed_devices": [],
        }
        results = [
            ({"returncode": 1, "stdout": "[HTTP_ZTP_TASK_RESULT] "
              + json.dumps(failed) + "\n", "stderr": ""}, False),
            ({"returncode": 0, "stdout": "[HTTP_ZTP_TASK_RESULT] "
              + json.dumps(success) + "\n", "stderr": ""}, False),
        ]
        statuses = []

        class Gate:
            cooldown_seconds = 600
            decision = SimpleNamespace(allowed=True, reason="allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def mark_success(self):
                return "2026-09-10T10:00:00+08:00"

        commands = [
            ["bash", str(ROOT / "ethernet/monitor/cron.sh")],
            ["bash", str(ROOT / "infiniband/monitor/cron.sh")],
        ]
        with mock.patch.object(
            self.switch_worker, "active_project_identity", return_value="project-a",
        ), mock.patch.object(
            self.switch_worker, "CollectionGate", return_value=Gate(),
        ), mock.patch.object(
            self.switch_worker, "commands_for_scope", return_value=commands,
        ), mock.patch.object(
            self.switch_worker, "run_interruptible", side_effect=results,
        ), mock.patch.object(
            self.switch_worker.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ), mock.patch.object(
            self.switch_worker, "write_status",
            side_effect=lambda state, **extra: statuses.append((state, extra)),
        ):
            self.assertTrue(self.switch_worker.collect("prod", 60, 7))

        self.assertEqual("partial", statuses[-1][0])
        self.assertEqual((3, 1, 2), (
            statuses[-1][1]["planned"],
            statuses[-1][1]["succeeded"],
            statuses[-1][1]["failed_count"],
        ))
        self.assertEqual(
            ["leaf01", "leaf02"],
            [item["hostname"] for item in statuses[-1][1]["failed_devices"]],
        )

    def test_worker_backup_workflow_completes_with_device_warnings(self):
        partial = {
            "schema_version": 1,
            "task": "yaml_backup",
            "state": "partial",
            "planned": 2,
            "succeeded": 1,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf02",
                "operation": "yaml_backup",
                "reason": "sudo denied",
            }],
        }
        statuses = []

        class Gate:
            cooldown_seconds = 600
            decision = SimpleNamespace(allowed=True, reason="allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def mark_success(self):
                return "2026-09-10T10:00:00+08:00"

        completed = {
            "returncode": 0,
            "stdout": "[HTTP_ZTP_TASK_RESULT] " + json.dumps(partial) + "\n",
            "stderr": "",
        }
        with mock.patch.object(
            self.switch_worker, "active_project_identity", return_value="project-a",
        ), mock.patch.object(
            self.switch_worker, "CollectionGate", return_value=Gate(),
        ), mock.patch.object(
            self.switch_worker, "run_interruptible", return_value=(completed, False),
        ), mock.patch.object(
            self.switch_worker, "write_yaml_backup_status",
            side_effect=lambda state, **extra: statuses.append((state, extra)),
        ):
            self.assertTrue(
                self.switch_worker.run_yaml_backup("sentinel", "prod", 60, 7)
            )

        self.assertEqual("partial", statuses[-1][0])
        self.assertEqual(1, statuses[-1][1]["failed_count"])
        self.assertEqual("leaf02", statuses[-1][1]["failed_devices"][0]["hostname"])

    def test_worker_backup_all_failed_status_keeps_the_device_summary(self):
        failed = {
            "schema_version": 1,
            "task": "yaml_backup",
            "state": "failed",
            "planned": 2,
            "succeeded": 0,
            "failed_count": 2,
            "failed_devices": [
                {"hostname": "leaf01", "operation": "connect", "reason": "timeout"},
                {"hostname": "leaf02", "operation": "connect", "reason": "no route"},
            ],
        }
        statuses = []

        class Gate:
            cooldown_seconds = 600
            decision = SimpleNamespace(allowed=True, reason="allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        completed = {
            "returncode": 1,
            "stdout": "[HTTP_ZTP_TASK_RESULT] " + json.dumps(failed) + "\n",
            "stderr": "",
        }
        with mock.patch.object(
            self.switch_worker, "active_project_identity", return_value="project-a",
        ), mock.patch.object(
            self.switch_worker, "CollectionGate", return_value=Gate(),
        ), mock.patch.object(
            self.switch_worker, "run_interruptible", return_value=(completed, False),
        ), mock.patch.object(
            self.switch_worker, "write_yaml_backup_status",
            side_effect=lambda state, **extra: statuses.append((state, extra)),
        ):
            self.assertFalse(
                self.switch_worker.run_yaml_backup("sentinel", "prod", 60, 7)
            )

        self.assertEqual("failed", statuses[-1][0])
        self.assertEqual(2, statuses[-1][1]["failed_count"])
        self.assertEqual(
            "all 2 selected device(s) failed", statuses[-1][1]["summary"]
        )
        self.assertEqual(
            ["leaf01", "leaf02"],
            [item["hostname"] for item in statuses[-1][1]["failed_devices"]],
        )

    def test_yaml_backup_workflow_summarizes_unreachable_devices_and_continues(self):
        devices = [
            {"hostname": name, "fmt": "eth", "eth0_ip": "192.0.2.1",
             "eth0_pfx": "24", "eth0_gw": "", "eth0_mac": "02:00:00:00:00:01",
             "eth1_ip": "", "eth1_pfx": "", "eth1_gw": "", "eth1_mac": ""}
            for name in ("leaf01", "leaf02", "leaf03")
        ]

        def result_for(device, *_args):
            if device["hostname"] == "leaf03":
                return (["all addresses unreachable"], None)
            result = dict(device)
            result.update({
                "sn": "SN", "yaml_ok": device["hostname"] == "leaf01",
                "yaml_error": "sudo denied" if device["hostname"] == "leaf02" else "",
            })
            return (["collected"], result)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "02-devices_config.csv"
            inventory.write_text("fixture\n", encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(self.yaml_backup, "SCRIPT_DIR", str(root)), \
                    mock.patch.object(
                        self.yaml_backup, "_parse_args",
                        return_value=(True, "prod", False, None),
                    ), mock.patch.object(
                        self.yaml_backup, "_inventory_paths",
                        return_value=[str(inventory)],
                    ), mock.patch.object(
                        self.yaml_backup, "load_devices_csv", return_value=devices,
                    ), mock.patch.object(
                        self.yaml_backup, "_resolve_backup_passwords",
                        return_value=("", "", ""),
                    ), mock.patch.object(
                        self.yaml_backup, "_confirm", return_value=True,
                    ), mock.patch.object(
                        self.yaml_backup, "collect_device", side_effect=result_for,
                    ), mock.patch.object(
                        self.yaml_backup, "compare_csv_files",
                    ), mock.patch.object(sys, "stdout", output):
                self.yaml_backup.main()

        markers = [
            line for line in output.getvalue().splitlines()
            if line.startswith("[HTTP_ZTP_TASK_RESULT] ")
        ]
        self.assertEqual(1, len(markers), output.getvalue())
        payload = json.loads(markers[0].split(" ", 1)[1])
        self.assertEqual("yaml_backup", payload["task"])
        self.assertEqual("partial", payload["state"])
        self.assertEqual((3, 1, 2), (
            payload["planned"], payload["succeeded"], payload["failed_count"],
        ))
        self.assertEqual(
            ["leaf02", "leaf03"],
            [item["hostname"] for item in payload["failed_devices"]],
        )

    def test_monitor_manifest_maps_backup_into_the_collection_workflow(self):
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        backup_rule = next(
            item for item in manifest["test_rules"] if item["id"] == "ztp_backup"
        )
        self.assertIn("test_cases.test_monitor_stack_review", backup_rule["tests"])
        workflow = next(
            item for item in manifest["workflows"]
            if item["id"] == "switch_collection_publication"
        )
        self.assertIn("ztp/backup/*", workflow["members"])

    def test_time_sync_is_independent_and_never_writes_a_ztp_round(self):
        writes = []

        def record(_hostname, state, **values):
            writes.append((state, values))

        completed = subprocess.CompletedProcess(
            ["time-sync"], 0,
            stdout=(
                '[TIME_SYNC_RESULT] {"state":"success",'
                '"offset_seconds":0.1,"uncertainty_seconds":0.2, '
                '"transport_ip":"192.0.2.10","interface":"eth0"}\n'
            ),
            stderr="",
        )
        with mock.patch.object(
            self.manual_worker, "write_device_status", side_effect=record,
        ), mock.patch.object(
            self.manual_worker, "command_for", return_value=["fixed-helper"],
        ), mock.patch.object(
            self.manual_worker.subprocess, "run", return_value=completed,
        ):
            self.manual_worker.execute_time_sync(
                "EXAMPLE-Leaf01", "prod", 30, "operation-1", "trigger-1",
            )
        self.assertEqual("time_sync_running", writes[0][0])
        self.assertEqual("time_sync_success", writes[-1][0])
        for _state, values in writes:
            self.assertTrue({"ztp_round", "baseline_round", "expected_round"}.isdisjoint(values))

    def test_replace_config_action_is_bound_across_cgi_worker_and_cli(self):
        request = json.dumps({
            "action": "replace-config",
            "hostname": "EXAMPLE-Leaf01",
            "phase": "config_sync",
        }).encode("utf-8")
        self.assertEqual(
            "replace-config",
            self.manual_cgi._decode_queue(request)[0]["action"],
        )
        self.assertEqual(
            "replace-config",
            self.manual_worker._decode_queue(request)[0]["action"],
        )
        command = self.manual_worker.command_for(
            "EXAMPLE-Leaf01", "prod", operation="replace-config",
            operation_id="operation-1", trigger_id="trigger-1",
        )
        self.assertIn("--replace-config", command)
        self.assertNotIn("--operation", command)
        self.assertEqual(8, self.manual_worker.parser().parse_args([
            "--scope", "prod",
        ]).max_workers)

    def test_replace_config_worker_has_distinct_running_and_success_states(self):
        writes = []

        def record(_hostname, state, **values):
            writes.append((state, values))

        completed = subprocess.CompletedProcess(
            ["replace-config"], 0, stdout="accepted\n", stderr="",
        )
        accepted = {
            "state": "triggered", "operation": "replace-config",
            "effective_operation": "replace-config",
            "trigger_source": "manual_config_sync_web",
        }
        with mock.patch.object(
            self.manual_worker, "write_device_status", side_effect=record,
        ), mock.patch.object(
            self.manual_worker, "latest_device_state", return_value={},
        ), mock.patch.object(
            self.manual_worker, "command_for", return_value=["fixed-helper"],
        ), mock.patch.object(
            self.manual_worker.subprocess, "run", return_value=completed,
        ), mock.patch.object(
            self.manual_worker, "accepted_result", return_value=accepted,
        ), mock.patch.object(
            self.manual_worker, "wait_for_completion",
        ) as wait_for_completion:
            self.manual_worker.execute(
                "EXAMPLE-Leaf01", "prod", 30, 60, 1,
                operation="replace-config", operation_id="operation-1",
                trigger_id="trigger-1", requested_operation="replace-config",
                preview_fingerprint={"current_sha256": "a" * 64},
            )
        self.assertEqual("config_sync_running", writes[0][0])
        self.assertEqual("config_sync_success", writes[-1][0])
        self.assertEqual("config_sync", writes[-1][1]["phase"])
        wait_for_completion.assert_not_called()

    def test_replace_config_page_contract_reconciles_button_column_and_states(self):
        html_source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8",
        )
        cgi_source = (ROOT / "monitor/manual-ztp-control.cgi").read_text(
            encoding="utf-8",
        )
        worker_source = (ROOT / "monitor/manual-ztp-worker.py").read_text(
            encoding="utf-8",
        )

        time_header = html_source.index(">时间同步</th>")
        config_header = html_source.index(">配置同步</th>")
        overall_header = html_source.index(">总体 / 诊断</th>")
        self.assertLess(time_header, config_header)
        self.assertLess(config_header, overall_header)
        self.assertIn('data-config-sync="status"', html_source)
        self.assertGreaterEqual(html_source.count('class="config-sync-button"'), 2)
        self.assertRegex(
            html_source,
            r'class="config-sync-button"[^>]*disabled[^>]*>'
            r'配置同步</button>',
        )
        self.assertIn('onclick="requestConfigSync(this)"', html_source)
        for label in (
            "未同步", "同步中", "已同步", "失败", "未知（未绑定身份）",
        ):
            self.assertIn(label, html_source)
        for state in (
            "config_sync_queued", "config_sync_running", "config_sync_success",
        ):
            self.assertIn(state, html_source)
            self.assertIn(state, cgi_source)
            self.assertIn(state, worker_source)
        self.assertIn("action=replace-config", html_source)
        self.assertIn('"replace-config"', cgi_source)
        self.assertIn('"replace-config"', worker_source)

    def test_replace_config_confirmation_warns_about_destructive_full_replace(self):
        html_source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8",
        )
        manual_source = (ROOT / "ztp/manual-ztp.py").read_text(
            encoding="utf-8",
        )
        warning = "本机手工配置若未出现在新生成配置中，将被删除"
        self.assertIn(warning, html_source)
        self.assertIn(warning, manual_source)
        self.assertIn("nv config replace", manual_source)
        self.assertNotIn("nv config patch", manual_source)

    def test_time_sync_rejects_high_measurement_uncertainty(self):
        client = mock.Mock()
        client.args = SimpleNamespace(command_timeout=30, connect_timeout=5)
        client.run.side_effect = [
            subprocess.CompletedProcess(["helper"], 0, stdout="ok\n", stderr=""),
            subprocess.CompletedProcess(["date"], 0, stdout="1010.0\n", stderr=""),
        ]
        times = [
            datetime.fromtimestamp(1000),
            datetime.fromtimestamp(1020),
        ]
        with mock.patch.object(self.manual, "datetime") as mocked_datetime:
            mocked_datetime.now.side_effect = times
            with self.assertRaisesRegex(
                self.manual.ManualZtpError, "无法证明时间偏移不超过 5 秒",
            ):
                self.manual.sync_management_time(
                    client, {"hostname": "EXAMPLE-Leaf01"}, "192.0.2.10", "eth0",
                )

    def test_worker_rejects_success_payload_with_unsafe_time_bound(self):
        writes = []

        def record(_hostname, state, **values):
            writes.append((state, values))

        completed = subprocess.CompletedProcess(
            ["time-sync"], 0,
            stdout=(
                '[TIME_SYNC_RESULT] {"state":"success",'
                '"offset_seconds":0.0,"uncertainty_seconds":10.5, '
                '"transport_ip":"192.0.2.10","interface":"eth0"}\n'
            ),
            stderr="",
        )
        with mock.patch.object(
            self.manual_worker, "write_device_status", side_effect=record,
        ), mock.patch.object(
            self.manual_worker, "command_for", return_value=["fixed-helper"],
        ), mock.patch.object(
            self.manual_worker.subprocess, "run", return_value=completed,
        ):
            self.manual_worker.execute_time_sync(
                "EXAMPLE-Leaf01", "prod", 30, "operation-unsafe", "trigger-unsafe",
            )
        self.assertEqual("time_sync_running", writes[0][0])
        self.assertEqual("failed", writes[-1][0])
        self.assertIn("最坏偏移不超过 5 秒", writes[-1][1]["reason"])

    def test_monitor_marks_zero_midpoint_offset_with_high_uncertainty_warning(self):
        device = {
            "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
            "ssh_ips": ["192.0.2.10"],
            "ssh_interfaces": {"192.0.2.10": "eth0"},
            "mac_plain": "020000000001",
            "stages": {
                name: self.monitor.stage() for name in self.monitor.STAGE_NAMES
            },
            "issues": [], "events": [],
        }
        self.monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-31T12:00:20+00:00",
            "connected_ip": "192.0.2.10", "attempts": [],
            "remote_hostname": "EXAMPLE-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:01",
            "remote_eth1_mac": "", "remote_interface_macs": {
                "eth0": "02:00:00:00:00:01",
            },
            "local_started_epoch": "1000", "local_finished_epoch": "1020",
            "remote_time_start": "1010", "remote_time_end": "1010",
            "boot_id": "boot-1", "boot_time": "1", "ztp_log": "",
            "ifreload_log": "", "failed_yaml": "", "stderr": "",
            "host_key_refreshed": False,
        })
        self.assertEqual("warning", device["time_sync"]["status"])
        self.assertEqual(0.0, device["time_sync"]["offset_seconds"])
        self.assertEqual(10.0, device["time_sync"]["uncertainty_seconds"])


class PublicationAndCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = load_module(
            "review_generate_html", ROOT / "monitor/generate-monitor-html.py"
        )
        cls.dot = load_module(
            "review_dot_html", ROOT / "monitor/dot_to_html.py"
        )
        cls.post = load_module(
            "review_post_collect", ROOT / "ethernet/monitor/post-collect.py"
        )
        cls.gate = load_module(
            "review_collection_gate", ROOT / "monitor/switch_collection_gate.py"
        )

    def test_shared_collector_keeps_reachable_devices_and_emits_one_summary(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertIn("DEVICE_FAILURES=$(mktemp)", source)
        self.assertIn("PLANNED_DEVICES=$(mktemp)", source)
        self.assertIn("record_device_failure()", source)
        self.assertIn("emit_collection_result()", source)
        self.assertIn("[HTTP_ZTP_TASK_RESULT]", source)
        self.assertIn('mv "$successful" "$hosts_file"', source)
        self.assertNotIn("return $((failed > 0 ? 1 : 0))", source)
        self.assertIn('record_device_failure "ssh_prepare"', source)

    def test_shared_collector_partial_batch_preserves_successful_host(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        valid_host = "valid_host_entry() {" + source.split(
            "valid_host_entry() {", 1,
        )[1].split("\n}\n\n# Append AIR-only", 1)[0] + "\n}\n"
        result_helpers = "# Record one device-scoped problem" + source.split(
            "# Record one device-scoped problem", 1,
        )[1].split("# parse_csv_hosts", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / "hosts"
            failures = root / "failures"
            planned = root / "planned"
            hosts.write_text(
                "leaf01|192.0.2.1\nleaf02|192.0.2.2\n", encoding="utf-8",
            )
            planned.write_text("leaf01\nleaf02\n", encoding="utf-8")
            failures.write_text("", encoding="utf-8")
            harness = root / "harness.sh"
            harness.write_text(
                "#!/bin/bash\nMAX_PARALLEL=2\n"
                f"DEVICE_FAILURES={shlex.quote(str(failures))}\n"
                f"PLANNED_DEVICES={shlex.quote(str(planned))}\n"
                + valid_host + result_helpers
                + f"run_parallel {shlex.quote(str(hosts))} "
                + "'[[ \"__NAME__\" == leaf01 ]]' retrieve_info\n"
                + "printf 'hosts-start\\n'; cat " + shlex.quote(str(hosts))
                + "; printf 'hosts-end\\n'\n"
                + "emit_collection_result\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["bash", str(harness)], cwd=root, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("hosts-start\nleaf01|192.0.2.1\nhosts-end", completed.stdout)
        marker = next(
            line for line in completed.stdout.splitlines()
            if line.startswith("[HTTP_ZTP_TASK_RESULT] ")
        )
        payload = json.loads(marker.split(" ", 1)[1])
        self.assertEqual("partial", payload["state"])
        self.assertEqual((2, 1, 1), (
            payload["planned"], payload["succeeded"], payload["failed_count"],
        ))
        self.assertEqual("leaf02", payload["failed_devices"][0]["hostname"])
        self.assertEqual("retrieve_info", payload["failed_devices"][0]["operation"])

    def test_unbound_identity_action_routes_source_write_by_runtime(self):
        rendered = self.html.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-09-06T12:00:00+08:00",
            "devices": [{
                "hostname": "DISCOVERED-CUMULUS-020000000021",
                "type": "pending_eth",
                "platform_family": "cumulus",
                "unbound_identity": True,
                "managed_ztp": True,
                "ip": "192.0.2.21",
                "mac": "02:00:00:00:00:21",
                "stages": {},
                "issues": [],
                "overall": "warning",
                "progress": {"done": 1, "total": 9, "percent": 11},
            }],
        })
        self.assertIn("Native/systemd", rendered)
        self.assertIn("DAY0-Prepare/11-load.py", rendered)
        self.assertIn("Docker/Supervisor", rendered)
        self.assertIn("infra/docker/deploy.sh deploy", rendered)
        self.assertIn("deploy-preloaded &lt;IMAGE_ID&gt;", rendered)
        self.assertIn("source write 后不得 load", rendered)

    def test_ztp_sort_rows_publish_primary_ipv4_and_complete_status_metadata(self):
        stages = {
            "dhcp": {"status": "failed"},
            "bootstrap": {"status": "warning"},
            "config_http": {"status": "running"},
            "ssh": {"status": "pending"},
            "network": {"status": "unknown"},
            "version": {"status": "not_applicable"},
            "config_apply": {"status": "skipped"},
            "ssh_keys": {"status": "success"},
            "complete": {"status": "success"},
        }
        rendered = self.html.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-09-07T14:28:28+08:00",
            "devices": [{
                "hostname": "AIR-h05-oobofoob-leaf10",
                "type": "air",
                "ip": "192.0.2.185",
                "ip_probe": {
                    "candidates": ["192.0.2.184", "192.0.2.9"],
                    "attempts": [],
                    "interfaces": {
                        "192.0.2.184": "eth0", "192.0.2.9": "swp1",
                    },
                },
                "mac": "02:88:e5:18:85:6d",
                "stages": stages,
                "overall": "skipped",
                "progress": {"percent": 33},
                "time_sync": {"status": "warning"},
                "issues": [],
            }],
        })

        self.assertIn(
            'class="ztp-ip-cell" data-sort-kind="ip" '
            'data-sort-value="3221226168" data-sort-missing="false"',
            rendered,
        )
        expected_stage_ranks = {
            "dhcp": ("failed", 0),
            "bootstrap": ("warning", 1),
            "config_http": ("running", 2),
            "ssh": ("pending", 3),
            "network": ("unknown", 4),
            "version": ("not_applicable", 6),
            "config_apply": ("skipped", 5),
            "ssh_keys": ("success", 7),
            "complete": ("success", 7),
        }
        for stage, (status, rank) in expected_stage_ranks.items():
            with self.subTest(stage=stage):
                self.assertIn(
                    f'data-ztp-stage="{stage}" data-sort-kind="status" '
                    f'data-sort-value="{rank}" data-sort-missing="false" '
                    f'data-sort-status="{status}"',
                    rendered,
                )
        self.assertIn(
            'data-ztp-stage="progress" data-sort-kind="number" '
            'data-sort-value="33" data-sort-missing="false"',
            rendered,
        )
        self.assertIn(
            'data-ztp-stage="overall" data-sort-kind="status" '
            'data-sort-value="5" data-sort-missing="false" '
            'data-sort-status="skipped"',
            rendered,
        )

    def test_ztp_initial_device_order_is_natural_and_missing_ip_is_explicit(self):
        def device(hostname, ip):
            return {
                "hostname": hostname, "type": "air", "ip": ip,
                "mac": "", "stages": {}, "overall": "pending",
                "progress": {"percent": 0}, "issues": [],
            }

        rendered = self.html.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-09-07T14:28:28+08:00",
            "devices": [
                device("AIR-h05-oobofoob-leaf10", "192.0.2.185"),
                device("AIR-h05-oobofoob-leaf2", "192.0.2.177"),
                device("AIR-h05-oobofoob-leaf20", ""),
            ],
        })

        self.assertLess(
            rendered.index("AIR-h05-oobofoob-leaf2"),
            rendered.index("AIR-h05-oobofoob-leaf10"),
        )
        missing_row = rendered.split(
            'data-hostname="AIR-h05-oobofoob-leaf20"', 1,
        )[1].split("</tr>", 1)[0]
        self.assertIn(
            'class="ztp-ip-cell" data-sort-kind="ip" data-sort-value="" '
            'data-sort-missing="true"',
            missing_row,
        )

    def test_link_rows_publish_typed_sort_metadata_for_every_sortable_column(self):
        headers = [
            "Hostname", "Interface", "Effective-BER", "Effective-Error",
            "Carrier-Down-Count", "State", "Peer",
        ]
        latest = {
            ("leaf10", "swp10"): [
                "leaf10", "swp10", "1E-8", "0.01", "10", "up", "leaf2",
            ],
            ("leaf2", "swp2"): [
                "leaf2", "swp2", "9E-9", "0.001", "", "down", "leaf10",
            ],
        }
        thead, tbody, _stats, _hist = self.html.build_link_content(
            [], headers, latest, datetime(2026, 9, 7, 14, 28), [], [],
            show_transceiver_temp=False,
        )

        self.assertIn(
            'class="sc" data-sort-kind="text" aria-sort="none" '
            'onclick="srt(this,0)"',
            thead,
        )
        self.assertIn(
            'data-sort-kind="number" aria-sort="none" '
            'onclick="srt(this,4)"',
            thead,
        )
        self.assertIn(
            'data-sort-kind="number" data-sort-value="9E-9" '
            'data-sort-missing="false">9E-9</td>',
            tbody,
        )
        self.assertIn(
            'data-sort-kind="number" data-sort-value="0.001" '
            'data-sort-missing="false">0.001</td>',
            tbody,
        )
        self.assertIn(
            'data-sort-kind="number" data-sort-value="" '
            'data-sort-missing="true"></td>',
            tbody,
        )
        self.assertLess(tbody.index('data-dev="leaf2"'), tbody.index('data-dev="leaf10"'))

        numeric_headers = {
            "Effective-BER", "Effective-Error", "Carrier-Transitions",
            "ECN-Marked", "PFC-Receive", "PFC-Send",
            "Carrier-Down-Count", "QP1-Drops-Receive", "QP1-Drops-Transmit",
            "Link-Downed", "QP1-Drops", "RX-Physical-Errors",
            "TX-Physical-Errors", "Transceiver Temp",
        }
        for header in numeric_headers:
            with self.subTest(header=header):
                self.assertEqual("number", self.html.link_sort_kind(header))
        for header in {"Hostname", "Interface", "State", "Peer", "Date", "Time"}:
            with self.subTest(header=header):
                self.assertEqual("text", self.html.link_sort_kind(header))

        history_thead, _tbody, _stats, _hist = self.html.build_link_content(
            [(datetime(2026, 9, 7, 13, 28), Path("history.csv"), latest)],
            headers, latest, datetime(2026, 9, 7, 14, 28), [1],
            ["Effective-Error"], show_transceiver_temp=False,
        )
        history_headers = re.findall(
            r'<th[^>]*class="diff-(?:th|sub)"[^>]*>', history_thead,
        )
        self.assertEqual(2, len(history_headers))
        for history_header in history_headers:
            self.assertNotIn("onclick=", history_header)
            self.assertNotIn('class="sc', history_header)

    def test_sorting_script_moves_device_groups_and_preserves_accessible_state(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("value.split('.')", source)
        self.assertIn("const SORT_STATE_KEY =", source)
        self.assertIn("function compareSortValues(left, right, direction)", source)
        self.assertIn("const numeric = Number(raw);", source)
        self.assertIn("if (!Number.isFinite(numeric)) missing = true;", source)
        self.assertIn("if (left.missing !== right.missing)", source)
        self.assertIn("return left.missing ? 1 : -1;", source)
        self.assertIn("environment.groups.sort", source)
        self.assertIn("saveSortState('ztp'", source)
        self.assertIn("restoreSortState();", source)
        self.assertIn("setAttribute('aria-sort'", source)
        self.assertIn(".link-tbl thead th.sc {{", source)
        self.assertIn(".link-tbl thead th:not(.sc) {{", source)

    def test_monitor_html_publish_is_atomic_and_generation_is_serialized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "monitor.html"
            self.html.atomic_write_text(output, "first")
            self.html.atomic_write_text(output, "second")
            self.assertEqual("second", output.read_text(encoding="utf-8"))
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual([], list(root.glob(".monitor.html.*.tmp")))

            lock = root / "generation.lock"
            first_entered = threading.Event()
            release = threading.Event()
            second_entered = threading.Event()

            def first():
                with self.html.generation_lock(lock):
                    first_entered.set()
                    release.wait(2)

            def second():
                first_entered.wait(2)
                with self.html.generation_lock(lock):
                    second_entered.set()

            one = threading.Thread(target=first)
            two = threading.Thread(target=second)
            one.start(); two.start()
            self.assertTrue(first_entered.wait(1))
            time.sleep(0.1)
            self.assertFalse(second_entered.is_set())
            release.set()
            one.join(2); two.join(2)
            self.assertTrue(second_entered.is_set())

    def test_dot_converter_aggregates_ports_and_escapes_script_end_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dot_path = root / "fabric.dot"
            dot_path.write_text(
                'graph {\n'
                '"Leaf</script><script>alert(1)</script>":"swp1" -- "Spine01":"swp1"\n'
                '"Leaf</script><script>alert(1)</script>":"swp2" -- "Spine01":"swp2"\n'
                '}\n', encoding="utf-8",
            )
            nodes, edges = self.dot.parse_dot(dot_path)
            self.assertEqual(2, len(nodes))
            self.assertEqual(1, len(edges))
            self.assertEqual(2, edges[0]["count"])
            self.assertEqual("swp1-2", edges[0]["source_label"])
            output = self.dot.convert(dot_path)
            document = output.read_text(encoding="utf-8")
            self.assertIn(r"<\/script>", document)
            self.assertNotIn("</script><script>alert(1)</script>", document)
            self.assertEqual([], list(root.glob(".fabric.html.*.tmp")))

    def test_cron_csv_fallback_is_order_independent_and_archive_names_are_utc(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        match = re.search(
            r"if ! awk -F',' '\n(.*?)\n    ' mode=", source, re.DOTALL,
        )
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "eth.csv"
            csv_path.write_text(
                "hostname,type,eth0_ip,netmask,vlan_id,svi_ip,netmask\n"
                "AIR-EXAMPLE-Leaf01,air,203.0.113.10,24,,,\n"
                "EXAMPLE-Leaf01,eth,203.0.113.10,24,100,203.0.113.20,24\n",
                encoding="utf-8",
            )
            outputs = {name: root / name for name in ("eth", "spx", "ib", "nv")}
            command = [
                "awk", "-F,", match.group(1), "mode=eth", "filter=air",
                f"eth_file={outputs['eth']}", f"spx_file={outputs['spx']}",
                f"ib_file={outputs['ib']}", f"nv_file={outputs['nv']}",
                str(csv_path),
            ]
            completed = subprocess.run(
                command, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(
                "AIR-EXAMPLE-Leaf01|203.0.113.10|203.0.113.20\n",
                outputs["eth"].read_text(encoding="utf-8"),
            )
        self.assertEqual(6, source.count('ts=$(date -u "+%Y%m%d-%H%M")'))
        self.assertIn("today=$(date -u '+%Y%m%d')", source)

    def test_ssh_askpass_uses_a_dedicated_executable_runtime_directory(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertIn("HTTP_ZTP_ASKPASS_TMPDIR", source)
        self.assertIn("/run/http-ztp/askpass", source)
        self.assertIn("create_ssh_askpass_helper", source)
        self.assertEqual(2, source.count("create_ssh_askpass_helper ||"))
        self.assertNotIn(
            'mktemp "${TMPDIR:-/tmp}/monitor-ssh-askpass.XXXXXX"',
            source,
        )
        helper = source.split("create_ssh_askpass_helper() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertIn('mktemp "${askpass_dir%/}/monitor-ssh-askpass.XXXXXX"', helper)
        self.assertIn("stat.S_ISDIR", helper)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o700", helper)
        self.assertIn("metadata.st_uid != os.geteuid()", helper)

        function_source = "create_ssh_askpass_helper() {" + source.split(
            "create_ssh_askpass_helper() {", 1,
        )[1].split("\ndetect_eth_environment() {", 1)[0]
        harness = (
            'log() { printf "%s\\n" "$*" >&2; }\n'
            'ASKPASS_FILE=""\n'
            + function_source
            + '\ncreate_ssh_askpass_helper || exit $?\n'
              'printf "%s\\n" "$ASKPASS_FILE"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            private = root / "askpass"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            unusable_tmp = root / "noexec-placeholder"
            unusable_tmp.write_text("not a directory\n", encoding="utf-8")
            environment = dict(os.environ)
            environment.update({
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(private),
                "TMPDIR": str(unusable_tmp),
            })
            completed = subprocess.run(
                ["bash", "-c", harness], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            helper_path = Path(completed.stdout.strip())
            self.assertEqual(private, helper_path.parent, repr(completed.stdout))
            self.assertEqual(0o700, stat.S_IMODE(helper_path.stat().st_mode))
            self.assertEqual(
                '#!/bin/sh\nprintf "%s\\n" "$MONITOR_SSH_PASSWORD"\n',
                helper_path.read_text(encoding="utf-8"),
            )
            helper_path.unlink()

            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            unsafe.chmod(0o755)
            environment["HTTP_ZTP_ASKPASS_TMPDIR"] = str(unsafe)
            rejected = subprocess.run(
                ["bash", "-c", harness], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual([], list(unsafe.glob("monitor-ssh-askpass.*")))

            alias = root / "askpass-alias"
            alias.symlink_to(private, target_is_directory=True)
            environment["HTTP_ZTP_ASKPASS_TMPDIR"] = str(alias)
            rejected = subprocess.run(
                ["bash", "-c", harness], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual([], list(private.glob("monitor-ssh-askpass.*")))

    def _write_executable(self, path: Path, body: str) -> None:
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def test_sw_info_and_sw_link_publish_complete_nvlink_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"; fake_bin.mkdir()
            temp_dir = root / "tmp"; temp_dir.mkdir()
            self._write_executable(fake_bin / "hostname", "printf '%s\\n' TestNV\n")
            inventory_fixture = root / "captured-inventory.txt"
            inventory_fixture.write_text(
                CAPTURED_UNNAMED_INVENTORY[1:], encoding="utf-8"
            )
            self._write_executable(fake_bin / "nv", r'''
if [ "$1 $2" = "show platform" ] && [ "$#" -eq 2 ]; then
  printf '%s\n' 'system-type MNV4'
elif [ "$1 $2 $3" = "show platform inventory" ] && [ "$#" -eq 3 ]; then
  cat "$MONITOR_REAL_INVENTORY_FIXTURE"
elif [ "$1 $2" = "show interface" ] && [ "$#" -eq 2 ]; then
  printf '%s\n' 'nvl1 up'
elif [ "$4 $5" = "link phy-detail" ]; then
  printf '%s\n' 'effective-ber 1e-12' 'effective-error 0'
elif [ "$4 $5" = "link counters" ]; then
  printf '%s\n' 'link-downed 2' 'qp1-drops 3'
else
  printf '%s\n' 'stub output'
fi
''')
            for command in ("timedatectl", "df", "free", "top", "uptime"):
                self._write_executable(fake_bin / command, "printf '%s\\n' stub\n")
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{fake_bin}:/usr/bin:/bin", "TMPDIR": str(temp_dir),
                "MONITOR_REAL_INVENTORY_FIXTURE": str(inventory_fixture),
            })
            for relative, suffix in (
                ("ethernet/monitor/sw-info.sh", ".info"),
                ("ethernet/monitor/sw-link.sh", ".link"),
            ):
                completed = subprocess.run(
                    ["bash", str((ROOT / relative).resolve())], cwd=root,
                    env=environment, text=True, capture_output=True, timeout=20,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                output = root / "monitor" / f"TestNV{suffix}"
                self.assertTrue(output.is_file(), relative)
                text = output.read_text(encoding="utf-8")
                if suffix == ".info":
                    self.assertIn("Switch Type:  NVLINK (MNV4)", text)
                    self.assertIn("# Collect complete", text)
                    parsed = self.html.parse_info_file("TestNV", text)
                    self.assertEqual(
                        CAPTURED_UNNAMED_INVENTORY_EXPECTED,
                        {
                            key: parsed[key]
                            for key in CAPTURED_UNNAMED_INVENTORY_EXPECTED
                        },
                    )
                else:
                    self.assertIn("TestNV,nvl1,1e-12,0,2,3,up", text)

    def test_deidentified_captured_inventory_corpus_parses_nonzero(self):
        payload = DEIDENTIFIED_INVENTORY_CORPUS_JSON.encode("utf-8")
        self.assertEqual(
            DEIDENTIFIED_INVENTORY_CORPUS_SHA256,
            hashlib.sha256(payload).hexdigest(),
        )
        corpus = json.loads(payload)
        self.assertEqual("monitor-inventory-deidentified-v2", corpus["format"])
        self.assertEqual(
            {
                "count": 118,
                "excluded": (
                    "package-import mirrors are outside the root glob; no sampling"
                ),
                "glob": "DAY0-Prepare/**/99-output-monitor/**/*.info",
            },
            corpus["selection"],
        )
        self.assertEqual(
            {
                "preserved": [
                    "header-and-separator-bytes", "component-name",
                    "state", "type", "field-occupancy",
                ],
                "replaced": [
                    "source-path", "hw-version-value", "model-value",
                    "serial-value",
                ],
                "replacement": (
                    "non-N/A characters in ignored hardware fields become X; "
                    "N/A and whitespace remain"
                ),
            },
            corpus["redaction"],
        )
        self.assertEqual(
            DEIDENTIFIED_INVENTORY_SOURCE_BINDING_SHA256,
            corpus["private_source_binding_sha256"],
        )
        profiles = {profile["id"]: profile for profile in corpus["profiles"]}
        self.assertEqual({"P1", "P2", "P3", "P4", "P5", "P6"}, set(profiles))
        self.assertEqual(118, len(corpus["records"]))

        observed_scopes = {"ETH": 0, "IB": 0}
        observed_profiles = {key: 0 for key in profiles}
        aggregate = {
            "psu_ok": 0, "psu_fail": 0,
            "fan_ok": 0, "fan_fail": 0,
        }
        profiles_with_non_na_components = set()
        for profile in profiles.values():
            section = profile["section"]
            self.assertEqual(
                profile["section_sha256"],
                hashlib.sha256(section.encode("utf-8")).hexdigest(),
            )
            for row in section.splitlines()[2:]:
                fields = row.split()
                self.assertEqual(6, len(fields), row)
                self.assertTrue(
                    all(
                        value == "N/A" or set(value) == {"X"}
                        for value in fields[1:4]
                    ),
                    row,
                )
                if fields[-1] in {"psu", "fan"} and "X" in "".join(fields[1:4]):
                    profiles_with_non_na_components.add(profile["id"])
        self.assertEqual({"P2", "P3", "P4", "P6"}, profiles_with_non_na_components)

        source_binding = hashlib.sha256()
        for record in corpus["records"]:
            self.assertRegex(
                record["private_command_block_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                {"id", "profile", "scope", "private_command_block_sha256"},
                set(record),
            )
            source_binding.update(
                (
                    f'{record["id"]}\0{record["scope"]}\0'
                    f'{record["private_command_block_sha256"]}\0'
                    f'{record["profile"]}\0'
                ).encode("ascii")
            )
            observed_scopes[record["scope"]] += 1
            observed_profiles[record["profile"]] += 1
            profile = profiles[record["profile"]]
            framed = (
                "Switch Type: ETH (captured)\n"
                "####################################################\n"
                "# Execute Command: nv show platform inventory\n"
                "####################################################\n"
                f'{profile["section"]}'
            )
            parsed = self.html.parse_info_file(record["id"], framed)
            expected = profile["expected"]
            self.assertEqual(
                expected,
                {key: parsed[key] for key in expected},
                record["id"],
            )
            self.assertEqual(
                DEIDENTIFIED_INVENTORY_PROFILE_COMPONENTS[record["profile"]],
                parsed["inventory_components"],
                record["id"],
            )
            self.assertEqual(sum(expected.values()), len(parsed["inventory_components"]))
            self.assertGreater(len(parsed["inventory_components"]), 0, record["id"])
            for key in aggregate:
                aggregate[key] += parsed[key]

        self.assertEqual({"ETH": 94, "IB": 24}, observed_scopes)
        self.assertEqual(
            DEIDENTIFIED_INVENTORY_SOURCE_BINDING_SHA256,
            source_binding.hexdigest(),
        )
        self.assertEqual(
            {"P1": 66, "P2": 13, "P3": 3, "P4": 6, "P5": 6, "P6": 24},
            observed_profiles,
        )
        self.assertEqual(
            {"psu_ok": 380, "psu_fail": 12, "fan_ok": 1236, "fan_fail": 0},
            aggregate,
        )
        self.assertEqual(1628, sum(aggregate.values()))

    def test_sw_collectors_reject_unknown_platform_and_unsafe_hostname(self):
        for hostname, platform in (("SafeHost", "UNKNOWN"), ("../escape", "MNV4")):
            with self.subTest(hostname=hostname, platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fake_bin = root / "bin"; fake_bin.mkdir()
                temp_dir = root / "tmp"; temp_dir.mkdir()
                self._write_executable(fake_bin / "hostname", f"printf '%s\\n' '{hostname}'\n")
                self._write_executable(fake_bin / "nv", f"printf '%s\\n' 'system-type {platform}'\n")
                environment = dict(os.environ)
                environment.update({"PATH": f"{fake_bin}:/usr/bin:/bin", "TMPDIR": str(temp_dir)})
                for script in ("sw-info.sh", "sw-link.sh"):
                    completed = subprocess.run(
                        ["bash", str((ROOT / "ethernet/monitor" / script).resolve())],
                        cwd=root, env=environment, text=True, capture_output=True,
                        timeout=10, check=False,
                    )
                    self.assertNotEqual(0, completed.returncode)
                self.assertFalse((root / "monitor").exists())

    def test_post_collect_selects_exact_environment_dot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "99-output-p2p"; output.mkdir()
            (root / "p2p.xlsx").write_bytes(b"fixture")
            expected = output / "p2p-lldpq.dot"
            expected.write_text("graph {}", encoding="utf-8")
            self.assertEqual(expected.resolve(), self.post.select_expected_dot(output, "prod"))
            self.assertEqual("20260831-1200-prod", self.post.archive_stem(
                Path("20260831-1200-prod.tar.gz")
            ))

    def test_collection_gate_serializes_and_enforces_success_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with self.gate.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status,
                cooldown_seconds=60, clock=lambda: 1000.0,
            ) as first:
                self.assertTrue(first.decision.allowed)
                first.mark_success()
            with self.gate.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status,
                cooldown_seconds=60, clock=lambda: 1001.0,
            ) as second:
                self.assertFalse(second.decision.allowed)
                self.assertEqual("cooldown", second.decision.reason)

    def test_collection_and_backup_use_independent_execution_lanes(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with self.gate.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status, cooldown_seconds=60, clock=lambda: 1000.0,
                lane="collection",
            ) as collection_gate:
                self.assertTrue(collection_gate.decision.allowed)
                with self.gate.CollectionGate(
                    "project-a", "prod", collection_keys=("yaml-backup",),
                    status_dir=status, cooldown_seconds=60, clock=lambda: 1000.0,
                    lane="backup",
                ) as backup_gate:
                    self.assertTrue(backup_gate.decision.allowed)
                    backup_gate.mark_success()
                collection_gate.mark_success()

            collection_state = status / ".switch-collection-cooldown.json"
            backup_state = status / ".yaml-backup-cooldown.json"
            self.assertTrue(collection_state.is_file())
            self.assertTrue(backup_state.is_file())
            self.assertNotEqual(collection_state.read_bytes(), backup_state.read_bytes())

    def test_worker_lane_dispatch_allows_cross_type_overlap_and_isolates_stop(self):
        worker = load_module(
            "review_switch_worker_lanes", ROOT / "monitor/switch-collection-worker.py"
        )
        entered = {"collection": threading.Event(), "backup": threading.Event()}
        release = threading.Event()

        def task(lane):
            entered[lane].set()
            self.assertTrue(entered["collection" if lane == "backup" else "backup"].wait(2))
            release.wait(2)

        self.assertTrue(worker.start_lane_task(
            "collection", "manual", task, "collection",
        ))
        self.assertTrue(worker.start_lane_task(
            "backup", "manual", task, "backup",
        ))
        self.assertTrue(entered["collection"].wait(2))
        self.assertTrue(entered["backup"].wait(2))
        self.assertFalse(worker.request_lane_stop("collection", origin="continuous"))
        self.assertFalse(worker.lane_cancelled("collection"))
        release.set()
        worker.join_lane_tasks(timeout=2)

        release.clear()
        entered = {"collection": threading.Event(), "backup": threading.Event()}
        self.assertTrue(worker.start_lane_task(
            "collection", "continuous", task, "collection",
        ))
        self.assertTrue(worker.start_lane_task(
            "backup", "manual", task, "backup",
        ))
        self.assertTrue(entered["collection"].wait(2))
        self.assertTrue(entered["backup"].wait(2))
        self.assertTrue(worker.request_lane_stop("collection", origin="continuous"))
        self.assertTrue(worker.lane_cancelled("collection"))
        self.assertFalse(worker.lane_cancelled("backup"))
        release.set()
        worker.join_lane_tasks(timeout=2)

    def test_worker_and_gate_workflow_runs_collection_and_backup_concurrently(self):
        worker = load_module(
            "review_switch_worker_gate_workflow",
            ROOT / "monitor/switch-collection-worker.py",
        )
        entered = {"collection": threading.Event(), "backup": threading.Event()}
        release = threading.Event()
        results = []

        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)

            def guarded(lane, keys):
                with worker.CollectionGate(
                    "project-a", "prod", collection_keys=keys,
                    status_dir=status, cooldown_seconds=60,
                    clock=lambda: 1000.0, lane=lane,
                ) as gate:
                    results.append((lane, gate.decision.allowed))
                    entered[lane].set()
                    other = "backup" if lane == "collection" else "collection"
                    self.assertTrue(entered[other].wait(2))
                    release.wait(2)
                    gate.mark_success()

            self.assertTrue(worker.start_lane_task(
                "collection", "manual", guarded, "collection", ("prod-ethernet",),
            ))
            self.assertTrue(worker.start_lane_task(
                "backup", "manual", guarded, "backup", ("yaml-backup",),
            ))
            self.assertTrue(entered["collection"].wait(2))
            self.assertTrue(entered["backup"].wait(2))
            release.set()
            worker.join_lane_tasks(timeout=2)
            self.assertEqual(
                [("backup", True), ("collection", True)], sorted(results),
            )
            self.assertTrue((status / ".switch-collection-cooldown.json").is_file())
            self.assertTrue((status / ".yaml-backup-cooldown.json").is_file())


class SwitchWorkerProcessLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = load_module(
            "review_switch_worker_lifecycle",
            ROOT / "monitor/switch-collection-worker.py",
        )

    @staticmethod
    def _wait_for(predicate, timeout: float = 8.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return bool(predicate())

    @staticmethod
    def _pid_is_running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _kill_group_for_cleanup(pid: int) -> None:
        if pid <= 1:
            return
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_direct_collector_group_cleanup_escalates_after_bounded_term_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "ready"
            heartbeat = root / "heartbeat"
            process = subprocess.Popen(
                [
                    sys.executable, "-B", "-c",
                    (
                        "import signal,time\n"
                        "from pathlib import Path\n"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                        f"Path({str(ready)!r}).write_text('ready\\n')\n"
                        f"heartbeat=Path({str(heartbeat)!r})\n"
                        "while True:\n"
                        " heartbeat.open('a').write('tick\\n')\n"
                        " time.sleep(0.03)\n"
                    ),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                self.assertTrue(
                    self._wait_for(lambda: ready.is_file() and heartbeat.is_file()),
                    "collector did not start",
                )
                started = time.monotonic()
                stopped = self.worker.terminate_collector_process(
                    process, term_grace_seconds=0.15,
                    kill_grace_seconds=1.0,
                )
                elapsed = time.monotonic() - started
                self.assertTrue(stopped)
                self.assertEqual(-signal.SIGKILL, process.returncode)
                self.assertGreaterEqual(elapsed, 0.10)
                self.assertLess(elapsed, 1.5)
                before = heartbeat.stat().st_size
                time.sleep(0.15)
                self.assertEqual(before, heartbeat.stat().st_size)
            finally:
                self._kill_group_for_cleanup(process.pid)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_supervisor_sigterm_workflow_stops_detached_collector_tree(self):
        supervisor = (ROOT / "infra/docker/supervisord.conf").read_text(
            encoding="utf-8",
        )
        block = supervisor.split("[program:switch-collection]", 1)[1].split(
            "[program:", 1,
        )[0]
        self.assertIn("stopsignal=TERM", block)
        self.assertIn("stopasgroup=true", block)
        self.assertIn("killasgroup=true", block)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            monitor = root / "monitor"
            tools = root / "tools"
            ethernet = root / "ethernet/monitor"
            project = root / "project"
            monitor.mkdir(parents=True)
            tools.mkdir()
            ethernet.mkdir(parents=True)
            project.mkdir()
            shutil.copy2(
                ROOT / "monitor/switch-collection-worker.py",
                monitor / "switch-collection-worker.py",
            )
            shutil.copy2(
                ROOT / "monitor/switch_collection_gate.py",
                monitor / "switch_collection_gate.py",
            )
            shutil.copy2(
                ROOT / "tools/project_contract.py",
                tools / "project_contract.py",
            )
            inventory = project / "02-devices_config.csv"
            inventory.write_text("hostname,type\n", encoding="utf-8")
            (monitor / "02-devices_config.csv").symlink_to(inventory)
            (monitor / "generate-monitor-html.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8",
            )

            collector = ethernet / "collector.py"
            collector.write_text(
                """#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
child = subprocess.Popen([sys.executable, "-B", str(root / "descendant.py")])
(root / "collector.pid").write_text(f"{os.getpid()}\\n")
(root / "descendant.pid").write_text(f"{child.pid}\\n")
heartbeat = root / "heartbeat"
while True:
    with heartbeat.open("a", encoding="utf-8") as stream:
        stream.write("collector\\n")
    time.sleep(0.03)
""",
                encoding="utf-8",
            )
            (ethernet / "descendant.py").write_text(
                """#!/usr/bin/env python3
from pathlib import Path
import time

heartbeat = Path(__file__).resolve().parent / "heartbeat"
while True:
    with heartbeat.open("a", encoding="utf-8") as stream:
        stream.write("descendant\\n")
    time.sleep(0.03)
""",
                encoding="utf-8",
            )
            cron = ethernet / "cron.sh"
            cron.write_text(
                '#!/bin/bash\nexec python3 "$(dirname "$0")/collector.py"\n',
                encoding="utf-8",
            )
            cron.chmod(0o755)
            status = monitor / "status"
            status.mkdir()
            (status / "switch-collection.request").write_text(
                "collect\n", encoding="utf-8",
            )

            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            worker = subprocess.Popen(
                [
                    sys.executable, "-B", str(monitor / "switch-collection-worker.py"),
                    "--scope", "air", "--poll", "1", "--timeout", "60",
                    "--lock-wait", "0",
                ],
                cwd=root, env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            collector_pid = 0
            descendant_pid = 0
            try:
                collector_pid_path = ethernet / "collector.pid"
                descendant_pid_path = ethernet / "descendant.pid"
                heartbeat = ethernet / "heartbeat"
                self.assertTrue(
                    self._wait_for(
                        lambda: collector_pid_path.is_file()
                        and descendant_pid_path.is_file()
                        and heartbeat.is_file(),
                    ),
                    "worker did not launch the collector tree",
                )
                collector_pid = int(collector_pid_path.read_text().strip())
                descendant_pid = int(descendant_pid_path.read_text().strip())
                self.assertTrue(self._pid_is_running(collector_pid))
                self.assertTrue(self._pid_is_running(descendant_pid))

                os.kill(worker.pid, signal.SIGTERM)
                self.assertEqual(143, worker.wait(timeout=8))
                self.assertTrue(
                    self._wait_for(
                        lambda: not self._pid_is_running(collector_pid)
                        and not self._pid_is_running(descendant_pid),
                    ),
                    "collector tree survived worker SIGTERM",
                )
                before = heartbeat.stat().st_size
                time.sleep(0.2)
                self.assertEqual(before, heartbeat.stat().st_size)
            finally:
                self._kill_group_for_cleanup(collector_pid)
                self._kill_group_for_cleanup(worker.pid)
                try:
                    worker.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass


class BringupSafetyTests(unittest.TestCase):
    def test_ndr_scripts_have_no_builtin_password_and_key_auth_is_default(self):
        collect = (ROOT / "infiniband/bringup/ndr/data-collect-IB.sh").read_text(encoding="utf-8")
        upgrade = (ROOT / "infiniband/bringup/ndr/OS-CPLD-upgrade.sh").read_text(encoding="utf-8")
        combined = collect + upgrade
        self.assertNotRegex(combined, r"(?m)^\s*password=['\"]admin['\"]")
        self.assertNotIn("sshpass -p", combined)
        self.assertIn("sshpass -e", collect)
        self.assertIn("BatchMode=yes", collect)
        self.assertIn("PasswordAuthentication=no", collect)
        self.assertIn("IB_SWITCH_PASSWORD", combined)

    def test_ndr_collect_invalid_target_has_no_output_or_network_phase(self):
        script = ROOT / "infiniband/bringup/ndr/data-collect-IB.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets"
            targets.write_text("192.0.2.1;touch-pwned\n", encoding="utf-8")
            output = root / "show.log"; errors = root / "errors.log"
            completed = subprocess.run([
                "bash", str(script), "--switches", str(targets),
                "--output", str(output), "--error-output", str(errors),
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, completed.returncode)
            self.assertIn("invalid switch target", completed.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(errors.exists())

    def test_ndr_upgrade_requires_yes_and_dry_run_has_no_side_effects(self):
        script = ROOT / "infiniband/bringup/ndr/OS-CPLD-upgrade.sh"
        refused = subprocess.run(
            ["bash", str(script)], cwd=ROOT, text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(2, refused.returncode)
        self.assertIn("without --yes", refused.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets"
            targets.write_text("192.0.2.10\n192.0.2.10\n", encoding="utf-8")
            image = root / "image.img"; image.write_bytes(b"image")
            log = root / "upgrade.log"
            completed = subprocess.run([
                "bash", str(script), "--dry-run", "--switches", str(targets),
                "--image", str(image), "--cpld-tool", str(root / "unused-tool"),
                "--wait", "0", "--log", str(log),
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(1, completed.stdout.count("target=192.0.2.10"))
            self.assertFalse(log.exists())

    def test_initial_setup_rejects_option_injection_before_outputs(self):
        script = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            completed = subprocess.run([
                sys.executable, str(script), "--eth-user=-oProxyCommand=bad",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, completed.returncode)
            self.assertIn("invalid --eth-user", completed.stderr)
            self.assertFalse((root / "xdr-initial-setup-logs").exists())
            conflict = subprocess.run([
                sys.executable, str(script), "--plan", "--apply",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, conflict.returncode)
            self.assertFalse((root / "xdr-initial-setup-logs").exists())

    def test_initial_setup_password_comes_only_from_env_or_hidden_prompt(self):
        source_path = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn('DEFAULT_IB_PASSWORD = "admin"', source)
        self.assertNotIn("--ib-initial-password ", source)
        module = load_module("review_initial_password", source_path)
        with mock.patch.dict(os.environ, {"TEST_NVOS_PASSWORD": "secret-value"}, clear=True):
            self.assertEqual(
                "secret-value",
                module.resolve_initial_ib_password(
                    "TEST_NVOS_PASSWORD", interactive=False,
                ),
            )
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(module.SetupError, "export NVOS_INITIAL_PASSWORD"):
                module.resolve_initial_ib_password(
                    "NVOS_INITIAL_PASSWORD", interactive=False,
                )
            with mock.patch.object(module.getpass, "getpass", return_value="typed-secret"):
                self.assertEqual(
                    "typed-secret",
                    module.resolve_initial_ib_password(
                        "NVOS_INITIAL_PASSWORD", interactive=True,
                    ),
                )

    def test_initial_setup_duplicate_ib_address_is_rejected(self):
        module = load_module(
            "review_initial_setup",
            ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ib.csv"
            path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-OOB01,eth,192.0.2.10,,,,,,\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(module.SetupError, "duplicate IB address"):
                module.load_devices(path)

    def test_xdr_upgrade_parses_both_supported_nvos_image_names(self):
        original = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.sh"
        source = original.read_text(encoding="utf-8")
        self.assertTrue(source.endswith("\nmain\n"))
        harness_source = source[:-len("main\n")] + r'''printf 'modern=%s\n' "$(os_ver_from_file 'nvos-amd64-25.03.1010.bin')"
printf 'legacy=%s\n' "$(os_ver_from_file 'nvosv25-03-1010amd64.bin')"
'''
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "upgrade-parser.sh"
            script.write_text(harness_source, encoding="utf-8")
            completed = subprocess.run(
                ["bash", str(script), "--method", "scp", "--os"],
                cwd=directory, text=True, capture_output=True, timeout=10,
                check=False,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            ["modern=25.03.1010", "legacy=25.03.1010"],
            completed.stdout.splitlines(),
        )

    def test_xdr_upgrade_generates_new_name_script_and_upgrade_path(self):
        original = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.sh"
        source = original.read_text(encoding="utf-8")
        old_target = '    "nvosv25-02-8008amd64.bin"'
        new_target = '    "nvos-amd64-25.03.1010.bin"'
        self.assertEqual(1, source.count(old_target))
        configured = source.replace(old_target, new_target, 1)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "upgrade.sh"
            script.write_text(configured, encoding="utf-8")
            completed = subprocess.run(
                [
                    "bash", str(script), "--method", "http", "--os",
                    "--scripts-only",
                ],
                cwd=root, text=True, capture_output=True, timeout=10,
                check=False,
            )
            generated = (
                root / "xdr-upgrade-logs/upgrade_scripts/http"
                / "os_upgrade_25.03.1010.sh"
            )
            generated_text = (
                generated.read_text(encoding="utf-8") if generated.is_file() else ""
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertRegex(completed.stdout, r"OS upgrade path:.*25[.]03[.]1010")
        self.assertIn('LOCAL_FILE="nvos-amd64-25.03.1010.bin"', generated_text)
        self.assertIn("Done. Reboot required to activate OS 25.03.1010.", generated_text)

    def test_xdr_upgrade_invalid_option_does_not_create_output_tree(self):
        original = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "upgrade.sh"
            shutil.copy2(original, script)
            completed = subprocess.run([
                "bash", str(script), "--method", "local", "--scripts-only",
                "--parallel-limit", "not-a-number",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(1, completed.returncode)
            self.assertIn("Invalid --parallel-limit", completed.stderr)
            self.assertFalse((root / "xdr-upgrade-logs").exists())


if __name__ == "__main__":
    unittest.main()
