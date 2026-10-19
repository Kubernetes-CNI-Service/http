# UFM initial-setup: local preparation, not seven-step completion

Run from a copy of this repository with Python 3.10+ and PyYAML 6.0.3.
This entry is independent of the NVOS initial-setup script.

    python3 -B tools/ufm_initial_setup.py --help
    python3 -B tools/ufm_initial_setup.py validate --project /absolute/private/project
    python3 -B tools/ufm_initial_setup.py plan --project /absolute/private/project
    python3 -B tools/ufm_initial_setup.py generate --project /absolute/private/project --address 192.0.2.21 --private-logs-root /absolute/private/xdr-initial-setup-logs

Input files are exactly 01-global.yaml and 02-devices_config.csv. The existing
servers list-of-single-key-families schema is retained, UFM version is a string
2.5.*, and alias maps logical interface to actual interface. Missing version
skips upgrade intent. Two-node installation UFM01 must be unique; CSV order is
not authority. VIP is a candidate only, never a live occupancy observation.

Generate requires the repository's existing monitor/02-devices_config.csv
active-project symlink to select the same requested project. It does NOT run
setup, change that link, or generate another project's artifacts. Its private
logs root must already exist, be mode 0700, have the basename
xdr-initial-setup-logs, and be outside the entire repository/HTTP tree.
Do not use real project inputs or copy a private project into this desktop
validation repository merely to run a smoke test. The supplied unittest
creates an independent private HTTP/project fixture.

Actual generation executes the existing builder API, with held no-follow
inputs, original source rechecks, unique run/node/stage directory, original
script readback/hash/fsync, mode 0600 script/manifest, and mode 0700 folders.
The generated script is only phase1_readonly_preflight. No local Bash, SSH,
upload, credential prompt or device operation is run by generate. It records
GENERATED_NOT_EXECUTED, syntax_check NOT_RUN, completion false.

The plan lists four phases and all seven operations. execute always returns
HOLD (exit 2) before any write because vendor write grammar is not confirmed.
No DONE/resume authorization is inferred from this plan or old progress files.

authenticate and establish-keys are exposed only behind explicit device/key-change consent and independently pinned files; see [UFM-AUTH-KEY-EXTENSION.md](UFM-AUTH-KEY-EXTENSION.md). stage-readonly remains unsupported. The local smoke tests do not prove a real installation or seven-step deployment.

IPv4-first/OOB policy is explicitly represented in plan/classify_ipv4_outcome.
Only explicit unreachable/connect-timeout permit considering OOB discovery;
auth rejection means credential recovery, host-key/MAC conflict or unknown
means STOP. The string policy helper does not prove a live connection,
actual P2P neighbor/FDB/VRF, SSH host pin, or management MAC. Automatic OOB
execution is NOT implemented by this entry.

Simple tests use private project fixtures and a fixed `/bin/bash -n` syntax-only
check of a generated script. They do not execute the script, access a device,
initialize an SSH SDK, or run full tests:

    python3 -B -m unittest -v test_cases.test_f01_initial_setup_entry

No release proof, full-test approval, native installation, HA, upgrade,
license activation, or hardware conformance is claimed.
