# UFM auth/key extension — explicit live gates, not seven-step deployment

The local validate/plan/generate/execute-HOLD behavior remains unchanged.
Two additional commands now delegate to the complete original authentication
and durable-key APIs, not a caller-supplied session, permission DTO, or success
stub. They are live device operations, NOT part of the no-network smoke test.

    python3 -B tools/ufm_initial_setup.py authenticate --project /absolute/project --address CSV_NODE_IP --known-hosts /private/known_hosts --known-hosts-sha256 INDEPENDENT_SHA256 --allow-device-access
    python3 -B tools/ufm_initial_setup.py establish-keys --project /absolute/project --address CSV_NODE_IP --known-hosts /private/known_hosts --known-hosts-sha256 INDEPENDENT_SHA256 --management-identity /private/management-key --private-logs-root /private/xdr-initial-setup-logs --allow-device-access --allow-key-change

Use the exact isolated environment in requirements-f01-ssh.lock (eight pins);
do not use system/FrozenP SDKs. No installer runs implicitly. A missing or
unproved environment remains HOLD. Passwords require a private terminal:
default, new, confirm new. They are never accepted in argv/environment. New
authentication is attempted first; only an actual explicit trusted rejection
can try default. Default success is CHANGE_REQUIRED, never key-install success.
These commands do not implement or guess a password-change recipe.

Establish-keys requires the current project's distinct mgmt-server.pub and
laptop.pub and a matching private management identity. The original API pins
the actual CSV IPv4/admin endpoint and management interface MAC/IP, runs the
fixed HOME backup script, pulls/readbacks/fsyncs private evidence, and only
then applies fixed project authorized_keys. It proves a fresh key-only
session and identity afterwards and emits PROJECT_KEY_ACCESS_ESTABLISHED_NOT_DEPLOYED.
Backup failure must prevent apply. The original 10s budget is unchanged.

The private evidence root is mode0700, basename xdr-initial-setup-logs and
outside HTTP/project; files are mode0600 and per-node/run. Logs and backups
may contain sensitive server configuration; never upload them as public data.
Unknown result is HOLD, not success. Do not retry writes blindly.

The current CLI exposes only direct IPv4 authentication/key setup. Automatic
OOB routing, stage-readonly, and vendor configuration operations are not
exposed. The plan still marks unconfirmed vendor steps HOLD, completion false.
Existing OOB/library helpers are not a claim of device-side implementation.

Current simple tests demonstrate CLI recognition/consent/pin refusal,
no prompt/SDK before the gate, local generation, and a three-reply identity
parser workflow. They do not prove a real install. The original public4,
Bash3, durable backup workflow and direct/source/SFTP/syntax tests are
retained unmodified as real regular-module mappings. Native local protocol
and real device cases require root's explicit scheduling; no full was run.
The original durable/SFTP peer fixture's pre-try acquisition and hostile
diagnostic-setter failure windows remain known test-fixture risks, not a
production PASS. Historical public/Bash PASS is not transplanted to this
new combined source epoch.

Current main local smoke verification (2026-10-19): 18 tests passed, including
the seven entry/generation/Bash-syntax checks, two consent/pin gates, two
direct IPv4 parser/argv checks, four original public-key tests and three
original private Bash workflows. This ran no device access. The Bash cases
include backup-before-replacement, failed backup comparison preserving the
original, and controlled interruption retaining the backup. This is not the
encrypted durable-key workflow or a real device installation; those remain
NOT RUN here, along with full and all seven-step vendor execution.
