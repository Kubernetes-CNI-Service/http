Finished-projects
=================

This directory is the local, non-deployable home for projects brought back from
a management server after a deployment is finished.

Boundary
--------

* DAY0-Prepare/<project>/ is the authoritative working tree for projects that
  are being prepared, validated or deployed.
* Finished-projects/<project>/<record-id>/ is an immutable review snapshot of a
  finished deployment. It is never an input to load, tar-for-upload or
  sync-code.
* DAY0-Prepare/<project>/finished-history/<record-id> may be a relative,
  read-only navigation link to that record. The dedicated finished-history
  subtree is excluded from every deployment/download path and is never an
  active 99-output-* or latest pointer.
* package-imports/ remains a temporary, per-import inspection area. A verified
  finished import can be promoted from that inspection area into this directory,
  but it must never overwrite an existing record.

Safety contract
---------------

Imported records can contain private data and are ignored by Git. Import uses
safe extraction, single-link regular-file checks, size limits and component
hash verification. Published directories and files are 0555/0444 to prevent
accidental edits, and record-inventory.json binds all other record objects.
Existing records are immutable: an identical bundle is already imported, while
a different bundle using the same record ID fails closed. No record is uploaded,
synchronized, executed by load, or used to restore a management server
automatically.

Only an explicit ``--finish`` publishes a verified finished bundle here. The
only supported link back into DAY0-Prepare is the importer-owned
finished-history/<record-id> navigation link in the same project. Never link a
record into project inputs, 99-output-*, latest, or any load-owned path.
