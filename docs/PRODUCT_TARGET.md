# Product target

RansomGuard is not a general antivirus. It is a Windows anti-encryption and recovery layer.

The finished product must provide three independent safety paths:

1. **Preserve** original data before destructive mutation through a production minifilter and copy-on-write/pre-image protection.
2. **Contain** continued destructive writes once the system has enough evidence that a process is encrypting or otherwise corrupting protected data.
3. **Recover** affected data through verified rollback and, when runtime state is available, adaptive cryptographic analysis/key-state recovery.

The detector is a trigger, not the product. ETW can remain useful for telemetry and forensics, but a release
is not prevention-capable merely because ETW identifies a suspicious process. Prevention requires a proven
pre-mutation preservation path.

## Current milestone

The current engineering branch extends the range-aware write COW gate with protocol v5 CREATE and RENAME destination semantics:

`CREATE -> classify disposition -> durable existing-file pre-image OR originally-absent baseline -> allow`

`WRITE -> durable original-length baseline + first touched blocks -> allow mutation`.

Rename, delete and truncate-class operations remain on a conservative full-file pre-image path.
An originally-absent path is remembered for the whole incident so later writes do not create a false pre-image
from data that did not exist before the incident.

The gate is intentionally not enabled in the normal bundle and is not production-safe yet. Existing-file
preservation is now additionally bound to a durable Windows `FILE_ID_INFO` identity journal
(volume serial + 128-bit file ID), so a path that changes to a different file during one incident is rejected.
CREATE existence classification itself is still path-based; post-create/kernel identity reconciliation remains required.

Protocol v5 now carries the normalized pre-operation rename destination. Before allowing a rename, the LAB gate
preserves the source, preserves an existing destination or commits its absence, and durably records a rename intent.
That intent is not treated as completion because Windows name tunneling can change the final normalized component.

The next core milestones are post-create/post-rename tunneled-name reconciliation, kernel binding of completed operations
to durable file identity, bounded concurrent and crash-reconciled gating, containment, process-state capture,
adaptive crypto analysis, and verified recovery orchestration.
