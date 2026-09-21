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

The current engineering branch extends the range-aware write COW gate with protocol v8 CREATE completion, RENAME destination and rename-completion semantics:

`CREATE -> classify disposition -> durable existing-file pre-image OR originally-absent baseline -> allow`

`WRITE -> durable original-length baseline + first touched blocks -> allow mutation`.

Rename, delete and truncate-class operations remain on a conservative full-file pre-image path.
An originally-absent path is remembered for the whole incident so later writes do not create a false pre-image
from data that did not exist before the incident.

The gate is intentionally not enabled in the normal bundle and is not production-safe yet. Existing-file
preservation is now additionally bound to a durable Windows `FILE_ID_INFO` identity journal
(volume serial + 128-bit file ID), so a path that changes to a different file during one incident is rejected.
CREATE classification still begins with a path-based pre-operation probe, but protocol v8 now records a durable CREATE intent before allow and correlates it with a post-operation result containing the tunneled final name and kernel `FileIdInformation` identity when available. Missing or partial reconciliation stays explicit and pending/unknown rather than being inferred.

Protocol v8 retains the normalized pre-operation rename destination and correlated post-operation `RenameResult`.
Before allowing a rename, the LAB gate preserves the source, preserves an existing destination or commits its absence,
and durably records a rename intent. After completion, the minifilter resolves the tunneled final name on a safe post-op
path and, only at PASSIVE_LEVEL with special kernel APCs enabled, queries `FileIdInformation` on the completed kernel
file object. Otherwise identity remains explicitly unresolved. User mode appends a second hash-chained record containing
final name and identity when available. The post-op identity must match the source identity committed
before allow. A missing or partially resolved result remains explicit; pre-operation intent is never promoted to success by inference.

The current LAB gate now uses bounded concurrent preservation: kernel admission caps simultaneous blocking gate sends at 8, while user mode dispatches a configurable 1..8 worker pool (default 4). Slow preservation no longer holds the global port mutex across the 30-second gate wait.

Crash/restart safety now includes fail-closed pending-intent quarantine: an earlier session with missing CREATE/RENAME completion evidence prevents a new blocking LAB session. Read-only inspection exposes exact pending request sequences; current filesystem state is never used to guess success or failure.

The next core milestones are verified/operator reconciliation for quarantined intents, memory-mapped write coverage,
containment, process-state capture,
adaptive crypto analysis, and verified recovery orchestration.
