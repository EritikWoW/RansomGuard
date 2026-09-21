# RansomGuard 0.7.1.0 - pre-write gate milestone

RansomGuard is moving from detection-only telemetry to `preserve -> contain -> recover`.
Version 0.7.1.0 connects the durable rollback primitive from 0.7.0.0 to a deliberately constrained
**engineering-only** minifilter gate so the preservation ordering can be validated on Windows before a
production filter is attempted.

## Required ordering

For an I/O request inside the explicitly negotiated LAB root:

1. The minifilter observes WRITE, rename, or delete-disposition before the filesystem mutation completes.
2. It sends the normalized source path and operation metadata to the single connected gate client.
3. The originating I/O remains waiting for a bounded reply.
4. `RansomGuard.GateClient` verifies that the path still belongs to the exact disposable LAB root.
5. `RansomGuard.Rollback` captures the incident's first pre-image, computes SHA-256, flushes the object,
   commits the hash-chained journal entry, and flushes the journal.
6. Only after that durable commit does user mode reply `SnapshotCommitted`.
7. The minifilter allows the original operation only for that reply and matching request sequence.
8. Capture failure, malformed reply, timeout, or an explicit deny causes the in-scope LAB I/O to return
   `STATUS_ACCESS_DENIED`.

This ordering is the core invariant we need for real anti-encryption protection: the source version must
exist durably before the destructive mutation is allowed to proceed.

## Why this is still LAB-only

The prototype deliberately gates only one explicit root negotiated at connection time. The gate client
requires a `.ransomguard-gate-lab-root` marker and rejects an entire drive, Windows, Program Files,
ProgramData and reparse roots. The rollback store must live outside the gated root. The gate client's own
PID is excluded in kernel mode to prevent recursive blocking while it commits snapshots and the journal.

Outside the exact root, or when a path cannot be resolved, the driver fails open. When no client is
connected it does not gate anything. This avoids turning a development fault into an OS-wide I/O outage.
The driver remains demand-start and automatic volume attachment remains suppressed. The unassigned lab
altitude `370099.4242` remains a placeholder and must never ship.

The ordinary product bundle does not contain/install/enable the driver and continues to report
`kernelWriteGateActive=false`. Only `build_lab.cmd` publishes the gate client and driver source/tools.

## Current rollback semantics

`RansomGuard.Rollback` still stores the first pre-image per path per incident session. Recovery writes a
new `.ransomguard-recovered` copy and verifies its SHA-256; it never overwrites a damaged source directly.
The journal remains append-only and hash chained.

This milestone protects the **content pre-image ordering**. It is not yet a complete filesystem transaction
model. In particular, production work still needs:

- explicit create semantics (new-file rollback currently is not modeled as "delete on rollback");
- rename destination capture and identity-safe rename rollback;
- range/block copy-on-write for large files instead of whole-file snapshots;
- bounded concurrent gate workers instead of one simple engineering client loop;
- crash/restart reconciliation for I/O that was pending during user-mode failure;
- durable per-volume identity rather than relying only on path identity;
- cache-manager / memory-mapped-write coverage and compatibility testing;
- a production fail-open/fail-closed policy with protected-root health state;
- signed driver distribution and a Microsoft-assigned minifilter altitude.

## Test target for this milestone

On a disposable Windows VM and disposable LAB directory:

1. Put a known file in the LAB root and hash it.
2. Start the LAB gate.
3. Modify the file from another process.
4. Verify the write completed only after a rollback object/journal record exists.
5. Verify the recovered copy hashes to the original pre-write file.
6. Force the gate client to fail or stop replying and verify in-scope destructive I/O is denied.
7. Verify files outside the LAB root remain unaffected by the gate.

Do not use the blocking prototype on a primary workstation or point it at real user data.
