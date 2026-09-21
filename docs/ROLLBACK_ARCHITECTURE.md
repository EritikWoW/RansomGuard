# RansomGuard 0.7.2.0 - range-aware pre-write COW milestone

RansomGuard is moving from detection-only telemetry to `preserve -> contain -> recover`.
0.7.2.0 keeps the deliberately constrained engineering minifilter gate and changes ordinary WRITE
preservation from whole-file snapshots to incident-scoped range/block copy-on-write.

## WRITE ordering

For a WRITE inside the explicitly negotiated LAB root:

1. The minifilter observes the write before it is completed.
2. The request remains pending while the event is sent to the single LAB gate client.
3. The gate client resolves and revalidates the exact disposable root/path.
4. On the first write to a file, `RangeRollbackStore` durably records the original file length.
5. Every original 1 MiB block intersecting the pending write is captured at most once for the session.
6. Each block is SHA-256 hashed, written with write-through semantics, and committed to an append-only
   SHA-256 hash-chained journal.
7. Only after all required blocks are committed does user mode reply `SnapshotCommitted`.
8. The minifilter allows the original write only for the matching successful reply.
9. Capture failure, malformed reply, timeout, unsupported negative/special offset, or explicit deny
   returns `STATUS_ACCESS_DENIED` for that in-scope LAB operation.

Writes that start at or beyond the original EOF still commit the original-length baseline. No old bytes
exist to copy, so rollback removes the append by restoring the recorded original length.

## Rename / delete / truncate ordering

Rename, delete-disposition, end-of-file, allocation-length and valid-data-length operations use the conservative
full-file pre-image store. These operations can destroy or relocate information in ways that are not yet modeled
as block-only transactions.

Protocol v3 therefore exposes four mutation classes:

- WRITE
- RENAME
- DELETE
- TRUNCATE

## Range recovery

Range recovery never modifies the damaged source.

It creates a new `.ransomguard-cow-recovered` copy by:

1. copying the current damaged file to a new temporary output;
2. verifying every committed original block by SHA-256;
3. overlaying those blocks at their original offsets;
4. restoring the original file length;
5. flushing the new output before publication.

If the damaged file is shorter than the original baseline, range reconstruction refuses to guess. That case
requires the full-preimage/transaction path.

The range journal also rejects sequence gaps, hash-chain mismatches, duplicate baselines/blocks,
missing/truncated block objects, path traversal, reparse storage, and unjournaled `.block` objects.

## Why this is still LAB-only

The prototype gates one explicit root negotiated at connection time. The gate client requires
`.ransomguard-gate-lab-root` and rejects an entire drive, Windows, Program Files, ProgramData and reparse roots.
The rollback store must live outside the gated root. The gate client's PID is excluded in kernel mode to avoid
self-deadlock while it writes rollback data.

Outside the exact root, or when the path cannot be resolved, the driver fails open. When no client is connected,
it does not gate anything. The filter remains demand-start, automatic attachment is suppressed, and
`370099.4242` remains an unassigned LAB altitude.

The normal product bundle does not install or enable this driver. Ordinary product operation remains AuditOnly.

## Still required before production

- explicit create/new-file transaction semantics;
- rename destination capture and identity-safe rename rollback;
- durable file identity (volume + file ID), not path identity alone;
- bounded concurrent pending-I/O workers;
- crash/restart reconciliation for requests pending during user-mode failure;
- memory-mapped/cache-manager write coverage;
- storage quotas, retention and pressure policy;
- transition from protected-root health to containment/block policy;
- process-state capture and adaptive crypto analysis;
- verified recovery orchestration across rollback and crypto recovery;
- signed driver distribution and Microsoft-assigned altitude.

## Windows LAB test target

On a disposable VM and disposable LAB directory:

1. Create a multi-megabyte known file and hash it.
2. Start the LAB gate.
3. Modify bytes in one block and verify only that original block is captured.
4. Modify the same block again and verify no second pre-image is created.
5. Modify another block and verify one additional block is captured.
6. Append data past EOF and verify only the original-length baseline is needed for that append.
7. Reconstruct to a new copy and compare it to the original known file.
8. Exercise truncate and verify the conservative full-file pre-image path is used.
9. Stop/fault the gate client and verify in-scope destructive I/O is denied.
10. Verify files outside the LAB root remain unaffected.

Do not load the blocking prototype on a primary workstation.
