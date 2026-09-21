# RansomGuard 0.7.3.0 - CREATE-aware preservation milestone

RansomGuard is moving from detection-only telemetry to `preserve -> contain -> recover`.
0.7.3.0 retains the deliberately constrained engineering minifilter gate, range-aware WRITE COW,
and adds explicit CREATE preservation semantics.

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

Protocol v4 exposes five mutation classes:

- CREATE
- WRITE
- RENAME
- DELETE
- TRUNCATE

## CREATE ordering

For `IRP_MJ_CREATE`, protocol v4 carries the original Windows CreateDisposition/CreateOptions before
the create completes.

- If an existing file is opened with `FILE_SUPERSEDE`, `FILE_OVERWRITE` or `FILE_OVERWRITE_IF`,
  the gate commits a conservative full-file pre-image before allowing the operation.
- If the target is missing and the disposition can create it (`FILE_SUPERSEDE`, `FILE_CREATE`,
  `FILE_OPEN_IF`, `FILE_OVERWRITE_IF`), `CreateRollbackStore` commits an append-only SHA-256
  hash-chained `originally absent` baseline.
- `FILE_DELETE_ON_CLOSE` on an existing file requires the same conservative full pre-image even with `FILE_OPEN`.
- Existing-directory delete-on-close is denied because directory-topology rollback is not modeled yet.
- `FILE_OPEN` / existing `FILE_OPEN_IF` without destructive create options need no preservation at CREATE time; later WRITE is still gated.
- Once a path is marked originally absent, later WRITE/rename/delete/truncate events do not capture incident-created
  bytes as if they were pre-incident data.

The absence journal never deletes a created file automatically. It records recovery intent only; final recovery
orchestration must decide how to quarantine/remove an incident-created path.

The current existence probe is path-based. A race between that probe and the kernel create is still possible;
production requires durable file identity plus post-create reconciliation.

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

Outside the exact root, or when the name query fails before the root can be established, the driver fails open.
If the bounded event path is truncated only after its prefix has already proven it is inside the gate root, user mode denies
the operation rather than committing preservation state for an ambiguous path. When no client is connected, the driver
does not gate anything. The filter remains demand-start, automatic attachment is suppressed, and
`370099.4242` remains an unassigned LAB altitude.

The normal product bundle does not install or enable this driver. Ordinary product operation remains AuditOnly.

## Crash-state validation

Rollback startup validation now treats ambiguous durable state as a hard failure rather than silently trusting it:

- every committed full pre-image is checked by length and SHA-256;
- unjournaled `.preimage` objects are rejected;
- unjournaled range `.block` objects are rejected;
- leftover `.tmp` artifacts are rejected as incomplete capture evidence;
- range block geometry must exactly match the recorded original file length and configured block size;
- repository-wide verification descends into each session's nested `write-cow` and `create-state` stores;
- the LAB gate validates all existing sessions before opening a new one.

These checks do not yet reconcile an interrupted in-flight kernel request. They prevent a restart from proceeding on top of rollback state whose commit boundary is ambiguous.

## Still required before production

- post-create identity reconciliation and tunneled-name/file-ID confirmation;
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
