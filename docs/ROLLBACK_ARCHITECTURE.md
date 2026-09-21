# RansomGuard 0.7.7.0 - completed CREATE/RENAME identity reconciliation milestone

RansomGuard is moving from detection-only telemetry to `preserve -> contain -> recover`.
0.7.7.0 retains the deliberately constrained engineering minifilter gate, range-aware WRITE COW,
durable CREATE/RENAME intents and completion reconciliation, and adds post-RENAME kernel file-identity
reconciliation without rewriting the existing rename completion journal.

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

Protocol v7 exposes five mutation classes and adds a normalized destination path/status to RENAME events:

- CREATE
- WRITE
- RENAME
- DELETE
- TRUNCATE

## CREATE ordering

For `IRP_MJ_CREATE`, protocol v7 carries the original Windows CreateDisposition/CreateOptions before
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

## CREATE completion reconciliation

Every gated CREATE that is allowed now has a second durable transaction layer:

1. before the gate reply, `CreateOperationStore` appends a write-through SHA-256 hash-chained intent containing
   the kernel request sequence, disposition/options, desired access, pre-operation target state and exact preservation proof;
2. the minifilter retains the pre-CREATE normalized name and returns `FLT_PREOP_SUCCESS_WITH_CALLBACK`;
3. after completion, a failed CREATE emits the final NTSTATUS without claiming a name or identity;
4. after successful CREATE, `FltGetTunneledName` reconciles Windows name tunneling;
5. on the actual completed `FileObject`, `FltQueryInformationFile(..., FileIdInformation, ...)` captures
   the volume serial plus 128-bit file ID;
6. protocol v7 emits a no-reply `CreateResult` correlated to the original request sequence;
7. user mode appends a separate write-through hash-chained completion record linked to the exact intent hash.

Successful completion can be authoritative or explicitly name-unresolved, identity-unresolved, or fully unresolved.
If the result cannot be delivered or persisted, the CREATE intent remains pending. Recovery must never infer
completion from the pre-operation intent alone.

The initial CREATE classification still uses a path-based pre-operation probe, but the completed operation is now
bound to the final tunneled name and kernel file identity when those are available.

## Durable existing-file identity

For existing files, the LAB gate now records a separate incident-scoped Windows identity journal before destructive
preservation. The identity is the `FILE_ID_INFO` pair:

- volume serial number;
- 128-bit file ID.

The journal is append-only, SHA-256 hash-chained and write-through flushed. Re-observing the same path with the same
identity reuses the committed baseline. If the same path resolves to a different file identity later in the incident,
the gate fails closed rather than capturing the replacement file as though it were the original object.

The expected identity is also passed into the full-preimage and range-COW stores. Those stores query `FILE_ID_INFO`
from the exact source handle they read, before copying any bytes. This closes the userspace gap where the path could
be replaced between an identity probe and a second snapshot open.

A renamed file may appear under another observed path with the same identity; the identity store keeps those aliases.
This is groundwork for identity-safe rename recovery, not the completed rename transaction model. Originally-absent
paths remain governed by the create baseline because replacing one incident-created file with another does not change
the pre-incident requirement that the path was absent.

Existing-file snapshot reads remain userspace path opens protected by exact-handle identity verification. Completed
CREATE and RENAME operations now additionally report identity from the actual completed kernel file object. For RENAME,
the final identity is accepted as authoritative only when it matches the source identity committed before the operation.

## RENAME destination ordering

For a rename inside the LAB root, protocol v7 carries the normalized destination obtained by the minifilter with
`FltGetDestinationFileNameInformation`.

Before returning `SnapshotCommitted`, user mode:

1. requires both source and destination names to be fully resolved and inside the explicit LAB root;
2. binds and preserves the source file by durable `FILE_ID_INFO`;
3. if the destination is missing, durably records that it was absent;
4. if the destination is an existing file, binds its distinct file identity and captures a full pre-image;
5. rejects existing directories, cross-root destinations, ambiguous/truncated destinations and same-file aliases;
6. appends a write-through SHA-256 hash-chained rename intent containing source/destination paths, identities,
   destination state, rename flags, information class and kernel request sequence.

The rename intent is deliberately a **pre-operation intent**, not proof that the filesystem completed the rename.

## RENAME completion reconciliation

After an allowed rename returns from the filesystem, the minifilter executes a post-operation completion path:

1. the pre-operation normalized destination name-info object is retained in the completion context;
2. `FltDoCompletionProcessingWhenSafe` moves reconciliation to a safe post-operation context when required;
3. a failed rename emits a correlated result carrying the final NTSTATUS and no successful topology claim;
4. on success, `FltGetTunneledName` reconciles the retained pre-operation destination against Windows file-name tunneling;
5. the driver emits a no-reply protocol-v7 `RenameResult` correlated by the original kernel request sequence;
6. `RenameRollbackStore` appends a separate write-through SHA-256 hash-chained completion record linked to the exact intent hash.

A completion may be `Succeeded`, `SucceededNameUnresolved`, or `Failed`. If the safe post path cannot run,
the result cannot be delivered, or user mode stops before persisting it, the intent remains **pending**. Recovery must
never infer success from the presence of a pre-operation intent alone.

The completion journal confirms filesystem outcome and reconciled final name when available. Identity authority is
tracked separately so the existing v0.7.5 completion schema and record hashes remain backward compatible.

## RENAME kernel identity reconciliation

For every successful rename completion delivered by protocol v7:

1. the safe post-operation callback queries `FileIdInformation` from the actual completed `FileObject`;
2. the same `RenameResult` carries the volume serial and 128-bit file ID when the query succeeds;
3. GateClient first persists the ordinary rename completion, preserving its existing hash-chain semantics;
4. `RenameIdentityStore` appends a separate write-through SHA-256 hash-chained record linked to the exact
   rename completion hash and kernel request sequence;
5. `Resolved` is valid only when the final identity equals the source identity committed in the pre-rename intent;
6. an observed different identity is persisted as `Mismatch`, never silently accepted;
7. an unavailable kernel identity is persisted as `QueryFailed`;
8. if the identity event cannot be persisted, the successful rename remains identity-pending and must not be
   treated as authoritative for automatic topology recovery.

This closes the user-mode path-alias ambiguity for completed renames without changing protocol-v7 ABI fields.

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
- repository-wide verification descends into each session's nested `write-cow`, `create-state`, `identity-state`, `rename-state` and `rename-identity-state` stores;
- CREATE and RENAME completion records are hash-chained separately and cryptographically linked to their exact pre-operation intents;
- post-RENAME identity records are hash-chained separately and cryptographically linked to the exact rename completion hash;
- the LAB gate validates all existing sessions before opening a new one.

These checks do not yet reconcile an interrupted in-flight kernel request. They prevent a restart from proceeding on top of rollback state whose commit boundary is ambiguous.

## Still required before production

- close the remaining pre-CREATE path-classification race against the completed kernel result;
- bounded concurrent pending-I/O workers;
- crash/restart reconciliation for requests pending during user-mode failure or missing CREATE/RENAME completion/identity delivery;
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
