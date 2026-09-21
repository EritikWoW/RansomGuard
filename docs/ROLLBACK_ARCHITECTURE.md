# RansomGuard 0.7.13.0 - CREATE completion and identity reconciliation milestone

RansomGuard is moving from detection-only telemetry to `preserve -> contain -> recover`.
0.7.13.0 retains the deliberately constrained engineering minifilter gate, range-aware WRITE COW,
CREATE/RENAME preservation and rename outcome reconciliation, and adds durable post-CREATE outcome,
tunneled-name and kernel file-identity reconciliation.

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

Protocol v10 exposes five mutation classes and adds a normalized destination path/status to RENAME events:

- CREATE
- WRITE
- RENAME
- DELETE
- TRUNCATE

## CREATE ordering

For `IRP_MJ_CREATE`, protocol v6 carries the original Windows CreateDisposition/CreateOptions before
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
CREATE and completed RENAME operations now additionally report identity from the actual kernel file object.
For RENAME, the completion identity must equal the source identity committed in the pre-operation intent; a mismatch
is rejected rather than being treated as authoritative topology evidence.

## RENAME destination ordering

For a rename inside the LAB root, protocol v6 carries the normalized destination obtained by the minifilter with
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
2. `FltDoCompletionProcessingWhenSafe` moves reconciliation to a context no higher than APC_LEVEL when required;
3. a failed rename emits a correlated result carrying the final NTSTATUS and no successful topology claim;
4. on success, `FltGetTunneledName` reconciles the retained pre-operation destination against Windows file-name tunneling;
5. because `FltQueryInformationFile` requires PASSIVE_LEVEL with special kernel APCs enabled, the driver queries
   `FileIdInformation` only when that stricter execution contract is satisfied; otherwise identity is explicitly unresolved;
6. the driver emits a no-reply protocol-v8 `RenameResult` correlated by the original kernel request sequence;
7. `RenameRollbackStore` appends a separate write-through SHA-256 hash-chained completion record containing the
   final name and volume/file identity when available, linked to the exact intent hash.

A completion may be authoritative `Succeeded`, `SucceededNameUnresolved`, `SucceededIdentityUnresolved`,
`SucceededNameAndIdentityUnresolved`, or `Failed`. Any supplied post-operation identity must exactly match the
source identity committed before allow. If the safe post path cannot run, the result cannot be delivered, or user mode
stops before persisting it, the intent remains **pending**. Recovery must never infer success from the pre-operation intent alone.

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
- repository-wide verification descends into each session's nested `write-cow`, `create-state`, `identity-state` and `rename-state` stores;
- CREATE and RENAME completion records are hash-chained separately and cryptographically linked to their exact pre-operation intents;
- the LAB gate validates all existing sessions before opening a new one.

These checks prevent a restart from proceeding on top of corrupt rollback state.

## Restart reconciliation evidence

0.7.13.0 adds a separate append-only, SHA-256 hash-chained `restart-reconciliation-journal.jsonl` for older CREATE/RENAME intents that have no authoritative completion record.

Before creating a new LAB session, GateClient validates the repository and then scans pending intents whose paths are still under the same explicit LAB root. It records current path state and, for ordinary files, `FILE_ID_INFO` from the exact opened handle. A pure classifier records one of four evidence outcomes:

- `SupportsCompleted`;
- `SupportsNotCompleted`;
- `Indeterminate`;
- `Ambiguous`.

For RENAME, source identity found at the destination while the source name is absent supports completion; the original source identity still at source with the original destination state supports non-completion. Other/conflicting topologies remain ambiguous. For CREATE, an originally absent target that remains absent supports non-completion, while a newly present file supports completion. Existing-file destructive CREATE remains indeterminate because overwrite may retain the same file identity.

Restart evidence is deliberately **not** a CREATE/RENAME completion. The original completion journals remain authoritative only when populated by the correlated kernel post-operation event. Repeated identical restart observations are idempotent.

## Writable-open pre-preservation

0.7.13.0 extends CREATE policy for existing files. If the requested DesiredAccess contains FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE, the LAB gate treats the open as preservation-sensitive even when the CreateDisposition itself is non-destructive.

Ordering is:

1. resolve the existing file inside the explicit LAB root;
2. bind its current FILE_ID_INFO;
3. commit the full-file pre-image;
4. commit the CREATE intent including DesiredAccess;
5. only then return SnapshotCommitted and allow CREATE to finish.

This is intentionally conservative. It establishes a durable pre-mutation baseline before a write-capable handle can later be used for writable memory mapping. Read-only opens still avoid eager full-file capture. Incident-created paths remain governed by their originally-absent baseline and never acquire a synthetic pre-incident image.

## Writable-section attestation

0.7.13.0 registers `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` as a no-reply observation path. For `SyncTypeCreateSection` with `PAGE_READWRITE` or `PAGE_EXECUTE_READWRITE`, the callback reads the existing nonpaged stream context and emits a correlated `WritableSection` event. The context carries the CREATE request sequence and the actual preservation decision returned before the handle was allowed.

GateClient resolves that request against the durable CREATE intent/completion and appends `writable-section-journal.jsonl`. A mapping is `BaselineVerified` only when the recorded CREATE preservation action and kernel gate decision agree. Missing intents, no-preservation mappings, path mismatches and decision mismatches remain explicit evidence states.

The section callback never calls `RgGateEvent`, never performs a file-name query, never calls `FltQueryInformationFile`, and never completes/denies the FSFilter operation. This follows the Filter Manager constraint that section-synchronization is not a general user-mode policy gate.

## Activation preflight

0.7.13.0 closes the major "mapping existed before GateClient" startup gap with an explicit activation barrier.

1. A LAB connection starts with the kernel gate in `NotActivated` state.
2. External CREATE plus non-paging WRITE/rename/delete/truncate-class mutations under the explicit root are fail-closed during preflight.
3. GateClient enumerates existing non-reparse files and opens each only for attributes.
4. The minifilter recognizes those gate-client opens only while activation is pending. In post-CREATE, at PASSIVE_LEVEL, it binds the final path/FILE_ID_INFO and calls `MmDoesFileHaveUserWritableReferences(FileObject->SectionObjectPointer)`.
5. Each result is queued as a no-reply `ActivationPreflight` event and persisted in a write-through SHA-256 hash-chained `activation-preflight-journal.jsonl`.
6. GateClient retains every successful probe handle with `FILE_SHARE_READ` only until activation. This forces pre-existing write/delete handles to surface as sharing failures and prevents new write/delete handles from racing the remaining scan; a mapped view whose handles were already closed is still detected by `MmDoesFileHaveUserWritableReferences`.
7. Failed/unresolved probes or a detected writable mapped view latch `gActivationHazard`. Only after every file is clean does GateClient call `FilterSendMessage` with `ActivateGate`; the kernel refuses activation while the hazard latch is set.

The activation callback does not perform rollback I/O. `MmDoesFileHaveUserWritableReferences` is used only from post-CREATE, where Filter Manager guarantees PASSIVE_LEVEL. The normal paging and section callbacks remain no-reply/non-blocking.

## Directory topology activation barrier

0.7.15 extends the protocol-v11 activation barrier to directory handles without adding a new kernel message type.

Before ordinary file probes begin, GateClient:

1. opens the protected root with FILE_READ_ATTRIBUTES and FILE_SHARE_READ only;
2. recursively opens every ordinary non-reparse directory with FILE_FLAG_BACKUP_SEMANTICS and the same read-only share mode;
3. queries FILE_ID_INFO from each exact directory handle;
4. appends identity-bound records to activation-topology-state/activation-topology-journal.jsonl;
5. keeps all directory handles open until the kernel accepts ActivateGate.

Because Windows share-access checks are bidirectional, an already-open directory handle carrying write or delete access is incompatible with the new read-only-share handle and activation fails before protection is declared active. Once the LAB client is connected but still NotActivated, new external CREATE/rename/delete operations are already fail-closed in the minifilter, so the held directory set closes the startup race through the activation handshake.

This milestone prevents pre-existing mutating directory handles from silently crossing startup. It does not yet implement directory-topology rollback for an allowed production rename/delete tree operation; those semantics remain future recovery work.

## Disposable-VM runtime proof

0.7.15.0 adds a manual integration harness for a preconfigured disposable Windows VM. It is deliberately separate from ordinary GitHub-hosted CI.

The runtime workflow requires a self-hosted runner labeled `ransomguard-lab-vm`, an elevated runner account, Visual Studio/WDK, lab signing already configured in the VM image, and a trusted test certificate with a private key. The workflow itself does not enable TESTSIGNING, modify Secure Boot, import trust roots, or change Defender.

The workflow builds the Engineering LAB bundle and driver from the exact checked-out commit, embeds/signs the current SYS, generates and signs the catalog, records commit/SHA-256 provenance, and executes two scenarios:

1. **Pre-existing mapped view** — a PAGE_READWRITE view remains alive after the original file and mapping handles are closed. GateClient startup preflight must detect the view through `MmDoesFileHaveUserWritableReferences`, refuse activation, and persist `writableViewPresent=true`.
2. **Post-activation mapped write** — after a clean activation, a new content-write handle creates a PAGE_READWRITE mapping, changes bytes and flushes them. The same session must contain a full pre-image whose SHA-256 matches the original file, a `BaselineVerified` writable-section record, and paging-write evidence.

The signed runtime driver package is deleted after the run and is not uploaded. Only logs, journals and a compact `runtime-result.json` evidence summary are retained.

This validates runtime ordering on one disposable VM image. It is not production compatibility certification and does not replace broader NTFS/ReFS, reboot, Driver Verifier, storage-pressure or fault-injection testing.

## Paging-write visibility

0.7.13.0 removes the registration-level `SKIP_PAGING_IO` blind spot without turning paging I/O into a synchronous user-mode gate.

After a successful in-scope CREATE, the minifilter attaches a nonpaged `FLT_STREAM_CONTEXT` containing the already-resolved bounded path plus kernel file identity when available. A paging write then:

1. checks only whether it is a paging/synchronous-paging IRP;
2. retrieves the existing stream context with `FltGetStreamContext`;
3. emits a bounded no-reply `PagingWrite` event with path, identity, offset and length;
4. returns immediately without `FltGetFileNameInformation`, `FltQueryInformationFile` or `RgGateEvent`.

GateClient persists those observations in a separate write-through SHA-256 hash-chained `paging-write-journal.jsonl`. Repository-wide validation includes that journal.

This closes the observability gap for memory-mapped/cache-manager writes associated with already tracked streams. The paging callback itself still captures no pre-image and remains deliberately non-blocking. For a stream whose content-write capable handle was opened after 0.7.11 policy became active, the required full-file pre-image was already committed during CREATE, so mapped mutations through that handle have a conservative recovery baseline.

## Bounded concurrent gate execution

0.7.13.0 removes the previous global serialization around blocking gate sends. The minifilter now:
- admits at most 8 simultaneous blocking gate requests;
- fails closed with STATUS_DEVICE_BUSY when that bound is exceeded;
- holds gPortMutex only long enough to acquire/release a client-port lease;
- waits for outstanding port users before disconnect/unload closes the client port.

The LAB GateClient receives messages continuously and dispatches preservation/reconciliation through a bounded worker pool. The default is 4 workers and the supported range is 1..8, matching the kernel admission ceiling. Store-level durability locks still serialize journal commit points where required.

Bounded concurrency and conservative restart evidence are implemented. A worker/process crash can still leave an intent without authoritative kernel completion; restart evidence preserves what can be observed without guessing.

## Verified rollback recovery planning

0.7.16 adds a recovery orchestration layer on top of the validated rollback stores without adding an in-place restore path.

For one session, the planner first runs repository/session validation, then hashes every session JSONL journal into an aggregate evidence digest. A deterministic PlanId binds that digest to the canonical recovery actions.

Actions are classified as:

- Ready: full-preimage or range-COW copy-out only;
- Review: authoritative topology evidence that still requires a human decision;
- Blocked: missing/unresolved authoritative completion evidence;
- Informational: no action required or superseded recovery evidence.

The executor treats the supplied plan file only as a freshness token. It rebuilds the current plan from repository evidence and requires PlanId plus evidence digest equality. It then executes the freshly rebuilt Ready list, never the caller-supplied action list.

Every output is written under a new recovery root outside the rollback repository. Full-preimage recovery uses the existing verified snapshot path. Range-COW recovery uses the current damaged source only as a base and overlays committed original blocks. The executor records recovered length and SHA-256 in recovery-execution.json.

No automatic delete, rename, overwrite-in-place, restore-in-place or originally-absent cleanup path exists. CREATE/RENAME topology remains Review/Blocked until explicit production recovery policy is designed and validated.

## Rollback storage admission and disk-pressure policy

0.7.17 adds a session-level storage admission layer around Engineering LAB preservation.

Before new rollback/evidence bytes are written, `RollbackStorageBudget` measures the actual committed session tree, reads the rollback volume's `AvailableFreeSpace`, and combines that state with every currently held reservation. Defaults are 8192 MiB maximum session size and 2048 MiB minimum free space.

Reservations are held across the corresponding durability operation and released in `finally`/async-dispose. The next admission re-measures the committed session tree, so completed files/journals remain charged after the transient reservation is released.

Estimated growth is operation-aware:

- full pre-image: current source length plus bounded journal/object overhead, or zero when the same path already has a committed full capture;
- range COW: only uncaptured original blocks intersecting the pending write plus journal overhead; already committed baseline/blocks are not reserved again;
- originally-absent baseline: metadata allowance only, or zero when already committed;
- activation/paging/section/completion evidence: bounded metadata reservation.

A blocking destructive operation that cannot satisfy session quota or free-space reserve receives a fail-closed denial before preservation is allowed to proceed. Evidence-only callbacks cannot block the underlying Memory Manager operation, but their journal append is also admitted through the same budget and fails instead of silently consuming the remaining disk reserve.

The storage walk refuses reparse-point files/directories. The LAB client exposes only bounded numeric tuning flags; there is no runtime switch to disable or bypass storage admission.

## Still required before production

- deeper crash recovery for requests interrupted before authoritative kernel completion delivery;
- broader live NTFS/ReFS validation beyond the automated mapping harness: directory-handle startup cases, reboot, Driver Verifier and fault injection;
- retention/cleanup policy for completed rollback sessions and long-running incident rotation;
- transition from protected-root health to containment/block policy;
- process-state capture and adaptive crypto analysis;
- production recovery UI/orchestration across rollback and crypto recovery;
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
