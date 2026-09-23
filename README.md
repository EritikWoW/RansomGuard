# RansomGuard 0.7.28.0

RansomGuard is a Windows **anti-encryption and recovery layer**, not a general antivirus.
Its target is to preserve original data before destructive mutation, contain continued encryption,
and recover data through rollback plus adaptive crypto analysis.

## Core preservation milestone

0.7.28.0 keeps the protocol-v15 preservation/recovery model and reproducible-build controls, and adds a manual bounded-concurrency VM qualification. An overload probe launches 16 independent CREATE helpers against the 8-request kernel gate and requires excess admission to fail closed without creating a pathname or durable user-mode transaction. The full CREATE/RENAME/TRUNCATE/DELETE/mapped-write qualification then runs at the supported concurrency ceiling of 8 and requires authoritative durable correlation, mapped-write pre-image integrity, writable-section evidence and paging-write evidence.

Ordinary WRITE operations still use **range-aware copy-on-write**:

    WRITE arrives
        -> minifilter holds it
        -> user mode records original file length
        -> only original blocks intersecting that write are durably captured
        -> block + hash-chained journal are flushed
        -> SnapshotCommitted
        -> original WRITE may continue

Each original block is captured at most once per incident session. Later writes to the same block reuse
the already committed pre-image. Appends beyond the original EOF need only the baseline length and are
undone by truncating the recovered copy to that length.

Rename, delete-disposition and explicit truncate/allocation-length operations remain on the conservative
**full-file pre-image** path for now.

The engineering minifilter protocol is now v15 and reports CREATE, WRITE, RENAME, DELETE and TRUNCATE-class metadata operations. DELETE can emit correlated no-reply `DeleteDispositionResult` and `DeleteFinalized` events without changing the fixed RG_EVENT wire size. A successful disposition result proves only that the filesystem accepted the disposition request; exact-handle cleanup is recorded separately and is not treated as proof that the pathname has disappeared.

For CREATE, the gate distinguishes Windows create dispositions instead of treating every open as destructive:
existing `FILE_SUPERSEDE`, `FILE_OVERWRITE` and `FILE_OVERWRITE_IF` require a durable full pre-image;
`FILE_DELETE_ON_CLOSE` also requires a pre-image for an existing file even with an ordinary open;
create-capable dispositions on a missing path durably record that the path was originally absent; ordinary
non-destructive opens require no snapshot. Existing-directory delete-on-close is denied until directory-topology rollback exists. Paths marked originally absent do not later manufacture rollback
pre-images from data created during the same incident.

Protocol v13 now also treats CREATE as a two-phase durable transaction. Before allow, the gate records a
hash-chained CREATE intent linked to the preservation proof. After the filesystem completes the operation,
the minifilter reconciles the final tunneled name with `FltGetTunneledName`, queries `FileIdInformation`
from the actual opened file object, and emits a correlated no-reply `CreateResult`. User mode records the
outcome, final name and 128-bit file identity in a separate hash-chained completion journal. Missing result
delivery leaves the intent pending; unresolved name/identity are represented explicitly rather than guessed.

For RENAME, the gate now preserves the source and classifies the normalized destination before allow. An existing
destination gets its own identity-bound full pre-image; a missing destination gets a durable absence baseline; then
a hash-chained rename intent records source identity, destination state, flags and exact pre-operation names. Cross-root,
ambiguous, directory-topology and same-file-alias cases fail closed. After the filesystem completes the rename, the
minifilter reconciles the result on a safe post-operation path, applies `FltGetTunneledName` for successful operations,
and, when the safe post-operation callback is at PASSIVE_LEVEL with special kernel APCs enabled, queries
`FileIdInformation` from the actual renamed kernel file object before sending a correlated `RenameResult`.
If that API contract is not satisfied, identity is explicitly unresolved rather than queried unsafely. User mode
durably records the final tunneled name and 128-bit file identity when available, with explicit name-only,
identity-only or fully unresolved success states. A post-op identity that differs from the pre-op source identity is
rejected. If reconciliation cannot be delivered, the intent remains pending instead of being treated as completed.

On LAB gate restart, older pending CREATE/RENAME/TRUNCATE intents under the same explicit root are re-observed before a new session starts. CREATE/RENAME use the shared restart journal; TRUNCATE keeps FILE_ID and length evidence in `truncate-state/truncate-restart-journal.jsonl`. EOF loss can support completed/non-completed only when the exact durable FILE_ID and requested/original length match. Allocation-size and valid-data-length loss remain indeterminate rather than guessed. Restart evidence never manufactures a filesystem completion record: authoritative completion still requires the original kernel post-operation result.

Protocol v13 also removes the previous blind skip of paging-write callbacks. After a successful in-scope CREATE, the minifilter attaches a nonpaged stream context containing the bounded tracked path and kernel file identity when available. A later paging write retrieves only that stream context and queues a no-reply `PagingWrite` event; it does not query file names, call the blocking gate, or perform filesystem I/O in the paging path. GateClient persists these observations in a separate hash-chained `paging-write-journal.jsonl`. PagingWrite itself remains visibility/evidence only. Starting with 0.7.11, mappings created from newly opened content-write capable handles have a full pre-image committed before the handle returns; this gives those mappings a recovery baseline without doing rollback I/O in the paging callback.

0.7.11 added a conservative pre-preservation rule for existing files opened with content-write capable access. If CREATE requests FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE, the LAB gate binds the current FILE_ID_INFO and commits a full pre-image plus CREATE intent before allowing the handle to return. This gives later writable mappings created from that handle a pre-mutation baseline without performing user-mode rollback work in paging I/O. Read-only opens remain non-eager, and incident-created paths still use the originally-absent baseline.

0.7.12 adds no-reply writable-section attestation. Before the Memory Manager creates a PAGE_READWRITE/PAGE_EXECUTE_READWRITE section, the minifilter reads the established stream context and emits a correlated `WritableSection` event carrying the originating CREATE request and preservation decision. GateClient links that event to the durable CREATE intent/completion and records whether the mapping is `BaselineVerified` or exposes an explicit invariant gap. The section callback never performs user-mode preservation or name/file-ID queries.

0.7.13 adds a fail-closed activation preflight for mappings/handles that existed before GateClient connected. A LAB connection begins in kernel `NotActivated` state. GateClient opens each existing file only for attributes; the minifilter checks the real stream with `MmDoesFileHaveUserWritableReferences`, binds `FILE_ID_INFO`, and emits a no-reply `ActivationPreflight` event. External in-root CREATE/WRITE/metadata mutations are denied until the scan completes. GateClient keeps every successfully probed file open with read-only sharing until activation, so pre-existing write/delete handles cause sharing violations and new write/delete handles cannot race the scan. A pre-existing mapped view with no live handle is detected by `MmDoesFileHaveUserWritableReferences`. GateClient sends `ActivateGate` only after every file is clean; the kernel also refuses activation when an authoritative preflight probe latched a hazard. Results are persisted in a write-through SHA-256 hash-chained `activation-preflight-journal.jsonl`.

0.7.14 adds a disposable-VM runtime integration harness. GitHub-hosted CI still stops at source, userspace and compile/API validation. A separate manual workflow can run only on a self-hosted Windows VM labeled `ransomguard-lab-vm`: it builds the exact checkout, signs the current SYS/catalog with a preinstalled LAB certificate, installs/attaches only inside that VM, then exercises two real mapping scenarios. First, a writable mapped view is created before GateClient while the original file/mapping handles are already closed; activation must fail and persist `writableViewPresent=true`. Second, a clean activation is followed by a writable mapping/write; the run must prove matching full pre-image SHA-256, `WritableSection = BaselineVerified`, and paging-write evidence. The workflow uploads runtime evidence/logs only and removes the signed driver package.

0.7.15 extends activation preflight from files to directory topology. Before file probing begins, GateClient opens the protected root and every ordinary non-reparse directory with FILE_READ_ATTRIBUTES and FILE_SHARE_READ only, records each directory FILE_ID_INFO in a write-through hash-chained activation-topology journal, and keeps all directory handles open until the kernel accepts ActivateGate. A pre-existing directory handle with write/delete/delete-on-close access therefore causes a sharing failure before activation, while new external CREATE/rename/delete operations are already denied by the NotActivated kernel barrier. This closes the main pre-existing directory-handle race without changing protocol v11.

0.7.16 adds deterministic verified rollback recovery planning and copy-out execution for Engineering LAB sessions. The planner revalidates the rollback repository, hashes all session journals, produces a stable PlanId, and classifies actions as Ready, Review, Blocked or Informational. Only full-preimage and range-COW copy-out actions can be Ready. The executor rebuilds the current plan before execution, refuses stale/tampered evidence, writes only into a new output tree, records SHA-256 for recovered files, and never deletes, renames or overwrites live source/evidence paths.

0.7.17 adds fail-closed rollback storage admission. Each LAB session has a concurrency-safe storage budget that combines actual committed session bytes, all in-flight reservations, and current filesystem free space. Defaults are 8192 MiB maximum session storage and a 2048 MiB free-space reserve; LAB runs may tighten these with `--max-store-mib` and `--min-free-mib`. WRITE range-COW, full pre-images, absence baselines, activation evidence, paging/section evidence and CREATE/RENAME completion journals all reserve capacity before writing. Blocking destructive I/O is denied when quota/free-space admission fails rather than allowing an unpreserved mutation.

0.7.18 adds explicit rollback session lifecycle and manual retention/cleanup. New sessions are hash-chain tracked as Created, Completed, Faulted and Hold-protected; only clean Completed, unheld, transaction-complete sessions may be selected. The default retention policy expires completed sessions after 30 days and caps managed completed storage at 32 GiB, with capacity-pressure purge limited to sessions at least 24 hours old. Cleanup is stale-plan resistant and crash-resumable: PurgeStarted is written before atomically moving Sessions/<id> to Retired/<id>, then Quarantined is committed, only the quarantined tree is deleted with reparse-safe traversal, and PurgeCompleted closes the audit chain. GateClient never runs retention automatically.

0.7.19 integrates durable restart reconciliation into verified recovery planning without fabricating missing kernel results. Restart observations are assessed only for the exact operation kind, kernel request sequence and intent hash. A pending CREATE/RENAME may move from `Blocked` to `Review` only when every matching durable observation consistently supports completion or consistently supports non-completion. Any absent, ambiguous, indeterminate or conflicting observation set remains `Blocked`. These crash-reconciliation actions are never `Ready`; the executor still runs only full-preimage/range-COW copy-out actions and never performs automatic delete, rename or in-place restore.

0.7.20 introduces protocol v12 and an explicit Engineering LAB containment mode. After activation preflight completes, GateClient may atomically activate the gate and bind containment to one requested process. The driver resolves that PID to a referenced kernel `PEPROCESS` and compares future requestors by process-object identity, so PID reuse does not inherit the latch. While connected, that process is denied mutation-capable CREATE plus non-paging WRITE/RENAME/DELETE/TRUNCATE operations inside the explicit LAB root before user-mode preservation is consulted. Read-only opens remain allowed, other processes continue through the normal preservation gate, no runtime release command exists, and disconnect/unload drops the referenced process object. This is still LAB-only and is not wired to the ordinary service detector.

0.7.21 introduces protocol v13 and a safer runtime transition primitive. An explicitly authorized LAB process is held open by GateClient so PID reuse cannot silently re-authorize a replacement. After a bounded number of successfully preserved mutations across multiple paths, GateClient first commits a write-through hash-chained containment request, then sets `RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR` on the reply for that exact kernel event. The minifilter references `FltGetRequestorProcess(Data)` for that IRP before allowing it to continue, emits a no-reply `ContainmentActivated` event, and GateClient commits a linked kernel-active receipt. Unknown reply flags, containment flags on denied/unpreserved operations, latch conflicts, missing activation receipts and journal-link mismatches fail closed. The ordinary service remains AuditOnly; this is the validated bridge required before production detector policy can be connected.

0.7.22 adds a disposable-VM completion-loss proof for CREATE. In an explicit LAB mode, GateClient may intentionally omit the first authoritative `CreateResult` only after the filesystem CREATE has completed, then exit cleanly and restart in reconciliation-only mode. The runtime harness proves the durable CREATE intent remains, the authoritative completion journal is empty, the created path exists, restart evidence classifies the exact pending intent as `SupportsCompleted`, and the recovery planner keeps the transaction in `Review` rather than promoting topology mutation to `Ready`. This replaces the earlier unsafe idea of hard-crashing GateClient while the kernel was still waiting for a blocking gate reply.

0.7.23 extends the same live proof to RENAME. The harness starts with a durable source file and absent destination, allows the rename to complete, intentionally omits the first authoritative `RenameResult`, then verifies after restart that the source path is missing and the destination carries the exact durable source FILE_ID_INFO. Restart reconciliation must classify that pending rename as `SupportsCompleted`; the recovery planner may expose the topology transaction only as `Review`, while verified content copy-out remains separate and automatic rename/delete of live paths stays forbidden.

0.7.24 introduces protocol v14 and makes TRUNCATE a two-phase durable transaction. Before allowing `FileEndOfFileInformation`, `FileAllocationInformation`, or `FileValidDataLengthInformation`, GateClient binds the exact FILE_ID_INFO, captures/reuses the verified full pre-image for a pre-existing file, records the requested length and safely observable original metric, and commits `truncate-intent-journal.jsonl`. The post-operation callback emits correlated `TruncateResult` evidence with authoritative NTSTATUS plus post-operation identity and EOF/allocation metric when safe for `FltQueryInformationFile`. Missing detail remains explicitly unresolved. Lost EOF completion may be classified only from exact same-FILE_ID requested/original lengths; allocation-size and valid-data-length loss remain `Indeterminate`. Recovery never changes a live file length automatically: the transaction is Informational/Review/Blocked while verified pre-image copy-out remains the only executable `Ready` action.

0.7.25 introduces protocol v15 and makes DELETE a durable lifecycle rather than treating a successful disposition call as equivalent to pathname deletion. Before allowing `FileDispositionInformation` or `FileDispositionInformationEx`, GateClient binds the exact FILE_ID_INFO, captures/reuses the verified full pre-image for a pre-existing file, records the exact disposition flags and commits `delete-intent-journal.jsonl`. The post-operation callback emits a correlated `DeleteDispositionResult` with authoritative NTSTATUS plus `DeletePending` and identity when they can be queried safely. A successful delete disposition binds a stream-handle context to that exact request; a later disposition-clear/superseding request emits cancellation evidence, while `IRP_MJ_CLEANUP` emits only handle-lifecycle `CleanupObserved` evidence. GateClient then probes pathname topology separately after a bounded delay, and restart reconciliation repeats that conservative probe for unsettled transactions. Missing pathname can support completion and the same FILE_ID still present can support non-completion, but replacement identities, query failures and conflicting evidence remain unresolved. Restart/finalization evidence never manufactures an authoritative disposition completion. Recovery exposes DELETE topology only as Informational/Review/Blocked; verified pre-image copy-out can be `Ready`, and live delete/recreate operations remain disabled.

0.7.26 adds a manual disposable-VM filesystem compatibility matrix without changing protocol v15. The runtime workflow creates an isolated expandable VHD under the guarded runner scratch directory, partitions only that new virtual disk, assigns a temporary unused drive letter, and formats the new volume as NTFS; it then repeats the same attempt for ReFS. NTFS support is mandatory. ReFS capability is detected at runtime: if the Windows edition cannot create ReFS, the result records an explicit unsupported reason rather than claiming compatibility. For each supported filesystem the minifilter is attached only to the scratch volume and must prove authoritative CREATE, RENAME, TRUNCATE and DELETE completion journals plus mapped-write full-preimage, writable-section and paging-write evidence. Cleanup stops GateClient, unloads the filter, detaches the VHD and deletes the VHD file. The harness contains no host-disk clean/select/delete operations and never formats a hard-coded existing drive.

0.7.27 hardens reproducibility and supply-chain inputs without changing protocol v15. `global.json` pins .NET SDK 10.0.401 with roll-forward disabled; CI installs that exact SDK; every third-party GitHub Action is referenced by a reviewed full commit SHA rather than a mutable version tag. A dedicated source gate rejects floating SDK/action references and verifies secret-bearing file patterns stay ignored. NuGet dependency graphs are committed as `packages.lock.json` files and restore runs in locked mode so an unreviewed graph change fails the build instead of silently resolving different transitive packages.

0.7.28 adds a separate manual self-hosted concurrency-stress workflow without changing protocol v15. The stress harness configures GateClient at its maximum 8 workers. A dedicated 16-wide CREATE overload probe must observe bounded fail-closed admission above the kernel cap without creating denied pathnames or durable transactions. The full CREATE, RENAME, synchronized TRUNCATE, synchronized DELETE and mapped-write qualification then runs at the supported concurrency ceiling of 8. The harness re-opens the durable JSONL evidence, requires unique request correlations and authoritative successful completions for every admitted mutation, requires DeletedObserved finalization for each delete, rejects GateClient worker failures, and verifies each mapped target's committed pre-image SHA-256 plus BaselineVerified writable-section and paging-write evidence.

0.7.29 adds a combined manual fault campaign without changing protocol v15. Low-disk testing uses only a newly created expandable NTFS VHD as the rollback-store volume: after gate activation the harness consumes scratch-volume free space below the configured reserve, requires an in-scope RENAME to fail closed with unchanged topology, then removes the filler and requires the same RENAME to succeed with a hash-verified full pre-image. Real reboot recovery is split into ARM and VERIFY phases because a self-hosted Actions job cannot resume through a VM reboot. ARM persists a completion-lost TRUNCATE intent, verified full pre-image and SHA-256-bound campaign state while deliberately leaving the LAB filter loaded. After the operator reboots the disposable VM, VERIFY requires a newer Windows boot time, proves the EOF mutation plus durable pending evidence survived, runs reconcile-only restart observation, and confirms the transaction remains Review-only while verified pre-image copy-out remains Ready. The workflow itself never issues reboot/shutdown, boot-policy or Driver Verifier commands.


## Recovery safety

Range recovery:

- never overwrites the damaged source;
- reconstructs into a new `.ransomguard-cow-recovered` file;
- verifies every captured block by SHA-256 before applying it;
- restores the original file length;
- refuses reconstruction when the damaged source is shorter than the recorded baseline, because that
  requires the full-preimage/transaction recovery path.

The existing full pre-image recovery remains available for rename/delete/truncate scenarios and also
writes only to a new recovery copy.

## LAB safety boundaries

The blocking gate is still deliberately restricted:

- one explicit disposable directory only;
- requires `.ransomguard-gate-lab-root`;
- refuses an entire drive, Windows, Program Files, ProgramData and reparse roots;
- rollback storage must be outside the gated root;
- rollback storage is bounded by a per-session quota plus a minimum filesystem free-space reserve; admission failure fails closed;
- out-of-root or name-query-failed I/O fails open;
- a path truncated after an already verified in-root prefix is denied rather than preserved against an ambiguous name;
- in-scope preservation failure or timeout fails closed;
- negative/special write offsets are denied rather than guessed;
- demand-start filter, automatic attachment suppressed;
- altitude `370099.4242` is an unassigned LAB placeholder and must never ship;
- no kernel file-writing, deletion, process-kill or process-suspend APIs are used.

Do **not** load this blocking prototype on a primary workstation or point it at real user data.

## Build

Normal product build:

    .\build_windows.cmd

Engineering LAB build:

    .\build_lab.cmd

Compile-only minifilter CI additionally builds Release x64 against the pinned Microsoft WDK,
runs x64 Universal DDI API validation, and publishes an intentionally unsigned driver artifact.
It does not install, load or attach the driver.

Use only userspace output from a run that ends with `BUILD PASSED`.

Normal UI:

    release\RansomGuard-v0.7.29.0-<timestamp>\UI\RansomGuard.Ui.exe

Manual disposable-VM runtime workflows:

    .github\workflows\minifilter-runtime-vm.yml
    .github\workflows\minifilter-crash-vm.yml

LAB gate documentation:

    docs\MINIFILTER_LAB.md
    docs\ROLLBACK_ARCHITECTURE.md
    docs\ROLLBACK_RECOVERY.md
    docs\ROLLBACK_RETENTION.md

## Current boundary

This milestone validates the preservation model and reduces write-path storage amplification.
It is not yet production ransomware blocking.

Bounded concurrent gate admission/workers are now implemented with a kernel cap of 8 and a configurable user-mode worker pool (default 4). The port mutex is no longer held across blocking FltSendMessage waits.

Restart evidence for pending/missing CREATE/RENAME/TRUNCATE completion events and unsettled DELETE lifecycle transactions is durable and conservative; authoritative completion is never inferred from a restart or topology probe. DELETE cleanup is handle-lifecycle evidence only, while pathname state is observed separately. The recovery planner may expose exact, fully consistent evidence as `Review` only, while cleanup-only, ambiguous, indeterminate or conflicting evidence stays `Blocked`. Paging writes on streams opened through the LAB gate are visible as durable evidence without synchronously blocking the paging path.

Remaining core work includes Driver Verifier qualification and broader long-duration/mixed-workload stress,
production retention UI/policy integration, production detector-to-containment authorization/policy, process-state capture, adaptive crypto reconstruction, production recovery UI/topology orchestration,
driver signing and Microsoft-assigned production altitude.
