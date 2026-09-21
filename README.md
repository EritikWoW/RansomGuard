# RansomGuard 0.7.17.0

RansomGuard is a Windows **anti-encryption and recovery layer**, not a general antivirus.
Its target is to preserve original data before destructive mutation, contain continued encryption,
and recover data through rollback plus adaptive crypto analysis.

## Core preservation milestone

0.7.17.0 retains the 0.7.2 range-aware COW gate and adds explicit CREATE preservation semantics.

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

The engineering minifilter protocol is now v11 and reports CREATE, WRITE, RENAME, DELETE and TRUNCATE-class metadata operations. RENAME events also carry a normalized destination path.

For CREATE, the gate distinguishes Windows create dispositions instead of treating every open as destructive:
existing `FILE_SUPERSEDE`, `FILE_OVERWRITE` and `FILE_OVERWRITE_IF` require a durable full pre-image;
`FILE_DELETE_ON_CLOSE` also requires a pre-image for an existing file even with an ordinary open;
create-capable dispositions on a missing path durably record that the path was originally absent; ordinary
non-destructive opens require no snapshot. Existing-directory delete-on-close is denied until directory-topology rollback exists. Paths marked originally absent do not later manufacture rollback
pre-images from data created during the same incident.

Protocol v11 now also treats CREATE as a two-phase durable transaction. Before allow, the gate records a
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

On LAB gate restart, every older pending CREATE/RENAME intent under the same explicit root is now re-observed before a new session starts. RansomGuard records current path/file-identity evidence in a separate write-through SHA-256 hash-chained restart journal. Evidence can support completed, support not-completed, be indeterminate, or ambiguous. It never manufactures a filesystem completion record: authoritative completion still requires the original kernel post-operation result.

Protocol v11 also removes the previous blind skip of paging-write callbacks. After a successful in-scope CREATE, the minifilter attaches a nonpaged stream context containing the bounded tracked path and kernel file identity when available. A later paging write retrieves only that stream context and queues a no-reply `PagingWrite` event; it does not query file names, call the blocking gate, or perform filesystem I/O in the paging path. GateClient persists these observations in a separate hash-chained `paging-write-journal.jsonl`. PagingWrite itself remains visibility/evidence only. Starting with 0.7.11, mappings created from newly opened content-write capable handles have a full pre-image committed before the handle returns; this gives those mappings a recovery baseline without doing rollback I/O in the paging callback.

0.7.11 added a conservative pre-preservation rule for existing files opened with content-write capable access. If CREATE requests FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE, the LAB gate binds the current FILE_ID_INFO and commits a full pre-image plus CREATE intent before allowing the handle to return. This gives later writable mappings created from that handle a pre-mutation baseline without performing user-mode rollback work in paging I/O. Read-only opens remain non-eager, and incident-created paths still use the originally-absent baseline.

0.7.12 adds no-reply writable-section attestation. Before the Memory Manager creates a PAGE_READWRITE/PAGE_EXECUTE_READWRITE section, the minifilter reads the established stream context and emits a correlated `WritableSection` event carrying the originating CREATE request and preservation decision. GateClient links that event to the durable CREATE intent/completion and records whether the mapping is `BaselineVerified` or exposes an explicit invariant gap. The section callback never performs user-mode preservation or name/file-ID queries.

0.7.13 adds a fail-closed activation preflight for mappings/handles that existed before GateClient connected. A LAB connection begins in kernel `NotActivated` state. GateClient opens each existing file only for attributes; the minifilter checks the real stream with `MmDoesFileHaveUserWritableReferences`, binds `FILE_ID_INFO`, and emits a no-reply `ActivationPreflight` event. External in-root CREATE/WRITE/metadata mutations are denied until the scan completes. GateClient keeps every successfully probed file open with read-only sharing until activation, so pre-existing write/delete handles cause sharing violations and new write/delete handles cannot race the scan. A pre-existing mapped view with no live handle is detected by `MmDoesFileHaveUserWritableReferences`. GateClient sends `ActivateGate` only after every file is clean; the kernel also refuses activation when an authoritative preflight probe latched a hazard. Results are persisted in a write-through SHA-256 hash-chained `activation-preflight-journal.jsonl`.

0.7.14 adds a disposable-VM runtime integration harness. GitHub-hosted CI still stops at source, userspace and compile/API validation. A separate manual workflow can run only on a self-hosted Windows VM labeled `ransomguard-lab-vm`: it builds the exact checkout, signs the current SYS/catalog with a preinstalled LAB certificate, installs/attaches only inside that VM, then exercises two real mapping scenarios. First, a writable mapped view is created before GateClient while the original file/mapping handles are already closed; activation must fail and persist `writableViewPresent=true`. Second, a clean activation is followed by a writable mapping/write; the run must prove matching full pre-image SHA-256, `WritableSection = BaselineVerified`, and paging-write evidence. The workflow uploads runtime evidence/logs only and removes the signed driver package.

0.7.15 extends activation preflight from files to directory topology. Before file probing begins, GateClient opens the protected root and every ordinary non-reparse directory with FILE_READ_ATTRIBUTES and FILE_SHARE_READ only, records each directory FILE_ID_INFO in a write-through hash-chained activation-topology journal, and keeps all directory handles open until the kernel accepts ActivateGate. A pre-existing directory handle with write/delete/delete-on-close access therefore causes a sharing failure before activation, while new external CREATE/rename/delete operations are already denied by the NotActivated kernel barrier. This closes the main pre-existing directory-handle race without changing protocol v11.

0.7.16 adds deterministic verified rollback recovery planning and copy-out execution for Engineering LAB sessions. The planner revalidates the rollback repository, hashes all session journals, produces a stable PlanId, and classifies actions as Ready, Review, Blocked or Informational. Only full-preimage and range-COW copy-out actions can be Ready. The executor rebuilds the current plan before execution, refuses stale/tampered evidence, writes only into a new output tree, records SHA-256 for recovered files, and never deletes, renames or overwrites live source/evidence paths.

0.7.17 adds fail-closed rollback storage admission. Each LAB session has a concurrency-safe storage budget that combines actual committed session bytes, all in-flight reservations, and current filesystem free space. Defaults are 8192 MiB maximum session storage and a 2048 MiB free-space reserve; LAB runs may tighten these with `--max-store-mib` and `--min-free-mib`. WRITE range-COW, full pre-images, absence baselines, activation evidence, paging/section evidence and CREATE/RENAME completion journals all reserve capacity before writing. Blocking destructive I/O is denied when quota/free-space admission fails rather than allowing an unpreserved mutation.

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

    release\RansomGuard-v0.7.17.0-<timestamp>\UI\RansomGuard.Ui.exe

Manual disposable-VM runtime workflow:

    .github\workflows\minifilter-runtime-vm.yml

LAB gate documentation:

    docs\MINIFILTER_LAB.md
    docs\ROLLBACK_ARCHITECTURE.md
    docs\ROLLBACK_RECOVERY.md

## Current boundary

This milestone validates the preservation model and reduces write-path storage amplification.
It is not yet production ransomware blocking.

Bounded concurrent gate admission/workers are now implemented with a kernel cap of 8 and a configurable user-mode worker pool (default 4). The port mutex is no longer held across blocking FltSendMessage waits.

Restart evidence for pending/missing CREATE/RENAME completion events is durable and conservative; authoritative completion is never inferred from a restart probe. Paging writes on streams opened through the LAB gate are now visible as durable evidence without synchronously blocking the paging path.

Remaining core work includes deeper crash recovery for in-flight kernel requests,
broader live NTFS/ReFS/fault-injection coverage beyond the automated disposable-VM mapping harness,
retention/cleanup policy for completed rollback sessions, containment policy, process-state capture, adaptive crypto reconstruction, production recovery UI/topology orchestration,
driver signing and Microsoft-assigned production altitude.
