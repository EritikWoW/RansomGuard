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

The current engineering branch extends the range-aware write COW gate with protocol v11 CREATE completion, RENAME destination and rename-completion semantics:

`CREATE -> classify disposition -> durable existing-file pre-image OR originally-absent baseline -> allow`

`WRITE -> durable original-length baseline + first touched blocks -> allow mutation`.

Rename, delete and truncate-class operations remain on a conservative full-file pre-image path.
An originally-absent path is remembered for the whole incident so later writes do not create a false pre-image
from data that did not exist before the incident.

The gate is intentionally not enabled in the normal bundle and is not production-safe yet. Existing-file
preservation is now additionally bound to a durable Windows `FILE_ID_INFO` identity journal
(volume serial + 128-bit file ID), so a path that changes to a different file during one incident is rejected.
CREATE classification still begins with a path-based pre-operation probe, but protocol v11 now records a durable CREATE intent before allow and correlates it with a post-operation result containing the tunneled final name and kernel `FileIdInformation` identity when available. Missing or partial reconciliation stays explicit and pending/unknown rather than being inferred.

Protocol v11 retains the normalized pre-operation rename destination and correlated post-operation `RenameResult`.
Before allowing a rename, the LAB gate preserves the source, preserves an existing destination or commits its absence,
and durably records a rename intent. After completion, the minifilter resolves the tunneled final name on a safe post-op
path and, only at PASSIVE_LEVEL with special kernel APCs enabled, queries `FileIdInformation` on the completed kernel
file object. Otherwise identity remains explicitly unresolved. User mode appends a second hash-chained record containing
final name and identity when available. The post-op identity must match the source identity committed
before allow. A missing or partially resolved result remains explicit; pre-operation intent is never promoted to success by inference.

The current LAB gate now uses bounded concurrent preservation: kernel admission caps simultaneous blocking gate sends at 8, while user mode dispatches a configurable 1..8 worker pool (default 4). Slow preservation no longer holds the global port mutex across the 30-second gate wait.

On restart, pending CREATE/RENAME intents are conservatively re-observed under the same explicit LAB root. Current path presence and Windows file identity are appended to a separate hash-chained restart-reconciliation journal and classified as evidence supporting completion, supporting non-completion, indeterminate, or ambiguous. This evidence never becomes an authoritative completion by inference.

Protocol v11 adds non-blocking visibility for paging writes associated with streams opened through the explicit LAB root. The driver attaches a nonpaged stream context after successful CREATE reconciliation and paging-write callbacks read only that context; they do not perform name queries or synchronously call the user-mode gate. GateClient records these observations in a separate write-through hash-chained paging evidence journal. The paging event itself is evidence only. For handles opened after 0.7.13 policy is active, content-write capable CREATE already committed a full pre-image before the handle returned, so later writable mappings have a conservative recovery baseline.

0.7.13 also pre-preserves an existing file before returning any CREATE that requests content-write capable access (FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE). This deliberately trades storage efficiency for correctness on handles that may later back writable memory mappings: the full pre-image and CREATE intent are durable before the application can create the mapping.

0.7.13 adds section-synchronization attestation for tracked streams: writable section creation is correlated to the originating CREATE request and its committed preservation decision without turning the Memory Manager callback into a blocking policy gate.

0.7.13 also adds an activation barrier for state that predates the gate. The kernel starts each LAB connection as not activated; GateClient scans every existing file, and post-CREATE preflight checks `MmDoesFileHaveUserWritableReferences` against the real stream's section pointers. External protected-root mutations are fail-closed during this scan. GateClient keeps read-shared probe handles open through activation, which rejects pre-existing write/delete handles and prevents new ones from racing the scan; handle-less writable mappings are detected by `MmDoesFileHaveUserWritableReferences`. The gate becomes active only after a successful explicit user-to-kernel `ActivateGate` handshake. Preflight evidence is durable and identity-bound.

0.7.14 adds a manual runtime-proof workflow for a preconfigured disposable self-hosted Windows VM. The workflow builds the Engineering LAB bundle and minifilter from the exact checked-out commit, signs the current SYS and generated catalog with a certificate already present in the VM, and validates real Filter Manager behavior. One scenario keeps a user-writable view alive after closing the original file/mapping handles and requires startup activation to reject it. A second scenario activates cleanly, creates a new writable mapping, mutates/flushed pages, and requires a matching full pre-image plus `BaselineVerified` section evidence and paging evidence. Signed driver packages are removed after the run and are not uploaded as artifacts.

0.7.15 extends startup protection to directory topology. GateClient holds the protected root and every ordinary non-reparse directory with read-only sharing through the explicit ActivateGate handshake, binds each directory to FILE_ID_INFO, and persists the set in a hash-chained activation-topology journal. Pre-existing directory handles carrying write/delete/delete-on-close access therefore prevent activation through Windows share-access enforcement; new external topology opens/mutations remain blocked by the kernel NotActivated barrier.

0.7.16 adds deterministic verified rollback recovery planning for Engineering LAB sessions. Repository and session journals are revalidated, all session JSONL evidence is bound into a SHA-256 digest, and a stable PlanId classifies actions as Ready/Review/Blocked/Informational. Only full-preimage and range-COW copy-out actions can be executed. The executor rebuilds the current plan before execution, rejects stale evidence, writes into a new output tree, records recovered SHA-256 values, and never performs automatic delete/rename/overwrite of live topology.

0.7.17 adds bounded rollback storage admission to the LAB gate. Every session measures its already committed bytes and combines them with concurrent in-flight reservations plus current filesystem free space. The default limit is 8192 MiB per session with 2048 MiB left free on the rollback-store volume. Preservation/evidence writers reserve estimated growth before commit; quota/free-space refusal is fail-closed for blocking destructive I/O. Repeated full/range/absence evidence is recognized so already committed preservation is not charged again.

0.7.18 adds explicit lifecycle and retention for rollback evidence. New sessions are managed as Created/Completed/Faulted with optional Hold, and retention can only select verified Completed, unheld sessions with no pending CREATE/RENAME transactions. The default policy is 30 days / 32 GiB with a 24-hour floor for pressure cleanup. Purge is manual, stale-plan resistant and crash-resumable through a repository-level Started/Quarantined/Completed audit journal and a Sessions-to-Retired quarantine step before deletion.

The next core milestones are broader NTFS/ReFS runtime/fault-injection coverage, production retention UI/policy integration, directory-topology rollback semantics beyond startup handle exclusion, deeper crash recovery for requests interrupted before authoritative kernel completion delivery,
containment, process-state capture,
adaptive crypto analysis, and production recovery UI/orchestration across rollback plus crypto evidence.
