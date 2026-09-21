# RansomGuard 0.7.5.0

RansomGuard is a Windows **anti-encryption and recovery layer**, not a general antivirus.
Its target is to preserve original data before destructive mutation, contain continued encryption,
and recover data through rollback plus adaptive crypto analysis.

## Core preservation milestone

0.7.5.0 retains the 0.7.2 range-aware COW gate and adds explicit CREATE preservation semantics.

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

The engineering minifilter protocol is now v6 and reports CREATE, WRITE, RENAME, DELETE and TRUNCATE-class metadata operations. RENAME events also carry a normalized destination path.

For CREATE, the gate distinguishes Windows create dispositions instead of treating every open as destructive:
existing `FILE_SUPERSEDE`, `FILE_OVERWRITE` and `FILE_OVERWRITE_IF` require a durable full pre-image;
`FILE_DELETE_ON_CLOSE` also requires a pre-image for an existing file even with an ordinary open;
create-capable dispositions on a missing path durably record that the path was originally absent; ordinary
non-destructive opens require no snapshot. Existing-directory delete-on-close is denied until directory-topology rollback exists. Paths marked originally absent do not later manufacture rollback
pre-images from data created during the same incident.

For RENAME, the gate now preserves the source and classifies the normalized destination before allow. An existing
destination gets its own identity-bound full pre-image; a missing destination gets a durable absence baseline; then
a hash-chained rename intent records source identity, destination state, flags and exact pre-operation names. Cross-root,
ambiguous, directory-topology and same-file-alias cases fail closed. After the filesystem completes the rename, the
minifilter reconciles the result on a safe post-operation path, applies `FltGetTunneledName` for successful operations,
and sends a correlated `RenameResult`. User mode durably records success, failure, or a successful-but-unresolved final
name in a separate hash-chained completion journal. If reconciliation cannot be delivered, the intent remains pending
instead of being treated as completed. Kernel file-ID confirmation of the completed object is still a separate milestone.

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

    release\RansomGuard-v0.7.5.0-<timestamp>\UI\RansomGuard.Ui.exe

LAB gate documentation:

    docs\MINIFILTER_LAB.md
    docs\ROLLBACK_ARCHITECTURE.md

## Current boundary

This milestone validates the preservation model and reduces write-path storage amplification.
It is not yet production ransomware blocking.

Remaining core work includes post-create reconciliation and kernel file-ID binding of completed create/rename operations,
bounded concurrent gate workers, crash reconciliation for pending/missing completion events, memory-mapped write coverage,
containment policy, process-state capture, adaptive crypto reconstruction, verified recovery orchestration,
driver signing and Microsoft-assigned production altitude.
