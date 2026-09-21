# RansomGuard 0.7.2.0

RansomGuard is a Windows **anti-encryption and recovery layer**, not a general antivirus.
Its target is to preserve original data before destructive mutation, contain continued encryption,
and recover data through rollback plus adaptive crypto analysis.

## Core milestone in 0.7.2.0

0.7.2.0 keeps the engineering-only pre-write gate from 0.7.1.0 and replaces whole-file snapshots
for ordinary WRITE operations with **range-aware copy-on-write**:

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

The minifilter protocol is v3 and reports WRITE, RENAME, DELETE and TRUNCATE-class metadata operations.

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
- unresolved/out-of-root I/O fails open;
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

Use only output from a run that ends with `BUILD PASSED`.

Normal UI:

    release\RansomGuard-v0.7.2.0-<timestamp>\UI\RansomGuard.Ui.exe

LAB gate documentation:

    docs\MINIFILTER_LAB.md
    docs\ROLLBACK_ARCHITECTURE.md

## Current boundary

This milestone validates the preservation model and reduces write-path storage amplification.
It is not yet production ransomware blocking.

Remaining core work includes exact create semantics, rename-destination identity tracking,
bounded concurrent gate workers, crash reconciliation, per-volume/file identity, memory-mapped write coverage,
containment policy, process-state capture, adaptive crypto reconstruction, verified recovery orchestration,
driver signing and Microsoft-assigned production altitude.
