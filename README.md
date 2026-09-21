# RansomGuard 0.7.1.0

RansomGuard is a Windows **anti-encryption and recovery layer**, not a general antivirus.
The target is: preserve original data before destructive mutation, contain continued encryption, and recover
verified data through rollback plus adaptive crypto analysis when sufficient runtime state exists.

## Core milestone in 0.7.1.0

0.7.0.0 introduced the durable incident-scoped rollback repository. 0.7.1.0 adds the first deliberately
constrained **pre-write preservation gate** for Windows engineering tests:

    destructive I/O arrives
            -> minifilter holds it
            -> user mode captures first pre-image
            -> snapshot + journal are durably flushed
            -> SnapshotCommitted reply
            -> original I/O may continue

For the explicit LAB root, a failed/missing/timed-out capture reply denies WRITE / rename / delete-disposition.
The gate client itself is excluded from gating so its rollback writes do not recursively block.

This is not enabled in the normal product bundle. `build_windows.cmd` remains the ordinary AuditOnly build.
`build_lab.cmd` publishes the engineering gate client, audit client and minifilter source/tools.

## LAB safety boundaries

The gate is intentionally limited while we validate the kernel/user-mode ordering:

- one explicit disposable directory only;
- requires `.ransomguard-gate-lab-root` marker;
- refuses an entire drive, Windows, Program Files, ProgramData and reparse roots;
- rollback store must be outside the gated root;
- unresolved/out-of-root I/O fails open rather than risking an OS-wide outage;
- in-scope capture failures fail closed;
- demand-start filter, automatic volume attachment suppressed;
- unassigned altitude `370099.4242` remains LAB-only and must never ship;
- no kernel file-writing, deletion, process-kill or process-suspend APIs were added.

Do **not** load this blocking prototype on a primary workstation or point it at real user data.

## Build

Normal product build:

    .\build_windows.cmd

Engineering LAB build:

    .\build_lab.cmd

Use only output from a run that ends with `BUILD PASSED`.

Normal UI:

    release\RansomGuard-v0.7.1.0-<timestamp>\UI\RansomGuard.Ui.exe

LAB gate instructions:

    docs\MINIFILTER_LAB.md
    docs\ROLLBACK_ARCHITECTURE.md

## Current boundary

This milestone proves the **ordering primitive**, not production protection. Remaining work includes create
semantics, rename destination tracking, range/block copy-on-write, crash reconciliation, memory-mapped writes,
production containment policy, process-state capture, adaptive crypto reconstruction, verified recovery
orchestration, signing and production driver distribution.

The authoring environment does not provide the Windows/.NET/WDK toolchain. C#, WPF, driver compilation and
live minifilter integration were therefore not executed here. Run the included Windows build and do not use a
partially built release.
