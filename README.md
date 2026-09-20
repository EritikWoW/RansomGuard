# RansomGuard 0.7.1.0

RansomGuard is being developed as a Windows **anti-encryption and recovery layer**, not as a general antivirus.
The target is: preserve original data before destructive mutation, contain continued encryption, and recover
verified data by rollback and adaptive crypto analysis.

## What 0.7.1.0 adds

This release adds the first durable rollback core:

- a separate rollback repository under the protected ProgramData state store;
- one independent rollback session per incident;
- first-preimage semantics inside an incident;
- SHA-256 calculated while a pre-image is copied;
- append-only, hash-chained journal records;
- write-through / `Flush(true)` commits for payload and journal;
- startup validation of existing rollback sessions before monitoring starts;
- recovery only to a **new verified copy**; the damaged source is never overwritten by this layer;
- corruption, sequence gaps, missing objects, unsafe session ids and ambiguous state are rejected.

The normal bundle does **not** yet capture pre-images automatically because the production minifilter pre-write
gate is not enabled in this milestone. Ordinary processes remain AuditOnly. ETW is telemetry/forensics, not the
future prevention path.

See [rollback architecture](docs/ROLLBACK_ARCHITECTURE.md) and [product target](docs/PRODUCT_TARGET.md).

## Build

Extract into a NEW source folder, then run:

    .\build_windows.cmd

Use only a release that ends with `BUILD PASSED`. Open:

    release\RansomGuard-v0.7.1.0-<timestamp>\UI\RansomGuard.Ui.exe

The build now executes the rollback-store test project in addition to the existing policy, recovery, trust,
localization and WPF smoke checks.

## Safety

Do not load the experimental minifilter on a primary machine. Public driver signing, assigned altitude,
production pre-write pending/timeout behavior, copy-on-write integration and verified automatic replacement of
user files remain unfinished.

The authoring environment used for this source package does not provide the Windows/.NET toolchain, therefore
C# compilation, WPF, SCM and minifilter integration were not executed here. Run the included Windows build and
use only a package that reports `BUILD PASSED`.
