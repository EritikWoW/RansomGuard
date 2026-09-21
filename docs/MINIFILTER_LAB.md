# RansomGuard minifilter engineering lab — v0.7.6.0

The minifilter has two mutually exclusive user-mode connection modes:

- **Audit** — metadata-only, non-blocking CREATE / WRITE / rename / delete-disposition / truncate observation.
- **LAB Gate** — one explicit disposable directory is synchronously gated so a destructive mutation is
  allowed only after the rollback client returns an explicit preservation decision.

The LAB Gate exists to validate preservation ordering. It is **not** a production driver configuration.
Do not load it on a primary workstation and do not point it at real documents.

## Safety boundaries

- Demand-start driver only.
- Automatic volume attachment remains suppressed in the INF.
- Local NTFS/ReFS only.
- One communication client at a time.
- Gate root is negotiated at connection time and is bounded to one NT path.
- Gate client requires an explicit marker in the directory.
- Entire-drive, Windows, Program Files, ProgramData and reparse roots are refused by the gate client.
- The gate client PID is excluded from kernel gating.
- I/O outside the exact gate root remains fail-open.
- Name-query failures remain fail-open rather than risking OS-wide denial.
- A truncated name whose known prefix is already inside the gate root is sent to user mode and denied; no snapshot or absence baseline is committed against an ambiguous path.
- In-scope LAB I/O is denied if required user-mode preservation fails or the reply times out.
- The driver still contains no kernel file-writing, file-deletion, process-kill or process-suspend code.
- Altitude `370099.4242` is an unassigned lab placeholder and must never ship.

## Build

Build the engineering package:

```powershell
.\build_lab.cmd
```

Then, from the generated `RansomGuard-Lab-v0.7.6.0-*` directory, build/install the minifilter only in a
Windows test VM using the existing lab scripts.

## Audit mode

```powershell
.\run_minifilter_audit.cmd
```

Audit mode remains non-blocking.

## Gate mode

The convenience command defaults to a disposable directory named `RansomGuard-Gate-Lab` on the Desktop:

```powershell
.\run_minifilter_gate_lab.cmd
```

Or choose another disposable non-system directory:

```powershell
.\minifilter-tools\run_minifilter_gate_lab.ps1 -Root 'C:\RG-Gate-Test'
```

The first run creates only the gate marker before connecting. Put **copies** of test files into that folder
before starting the gate. Once connected, CREATE / WRITE / rename / delete-disposition / truncate requests in that folder are gated.
Protocol v7 distinguishes destructive replacement of an existing file from creation of an originally-absent path and carries a normalized destination for rename operations.
It also treats `FILE_DELETE_ON_CLOSE` on an existing file as destructive and captures a full pre-image first;
existing-directory delete-on-close is denied because directory-topology rollback is not modeled yet.
An originally-absent path is committed as metadata-only recovery state; it does not cause the recovery library to delete files.
For rename, source and destination preservation plus a durable pre-operation intent are committed before allow. A destination
outside the LAB root, an unresolved/truncated destination, an existing directory, or a same-file alias is denied. After the
filesystem completes the operation, protocol v7 emits a correlated no-reply `RenameResult`. Successful renames reconcile
the retained destination name through `FltGetTunneledName`; failures are recorded as failures. If reconciliation cannot be
delivered, the durable intent remains pending and must not be treated as completed. Post-operation file-ID binding for rename is not yet implemented.

For CREATE, the gate now also commits a durable operation intent before allow. After completion, protocol v7 emits
a correlated no-reply `CreateResult`: successful operations reconcile the tunneled final name and query
`FileIdInformation` from the actual completed file object; failed operations record their NTSTATUS without claiming
success. Missing or partially resolved completion data remains explicit, and missing delivery leaves the intent pending.

CREATE classification still begins with a path-based pre-operation probe, so do not use the lab gate as a
general-purpose protected folder yet.

Stop the client with Ctrl+C before unloading the filter.

## What a successful gate test proves

It proves that, for the tested path and operation, the minifilter can hold the destructive I/O while user
mode durably captures the pre-image and can deny the I/O when that commit is unavailable. It does **not**
prove production compatibility, crash safety, memory-mapped-write coverage, large-file performance,
containment efficacy, or universal rollback.
