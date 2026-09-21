# RansomGuard minifilter engineering lab — v0.7.11.0

The minifilter has two mutually exclusive user-mode connection modes:

- **Audit** — metadata-only, non-blocking CREATE / WRITE / rename / delete-disposition / truncate observation.
- **LAB Gate** — one explicit disposable directory is synchronously gated so a destructive mutation is
  allowed only after the rollback client returns an explicit preservation decision.

The LAB Gate exists to validate preservation ordering. It is **not** a production driver configuration.
Do not load it on a primary workstation and do not point it at real documents.

On startup, v0.7.11.0 also scans older pending CREATE/RENAME intents under the same LAB root and appends conservative restart evidence (path state + FILE_ID_INFO when available). This evidence is diagnostic/recovery input only and never substitutes for the original kernel completion event.

Protocol v9 also observes paging writes on streams that were successfully opened inside the LAB root. The driver uses a pre-established nonpaged stream context and emits no-reply evidence only; it does not run a filesystem name query or synchronous preservation gate in the paging path. Treat these events as visibility, not as proof that memory-mapped writes are recoverable.

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

Then, from the generated `RansomGuard-Lab-v0.7.11.0-*` directory, build/install the minifilter only in a
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
Protocol v9 distinguishes destructive replacement of an existing file from creation of an originally-absent path and carries a normalized destination for rename operations.
It also treats `FILE_DELETE_ON_CLOSE` on an existing file as destructive and captures a full pre-image first;
existing-directory delete-on-close is denied because directory-topology rollback is not modeled yet.
An originally-absent path is committed as metadata-only recovery state; it does not cause the recovery library to delete files.
For rename, source and destination preservation plus a durable pre-operation intent are committed before allow. A destination
outside the LAB root, an unresolved/truncated destination, an existing directory, or a same-file alias is denied. After the
filesystem completes the operation, protocol v9 emits a correlated no-reply `RenameResult`. Successful renames
reconcile the retained destination name through `FltGetTunneledName`. The driver queries `FileIdInformation` from the
completed kernel file object only at PASSIVE_LEVEL with special kernel APCs enabled; otherwise identity is explicitly
unresolved. User mode records both name and identity when available and rejects a final identity that differs from the
pre-operation source identity. If reconciliation cannot be delivered, the durable intent remains pending and must not
be treated as completed.

For CREATE, the gate now also commits a durable operation intent before allow. After completion, protocol v9 emits
a correlated no-reply `CreateResult`: successful operations reconcile the tunneled final name and query
`FileIdInformation` from the actual completed file object; failed operations record their NTSTATUS without claiming
success. Missing or partially resolved completion data remains explicit, and missing delivery leaves the intent pending.

CREATE classification still begins with a path-based pre-operation probe, so do not use the lab gate as a
general-purpose protected folder yet.

Stop the client with Ctrl+C before unloading the filter.

## Writable-open preservation

For an existing test file, opening it with FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE now requires a committed full pre-image before the handle is returned. This is deliberate LAB behavior to establish a safe baseline for later writable mappings.

Read-only opens remain non-eager. Paths recorded as originally absent remain absence-governed even if they are later reopened writable.

## Paging-write evidence test

On a disposable VM, open a test file through the LAB root, create a writable memory mapping, modify a page and flush/unmap it. A protocol-v9 `PagingWrite` record should appear in the session's `paging-state` journal with the tracked path, offset/length and kernel identity when available.

This test proves visibility only. It does not prove pre-preservation of mapped writes.

## What a successful gate test proves

It proves that, for the tested path and operation, the minifilter can hold the destructive I/O while user
mode durably captures the pre-image and can deny the I/O when that commit is unavailable. It does **not**
prove production compatibility, crash safety, memory-mapped-write coverage, large-file performance,
containment efficacy, or universal rollback.


## Bounded gate concurrency (0.7.11.0)

The LAB gate no longer serializes the full blocking FltSendMessage duration under the global port mutex. Up to 8 kernel gate requests may be in flight. Additional in-scope destructive I/O fails closed rather than creating an unbounded queue.

GateClient uses a bounded worker pool. Default: 4 workers. Override only in a disposable LAB environment with:

    --gate-workers <1..8>

The upper bound intentionally matches the kernel admission ceiling. This change improves independent timeout behavior and allows preservation work on unrelated files to overlap; it does not make the prototype production-safe.
