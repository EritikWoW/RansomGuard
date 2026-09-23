# RansomGuard minifilter engineering lab — v0.7.25.0

The minifilter has two mutually exclusive user-mode connection modes:

- **Audit** — metadata-only, non-blocking CREATE / WRITE / rename / delete-disposition / truncate observation.
- **LAB Gate** — one explicit disposable directory is synchronously gated so a destructive mutation is
  allowed only after the rollback client returns an explicit preservation decision.

The LAB Gate exists to validate preservation ordering. It is **not** a production driver configuration.
Do not load it on a primary workstation and do not point it at real documents.

On startup, older pending CREATE/RENAME/TRUNCATE intents and unsettled DELETE lifecycle transactions under the same LAB root are conservatively re-observed. CREATE/RENAME record path state + FILE_ID_INFO in restart-state; TRUNCATE records FILE_ID plus safely queryable EOF evidence in truncate-state; protocol-v15 DELETE records intent/disposition/finalization evidence in delete-state. DELETE handle cleanup is not pathname-deletion proof: live/restart topology is probed separately. Restart/finalization evidence never substitutes for the original kernel completion event. Exact consistent evidence may become Review-only crash recovery; cleanup-only, absent, ambiguous, indeterminate or conflicting evidence remains Blocked.

Protocol v11 also observes paging writes on streams that were successfully opened inside the LAB root. The driver uses a pre-established nonpaged stream context and emits no-reply evidence only; it does not run a filesystem name query or synchronous preservation gate in the paging path. Treat these events as visibility, not as proof that memory-mapped writes are recoverable.

## Activation preflight

A v0.7.26.0 LAB connection is not active immediately after `FilterConnectCommunicationPort`. GateClient first scans all existing non-reparse files under the disposable root. For every file, the kernel post-CREATE probe records final path/FILE_ID_INFO and tests `MmDoesFileHaveUserWritableReferences`.

If any file already has a user-writable mapped view, if a probe cannot be completed authoritatively, or if a pre-existing write/delete handle prevents the read-shared probe from opening the file, activation is refused. GateClient keeps every successful read-shared probe handle open until the explicit `ActivateGate` message succeeds, preventing a new write/delete handle from racing the rest of the scan.

0.7.15 applies the same activation-boundary rule to directory topology. Before file probes, GateClient opens the protected root and every ordinary non-reparse directory with FILE_READ_ATTRIBUTES and FILE_SHARE_READ only, records FILE_ID_INFO in activation-topology-state, and keeps those handles open through ActivateGate. A pre-existing directory handle with write/delete/delete-on-close access therefore prevents activation. New external CREATE/rename/delete requests remain blocked by the kernel NotActivated barrier while the scan is running.

Compile-only CI does not prove this ordering. 0.7.14 adds a separate disposable-VM runtime workflow that exercises both a mapping created before GateClient and a mapped write created after clean activation.

## Automated disposable-VM runtime workflow

The manual GitHub Actions workflow `.github/workflows/minifilter-runtime-vm.yml` runs only on a self-hosted Windows runner with labels `self-hosted, Windows, X64, ransomguard-lab-vm`.

Required VM image prerequisites:

- the runner account is Administrator;
- Visual Studio C++ tools + WDK/SDK are installed;
- driver lab/test signing is already configured in the disposable VM image;
- a trusted test-signing certificate with private key already exists in `CurrentUser\My` or `LocalMachine\My`;
- environment secret `RANSOMGUARD_LAB_CERT_THUMBPRINT` contains that certificate thumbprint;
- the VM is snapshot/revertable and contains no real user data.

The workflow and scripts deliberately **do not** enable TESTSIGNING, alter Secure Boot, add certificates to trust stores, or change Defender settings.

Runtime scenario 0 holds an ordinary subdirectory open with DELETE access before GateClient starts. Activation must fail because the topology preflight can no longer acquire its FILE_SHARE_READ-only directory handle.

Runtime scenario A creates a PAGE_READWRITE view, closes both original file/mapping handles while keeping the view alive, then starts GateClient. Activation must fail and `activation-preflight-journal.jsonl` must contain `writableViewPresent=true`.

Runtime scenario B activates cleanly, opens the test file for content-write access, creates a writable mapping, changes/flushed bytes, and requires all of the following in the same session:

- a full pre-image whose SHA-256 equals the original file;
- `WritableSectionAttestationState.BaselineVerified`;
- at least one paging-write evidence record;
- a final test-file hash different from the original hash.

Only runtime logs/journals and `runtime-result.json` are uploaded. The signed test driver package is deleted after the run.

0.7.26 extends the same manual workflow with an isolated filesystem compatibility matrix. The harness creates an expandable VHD file only under the guarded `RansomGuard-Filesystem-Matrix-Scratch` runner directory, attaches that new virtual disk, creates one partition, assigns an unused temporary drive letter, and formats only that new volume. NTFS is mandatory. ReFS is attempted separately; if the runner Windows edition cannot create ReFS, the evidence records the explicit capability failure and does not claim ReFS compatibility.

For every supported filesystem, the minifilter is attached only to the temporary volume and the run must prove real CREATE, RENAME, EOF TRUNCATE and DELETE completion journals plus a mapped-write full pre-image, `WritableSection = BaselineVerified` and paging-write evidence. Cleanup stops GateClient, unloads the minifilter, confirms unload before VHD detach, detaches the VHD and only then deletes the VHD file. A stale matrix VHD/volume or an unload failure is fail-fast and requires reverting the disposable VM checkpoint; the workflow does not repeatedly unload or blindly delete scratch state.

The matrix script contains no DiskPart `select disk`, `clean`, host partition deletion/conversion commands, hard-coded existing-volume formatting, boot changes, trust-store changes or Defender changes. Matrix evidence is uploaded separately as `ransomguard-filesystem-matrix-evidence`.

## Verified rollback recovery

0.7.16 adds a LAB-only `RollbackRecovery\RansomGuard.RollbackRecovery.exe` plus `rollback_recovery.cmd`.

Use `plan` first to generate a deterministic recovery plan for one rollback session. The plan classifies full-preimage/range-COW copy-out as Ready and keeps CREATE/RENAME/TRUNCATE/DELETE/topology transaction work in Informational, Review or Blocked states.

Use `execute` only with a saved plan. Before any output directory is created, the executor rebuilds the current plan from validated journal evidence and refuses stale PlanId/evidence digests. Only freshly rebuilt Ready actions are executed.

Recovery output must be a new non-reparse path outside the rollback repository. The executor never overwrites, deletes or renames live source/evidence files. See `docs/ROLLBACK_RECOVERY.md`.

0.7.19 additionally evaluates restart evidence for pending CREATE/RENAME transactions. Assessment is exact-match only (`operation kind + request sequence + intent hash`) and becomes Review only when every matching durable observation agrees on completion or non-completion. This does not create a completion record and does not add a new executable recovery action.

## Rollback storage budget

0.7.17 bounds LAB rollback growth before preservation writes are admitted.

Default policy:

- maximum rollback session size: **8192 MiB**;
- minimum free space kept on the rollback-store volume: **2048 MiB**.

Optional LAB-only tuning:

    --max-store-mib <64..1048576>
    --min-free-mib <64..1048576>

The client re-measures committed session bytes and combines them with all concurrent reservations before each preservation/evidence append. Existing full pre-images, existing COW blocks/baselines and existing absence baselines are recognized so they are not charged as new full captures.

If a blocking CREATE/WRITE/RENAME/delete/truncate operation cannot reserve enough rollback capacity, GateClient replies deny (internal error code 13). The original destructive operation is not allowed to continue without its required preservation proof.

Activation, paging, writable-section and completion evidence journals use the same storage budget. Those callbacks remain evidence-only where required by Filter Manager/Memory Manager semantics; budget failure stops the journal append rather than consuming the configured free-space reserve.

There is no `--disable-budget`, unlimited mode, or automatic free-space override.

## Rollback retention maintenance

0.7.18 adds LAB-only `RollbackMaintenance\RansomGuard.RollbackMaintenance.exe` plus `rollback_maintenance.cmd`.

Retention is never automatic. Generate a plan first, review candidates/issues, then execute that exact plan. Default policy is 30 days, 32 GiB managed completed storage and a 24-hour minimum age for pressure cleanup.

Only lifecycle-Completed, unheld sessions with no pending CREATE/RENAME/TRUNCATE intent and no unsettled DELETE lifecycle can become new purge candidates. Active, Faulted, Held, legacy and unresolved transaction sessions remain protected.

Cleanup is staged through `Retired\<session>` and the repository-level retention journal before deletion. See `docs/ROLLBACK_RETENTION.md`.

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

Then, from the generated `RansomGuard-Lab-v0.7.26.0-*` directory, build/install the minifilter only in a
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
Protocol v11 distinguishes destructive replacement of an existing file from creation of an originally-absent path and carries a normalized destination for rename operations.
It also treats `FILE_DELETE_ON_CLOSE` on an existing file as destructive and captures a full pre-image first;
existing-directory delete-on-close is denied because directory-topology rollback is not modeled yet.
An originally-absent path is committed as metadata-only recovery state; it does not cause the recovery library to delete files.
For rename, source and destination preservation plus a durable pre-operation intent are committed before allow. A destination
outside the LAB root, an unresolved/truncated destination, an existing directory, or a same-file alias is denied. After the
filesystem completes the operation, protocol v11 emits a correlated no-reply `RenameResult`. Successful renames
reconcile the retained destination name through `FltGetTunneledName`. The driver queries `FileIdInformation` from the
completed kernel file object only at PASSIVE_LEVEL with special kernel APCs enabled; otherwise identity is explicitly
unresolved. User mode records both name and identity when available and rejects a final identity that differs from the
pre-operation source identity. If reconciliation cannot be delivered, the durable intent remains pending and must not
be treated as completed.

For CREATE, the gate now also commits a durable operation intent before allow. After completion, protocol v11 emits
a correlated no-reply `CreateResult`: successful operations reconcile the tunneled final name and query
`FileIdInformation` from the actual completed file object; failed operations record their NTSTATUS without claiming
success. Missing or partially resolved completion data remains explicit, and missing delivery leaves the intent pending.

CREATE classification still begins with a path-based pre-operation probe, so do not use the lab gate as a
general-purpose protected folder yet.

Stop the client with Ctrl+C before unloading the filter.

## Writable-open preservation

For an existing test file, opening it with FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE now requires a committed full pre-image before the handle is returned. This is deliberate LAB behavior to establish a safe baseline for later writable mappings.

Read-only opens remain non-eager. Paths recorded as originally absent remain absence-governed even if they are later reopened writable.

## Writable-section attestation test

Open an existing test file with GENERIC_READ | GENERIC_WRITE after the LAB gate is connected, then call `CreateFileMapping(..., PAGE_READWRITE, ...)`. The session should contain a `section-state/writable-section-journal.jsonl` record linked to the CREATE request. For a correctly pre-preserved file the state must be `BaselineVerified`.

The section callback is evidence-only and must not block or deny the Memory Manager operation. A mapping created from a handle that existed before gate activation remains outside this milestone.

## Paging-write evidence test

On a disposable VM, open a test file through the LAB root, create a writable memory mapping, modify a page and flush/unmap it. A protocol-v9 `PagingWrite` record should appear in the session's `paging-state` journal with the tracked path, offset/length and kernel identity when available.

The PagingWrite record proves visibility. For the mapped file to count as pre-preserved, the same session must also contain the full pre-image/CREATE intent committed when its content-write capable handle was opened. Handles that existed before the LAB gate connected are not covered by this milestone.

## What a successful gate test proves

It proves that, for the tested path and operation, the minifilter can hold the destructive I/O while user
mode durably captures the pre-image and can deny the I/O when that commit is unavailable. It does **not**
prove production compatibility, crash safety, coverage for pre-existing writable handles, large-file performance,
containment efficacy, or universal rollback.


## Bounded gate concurrency (0.7.13.0)

The LAB gate no longer serializes the full blocking FltSendMessage duration under the global port mutex. Up to 8 kernel gate requests may be in flight. Additional in-scope destructive I/O fails closed rather than creating an unbounded queue.

GateClient uses a bounded worker pool. Default: 4 workers. Override only in a disposable LAB environment with:

    --gate-workers <1..8>

The upper bound intentionally matches the kernel admission ceiling. This change improves independent timeout behavior and allows preservation work on unrelated files to overlap; it does not make the prototype production-safe.


## Explicit LAB containment — 0.7.20

Protocol v12 adds an optional `--contain-pid <pid>` GateClient mode for isolated runtime testing. The PID is accepted only as activation input; the driver immediately resolves it to a referenced `PEPROCESS`. Future enforcement compares the requestor process object, not the numeric PID.

Containment is armed atomically with successful activation preflight. For the contained process only, mutation-capable CREATE and non-paging WRITE/RENAME/DELETE/TRUNCATE inside the selected root are denied in kernel mode before the normal user-mode preservation gate. Read-only opens are not denied by the containment classifier. Other processes continue through the ordinary preservation workflow.

The control protocol intentionally has no release/clear/bypass command. Disconnecting GateClient or unloading the LAB driver releases the process reference and clears containment. This is Engineering LAB functionality only; the ordinary service/detector does not invoke it.

## Event-bound containment transition — 0.7.21

Protocol v14 retains all v13 containment semantics and adds correlated no-reply `TruncateResult` evidence. EOF pre-operation requests carry the exact requested length; the safe post-operation path records authoritative status, FILE_ID_INFO and observed EOF when available. Allocation-size/VDL loss is intentionally not inferred during restart.

Protocol v15 adds correlated `DeleteDispositionResult` plus exact-handle `DeleteFinalized` lifecycle evidence. A successful disposition result proves only disposition acceptance. `IRP_MJ_CLEANUP` records `CleanupObserved`; GateClient probes pathname topology separately, and restart reconciliation repeats that conservative probe for unsettled DELETE transactions. Missing pathname, same-FILE_ID presence, replacement identity and ambiguous query outcomes remain distinct evidence states. None of these probes manufactures an authoritative disposition completion.

Protocol v13 keeps the pre-armed `--contain-pid` path and adds an explicit transition test path with `--contain-after-pid <pid>`. GateClient opens and keeps a handle to that exact process; if it exits, the authorization is invalid and a later process reusing the same numeric PID is not accepted.

The transition counter advances only for successful blocking gate replies that already committed a full pre-image or originally-absent baseline. The default LAB threshold is four preserved mutation events across two distinct paths, configurable only within bounded test ranges.

When the threshold is met, GateClient reserves storage and durably appends a Requested record to `containment-state\containment-journal.jsonl` before setting the containment reply flag. The minifilter accepts that flag only on an allowed preservation decision, references the exact requestor process object from the current callback data, installs the latch, and queues a no-reply `ContainmentActivated` event related to the original gate sequence. GateClient then appends the linked KernelActive receipt.

There is still no release/bypass command. A missing KernelActive receipt leaves the session faulted. This path is intentionally LAB-only and does not allow the ordinary service heuristic to contain arbitrary applications.
