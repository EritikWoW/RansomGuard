# RansomGuard 0.8.6.0

- Added the first normal-service Production Enforce lifecycle above `ReadyForLifecycle` package admission while keeping the default package/configuration Audit.
- Windows Service startup now uses an SCM-first outer host: `WindowsServiceLifetime` is established before SecureStore, rollback verification, package admission or driver lifecycle work; a hosted bootstrap then starts the normal inner runtime. This prevents SCM 1053 startup failure while retaining the main-thread global instance mutex.
- Enforce now validates rollback readiness before any kernel-start transition, verifies/registers the admitted demand-start minifilter, validates registered altitude/flags and installed SYS hash, then loads and attaches only the protected-root volume.
- The service spawns the exact admitted ProductionGate client and publishes `Protected` only after a bounded structured readiness signal emitted after activation preflight/kernel `ActivateGate`.
- Added production-only redirected-stdin lifecycle control; GateClient emits structured READY/STOPPED signals and clean shutdown still requires durable terminal evidence before `DeactivateGate`.
- Unexpected ProductionGate loss publishes `DegradedProtected`; the service retries the same ProductionGate/root profile and returns to `Protected` only after a fresh activation preflight.
- Loss of the supervising Service control channel is explicitly unauthorized: ProductionGate exits without `DeactivateGate`, preserving the kernel fail-safe latch across a Service process crash until a later validated reconnect.
- The production supervisor now selects one SHA-256 root-bound rollback session before its reconnect loop. GateClient loss and Service restart reopen that same Active session after repository/restart reconciliation; multiple Active sessions or a session bound to another root fail closed instead of silently starting a disconnected evidence namespace.
- Production rollback lifecycle completion now occurs only after `DeactivateGate` returns kernel `Maintenance`; GateClient emits clean STOPPED only after the durable `Completed` record. Faulted or legacy-unmanaged service-owned production sessions block new Enforce session creation until explicit recovery.
- Clean service shutdown may detach/unload the driver only after the kernel confirms `Maintenance`; failure to prove graceful deactivation does not unload the fail-safe driver. Shutdown confirmation/exit/driver cleanup are bounded to 10s/3s/10s budgets.
- Added bounded Enforce settings for GateClient workers, rollback quota/free-space reserve and reconnect delay. Automatic detector-to-containment remains disabled.
- Added source/state tests for lifecycle ordering, admitted-package binding, reconnect semantics and maintenance shutdown. Exact-head disposable-VM lifecycle qualification remains a merge/release gate.
- ProductionGate profile qualification now isolates and removes its qualification-only fixed ProgramData state root before the normal-Service lifecycle runs; it can no longer leave an unmarked `RansomGuardV03\Rollback` directory that correctly triggers SecureStore's fail-closed trusted-generation check.
- The same profile-qualification cleanup now removes its LAB `RansomGuardMinifilter` service registration and matching Driver Store package after unload, so the following production lifecycle starts from the required service-absent boundary instead of being forced to reject stale LAB altitude/image registration.

# RansomGuard 0.8.5.0

- Removed trust in the user-mode `ClientProcessId` field as a security identity while retaining protocol v18.
- The minifilter connect callback now references `PsGetCurrentProcess()`, derives the actual PID through `PsGetProcessId`, and rejects a context whose claimed PID differs from the connecting process.
- The connected GateClient `PEPROCESS` is retained for the lifetime of the port and released on rejected connect, disconnect and unload paths.
- GateClient rollback/protocol self-I/O exemption now compares the exact requestor process object instead of a PID supplied in the wire context.
- LAB containment refuses the exact connected GateClient process object in addition to PID/system checks.
- Added a runtime negative probe that submits a valid protocol/root/volume connect context with a forged PID and requires the kernel to reject it before ordinary GateClient qualification continues.
- Existing FSCTL, hard-link, dormant-handle, mapped-write, degraded reconnect, scope, containment, filesystem-matrix and ProductionGate regressions remain required.

# RansomGuard 0.8.4.0

- Registered `IRP_MJ_FILE_SYSTEM_CONTROL` in the minifilter while retaining protocol v18.
- Added explicit mediation for `FSCTL_SET_ZERO_DATA`, `FSCTL_DUPLICATE_EXTENTS_TO_FILE`, `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX`, `FSCTL_OFFLOAD_WRITE`, `FSCTL_FILE_LEVEL_TRIM` and `FSCTL_SET_SPARSE`.
- Audit mode remains non-blocking; proven outside-scope operations remain outside the protected gate.
- Inside-root or protected-volume ambiguous data-mutating FSCTLs fail closed during Preflight, Maintenance, DegradedProtected, containment, or when no durable stream preservation context exists.
- An active FSCTL is allowed only when the stream already carries a durable `SnapshotCommitted` or `BaselineCommitted` CREATE preservation context; no synchronous user-mode preservation is attempted from the FSCTL callback.
- Added a real `FSCTL_SET_ZERO_DATA` runtime probe that must mutate the protected file while the committed full pre-image retains the exact original SHA-256.
- Hard-link, dormant writable-handle, mapped-write, disconnect/reconnect, scope, containment, filesystem-matrix and ProductionGate regressions remain required.

# RansomGuard 0.8.3.0

- Closed the hard-link alias protection gap while retaining protocol v18.
- Activation preflight now queries the exact frozen file handle and refuses any protected regular file with `NumberOfLinks != 1`.
- Kernel `IRP_MJ_SET_INFORMATION` handling now recognizes `FileLinkInformation` and `FileLinkInformationEx` in gate modes.
- Hard-link source and destination names are normalized/classified together: touching the protected root is denied, ambiguity on the protected volume fails closed, and proven outside-to-outside hard links remain allowed.
- Added RuntimeHarness `hard-link` probes plus VM evidence requirements for pre-existing alias rejection, inside-to-outside denial, outside-to-inside denial and outside-to-outside non-overblocking.
- The normal product remains Audit by default; production service lifecycle activation is still separate.

# RansomGuard 0.8.2.0

- Advanced the minifilter/GateClient wire contract to protocol v18 and added the distinct `RgClientProductionGate` mode.
- LAB and ProductionGate retain the same protected-root/volume preservation, activation-preflight, maintenance and DegradedProtected foundation; a degraded session now also retains its original gate profile, preventing LAB <-> ProductionGate reconnect substitution.
- ProductionGate rejects containment reply flags in kernel and returns `STATUS_NOT_SUPPORTED` for LAB-only containment/query/fault-injection controls. The containment/scope-injection helpers also enforce LAB mode directly.
- GateClient adds explicit `--production` profile selection. Production profile has no LAB root marker, requires an existing explicit local non-system/non-reparse protected root, uses the fixed ProgramData rollback repository, and rejects LAB prepare/fault/reconciliation/shutdown/containment options before connecting.
- Gate-specific post-operation/no-reply evidence is routed by the retained gate profile rather than the mutable current connection mode, preventing cross-profile evidence delivery across disconnect/reconnect.
- FilterClient and ProductionProtection package admission now require protocol v18; package version is 0.8.2.0.
- This milestone still performs no production driver install/start/load/attach and no service-to-GateClient supervision. `Mode=Enforce` therefore remains `EnforceUnavailable` in the normal service until the lifecycle milestone is implemented and VM-qualified.

# RansomGuard 0.8.1.0

- Added the fixed ProductionProtection package descriptor/layout for future Enforce lifecycle activation.
- Package admission validates exact version/protocol, SHA-256 digests, non-reparse/final file identity, GateClient FileVersion, INF provider/DriverVer/altitude, and rejects the Engineering LAB provider/placeholder altitude.
- The running service executable, GateClient and driver catalog must all pass cache-only Authenticode verification; GateClient and CAT must be signed by the same certificate as the actual running service image.
- Added Windows catalog-mode trust verification using `CryptCATAdminAcquireContext2`, `CryptCATAdminCalcHashFromFileHandle2` and catalog-mode `WinVerifyTrust`; both SYS and INF must verify as members of the supplied signed CAT.
- A successfully admitted package exposes signer identity and `ReadyForLifecycle=true`, but the normal service still reports `EnforceUnavailable`: no driver install/start/load/attach or GateClient process supervision is performed in 0.8.1.
- The normal release bundle still excludes SYS/CAT/INF/GateClient and defaults to Audit.
- A numeric altitude is not treated as proof of Microsoft assignment; external release governance remains required.
- Protocol remains v17 and the qualified LAB kernel behavior is unchanged.

# RansomGuard 0.8.0.0

- Added configuration schema 4 with explicit `Mode=Audit` / `Mode=Enforce`. Audit remains the default.
- Added a pure production protection state machine covering AuditOnly, EnforceStarting, EnforceUnavailable, KernelConnected, Protected, DegradedProtected, Maintenance, Failed and Stopped.
- Rollback repository validation is now represented as an explicit prerequisite before future production kernel startup may proceed.
- The read-only status/diagnostics API now exposes requested mode, effective protection state, rollback readiness, kernel-channel connection, kernel-enforcement claim and automatic-containment state.
- `KernelEnforcementActive` is never inferred from an installed/running driver service. It becomes true only for explicit Protected/DegradedProtected state-machine phases.
- Enforce foundation configuration requires exactly one explicit non-drive protected root, cannot disable the signed-driver requirement, and keeps automatic containment disabled until a dedicated detector-to-containment policy milestone is qualified.
- This milestone deliberately does **not** install/start/load the driver or spawn GateClient from the normal service. The normal bundle still excludes SYS/CAT/INF/GateClient, and an Enforce request reports `EnforceUnavailable` until the production lifecycle milestone is implemented and qualified.
- Protocol remains v17; the previously qualified 0.7.33 LAB kernel path is unchanged.

# RansomGuard 0.7.33.0

- Introduced minifilter/GateClient protocol v17 without increasing the fixed 544-byte connect-context size; the former reserved field now carries the protected NT-volume prefix length.
- GateClient derives the exact NT device-volume prefix for the selected local LAB root and the kernel resolves it to a referenced Filter Manager `PFLT_VOLUME`.
- Destructive ordinary user-mode CREATE/WRITE/RENAME/DELETE/TRUNCATE operations with unresolved/unknown normalized scope now fail closed when the callback is on the bound protected volume instead of silently treating ambiguity as out-of-scope; before entering Ambiguous, normalized source/destination lookup gets a second Filter Manager cache-only-safe opportunity via `QUERY_ALWAYS_ALLOW_CACHE_LOOKUP`.
- Mutation-capable ambiguous CREATE is denied while read-only CREATE remains available.
- RENAME scope now evaluates both source and destination. If either side is inside the protected root the operation is gated; if one side is unresolved on the protected volume the operation fails closed; only two proven-outside sides bypass the root gate.
- Ambiguous callbacks on other volumes remain out of this gate, limiting availability blast radius.
- GateClient's own process identity is excluded from ambiguous-volume denial so rollback-store I/O cannot self-deadlock the synchronous policy channel.
- The referenced protected volume is retained through `DegradedProtected`, exact-root reconnect requires the same Filter Manager volume object, and graceful release/unload dereferences it explicitly.
- The normal product remains AuditOnly. Kernel-mode requestors, paging/section evidence semantics, Administrator/SYSTEM lifecycle tamper, production signing/altitude and production Enforce orchestration remain outside this milestone.
- Bumped userspace/LAB and driver package version to 0.7.33.0.

# RansomGuard 0.7.32.0

- Introduced minifilter/GateClient protocol v16 with explicit protection states: Inactive, Preflight, Protected, DegradedProtected and Maintenance.
- An activated LAB gate now records a kernel protection-required latch. Unexpected GateClient loss publishes DegradedProtected before publishing client disconnect, retains the exact negotiated root and denies resolved ordinary user-mode mutation-capable CREATE, non-paging WRITE, RENAME, DELETE and TRUNCATE operations in that root.
- A replacement protocol-v16 GateClient may reconnect only to the exact retained root and must rerun activation preflight before returning to Protected.
- Added the whole-session DeactivateGate maintenance command. GateClient requests it only after a clean, transaction-complete lifecycle terminal record; the first request atomically closes new gate and queued-evidence admission, and already-replied requests racing the transition are denied before allow processing.
- Maintenance-requested is not release authorization. While blocking gate sends or queued evidence work remain, deactivation stays busy and an intervening client death still enters DegradedProtected. Only a fully drained deactivation clears the containment/protection latches and authorizes port-close release.
- Closed the atomic state-transition window by publishing DegradedProtected before connected=0 on unexpected disconnect and publishing connected=1 before clearing DegradedProtected on reconnect.
- Added static source gates for protocol-v16 state ordering, exact-root reconnect and graceful-deactivation invariants.
- This milestone remains Engineering LAB only. Unresolved path/scope classification still fails open, paging/mapped I/O keeps the existing pre-preserved-baseline model, kernel-mode requestors remain out of the ordinary gate, and Administrator/SYSTEM unload/tamper is not yet a protected boundary.
- Bumped userspace/LAB and driver package version to 0.7.32.0.

# RansomGuard 0.7.31.0

- Added a dedicated manual sustained mixed-workload qualification without changing minifilter protocol v15.
- The existing bounded-concurrency harness now supports an optional long-lived mixed phase while preserving its default 0.7.28 behavior when mixed rounds are disabled.
- One loaded exact-commit signed minifilter and one GateClient/rollback session survive the entire campaign; the default profile runs 60 mixed waves with 10-second pauses between waves.
- Every mixed wave releases CREATE, RENAME, EOF TRUNCATE, DELETE and mapped-write helpers behind one shared barrier, for 300 mixed mutations in the default profile.
- Mixed source files are prepared before gate activation so the workload does not bypass the protected path while constructing its own fixtures.
- Each round requires expected filesystem topology, durable DELETE finalization, live GateClient and healthy workers before continuing.
- Final validation reuses the strict transaction proof: unique intent/completion correlation, zero pending CREATE/RENAME/TRUNCATE/DELETE transactions, hash-verified mapped-write full pre-images, writable-section evidence and paging-write evidence.
- The result records mixed start/finish UTC timestamps and stopwatch elapsed seconds and proves the configured inter-round pause budget was actually consumed.
- Added a dedicated manual `Minifilter mixed endurance VM lab` workflow with exact-commit signed-driver provenance, guarded disposable-VM roots, bounded inputs and evidence artifact upload. It does not reboot Windows, enable Driver Verifier, alter boot policy or manage disks.
- Added source gates for the mixed harness/workflow and wired them into hosted build/minifilter CI.
- Bumped userspace/LAB and driver package version to 0.7.31.0.

# RansomGuard 0.7.30.0

- Added a dedicated manual disposable-VM Driver Verifier qualification without changing minifilter protocol v15.
- ARM refuses any pre-existing verifier configuration, registers the exact signed `RansomGuardMinifilter.sys` package without loading it, enables the Windows standard Driver Verifier profile, switches verifier boot mode to `oneboot`, and writes SHA-256-bound exact-commit campaign state before reboot. Verifier return code 2 is treated as the documented `EXIT_CODE_REBOOT_NEEDED`, not as failure; postconditions still re-query the exact target and OneBoot mode.
- The runtime phase refuses to proceed unless a real reboot occurred after ARM, then loads the exact signed driver and requires `verifier /query` to name that loaded target before exercising the existing bounded-concurrency qualification.
- Verifier runtime covers admission overflow plus concurrent CREATE, RENAME, TRUNCATE, DELETE and mapped-write paths with the same durable transaction/pre-image/section/paging evidence requirements as 0.7.28. The RuntimeHarness now synchronizes CREATE/RENAME/mapped-write helpers on shared start barriers so Driver Verifier process-start overhead cannot serialize the workload and mask the kernel admission cap.
- Any Windows bugcheck event in the Driver Verifier qualification window fails the campaign rather than being treated as a successful stress result.
- A successful runtime phase executes `verifier /reset`, verifies persistent settings are cleared for the next boot, and persists a reset-bound campaign state.
- CLEAR requires a second real reboot, proves both scheduled and current verifier activity no longer names the RansomGuard driver, proves the minifilter is unloaded, and archives the completed campaign.
- A later ARM may archive a prior `runtime-failed-reset` campaign only after validating its SHA-256-bound state, proving `verifier /reset` had been scheduled, observing a newer boot, and confirming verifier persistent/querysettings state is clear; every other pre-existing `Active` state remains fail-closed.
- Driver Verifier handoff timestamps are now read from the SHA-bound raw JSON with `System.Text.Json` and parsed as offset-bearing `DateTimeOffset` values. This prevents `ConvertFrom-Json` date coercion from stripping the original `Z`/offset and weakening real-reboot proofs on non-UTC runners.
- Added a dedicated source gate that forbids `/all`, wildcard driver selection, volatile/persistent verifier modes, direct VerifyDrivers/VerifyDriverLevel registry mutation, automatic reboot/shutdown and BCD mutation.
- Added `.github/workflows/minifilter-verifier-vm.yml` with explicit `arm`, `runtime` and `clear` phases. The workflow never reboots the VM itself.
- Bumped userspace/LAB and driver package version to 0.7.30.0.

# RansomGuard 0.7.29.0

- Added a combined manual disposable-VM fault campaign without changing minifilter protocol v15.
- Added an isolated low-disk campaign that creates and formats only a newly created expandable VHD under a guarded RansomGuard scratch path, places the rollback store on that VHD, activates the real gate, then consumes only the scratch-volume free space until it crosses the configured 64 MiB reserve.
- Under storage pressure, a real protected-root RENAME attempt must fail closed at the mutation-capable source CREATE/open admission boundary before any RENAME intent is persisted; the source pathname must remain present, the destination must remain absent, and the gate must stay alive.
- After the VHD filler is removed, the same RENAME must succeed with one correlated durable intent/completion pair plus a physically present full pre-image whose length and SHA-256 match the original bytes, proving recovery from pressure without restarting the gate.
- Added a real-reboot qualification split into explicit ARM and VERIFY phases because a self-hosted GitHub Actions job cannot survive a VM reboot.
- ARM deliberately drops the first authoritative TRUNCATE completion only after the filesystem EOF mutation succeeds, commits the intent plus full pre-image, writes a flushed/hash-bound persistent state file, and intentionally leaves the LAB minifilter loaded for the reboot boundary.
- VERIFY refuses to run unless Windows boot time changed, requires the filter to be cleared by reboot, proves the changed EOF plus pending durable intent and pre-image survived the reboot, runs reconcile-only, requires exact SupportsCompleted restart evidence, and confirms recovery keeps the TRUNCATE transaction Review-only while the verified full pre-image remains the sole Ready copy-out.
- Added a dedicated fault-campaign source gate. It forbids host-disk clean/select operations, hard-coded existing-volume formatting, automatic reboot/shutdown/boot-policy mutation, and Driver Verifier commands in this milestone.
- Extended the existing manual minifilter crash workflow with campaign choices: completion-loss, low-disk, reboot-arm and reboot-verify.
- Bumped userspace/LAB and driver package version to 0.7.29.0.

# RansomGuard 0.7.28.0

- Added a separate manual disposable-VM concurrency stress campaign without changing minifilter protocol v15.
- GateClient runs with the maximum 8 user-mode workers. A dedicated CREATE admission-overflow probe launches 16 helpers against the kernel cap of 8 and requires at least one excess request to fail closed with access denied, no created pathname and no durable user-mode transaction.
- After the overflow proof, qualification phases run at the supported concurrency ceiling of 8 and cover CREATE, RENAME, barrier-synchronized EOF TRUNCATE, barrier-synchronized DELETE and mapped-write operations on distinct protected files.
- Durable evidence validation is target-specific rather than count-only: every admitted CREATE/RENAME/TRUNCATE/DELETE operation must bind to exactly one matching intent/request and one authoritative successful completion; each delete must also reach durable DeletedObserved topology finalization, while denied overflow CREATEs must remain absent and leave no intent/completion record.
- Mapped-write qualification requires a committed full pre-image for every admitted target, verifies the stored object SHA-256 against the journal, and requires BaselineVerified writable-section plus paging-write evidence.
- Added a source gate that parses and validates the stress harness/workflow, requires overflow width 16 > gate cap 8, requires cap-level qualification at 8, and forbids formatting, reboot/shutdown, boot-policy or Driver Verifier commands in this milestone.
- Added a dedicated manual `Minifilter concurrency stress VM lab` workflow using the exact checked-out commit, signed LAB driver provenance, bounded cleanup and evidence artifact upload.
- Fixed a real concurrency race found by the VM campaign: storage-budget measurement can enumerate a transient pre-image `.tmp` immediately before another gate worker atomically renames it to the committed object. Such already-reservation-accounted transient names no longer fault unrelated evidence workers.
- DELETE qualification now waits for durable `DeletedObserved` finalization before advancing, and any GateClient worker failure is a hard stress-test failure.
- Bumped userspace/LAB and driver package version to 0.7.28.0.

# RansomGuard 0.7.27.0

- Hardened build reproducibility without changing minifilter protocol v15.
- Added `global.json` pinning .NET SDK 10.0.401 with roll-forward disabled; CI installs and the local build preflight requires that exact SDK.
- Replaced mutable GitHub Action tags with reviewed full-length immutable commit SHAs for checkout, setup-dotnet, upload-artifact, cache, setup-msbuild and setup-nuget.
- Added a supply-chain source gate that rejects floating SDK selectors, unreviewed/mutable Action references, missing deterministic/lock-file properties and missing secret-file ignore patterns.
- Added common certificate/private-key/environment secret patterns to `.gitignore`.
- Replaced the install-record SHA-256 self-comparison with explicit 64-hex validation and a regression source gate.
- Refreshed guided setup, audit quick-start and product-target documentation to match the current audit-only UI and protocol-v15 preservation/reconciliation model.
- NuGet dependency lock files are generated by Windows CI and are committed before this milestone is considered complete; restore then runs in locked mode.

# RansomGuard 0.7.26.0

- Added a manual disposable-VM filesystem compatibility matrix without changing protocol v15.
- The matrix creates only isolated expandable VHD scratch disks under a guarded RansomGuard runner directory; it never selects, cleans, partitions or formats an existing host disk.
- NTFS scratch-volume coverage is mandatory. ReFS is attempted separately and records an explicit unsupported capability reason when the runner Windows edition cannot create ReFS.
- Each supported filesystem must prove real authoritative CREATE, RENAME, TRUNCATE and DELETE completion evidence through the minifilter/GateClient path.
- Each supported filesystem also exercises a real writable mapping and requires verified full-preimage SHA-256, WritableSection BaselineVerified evidence and paging-write evidence.
- The minifilter is explicitly attached only to the temporary matrix volume; cleanup stops GateClient, unloads the filter, detaches the VHD and deletes the VHD file.
- Added a source safety gate forbidding host-disk clean/select/delete operations, hard-coded Format-Volume targets and boot/security policy mutation.
- Extended the existing manual runtime VM workflow to upload separate filesystem-matrix evidence.
- Bumped userspace/LAB and driver package version to 0.7.26.0.

# RansomGuard 0.7.25.0

- Bumped the Engineering LAB minifilter wire protocol to v15 without changing the fixed RG_EVENT structure size.
- Added durable DELETE intent, disposition-completion and finalization journals, all write-through, hash-chained and bound to the exact request sequence, pathname and FILE_ID_INFO.
- Before allowing FileDispositionInformation/FileDispositionInformationEx delete requests, GateClient captures/reuses the verified full pre-image for pre-existing files and commits the exact disposition flags plus durable DELETE intent.
- Added correlated no-reply DeleteDispositionResult evidence with authoritative NTSTATUS plus DeletePending and FILE_ID_INFO when those fields can be queried safely.
- Successful delete dispositions bind an exact stream-handle context. A later disposition clear/superseding request records cancellation; IRP_MJ_CLEANUP records CleanupObserved for that exact handle/request.
- CleanupObserved is deliberately not treated as pathname deletion. GateClient persists cleanup first, then performs a separate bounded live topology probe; restart reconciliation performs the same conservative probe for unsettled transactions.
- Missing pathname can support completed DELETE topology, the same FILE_ID still present can support non-completion, and replacement identities/query failures/conflicting observations remain unresolved. Restart/finalization evidence never manufactures an authoritative disposition completion.
- Recovery planning adds ReviewDeleteTransaction. DELETE topology remains Informational/Review/Blocked and is never an executable Ready mutation; verified pre-image copy-out remains separate.
- Session lifecycle and retention protect missing-completion, cleanup-only, same-identity-present, ambiguous and conflicting DELETE transactions from cleanup.
- Added LAB-only --drop-first-delete-completion plus a synchronized native FileDispositionInfo helper and extended the manual disposable-VM completion-loss harness with CREATE/RENAME/TRUNCATE/DELETE evidence requirements.
- Bumped userspace/LAB and driver package version to 0.7.25.0.

# RansomGuard 0.7.24.0

- Bumped the Engineering LAB minifilter wire protocol to v14 without changing the fixed RG_EVENT structure size.
- Added correlated no-reply `TruncateResult` post-operation evidence for FileEndOfFileInformation, FileAllocationInformation and FileValidDataLengthInformation.
- Added hash-chained write-through `truncate-state` intent/completion/restart journals. The intent records exact request sequence, requested length, original observable length, FILE_ID_INFO and preservation proof before allow.
- Existing files retain/reuse a verified full pre-image before a TRUNCATE intent is committed; incident-created files do not manufacture a pre-incident image.
- Successful post-operation evidence queries FILE_ID_INFO plus EOF/allocation size only from PASSIVE_LEVEL with special kernel APCs enabled. Unavailable identity/metric detail remains explicit rather than guessed.
- Lost EOF completion can be classified after restart only when the same FILE_ID has either the exact requested length or the exact original length. Unexpected lengths are Ambiguous; allocation-size and valid-data-length loss remain Indeterminate.
- Recovery planning adds ReviewTruncateTransaction. Transaction state never becomes an executable live-length mutation; verified full-preimage/range-COW copy-out remains the only Ready recovery path.
- Session lifecycle and retention now treat pending TRUNCATE intents as unresolved transaction evidence and protect those sessions from cleanup.
- Added LAB-only `--drop-first-truncate-completion`, a single-operation native EOF helper, and disposable-VM evidence requirements for lost TruncateResult restart reconciliation.
- Bumped userspace/LAB and driver package version to 0.7.24.0.

# RansomGuard 0.7.23.0

- Extended disposable-VM completion-loss proof to RENAME.
- GateClient can intentionally omit the first authoritative RenameResult only after the filesystem rename has completed, then exit cleanly for restart reconciliation.
- The VM harness proves source removal, destination presence, FILE_ID continuity, durable rename intent, absent authoritative completion, SupportsCompleted restart evidence, and Review-only topology recovery.
- CREATE completion-loss remains a regression scenario in the same manual workflow.
- Kept automatic live rename/delete/topology mutation disabled; verified content copy-out remains separate.
- Synchronized userspace/LAB manifests, driver INF and product package version to 0.7.23.0.

# RansomGuard 0.7.22.0

- Added disposable-VM completion-loss proof for CREATE without hard-crashing GateClient while the kernel is waiting for a blocking reply.
- GateClient can intentionally omit the first authoritative CreateResult after the filesystem CREATE has completed, then cancel its receive loop and exit cleanly.
- Restart reconciliation proves an originally absent target that now exists as SupportsCompleted while leaving the authoritative completion journal empty.
- Recovery planning keeps the pending CREATE transaction Review-only and never promotes automatic deletion/topology mutation to Ready.
- Added bounded minifilter unload handling so failed runtime experiments cannot hang the self-hosted VM cleanup path indefinitely.

# RansomGuard 0.7.21.0

- Bumped the Engineering LAB minifilter wire protocol to v13.
- Added an event-bound containment flag on RG_GATE_REPLY: containment can be requested only on the reply for an already preserved gate event.
- The driver binds the exact FltGetRequestorProcess(Data) PEPROCESS for that IRP before allowing the preserved operation to continue; no second PID lookup is used for the transition.
- Unknown reply flags and containment flags attached to denied/unpreserved operations are rejected fail-closed.
- Added no-reply ContainmentActivated kernel evidence correlated to the exact gate sequence.
- Added a write-through SHA-256 hash-chained containment journal with durable Requested and KernelActive phases, including process creation time, trigger counters, path, event type and preservation decision.
- GateClient can explicitly authorize a LAB transition target with --contain-after-pid, while holding the exact process handle open to prevent silent PID-reuse authorization.
- Transition thresholds are bounded and explicit; default LAB values are four preserved mutation events across two distinct paths. Pre-armed --contain-pid and event-bound transition modes are mutually exclusive.
- A session with a containment request but no matching kernel-active receipt is marked Faulted rather than cleanly Completed.
- Added rollback journal tests and a disposable-VM scenario proving preserved mutations reach the threshold, the exact requestor is latched, the next mutation is denied, and the request/activation evidence chain is durable.
- Ordinary product service behavior remains AuditOnly; production detector-to-containment authorization is not enabled.
- Fixed service/evidence version provenance: GuardWorker now derives the product version from assembly metadata through ProductInfo.Version instead of hard-coded runtime strings.
- Added a build-time version provenance gate so startup logs, startup audit records and incident evidence cannot silently drift from Directory.Build.props.
- Added a reusable self-hosted runtime VM readiness check for elevation, VM identity, signing certificate/private key, Visual Studio C++ tooling, complete x64 WDK tooling and required Windows driver commands.
- The manual Minifilter runtime VM lab workflow now executes that readiness contract before building/signing/installing the exact-commit driver package.
- Bumped userspace/LAB and driver package version to 0.7.21.0.

# RansomGuard 0.7.20.0

- Added minifilter protocol v12 with an explicit LAB-only atomic activation-and-containment command.
- Kernel containment resolves the requested PID with PsLookupProcessByProcessId and holds a referenced PEPROCESS; enforcement compares requestor process objects rather than trusting reusable numeric PIDs.
- A contained process is denied mutation-capable CREATE plus non-paging WRITE/RENAME/DELETE/TRUNCATE inside the explicit LAB root before user-mode preservation is consulted.
- Read-only CREATE/open remains allowed and non-contained processes continue through the normal preservation gate.
- Containment rejects system PIDs and GateClient itself, exposes query-only status, has no runtime release/bypass command, and is cleared on client disconnect or driver unload.
- GateClient exposes containment only through explicit --contain-pid and binds it atomically with successful activation preflight.
- Added disposable-VM containment coverage proving the contained target cannot change while an ordinary peer can still mutate through the normal gate.
- Fixed the Audit FilterClient connect context to use the current protocol constant instead of a stale protocol-v8 literal.
- Extended minifilter, GateClient and runtime source gates for protocol-v12/process-object containment invariants.
- Bumped userspace/LAB and driver package version to 0.7.20.0.

# RansomGuard 0.7.19.0

- Added conservative restart-evidence assessment for pending CREATE/RENAME operations, bound to exact operation kind, kernel request sequence and intent record SHA-256.
- Recovery planning may move a pending CREATE/RENAME from Blocked to Review only when all matching durable restart observations consistently support completion or consistently support non-completion.
- Consistency includes observed source/destination path state and durable file identity; same-decision evidence with topology or FILE_ID_INFO drift remains unresolved.
- No evidence, ambiguous/indeterminate evidence, or conflicting observations remain Blocked.
- Crash-reconciled topology actions are never Ready; automatic delete, rename, overwrite and in-place restore remain forbidden.
- Restart reconciliation still never writes authoritative CREATE/RENAME completion records; correlated kernel post-operation completion journals remain the only authoritative source.
- Recovery plan identity continues to bind all session JSONL evidence, so any later restart observation or completion invalidates an older plan before output creation.
- Added rollback tests covering exact-match assessment, conflicting evidence, review-only CREATE/RENAME crash recovery, ambiguous fail-closed behavior and stale-plan rejection.
- Extended rollback recovery source gates to require exact evidence binding and forbid restart code from exposing a completion writer.
- Bumped userspace/LAB package version and driver INF version to 0.7.19.0; minifilter protocol remains v11.

# RansomGuard 0.7.18.0

- Added tamper-evident rollback session lifecycle journals with Created, Completed, Faulted, HoldSet and HoldReleased events.
- GateClient marks Completed only after worker drain, repository verification, zero worker failures and no pending CREATE/RENAME intents; otherwise graceful shutdown is Faulted, while crashes remain Active.
- Legacy sessions without lifecycle metadata are protected from automatic retention.
- Added default retention policy: 30-day max completed age, 32 GiB managed completed storage cap, and 24-hour minimum age for pressure-driven purge.
- Held and pending-transaction completed sessions count toward retained completed bytes but are never purge candidates; unresolved excess is reported instead.
- Added deterministic retention PlanId/inventory/session SHA-256 binding and stale-plan refusal.
- Session evidence digests are streamed with sequential SHA-256 reads, so multi-gigabyte rollback objects are never buffered into process memory during retention planning/revalidation.
- Added repository-wide cross-process maintenance lease (`FileShare.None`) shared by retention execution and Hold changes, closing the revalidation-to-purge Hold race.
- Added crash-resumable purge journal: PurgeStarted -> atomic Sessions-to-Retired move -> Quarantined -> reparse-safe delete -> PurgeCompleted.
- Added resume support for interrupted purge from Sessions, Retired, or missing quarantine after delete-before-final-receipt.
- Added LAB-only RollbackMaintenance CLI: status, retention-plan, retention-execute, hold and release-hold.
- Cleanup never runs automatically in GateClient or the normal Audit bundle.
- Added tests for hold protection, Active/Faulted/pending exclusion, age expiry, capacity pressure, stale-plan refusal, full purge chain and crash resume.
- Added mandatory retention source gate enforcing quarantine-before-delete, no direct Sessions deletion, no force/ignore-hold verbs and LAB-only packaging.

# RansomGuard 0.7.17.0

- Added fail-closed rollback storage admission for Engineering LAB gate sessions.
- Default storage policy is 8192 MiB maximum committed session size plus a 2048 MiB minimum free-space reserve on the rollback-store filesystem.
- Added explicit LAB tuning flags `--max-store-mib` and `--min-free-mib`; there is no disable/unlimited bypass switch.
- Storage admission re-measures committed session bytes and combines them with all concurrent in-flight reservations before allowing new preservation work.
- Blocking WRITE range-COW, full pre-image, CREATE absence-baseline and RENAME source/destination preservation reserve estimated growth before capture.
- Activation topology/file evidence, paging/write-section evidence and CREATE/RENAME completion journals also reserve metadata capacity before append.
- Restart reconciliation appends into older sessions are admitted against each older session's own quota/free-space budget before a new gate session starts.
- Blocking destructive I/O returns fail-closed deny code 13 when session quota or free-space reserve cannot be satisfied.
- Added estimators that avoid reserving full bytes again for already committed full pre-images, COW blocks/baselines and absence baselines.
- Added recursive reparse-point refusal while measuring rollback-session storage.
- Added tests for concurrent reservation accounting, committed-byte remeasurement and idempotent full/range/absence estimates.
- Added static source gate preventing removal of quota/free-space checks or introduction of runtime budget bypass switches.
- Normal Audit product behavior remains unchanged; this remains Engineering-LAB preservation policy.

# RansomGuard 0.7.16.0

- Added deterministic verified rollback recovery planning for Engineering LAB sessions.
- Planner revalidates the rollback repository/session, hashes all session JSONL journals, and derives a stable SHA-256 PlanId.
- Recovery actions are classified as Ready, Review, Blocked or Informational; only full-preimage and range-COW copy-out actions can be Ready.
- Added stale-plan refusal: executor rebuilds the current plan and requires PlanId/evidence digest equality before creating the recovery output root.
- Added copy-out executor that writes only to a new output tree, records recovered length/SHA-256, and never deletes, renames or overwrites live source/evidence paths.
- Originally-absent paths and successful CREATE/RENAME topology changes remain review-only; pending or unresolved CREATE/RENAME operations remain blocked.
- Added LAB-only RansomGuard.RollbackRecovery CLI with plan/execute commands and rollback_recovery.cmd convenience launcher.
- Added reparse/junction ancestor refusal for plan and recovery output paths.
- Added tests for deterministic plan identity, full-preimage vs range-COW precedence, successful byte-identical copy-out, untouched damaged sources, and stale-plan rejection before output creation.
- Added static source gates ensuring the executor never consumes caller-supplied actions or exposes destructive topology verbs.
- Normal Audit bundle remains unchanged; rollback recovery CLI is Engineering-LAB-only.

# RansomGuard 0.7.15.0

- Extended activation preflight from ordinary files to the protected directory topology without changing protocol v11.
- GateClient now opens the protected root and every ordinary non-reparse directory with FILE_READ_ATTRIBUTES plus FILE_SHARE_READ only before file probing.
- Directory handles remain open through the explicit kernel ActivateGate handshake, so pre-existing write/delete/delete-on-close directory handles fail activation through Windows share-access enforcement.
- Each held directory is bound to FILE_ID_INFO and persisted in a write-through SHA-256 hash-chained activation-topology journal.
- Added repository-wide activation-topology verification, identity-drift/idempotency/corruption tests and GateClient source gates.
- Extended the disposable-VM runtime harness with a pre-existing directory DELETE-handle scenario; activation must fail before the holder releases that handle.
- Source gates require FILE_FLAG_BACKUP_SEMANTICS, forbid ShareWrite/ShareDelete in the topology-open helper, require the root handle before recursive directory enumeration, and require activation before handle release.
- New external protected-root CREATE/rename/delete activity remains blocked by the protocol-v11 NotActivated kernel barrier during topology/file preflight.
- Normal product remains AuditOnly; topology preflight remains Engineering-LAB-only pending broader live VM/fault-injection coverage.

# RansomGuard 0.7.14.0

- Added a manual disposable-VM minifilter runtime workflow on a dedicated self-hosted `ransomguard-lab-vm` runner.
- Engineering LAB bundle now publishes a dedicated mapping helper used only by runtime validation.
- Runtime scenario A keeps a PAGE_READWRITE view alive after closing the original file/mapping handles and requires activation preflight to reject it with durable `writableViewPresent=true` evidence.
- Runtime scenario B activates cleanly, performs a real mapped write/flush, and requires a matching full pre-image SHA-256, `WritableSection = BaselineVerified`, paging-write evidence, and a changed live-file hash.
- Added exact-commit runtime driver packaging: current SYS is built from checkout, embedded-signed with a preinstalled LAB certificate, cataloged/signed, and bound to commit/SHA-256 provenance.
- Runtime scripts refuse non-VM/non-admin execution and require an explicit `RANSOMGUARD_LAB_VM=I_UNDERSTAND` marker.
- Runtime workflow does not enable TESTSIGNING, change Secure Boot, import trust roots, alter Defender, or upload the signed driver package.
- Added static source gates ensuring the runtime workflow remains manual/self-hosted and the mapping holder closes original handles before advertising the surviving mapped view.
- LAB installer now accepts an explicit `LAB-MINIFILTER` confirmation argument for noninteractive execution inside the already-validated VM.
- LAB INF DriverVer is aligned to 0.7.14.0.
- Normal product remains AuditOnly; runtime driver load remains opt-in Engineering-LAB-only.

# RansomGuard 0.7.13.0

- Bumped the engineering minifilter protocol to v11 with an explicit startup activation barrier.
- New LAB connections begin in kernel `NotActivated` state; external in-root CREATE/WRITE/metadata mutations fail closed until activation succeeds.
- GateClient performs a full existing-file preflight before entering the normal receive loop.
- Preflight opens are recognized only for the connected GateClient process while activation is pending.
- Post-CREATE preflight checks `MmDoesFileHaveUserWritableReferences` on the real stream section pointers and binds `FILE_ID_INFO`.
- Added no-reply `ActivationPreflight` events and a write-through SHA-256 hash-chained `activation-preflight-journal.jsonl`.
- GateClient holds every successful probe handle with read-only sharing through activation, exposing pre-existing write/delete handles as sharing failures and preventing new write/delete handles from racing the scan.
- Handle-less pre-existing writable mappings are detected by `MmDoesFileHaveUserWritableReferences`; failed/unresolved probes or detected writable views latch the kernel activation hazard.
- GateClient uses `FilterSendMessage` / `RgControlActivateGate`; the kernel refuses activation while any hazard is latched.
- Added repository verification, corruption/idempotency tests and kernel/userspace source gates for activation ordering.
- Normal product remains AuditOnly; activation preflight remains Engineering-LAB-only pending live disposable-VM validation.

# RansomGuard 0.7.12.0

- Bumped the engineering minifilter protocol to v10 with a no-reply `WritableSection` attestation event.
- Registered `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` to observe `SyncTypeCreateSection` requests for `PAGE_READWRITE` and `PAGE_EXECUTE_READWRITE`.
- CREATE gate decisions and request sequences are propagated into the nonpaged stream context after successful CREATE.
- Writable-section callbacks read only the established stream context and never call the blocking gate, file-name queries, `FltQueryInformationFile`, or complete/deny the FSFilter operation.
- GateClient correlates writable-section events to durable CREATE intent/completion state and records `BaselineVerified`, `Unprotected`, `MissingCreateIntent`, `DecisionMismatch`, or `PathMismatch`.
- Added a write-through SHA-256 hash-chained `writable-section-journal.jsonl` plus repository-wide verification and corruption/idempotency tests.
- This attests mappings created from handles opened under the LAB gate; handles that predate gate activation remain a known gap.
- Normal product remains AuditOnly and the section/paging paths remain engineering LAB-only.

# RansomGuard 0.7.11.0

- Existing files opened with content-write capable CREATE access now receive a durable full pre-image before the handle is returned.
- CREATE policy treats FILE_WRITE_DATA, FILE_APPEND_DATA and GENERIC_WRITE as eager-preservation triggers while read-only opens remain non-eager.
- Writable-open preservation reuses exact FILE_ID_INFO binding, full-preimage SHA-256 verification and CREATE intent-before-allow ordering.
- Incident-created/originally-absent paths remain governed by their absence baseline and never manufacture a pre-incident image.
- This establishes a pre-mutation baseline for writable mappings created from handles opened after the LAB gate is active.
- Protocol remains v9; paging-write callbacks remain non-blocking evidence-only and still do not perform user-mode preservation.
- Normal product remains AuditOnly; this policy remains engineering LAB-only.

# RansomGuard 0.7.11.0

- Bumped the engineering minifilter protocol to v9 and added a no-reply `PagingWrite` evidence event.
- Removed the registration-level `SKIP_PAGING_IO` blind spot for IRP_MJ_WRITE callbacks.
- Successful in-scope CREATE completion now seeds a nonpaged `FLT_STREAM_CONTEXT` with the bounded tracked path and kernel file identity when available.
- Paging-write callbacks read only that stream context and explicitly avoid filesystem name queries, `FltQueryInformationFile`, and synchronous `RgGateEvent` calls.
- GateClient persists paging-write observations in a separate write-through SHA-256 hash-chained `paging-write-journal.jsonl`.
- Added repository-wide paging-state verification, idempotent/conflict tests, journal-corruption tests and kernel/userspace source gates.
- This milestone closes paging-write observability only; memory-mapped/cache-manager modifications are not yet claimed recoverable until safe pre-preservation is implemented.
- Normal product remains AuditOnly; protocol-v9 paging visibility remains engineering LAB-only.

# RansomGuard 0.7.9.0

- Added conservative crash/restart reconciliation evidence for pending CREATE and RENAME intents without changing protocol v8.
- GateClient validates the existing rollback repository and records restart evidence before creating a new LAB session.
- Added a write-through SHA-256 hash-chained `restart-reconciliation-journal.jsonl` cryptographically linked to the exact pending intent hash.
- Restart probes record current path state and Windows `FILE_ID_INFO` where available, then classify evidence as supporting completion, supporting non-completion, indeterminate, or ambiguous.
- Restart evidence never manufactures an authoritative CREATE/RENAME completion; only correlated kernel post-operation results populate completion journals.
- Repeated identical restart observations are idempotent, and repository-wide verification includes nested restart-state journals.
- Added pure classifier/store tests and source gates for the restart reconciliation boundary.
- Normal product remains AuditOnly; the blocking/reconciliation path remains engineering LAB-only.

# RansomGuard 0.7.8.0

- Added bounded concurrent LAB gate execution without changing protocol v8.
- Kernel gate admission is capped at 8 simultaneous blocking preservation requests and fails closed when saturated.
- Removed long-held gPortMutex coverage around FltSendMessage; port lifetime is protected by short leases and disconnect/unload waits for active users.
- GateClient now dispatches messages through a configurable bounded worker pool (default 4, range 1..8).
- Already-received blocking messages are still dispatched during shutdown so they can return an explicit deny instead of being silently abandoned.
- Added source gates preventing regression to globally serialized FltSendMessage and enforcing matching concurrency bounds.

# RansomGuard 0.7.8.0
- Protocol v8 binds successful post-RENAME reconciliation to `FileIdInformation` from the actual completed kernel file object only at PASSIVE_LEVEL with special kernel APCs enabled; otherwise identity remains explicitly unresolved.
- Rename completion journals now persist final volume serial + 128-bit file ID alongside the reconciled destination name.
- Successful rename completion distinguishes authoritative, name-unresolved, identity-unresolved and fully unresolved states.
- Any reported post-op identity that differs from the source identity committed in the rename intent is rejected.
- Added rollback tests and source gates for rename identity persistence, partial reconciliation and mismatched-identity rejection.
- Normal product remains AuditOnly; blocking preservation remains engineering LAB-only.

# RansomGuard 0.7.6.0
- Protocol v7 adds a correlated no-reply `CreateResult` event for post-operation CREATE outcomes.
- The gate durably records a hash-chained CREATE intent linked to its preservation proof before returning any allow decision.
- Successful post-CREATE reconciliation uses `FltGetTunneledName` and queries `FileIdInformation` from the actual completed kernel file object.
- Added a separate write-through SHA-256 hash-chained `create-completion-journal.jsonl` linked to the exact CREATE intent hash and kernel request sequence.
- CREATE completion distinguishes authoritative success, unresolved name, unresolved identity, fully unresolved success, and filesystem failure; missing delivery leaves the intent pending.
- GateClient persists `CreateResult` without `FilterReplyMessage`; normal product remains AuditOnly and the blocking path remains LAB-only.
- Added CREATE intent/completion correlation, reopen, duplicate-conflict, pending-state and journal-corruption tests plus protocol-v7 kernel/userspace source gates.
- Completed CREATEs now carry kernel file identity when available; completed RENAME still needs post-operation kernel file-ID binding.

# RansomGuard 0.7.5.0
- Protocol v6 adds a correlated no-reply `RenameResult` event for post-operation rename outcomes.
- The minifilter retains the pre-operation destination name-info, uses `FltDoCompletionProcessingWhenSafe`, and reconciles successful renames with `FltGetTunneledName`.
- Added a separate write-through SHA-256 hash-chained `rename-completion-journal.jsonl` linked to the exact pre-operation intent hash and kernel request sequence.
- Rename completion explicitly distinguishes `Succeeded`, `SucceededNameUnresolved`, and `Failed`; missing result delivery leaves the intent pending instead of inferring success.
- GateClient persists rename results without sending `FilterReplyMessage` for the no-reply post-operation event.
- Added completion correlation, reopen, duplicate-conflict and journal-corruption rollback tests plus protocol-v6 kernel/userspace source gates.
- This milestone confirms rename outcome/final tunneled name when available; post-operation kernel file-ID confirmation and post-CREATE reconciliation are still required.

# RansomGuard 0.7.4.0
- Protocol v5 adds a normalized destination path and destination path status for RENAME events.
- The minifilter obtains rename destinations with `FltGetDestinationFileNameInformation` instead of reconstructing relative names in user mode.
- LAB rename gating now preserves the source and, when present, the destination file before allow; missing destinations receive a durable absence baseline.
- Added a write-through SHA-256 hash-chained `rename-state` intent journal with source/destination identities, destination state, rename flags, information class and kernel request sequence.
- Cross-root, unresolved/truncated destination, directory-topology and same-file-alias rename cases fail closed in LAB mode.
- Repository startup validation now includes nested `rename-state` journals.
- Audit client decodes and records protocol-v5 rename destination metadata.
- This milestone records pre-operation rename intent only; post-operation tunneled-name/file-ID reconciliation is still required before automatic topology recovery.

# RansomGuard 0.7.3.0
- Added incident-scoped durable existing-file identity tracking using Windows `FILE_ID_INFO` (volume serial + 128-bit file ID).
- The LAB gate captures/verifies identity before destructive existing-file preservation and rejects a path that changes to a different file identity during the same incident.
- Full-preimage and range-COW capture additionally verify the expected identity on the exact source handle used to read snapshot bytes, closing the userspace identity-probe/snapshot-open TOCTOU.
- Added a write-through SHA-256 hash-chained `identity-state` journal with alias lookup, repository-wide validation, replacement-path tests and source-gate invariants.
- This is identity hardening only; post-create/kernel file-object reconciliation and rename-destination transactions remain required.


- Added explicit `IRP_MJ_CREATE` events to the engineering minifilter protocol.
- Protocol v4 carries CreateDisposition/CreateOptions and desired access without changing the fixed event size.
- Existing `FILE_SUPERSEDE`, `FILE_OVERWRITE` and `FILE_OVERWRITE_IF` targets require a durable full-file pre-image before allow.
- Existing files opened with `FILE_DELETE_ON_CLOSE` also require a pre-image; existing-directory delete-on-close is denied until topology rollback is modeled.
- Missing targets for create-capable dispositions receive a durable hash-chained `originally absent` baseline.
- Incident-created paths do not later manufacture range/full pre-images from data that did not exist before the incident.
- Added explicit gate replies for committed absence baselines and non-destructive opens that require no preservation.
- Added a pure create-disposition policy and matrix tests, plus repository-wide validation of nested `create-state` journals.
- Normal product remains AuditOnly; CREATE gating remains engineering LAB-only and still needs identity-safe post-create reconciliation.
- Added pinned x64 WDK/SDK compile CI for the minifilter with fail-fast MSBuild, explicit x64 Universal DDI ApiValidator validation, unsigned-artifact enforcement and SHA-256 artifact manifest.

# RansomGuard 0.7.2.0

- Added range-aware 1 MiB copy-on-write preservation for gated WRITE operations.
- The first write to a file durably records its original length; only original blocks intersecting writes are captured, and each block is captured at most once per incident.
- Range objects and baselines use an append-only SHA-256 hash-chained journal with write-through/Flush(true) commits.
- Added copy-only range reconstruction: damaged source is never overwritten; captured blocks are SHA-256 verified before overlay and the original file length is restored.
- Appends beyond the original EOF are reversible from the baseline length without storing nonexistent blocks.
- Range recovery refuses a damaged source shorter than the original baseline rather than guessing missing bytes.
- Protocol bumped to v3 and added explicit TRUNCATE-class events for end-of-file/allocation/valid-data-length changes.
- Rename, delete and truncate-class operations continue to use conservative full-file pre-images.
- Added rollback tests for multi-block writes, repeated writes to one block, append rollback and range-journal verification.
- Normal product remains AuditOnly; the blocking minifilter path remains engineering LAB-only.
- Hardened rollback restart validation: committed full pre-images are SHA-256 verified, orphaned pre-image/range objects and leftover temp artifacts are rejected, nested `write-cow` stores are included in repository verification, and the LAB gate refuses to start on ambiguous existing rollback state.

# RansomGuard 0.7.1.0

- Added protocol v2 for the engineering minifilter path with an explicit single-root LAB pre-write gate.
- Added `RansomGuard.GateClient`, which replies `SnapshotCommitted` only after `RansomGuard.Rollback` has durably committed the first pre-image for the incident session.
- In the explicit LAB root, WRITE / rename / delete are denied when capture fails, times out, the client cannot verify the path, or the user-mode gate does not reply successfully.
- Outside the negotiated LAB root, and when no gate client is connected, the prototype remains fail-open; the normal product bundle still does not install or enable the driver.
- The gate client PID is excluded from gating so its own rollback-store writes cannot recursively block themselves.
- The LAB gate refuses an entire drive, Windows, Program Files, ProgramData, reparse roots, and roots without the explicit `.ransomguard-gate-lab-root` marker.
- The rollback store must be outside the protected LAB root.
- Updated the read-only audit client to protocol v2 negotiation; audit mode remains metadata-only and non-blocking.
- Added build/source gates for protocol/root scoping, durable-preimage-before-allow ordering, demand-start/manual attachment, and absence of kernel file-writing/process-control APIs.
- This is a Windows-VM engineering milestone, not a production kernel protection release. Main-machine automatic minifilter installation remains disabled.

## 0.7.0.0
- Added `RansomGuard.Rollback`: durable incident-scoped pre-image store.
- Added append-only SHA-256 hash-chained rollback journal with write-through commits.
- Added copy-only verified recovery; rollback core never overwrites the damaged source.
- Added repository/session validation at service startup.
- Added rollback tests and a source gate to the Windows build.
- Automatic minifilter pre-write capture is deliberately not enabled yet; normal operation remains AuditOnly.


## 0.7.0.0
- Fixed UI connection to an installed LocalSystem service: the desktop UI now authenticates the pipe owner by matching its PID to the fixed SCM registration and then verifies the protected installed service image/hash. It no longer requires OpenProcess access to the LocalSystem process for the installed-service path.
- Portable audit-console pairing remains strict and still verifies the exact sibling executable.
- No write/control verbs were added to the live pipe.
# 0.7.0.0 - State-store recovery compatibility

- Fixes `ERROR_ACCESS_DENIED (5)` while archiving an old `C:\ProgramData\RansomGuardV03` store on hosts where handle-based `FileRenameInfo` is rejected.
- Before archival, the old root DACL is deliberately restricted to SYSTEM and Administrators. Child ACLs/content are not recursively rewritten or imported.
- Recovery first attempts the identity-pinned handle rename. On `ERROR_ACCESS_DENIED` only, it uses a bounded `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` compatibility fallback while the verified handle is still open with delete sharing. The final handle path is checked.
- Adds `.ransomguard-state-v1` to newly created trusted stores. Existing roots without this marker are never silently reused, including after a partial recovery attempt.
- Adds a localized friendly message for Windows access-denied archival failures; raw exception details remain under Technical details.
- No driver, Defender, process-suspension or ordinary-app blocking policy changes.

- Replace service/state technical forms with one in-place wizard, no nested recovery windows.
- Separate folder selection, read-only verification, explicit state-reset consent and install/start.
- GUI confirmations are explicit buttons/acknowledgements; native/CLI tokens remain internal and unchanged.
- Collapse SID/ACL/hash/debug detail; preserve unknown/partial-error reporting and both languages/themes.
- Preserve original detector, state-recovery mutation code, read-only live IPC and all icon bytes.
- Print WPF report details before failing a UI build; no UI validation bypass.
- Add setup policy tests and bilingual themed synthetic wizard scenes. Windows execution pending.

## Earlier changes

# 0.6.3.0

- Two bundled UI languages, Ukrainian default and English, with hot switching in Settings.
- Locale-aware visible dates/numbers; stable schema IDs, hashes and confirmation tokens.
- Locale passed explicitly into the elevated same-UI administrative dialog.
- Localized operation errors with an expandable original technical message.
- Separate explicit state-store inspection/recovery UI, exact-handle legacy rename,
  guarded by revision/ownership/idle checks; no deletion or automatic trust import.
- Archive ACLs intentionally unchanged and explicitly disclosed as not isolated.
- Fresh state created with the original private ACL policy; no service auto-start.
- Resource/placeholder tests and two-language/two-theme WPF smoke-test coverage.
- Existing assets, read-only live protocol, kernel and ordinary AuditOnly boundaries retained.

The features above are source changes. Windows compilation, UI execution and native
recovery have not been performed by the authoring environment.

---

# v0.6.3.0 - integrated administration

- Native GUI trust editor, process/EXE/folder selection, review/confirm/reverify, full edit reapproval.
- Own Windows service registration/start/stop/restart/unregister in Settings.
- Non-elevated dashboard plus short-lived explicit-UAC window of the SAME UI executable.
- No privileged control added to the live data pipe. No arbitrary process or driver control.
- New protected versioned service install directory; integrity verification; explicit monitored roots.
- Exact-hash pairing of portable UI with the installed copy of its sibling Service binary.
- Default bundle no longer includes a separate manage_exceptions menu/script.
- Existing activity artwork/themes preserved; added synthetic admin-dialog screenshots and pure contract tests.

# 0.6.3.0 - scoped trust (audit/review only)

- Strict SHA-256 + canonical EXE + token-user SID + directory/operation/lifetime rules.
- Current open-handle hash verification; exact optional signer fingerprint and instance.
- No filename/folder/process-tree immunity, score discount or evidence removal.
- AnnotateOnly default; bounded QuietRepeat for repeated console warnings only.
- Unknown rename destination, canary/content signals, stale/truncated evidence,
  deny/revocation, expired/revoked/corrupt rules all preserve ordinary review.
- Administrator CLI/menu, typed confirmation, private versioned atomic store/audit.
- Existing Rules page shows sanitized summaries; v2 read-only IPC unchanged.
- Pure policy test suite and isolated Windows native selftest added.
- Existing kernel/recovery/detection algorithms and graphic assets not rewritten.

# 0.6.0.0 (previous release)

Live read-only subscription v2; per-connection sequence and boot ID; bounded coalescing
and disconnect/reconnect; telemetry separated from disk heartbeat. UI polling removed.
Independent offline dump key candidate search and authenticated RGTEST03 decryption.
New-file-only recovered output with post-write hash verification; lab baseline hashes.
Known-key LabKeyVerifier removed. Full lab resume precedes scanning/decryption.
Standalone Recovery executable and offline tests added. No ordinary-process automatic
containment or kernel behavior changes. UI themes and approved icon assets preserved.

See RECOVERY_AND_LIVE.md for supported scope and limitations; VALIDATION.json for
which checks actually ran. Historical claims of universal recovery are not applicable.
