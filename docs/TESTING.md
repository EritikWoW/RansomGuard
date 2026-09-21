# Testing and validation

Build executes existing policy tests plus RansomGuard.Recovery.Tests (offline only).
New cases cover AES schedule vectors, BE/LE word order, corrupted schedules, a
synthetic minidump with decoy keys, poison reference-key file, authenticated recovery,
unchanged evidence, original SHA-256 verification, existing output rejection, bad
GCM tag, missing key, unsupported format, partial recovery, malformed dump ranges,
cancellation, fragmented/coalesced framing, oversized frame rejection, subscriber
limits and wake-up coalescing. These tests do not suspend any live process.

WPF test uses synthetic data only, both themes and existing icon/layout checks.
It is not an IPC integration test. Test the live pipe separately using two consoles,
close/reopen UI, stop/restart audit, and verify unknown/offline statuses and new boot ID.
Try up to four local UIs; a fifth must retry without impacting file processing.
No five-second UI query timer should exist. Incidents/state should publish on change;
metrics publish every 500 ms; log heartbeat remains 30 seconds. No hard-real-time
latency guarantee is made. ETW latency remains separately measured.

Before full lab: stop audit (do not run both); start test_lab_full_dump.cmd from
Lab release and type LAB. Run UI from that SAME release. Read response.json and
crypto-recovery.json. Require GCM authentication and all ten original hash matches,
not just a key-presence test. Unsupported/no-capture cases must fail honestly.

Reference experiment from prior submitted dump: docs/INDEPENDENT_PROOF.json.
New C# binary/WPF/Windows integration not run in the build-authoring environment.
Do not post keys, full dumps or recovered personal content to support.

## 0.6.3.0 additional coverage

The build runs RansomGuard.Localization.Tests against the actual two embedded JSON
catalogs: key parity, nonempty values, format parsing/slots, English script, known
translations, and unchanged privileged confirmation tokens under both cultures.
These tests do not touch a service or the filesystem outside their bundled resources.

UiSmokeTest renders all pages and administration previews for uk-UA/en-US x Dark/Light,
including state-repair, failed ETW, disconnected UI and large text. It checks that the
language selector stays in Settings and changing language does not reset the semantic
filter codes. The test has a bounded 300-second deadline; only the child test UI is
terminated on timeout. Production UI/service processes are not terminated by this test.

These native scenarios are NOT performed by source checks: UAC under another account,
ACL read denial, wrong owner, reparse point, existing extra-user FullControl entry,
no-op for correct ACL, content retention after recovery, existing handles, concurrent
start/save attempts, rename failure, fresh-root failure, audit failure, service restart.
Use an isolated test environment and snapshots for fault injection.


## Protocol v4 CREATE preservation coverage

The rollback policy tests exercise every supported Windows create disposition against existing and missing
file states. Existing `SUPERSEDE`, `OVERWRITE` and `OVERWRITE_IF` must select a full pre-image.
An existing file opened with `FILE_DELETE_ON_CLOSE` must also select a full pre-image, while an existing
directory with delete-on-close is denied as unsupported topology mutation.
Missing `SUPERSEDE`, `CREATE`, `OPEN_IF` and `OVERWRITE_IF` must select an originally-absent
baseline. Invalid disposition values are rejected.

The tests also reopen and verify the hash-chained create journal, reject corruption, reject attempts to mark
an existing target as absent, and verify that repository-wide startup validation includes nested
`create-state` stores.

These are userspace policy/store tests plus kernel source gates. They do not prove native IRP_MJ_CREATE
execution, tunneled-name handling, or file-ID race safety; those still require an isolated Windows VM.


## Automated x64 minifilter compile gate

GitHub Actions restores pinned Microsoft WDK/SDK C++ 10.0.28000.2526 packages and builds
`driver/RansomGuard.Minifilter/RansomGuard.Minifilter.vcxproj` as Release x64 with x64 MSBuild.
The build is compile-only and signing is disabled.

The workflow then runs the x64 WDK `ApiValidator.exe` against the produced SYS with the x64
Universal DDI XML/allow-list and refuses the artifact if API validation fails. The compile artifact
must remain unsigned; only the SYS, INF, shared protocol header and SHA-256 manifest are uploaded.

This proves C/WDK compilation, link resolution and Universal DDI API compatibility. It does not prove
driver loadability on a target machine, minifilter attachment, Filter Manager message exchange,
IRP ordering, filesystem semantics, Driver Verifier behavior or production signing.


## Protocol v8 RENAME completion identity reconciliation coverage

The rollback tests now treat a rename as two durable records: a pre-operation preservation intent and a correlated
post-operation completion. They verify successful final-name recording, failed filesystem operations, authoritative success with final name plus kernel identity, successful operations with name-only or identity-only
partial reconciliation, fully unresolved success, reopen/rebuild correlation, pending-intent semantics, conflicting
duplicate rejection, source-identity mismatch rejection, and completion-journal corruption detection.

The minifilter source gate requires the safe post-operation path, `FltDoCompletionProcessingWhenSafe`,
`FltGetTunneledName`, and an explicit PASSIVE_LEVEL plus special-kernel-APC guard before
`FltQueryInformationFile(..., FileIdInformation, ...)`. It also requires the correlated `RenameResult` event
and protocol-v8 completion identity fields. The GateClient
source gate additionally requires result persistence without `FilterReplyMessage`.

These tests and compile gates do not prove real filesystem tunneling behavior or completion-message delivery under
fault injection. Those require an isolated Windows VM and remain separate from the normal product bundle.


## Protocol v7 CREATE completion reconciliation coverage

CREATE rollback tests now model the operation as a durable pre-operation intent plus a correlated completion.
Coverage includes authoritative success with final path and kernel identity, name-only and identity-only partial
reconciliation, fully unresolved successful completion, failed filesystem completion, pending intent after missing
result delivery, reopen/rebuild correlation, exact duplicate idempotence, conflicting duplicate rejection, missing-intent
rejection, and completion-journal corruption detection.

The minifilter source gate requires the post-CREATE callback, `FltGetTunneledName`,
`FltQueryInformationFile(..., FileIdInformation, ...)`, the correlated `CreateResult` event and protocol-v8
identity fields. The GateClient source gate requires CREATE intent persistence before allow and result persistence
without `FilterReplyMessage`.

These tests and compile gates do not prove real filesystem tunneling behavior, completion-message delivery under
fault injection, or all NTFS/ReFS create edge cases. Those remain isolated Windows-VM validation work.


## 0.7.16 verified rollback recovery coverage

Rollback tests build one mixed durable session containing a full pre-image, overlapping range-COW evidence, a range-only damaged file, an originally-absent CREATE, a pending CREATE, an authoritative successful RENAME and a pending RENAME.

The expected plan is checked exactly:

- only full-preimage and range-only COW are Ready;
- COW for a path that already has a full pre-image is Informational;
- originally-absent and authoritative topology changes are Review;
- pending CREATE/RENAME are Blocked;
- automatic topology mutation remains disabled.

The test then damages the live full-preimage and range-COW sources, executes the plan, and requires recovered output bytes to equal the originals while the damaged live sources remain unchanged. The execution report must contain SHA-256 values and Review/Blocked counts with no topology mutation.

A new completion record is then appended after plan creation; execution with the old plan must be rejected before the requested output directory exists.

Static source gates additionally require fresh-plan reconstruction inside the executor, forbid use of caller-supplied action arrays, forbid delete/move primitives in planner/executor/CLI, restrict Ready execution to full-preimage/range-COW, and reject destructive CLI verbs.

## 0.7.17 rollback storage-budget coverage

Userspace rollback tests validate session-level storage admission without loading the driver.

Coverage includes:

- two concurrent reservations whose combined size exceeds the session quota; the second must be rejected while the first remains held;
- reservation release returning transient capacity to zero;
- actual committed session bytes being re-measured before the next admission;
- full-preimage estimator charging source bytes before first capture and zero after that capture is committed;
- range-COW estimator charging only the uncaptured original block/baseline and zero for the same already committed block;
- originally-absent estimator charging bounded metadata only before the first baseline.

The source gate requires DriveInfo/AvailableFreeSpace enforcement, session quota plus in-flight reservations, recursive reparse refusal, fail-closed GateClient denial code 13, defaults of 8192 MiB session / 2048 MiB free reserve, and budget admission on blocking preservation plus activation/paging/section/completion evidence.

The gate also rejects source changes that introduce an unlimited/disable/bypass storage mode.

These tests validate userspace accounting/policy. Native low-disk behavior under real Filter Manager load still requires the disposable-VM/fault-injection campaign.

## 0.7.18 rollback lifecycle and retention coverage

Rollback tests validate that new sessions start Active, old clean Completed sessions become eligible, and Held, Active, Faulted and pending-transaction sessions are excluded. They also require a second concurrent maintenance lease to fail and verify that the lease can be reacquired after release.

A stale plan is created, then the candidate session is put on Hold; execution must reject the old plan and leave the session in Sessions. After releasing Hold, execution must produce the exact Started/Quarantined/Completed audit chain, remove the candidate from Sessions, remove the transient Retired tree and leave protected sessions untouched.

A separate capacity-pressure test uses a tiny completed-byte cap and verifies selection of the oldest eligible session while respecting the minimum pressure age.

Crash-resume coverage writes PurgeStarted, moves the session into Retired and simulates process loss before Quarantined. The next plan must emit ResumePurgeFromRetired, complete the audit chain and remove the quarantined tree.

The source gate additionally requires manual-only maintenance CLI packaging, lifecycle hash chains, no automatic retention invocation in GateClient, no direct Sessions deletion, no force/ignore-hold commands and reparse-safe quarantine cleanup.

## 0.7.19 crash reconciliation recovery coverage

Rollback tests now bind restart assessment to the exact operation kind, kernel request sequence and intent-record SHA-256. A single decisive observation must produce a consistent assessment with the latest restart-record hash, while conflicting observations for the same intent must collapse to Unresolved. A lookup using another request/hash must return NoEvidence rather than borrowing nearby evidence.

The mixed recovery-plan test includes a pending CREATE and pending RENAME with consistent SupportsNotCompleted restart evidence plus a second pending RENAME with Ambiguous evidence. The expected plan requires:

- the consistent pending CREATE to be Review, bound to its restart-record SHA-256;
- the consistent pending RENAME to be Review, bound to its restart-record SHA-256;
- the ambiguous pending RENAME to remain Blocked;
- Ready actions to remain limited to verified full-preimage/range-COW copy-out;
- the executor to skip every Review/Blocked topology action and perform no automatic topology mutation.

After plan creation, an authoritative CREATE completion is appended. Execution with the old plan must still fail stale-plan validation before any output directory is created.

Static source gates require exact operation/request/intent binding, all-observations agreement for a decisive assessment, Review-or-Blocked planner behavior, and an explicit absence of authoritative completion writers in restart reconciliation code.

## Manual disposable-VM minifilter runtime gate

0.7.15 uses `.github/workflows/minifilter-runtime-vm.yml`, a manual workflow that is intentionally excluded from push/pull-request CI. It requires a self-hosted Windows VM runner labeled `ransomguard-lab-vm`, Administrator execution, installed WDK/VS tooling, preconfigured lab signing, and an already trusted certificate/private key referenced by the environment secret `RANSOMGUARD_LAB_CERT_THUMBPRINT`.

The workflow rebuilds both userspace and the minifilter from the exact checkout. The runtime driver preparation step signs the exact current SYS, generates/signs the catalog, and writes a commit/SHA-256 provenance record. It does not change BCD/test-signing policy, Secure Boot, trust roots, or Defender.

The runtime harness performs three required scenarios:

1. **Pre-existing directory DELETE handle**: keep an ordinary subdirectory open with DELETE access before GateClient starts. Activation must fail because topology preflight cannot acquire its FILE_SHARE_READ-only directory hold.
2. **Pre-existing writable mapping**: keep a PAGE_READWRITE user view alive after closing the original file and mapping handles. GateClient startup must refuse activation, and the durable activation journal must report `writableViewPresent=true` for that file.
3. **Post-activation mapped mutation**: activate on a clean root, then open a file with content-write access, create PAGE_READWRITE mapping, change bytes and flush. The run must prove that:
   - a full pre-image exists and hashes to the pre-mutation SHA-256;
   - the writable-section journal reports state `BaselineVerified`;
   - paging-write evidence is present;
   - the live file hash changed.

Only logs/journals and `runtime-result.json` are retained as workflow artifacts. The signed test driver package is deleted.

A successful run proves the expected ordering on that VM image. It still does not prove reboot behavior, Driver Verifier stability, storage-pressure handling, all NTFS/ReFS edge cases, production signing, or Microsoft altitude suitability.



## 0.7.20 kernel containment coverage

Static minifilter gates require protocol v12, atomic activation-and-containment, `PsLookupProcessByProcessId`, a retained `PEPROCESS`, requestor comparison via `FltGetRequestorProcess`, system/self PID rejection, and explicit cleanup with `ObDereferenceObject` on disconnect/unload. They also require the contained process to be denied before `RgGateEvent` on mutating CREATE, non-paging WRITE and RENAME/DELETE/TRUNCATE paths.

GateClient source checks require `--contain-pid` to be explicit, reject PID <= 4 and GateClient itself, forbid prepare-only use, send containment only as part of activation, and verify that the kernel reply reports the exact requested contained PID. No release/clear containment verb is permitted.

The disposable-VM runtime harness adds a fourth scenario: a helper process exists before activation but holds no protected-root handle. GateClient activates with that helper's PID; after the kernel reports containment active, the helper attempts an append and must receive access denial while the target SHA-256 stays unchanged. A separate ordinary helper must still be able to mutate another file through the normal preservation gate, proving containment is single-process scoped rather than root-wide shutdown.

## 0.7.21 event-bound containment transition coverage

Rollback store tests require a containment Requested record to be durably committed before a KernelActive receipt can exist. The active receipt must match the exact request by kernel sequence, process ID and creation time, event type, path, preservation decision and trigger counters. Duplicate identical receipts are idempotent, orphan activation is rejected, reopen rebuilds both phases, and repository-wide verification rejects corruption in nested containment-state journals.

Static minifilter gates require protocol v13, the single known reply flag, fail-closed rejection of unknown flags, rejection of containment flags on denied/unpreserved operations, and ordering from the flagged reply through `RgBindContainedRequestor(Data,...)`. The binding path must reference `FltGetRequestorProcess(Data)`, hold a `PEPROCESS`, correlate the no-reply `ContainmentActivated` event to the original gate sequence and retain the existing disconnect/unload cleanup boundary.

GateClient source checks require an exact process handle for `--contain-after-pid`, bounded event/path thresholds, durable Requested evidence before the reply flag, no reply to the `ContainmentActivated` evidence event, a linked KernelActive receipt, and lifecycle faulting when the receipt is missing.

The disposable-VM runtime harness adds an event-bound transition scenario. The target helper starts before GateClient but holds no protected-root handle during activation. After activation it opens two files for write and performs preserved mutations. With the explicit threshold set to four preserved events across two paths, the threshold event is allowed only after preservation and atomically latches its exact requestor; the helper's next write must receive access denial. The containment journal must contain matching Requested and KernelActive records for the same gate sequence and process.
