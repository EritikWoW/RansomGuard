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


## Protocol v6 RENAME completion reconciliation coverage

The rollback tests now treat a rename as two durable records: a pre-operation preservation intent and a correlated
post-operation completion. They verify successful final-name recording, failed filesystem operations, successful
operations whose tunneled final name cannot be resolved, reopen/rebuild correlation, pending-intent semantics,
conflicting duplicate rejection, and completion-journal corruption detection.

The minifilter source gate requires the safe post-operation path, `FltDoCompletionProcessingWhenSafe`,
`FltGetTunneledName`, the correlated `RenameResult` event, and protocol-v6 completion fields. The GateClient
source gate additionally requires result persistence without `FilterReplyMessage`.

These tests and compile gates do not prove real filesystem tunneling behavior, completion-message delivery under
fault injection, or post-operation file-ID identity. Those require an isolated Windows VM and remain separate
from the normal product bundle.


## Protocol v7 CREATE completion reconciliation coverage

CREATE rollback tests now model the operation as a durable pre-operation intent plus a correlated completion.
Coverage includes authoritative success with final path and kernel identity, name-only and identity-only partial
reconciliation, fully unresolved successful completion, failed filesystem completion, pending intent after missing
result delivery, reopen/rebuild correlation, exact duplicate idempotence, conflicting duplicate rejection, missing-intent
rejection, and completion-journal corruption detection.

The minifilter source gate requires the post-CREATE callback, `FltGetTunneledName`,
`FltQueryInformationFile(..., FileIdInformation, ...)`, the correlated `CreateResult` event and protocol-v7
identity fields. The GateClient source gate requires CREATE intent persistence before allow and result persistence
without `FilterReplyMessage`.

These tests and compile gates do not prove real filesystem tunneling behavior, completion-message delivery under
fault injection, or all NTFS/ReFS create edge cases. Those remain isolated Windows-VM validation work.
