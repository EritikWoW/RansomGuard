# RansomGuard 0.8.6.0 - guided setup

This document describes the default Audit guided setup. Version 0.8.6 retains protocol-v18 ProductionGate/LAB separation, single-link, mutating-FSCTL and kernel-bound GateClient identity policy, and adds an explicit Enforce lifecycle for a separately provisioned admitted ProductionProtection package. The ordinary Audit bundle still excludes SYS/CAT/INF/GateClient and does not activate kernel blocking. Enforce activation requires the fixed signed package, one explicit protected root, rollback readiness, driver load/attach verification and a successful ProductionGate activation handshake. Automatic containment remains disabled.
It does not change Defender or widen trust rules.
The dashboard, chosen icons, Ukrainian/English languages and theme palettes remain.

## Ordinary user workflow

1. Open the newly published `UI\RansomGuard.Ui.exe` normally.
2. Settings > Background monitoring > Set up RansomGuard. Approve Windows UAC.
3. In the single setup window, add the data folders you want to monitor.
   Check the full paths, especially if UAC used a different administrator account.
   No user profile or entire drive is guessed. Folder shortcuts/reparse paths remain
   subject to the existing backend validation.
4. Start with Windows is OFF by default. Start after installation is shown as an
   explicit checked option. The final action is named either Install and start or
   Install, and the review screen describes exactly what will happen.
5. After the selected operation finishes, return to Overview to check actual ETW
   health. SCM Running alone is never displayed as proof of file monitoring.

Do not mix an older service with this UI. The existing exact service-hash pairing
is retained. Existing registrations are not overwritten or silently upgraded.

## When settings need attention

A separate, nested recovery window is no longer opened. The setup pane switches to
an in-place explanation:

- personal documents are unchanged;
- existing trust rules will NOT be applied automatically;
- previous application data is kept separately with its OLD permissions.

The administrator must acknowledge these consequences before clicking the specific
preserve-and-create button. The old state is renamed by the SAME fixed-path,
handle-verified recovery implementation used by the legacy state-recovery path. It is not a confidential
archive, no data is imported/deleted, and the old root ACL is restricted to SYSTEM/Administrators before archival; child ACLs and already-open handles are not rewritten.

Recovery does not install or start the service. For installation, the pane returns
to the preserved folder selection and requires a NEW review/click. For standalone
settings review, it simply shows the result. A private store needs no reset.
Unknown/denied state, a wrong owner, a running engine or concurrent changes cause
refusal, not forced recovery. Errors and exact native details remain available.

## Confirmations

The GUI no longer asks the user to type INSTALL, QUARANTINE or TRUST plus a hash.
These are not authentication secrets. User consent is an explicit action button;
reset/stop/remove/reapproval also requires the relevant unchecked acknowledgement.
The elevated code creates the existing internal operation token only in that
reviewed click handler. CLI token contracts are unchanged.

The real security boundaries are still elevation, fixed own-service operations,
package hash/version, held file handles, state ACLs, complete rule verification,
revision checks and maintenance synchronization. No mutation command was added to
the live read-only IPC. Preview mode cannot call native mutations.

Trust forms show a concise rule summary; raw JSON, hashes and certificate details
are collapsed. SID and process-instance fields are in Advanced. Changing a form
invalidates the prepared approval and clears consent. The backend rechecks before
saving. Users can still deliberately inspect all technical details.

## Failures and cancellation

Cancel before the action changes nothing. During a native operation the window
waits instead of killing a process or promising to undo already applied changes.
If installation succeeded but startup failed, the pane says so and checks current
status before any retry. A current installation is never overwritten as a retry.
Open old settings archives only deliberately; they may include sensitive dumps.

## Build and tests

Run `build_windows.cmd` in a new source directory (.NET 10 SDK on the build PC).
The build runs policy, offline recovery, trust, admin-contract and locale tests,
then renders synthetic WPF scenes in both locales and both themes. Additional setup
scenes cover selection, review, reset, progress, completion and errors. The setup
preview asserts that technical details are collapsed, mutation buttons are disabled
and footer buttons remain inside the window.

`test_ui.ps1` now prints `ui-smoke-test.json` failure details BEFORE throwing on an
exit code. A previous unexplained `exit=2` is NOT diagnosed merely by this change.
The UI test remains mandatory; a failed test never becomes a passed build.

This source update was not compiled or executed on Windows in the authoring
environment. See VALIDATION.json for actual checks, distinct from included tests.
## Legacy state recovery note

If an older store has an extra writable user ACE, the wizard does not reuse it. It first
restricts the old root DACL to SYSTEM/Administrators, then archives that root. The
preferred path is still `SetFileInformationByHandle(FileRenameInfo)`. If Windows returns
`ERROR_ACCESS_DENIED (5)`, the wizard may use `MoveFileExW` as a compatibility fallback
only after the root has been hardened and re-opened with its volume/file identity checked.
The held handle's final path must match the generated archive path.

New trusted roots contain `.ransomguard-state-v1`. A root without that marker remains a
legacy/untrusted store even if a partial recovery already made its ACL private. This
prevents a failed archival attempt from accidentally turning old trust rules into accepted
state on the next run.

