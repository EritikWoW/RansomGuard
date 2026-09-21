# Current UI workflow

For v0.7.1.0 use [GUIDED_SETUP.md](GUIDED_SETUP.md). Service and state preparation
use one wizard; GUI review uses explicit buttons/acknowledgements, not typed tokens.
Underlying privilege checks and operation semantics described below are retained.
The earlier two-window instructions and user-typed GUI confirmations are superseded.

## 0.6.3.0 and earlier implementation reference

# RansomGuard 0.6.3.0 - integrated UI administration

## User workflow

Build on Windows with `.\build_windows.cmd` (.NET 10 SDK). Open the published
`UI\RansomGuard.Ui.exe` normally. You do NOT have to open an administrator console,
run manage_exceptions.cmd, use sc.exe, or edit rule JSON.

- **Rules**: Add rule; Edit/reapprove; Disable; Remove. The all-rules editor also works
  when the service is stopped. The stream view shows summaries, not hidden full rules.
- **Settings / Windows service**: Install; Start; Stop; Restart; Unregister;
  refresh current Windows service registration/status.
- The four activity icons, themes and dashboard layout are not redesigned.

A button starts a short-lived, UAC-elevated *instance of the same UI executable*.
There is no separate user-facing management program, console or script. Its themed
administration dialog shows the full operation for review. Merely opening it never
changes rules or starts the service. The normal dashboard does not elevate itself.

This is privilege separation, not a claim of PPL/ELAM/tamper-proof operation.
The local live pipe stays read-only: no privileged control verbs were added to it.

## First service installation

1. Close any older audit console with Ctrl+C; do not kill processes by name.
2. Settings -> Windows service -> Install. Approve UAC.
3. Pick explicit user data folders. Nothing guesses the interactive user's profile
   from LocalSystem. Verify paths especially when using a different UAC account.
4. Autostart is OFF by default. Check it only deliberately.
5. Review and type INSTALL in the graphical confirmation box, then apply.
6. Installation registers the service but does NOT start it. Close the dialog and
   use Start (UAC + START). The main window reconnects to the verified installed copy.
7. Check *monitoring health* in Overview, not merely the SCM Running label.

Only the own fixed `RansomGuardV03` Win32 service is managed. Payload is placed in a
new admin/SYSTEM-write-only directory beneath:

    %ProgramFiles%\RansomGuardV03\v0.6.3.0-<unique-id>\
        RansomGuard.Service.exe
        appsettings.json
        install.json

Users receive read/execute, not write permissions. Configuration is freshly generated
as Audit with explicit monitored directories, not copied from arbitrary user JSON.
The source EXE is fixed to the sibling from the current release, held read-locked,
checked for version AND against the service SHA-256 embedded into the UI assembly at build time,
copied with CreateNew and checked by SHA-256. `install.json`
records that exact hash. No arbitrary executable, arguments, service account or
remote computer can be supplied. No driver gets installed/loaded.

Keep the complete published package for the UI: the service installer does not install
or move the UI, Recovery tool, shortcuts, or a production updater. This is integrated
SERVICE installation, not yet a signed full-product setup.exe. The UI verifies its
embedded service hash against the protected installed copy before accepting its pipe.
It does not accept a changed EXE merely because an editable manifest or filename matches.
Different releases fail that pairing instead of silently talking to an unknown agent.

Start/stop/restart use Windows SCM with bounded 30-second waits, never process kill.
Start refuses a second running audit console. A startup failure or pending timeout
remains an error, and a Running service can still report ETW unavailable.
Unregister requires Stopped and removes only the registration; program files and all
ProgramData evidence/settings are preserved. There is no silent upgrade/replacement.
To migrate an older registered version, explicitly stop/unregister it first; the UI
refuses registrations outside the recognized protected Program Files path.

## Trust rules

Add/edit is a native graphical form: EXE picker, optional live-process picker (query
only), SID, optional one-generation PID, explicit directories, operations, effect,
budgets, 1-720-hour lifetime and review reason. The process picker fills EXE, SID and
PID; clear PID only when a time-limited exact-hash rule for future matching launches
is intended. Unavailable processes are not guessed.

1. Enter the form and press Verify EXE.
2. Review fresh SHA-256, embedded signature and all proposed rule fields.
3. Type TRUST <first 12 SHA-256 characters>, then Save.
4. The binary, signature, user/process identity (if pinned), scope, expiry and rule
   document digest are checked AGAIN before committing atomically.

Editing is a full reapproval: it renews time and enables the rule after explicit review.
A disabled/expired rule cannot regain trust via an unchecked enable checkbox.
Disable/remove require an existing id, current store digest, reason and confirmation.
All prior scoped-trust vetoes and incident storage remain in force. Ordinary programs
stay AuditOnly. This change does not add global scan exclusions or process suspension.

The elevated dialog uses the exact SAME store/verifier implementations as the service,
linked into a query-and-management library. It does not include NtSuspendProcess,
NtResumeProcess, injection, dump, driver or arbitrary-shell operations.

## Safety and limitations

This unsigned developer release still requires explicit trust in the supplied build
before approving UAC. Self-computed hashes/version metadata are integrity checks, not
publisher authentication. Production signed installation/update/recovery remains work.
State ACL repair is not silently performed. Use the new explicit UI inspection/recovery
dialog, review the consequences, and confirm QUARANTINE. Old content/ACLs are retained,
not trusted or imported. See LOCALIZATION_AND_STATE_RECOVERY.md. Administrator/kernel compromise is outside guarantees.
If an operation applied but a final audit write failed, the error explicitly says it
may already be applied: refresh before repeating. No unreported rollback is promised.
A client closing during administrator review does not secretly cancel or undo it; the
privileged dialog remains visible until closed. No background privileged agent persists.

## Tests

- New pure administration contract tests: fixed verbs, rule-id validation, confirmation
  and rejection of weak/absent hashes. They cannot access SCM.
- UI smoke test renders add/edit/disable/remove/install/start/stop/unregister dialogs
  in both themes using preview-only mode, no native queries, UAC or mutations.
- Existing tests, source gates, dependency audits and activity-icon checks remain.
- Actual UAC / install / start / stop / cancellation / wrong-hash / ACL behavior needs
  Windows integration testing. It was not run in the authoring Linux environment.

Manual test: cancel UAC (no change); open then close admin form (no change); invalid
confirmation (no change); edit during review invalidates approval; install then start;
stop while UI connected (UI alive, data stale); restart; disabled/expired rule; attempt
stale form commit; changed installed EXE; uninstall while running (must refuse).
Do not use fake malware or load the experimental minifilter on the main machine.
