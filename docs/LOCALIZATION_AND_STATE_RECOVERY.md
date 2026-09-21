# Current version note

v0.7.1.0 retains both locales and the same state-store recovery backend. Use
[GUIDED_SETUP.md](GUIDED_SETUP.md): it replaces the nested dialog and typed GUI
confirmation with a single in-place review and explicit consent. The old archive
still keeps its original ACL. It is NOT a protected backup. The exact-token CLI
contract remains unchanged; no security decision depends on the display language.

## Earlier implementation reference

# RansomGuard 0.6.3.0 - Ukrainian / English and deliberate state-store recovery

## User interface languages

This release has exactly two interface languages: Ukrainian (`uk-UA`, default) and
English (`en-US`). Settings > Interface language switches the main window immediately.
Navigation, cards, event labels, diagnostics labels, settings, trust forms, service
management dialogs, file pickers and application-owned error summaries use bundled
resources. Dates and numbers follow the selected UI culture. The appearance and the
four user-supplied activity SVG icons are unchanged.

The preference is per-user, in the existing LocalAppData UI preferences file. Older
preferences without a language field retain theme/text scale and default to Ukrainian.
Administrative operations forward the selected, allowlisted language to the elevated
instance of the SAME UI executable. An already-open privileged confirmation dialog
keeps its language until closed; switch language before opening it.

Paths, account names, SIDs, SHA-256, rule names/reasons entered by the user, backend
JSON field names, CLI commands and exact confirmation tokens are not translated.
`INSTALL`, `START`, `STOP`, `TRUST <hash>` and `QUARANTINE` stay invariant. Original
Windows/engine exception details remain verbatim in the expandable technical-details
panel for diagnosis. Console/build/driver tooling is not part of the localized UI.
Unknown future engine messages are shown verbatim rather than mistranslated or hidden.

## Build and inspect the interface

Extract into a NEW source folder (not inside a prior release). Run build_windows.cmd.
No WDK installation or kernel-driver load is needed for this change. Open
release/RansomGuard-v0.6.3.0-<timestamp>/UI/RansomGuard.Ui.exe.

Use Settings > Interface language. The main dashboard and service used together must
come from the same release; the existing embedded SHA-256 pairing is unchanged.
The build executes localization resource tests, existing policy/recovery tests and
synthetic WPF rendering in BOTH languages and BOTH themes. Screenshots are below
build-logs/ui-<timestamp>/uk-UA and /en-US. UI tests do not connect to a service,
load a driver, access the live state store or actually approve a privileged action.

## Existing insecure state directory

A separate FullControl ACE for a normal user SID is rejected by the existing private
state-store policy. This finding is not itself evidence of malware. The application
must not silently weaken its checks or continue trusting the old rules.

In Settings > Windows service choose Inspect / recover state storage. The same
operation is also reachable inside the failed installation dialog. Approve UAC.
Opening the dialog INSPECTS only. It shows the fixed path, owner SID, ACL entries and
whether private permissions are verified. If already private, recovery is unnecessary
and its Apply button is disabled.

When explicitly confirmed with QUARANTINE, recovery:

1. Requires administrator rights, idle SCM state and no RansomGuard.Service process.
   Acquires the cooperating maintenance mutex and the normal instance mutex. It
   does not kill processes, stop ETW sessions or silently stop a service.
2. Rechecks the inspected directory's file identity and ACL using a held handle.
   Refuses reparse paths, wrong owners or a changed inspection revision.
3. Renames only that directory, by handle without replacement, to a unique sibling
   RansomGuardV03.UNTRUSTED.<timestamp>.<id>. It does not recursively enumerate or
   rewrite anything inside the archive.
4. Creates a new fixed RansomGuardV03 store with the existing private ACL helper:
   Administrators and SYSTEM only. Verifies the new root and writes an audit record.
5. Does not copy old trust rules, restore prior preferences or install/start a service.
   Return to the service installation dialog and deliberately perform that action.

IMPORTANT: the archive root is restricted to SYSTEM/Administrators before the move; child permissions are not recursively rewritten. Existing open handles are not
revoked. Renaming is not a confidentiality barrier, malware removal or proof that
archived files are isolated. Sensitive older dumps may still be accessible under the
old ACL. No original content is deleted. Old rules require explicit new approval and
are not automatically imported. On partial failure, the exception includes archive
and new-root paths: inspect before retrying; no rollback is claimed.

This cooperative recovery is not tamper-proof against administrators, SYSTEM, kernel
code or non-cooperating older versions. It cannot guarantee exclusivity against
arbitrary privileged software. Uncertain state leads to refusal, not a forced reset.

The normal UI never loads a minifilter, changes Defender or enables automatic process
suspension. Ordinary applications remain AuditOnly. Closing the dashboard does not
stop the service.

## Validation boundaries

The authoring environment performed XML/JSON parsing, localization key/placeholder
checks, source-level safety checks and byte comparisons of unchanged UI assets.
It did NOT compile or run C#, WPF, UAC, SCM or Windows ACL recovery. The included
Windows tests are planned/executable checks, not results already achieved.

Before distribution, test in an isolated Windows environment: both locales on every
page, switching with data/disconnection, UAC cancel/different account, correct store
(no reset), explicit extra-user ACE, denied inspection, wrong owner, reparse path,
concurrent store change, running service/console, old content preserved, new private
ACL, partial failure and install/start/stop after recovery. No production-ready
security certification is asserted.
