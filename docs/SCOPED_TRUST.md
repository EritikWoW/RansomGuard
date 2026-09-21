# Scoped trust / process exceptions - v0.6.3.0

## What it does (and does NOT do)

A rule matches an exact SHA-256 + canonical EXE path + token-user SID, optionally
one PID/creation-time pair. One complete rule must cover every event in the risk
window. It never filters events before RiskEngine, subtracts scores, hides incidents,
skips a scan, changes Defender, authorizes suspension, or grants children trust.
Ordinary programs stay AuditOnly. The owned laboratory workflow is never exempted.

Effects:
- **AnnotateOnly** (default): record the matched context; all warnings are retained.
- **QuietRepeat**: after the FIRST visible warning, an unchanged pattern for this
  process/rule is logged at Information instead of Warning for at most 120 seconds
  from the previous visible notification. ALL cases remain in the UI/archive with
  unchanged severity and counters. No Windows toast system is introduced.

This is NOT a filesystem access-control policy or an antivirus scan exclusion.
It is a constrained audit/review preference. It cannot prove that running memory is
unmodified: a clean signed EXE can host injected code. Keep independent protection on.

## Conditions / fail closed

- No MD5, filename-only rule, wildcard, whole-drive root, network path, ADS,
  environment-variable expansion, publisher-name-only or indefinite rule.
- 1-8 canonical existing directories; no overlap with Windows, Program Files,
  ProgramData or RansomGuard's security store.
- Allowed operations are selected explicitly; bounded file/write/rename/delete counts.
- Default budgets: 16 distinct files, 256 writes, 16 renames, 16 deletes per observed
  risk window. The rule file schema rejects excessive budgets.
- Approval lifetime is 1-720 hours, UTC; one-run PID + creation time is optional.
- A signed rule needs a successful current embedded WinVerifyTrust result and the
  exact SHA-256 fingerprint of its signer. Revocation uses the existing offline
  cache policy. Missing/unknown/revoked signatures do not count as verified.
- A reviewed unsigned binary requires explicit --allow-unsigned-exact-hash. This
  only accepts NoEmbeddedSignatureOrCatalogOnly, not BadDigest or unknown/revoked.
- Current process identity and token user are queried again; no SeDebug enablement.
- EXE is opened by the live process path with FileShare.Read, hash computed fresh
  with a 128 MiB limit and a 5-second cancellable hash-read budget. Signature checking
  itself is the existing synchronous OS trust call, not a hard real-time deadline.
- The same process and file handles are held until evaluation completes. No
  path-only cached ImageInspector result can grant an exception.
- Canaries (even pending), known local deny, suspicious sampled-content changes,
  lost/truncated/stale or internally inconsistent evidence override the rule.
- Partial evidence arrays cannot be used to soften complete event counters.
- Missing/mismatching paths, dead processes, changed hashes and scope violations use
  NORMAL audit/review. They are not automatically called malware or terminated.
- Rule store is read again after verification, before allowing a preference; a
  concurrent revocation/change cancels it. No fallback to old trusted rules.

## Rename/deletion and telemetry limitations

The present ETW source does not populate an authoritative rename destination.
A rename therefore does NOT receive an exception even when Rename was approved.
The policy understands both endpoints for future reliable telemetry and tests them;
it does not invent them from file extensions.

For a deletion whose old file no longer exists, current parent-directory resolution
and absence of reparse points are checked. This is an observational snapshot, not
proof of the historical path's immutable identity. Consequently this feature ONLY
labels/reduces repeat-console warnings, never suppresses detection or access checks.
A write to a file that vanished before the check is not eligible.

Global empty-name ETW events, exclusions already inherent in configured monitored
roots/extensions, and seconds of ETW delivery delay are NOT fixed by this release.
Rules do not add their directories to ProtectedRoots. Existing detector coverage
remains unchanged; a rule is evaluated only when the detector records a candidate.

## Build and view

    .\build_windows.cmd

Use UI and Service from the SAME new release. Start run_audit.cmd and launch_ui.cmd.
The existing Rules page shows summaries, validity period and last observed check.
A Configured status means a rule exists; it does NOT assert that a running process
currently meets it. UI shows no connection if fresh service state is unavailable.
Read-only v2 IPC is retained; approval reasons, full scope paths and token SIDs are
not included in the new public rule summaries. Full rules are admin-only.

## Manage rules inside the UI (0.6.3.0)

Use Rules -> Add rule / Edit / Disable / Remove. Full rule details and editing are
handled by the UAC-approved graphical dialog of the SAME RansomGuard UI executable.
No separate manager or console is necessary. A stopped service is supported via
Rules -> All rules. The live data pipe stays read-only; administration is not a pipe
command. Review the EXE/SID/scopes and confirm the fresh hash before saving. Editing
is full reapproval, not an unchecked enable operation.

See [UI_ADMINISTRATION.md](UI_ADMINISTRATION.md). The original `--rules` CLI remains
in source as an engineering fallback, not a recommended user workflow or default
packaged menu. It shares the same strict store/identity/scope implementation.

## Stored data / reports

    %ProgramData%\RansomGuardV03\ScopedTrust\rules.json

Private owner and DACL: Administrators/SYSTEM. Atomic same-volume writes, protected
cross-process lock file, bounded JSON with duplicate-field rejection, document
revision/digest, prepared/committed audit records. Existing trust-store.json is not
imported: previous ReviewedTrusted labels do not grant these exceptions.

Incident/response JSONs contain ScopedTrust: Applies, RuleId, Effect, Reason,
NotificationQuieted, RulesDigest and CheckedUtc. Audit has a ScopedRuleEvaluated
record with the fresh verification result. Records are evidence, not a guarantee
against administrator/kernel compromise. Administrator-controlled timestamps/store
can be altered by an attacker with equivalent privileges; no PPL/ELAM promise.

## Validation boundaries

The new pure C# tests run in build_windows.cmd. A separate native selftest exercises
Windows ACL I/O and the actual token query. Existing UI tests also render the Rules
page in both themes on synthetic data. They are not malware efficacy tests.
No .NET SDK or Windows runtime was available in the authoring environment; C# build,
ACL/native execution and WPF rendering are not reported as passed here. See
VALIDATION.json for the actual static checks performed.
