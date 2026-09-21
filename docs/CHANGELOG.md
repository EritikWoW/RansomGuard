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
