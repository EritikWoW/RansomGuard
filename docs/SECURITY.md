# 0.7.1.0 administrative UX boundary

Only presentation and read-only installation preflight are added. A GUI acknowledgement
is not an authentication secret. System-changing clicks remain in the UAC-elevated
same-EXE dialog; Management independently checks privileges, input, hashes and state.
Preflight does not create state. State migration still uses the unchanged guarded
backend and requires distinct consent; it does not automatically continue to install.
No claim of tamper-proof state or safe archive isolation is added. Kernel/loading,
Defender settings, ordinary-process containment and live IPC permissions are unchanged.

# Scoped trust additions (0.6.3.0)

Read SCOPED_TRUST.md for the exact scope and limitations. This is NOT a scan
exclusion or a file-I/O allow rule. All incidents and original risk scores remain.
Only repeated console warnings can be downgraded to Information after full
context verification; first/changed/critical/unknown cases are not quieted.
The admin-only CLI does not change the read-only pipe or Windows Defender.
New binary hash or unknown/mismatched signer requires a NEW explicit review.
Current filesystem-path snapshots do not prove historical identity under races.
No defense against equal/higher-privilege compromise is claimed.

# Security boundary, 0.6.3.0

The ordinary-process policy remains audit-only. No new driver, process injection,
security weakening or unrestricted file encryption is added. Read RECOVERY_AND_LIVE.md
for offline limits, candidate validation and exact lab authorization.

Recovery does not provide an HTTP/named-pipe write endpoint. It is either the
explicit standalone offline CLI or the existing authorized lab pipeline.
Unknown formats never produce guessed plaintext. Recovery outputs are new copies.
Private keys, candidates, dump addresses and plaintext are not sent to the UI.
Dumps can contain environment variables, secrets and other unrelated data.
Protect the complete incident directory and recovered plaintext as sensitive.

The current IPC release-path check is not cryptographic executable attestation.
Local administrators can modify files and security state. Four local subscribers
can exhaust the permitted UI slots (bounded denial of service, not detector blocking).
The snapshot protocol retains only the latest 100 in-memory summaries and sends 50;
this is not unlimited event replay. Slow clients are disconnected; other work stays
independent. Physical non-privileged isolation/PPL and production installer/signing
are separate work. Never claim this development package is tamper-proof.

File path checks and open-handle sharing reduce accidental or adversarial reparse
and overwrite risks but are not a guarantee against an administrator/kernel attacker.
Scan limits are intentional; NotFound and Incomplete are not evidence of no key.
On cancellation or an I/O failure, partial NEW output files can remain; source
files are never overwritten. Sensitive managed buffers are cleared where controlled,
but no absolute whole-process zeroization guarantee is made.

Source gates are inexpensive regression checks, not security proofs. Windows
integration, named-pipe ACL behavior, native dump capture, WPF and clean shutdown
still require actual local tests. Keep all existing Windows security enabled.

## 0.6.3.0 state-store recovery boundary

Localization is presentation-only. The maintenance dialog does not relax access-control
checks. Recovery is fixed-path, explicit, requires a reviewed directory revision and
idle service/instance state, then renames by an identity-checked handle without replacing
another object. It never recursively changes child ACLs or imports old rules. The
archive keeps its permissions and previously opened handles; it is NOT guaranteed
isolated or private. The new root is created and verified by the existing private store
code. Partial operations are reported rather than presented as a completed rollback.

Cooperating startup/management use a short-lived maintenance lease. SCM startup releases
its own lease BEFORE waiting for a new service to start. No new handle is held across
await; the normal service instance mutex remains separate. These measures do not defend
against arbitrary administrators, kernel code, or non-cooperating third-party tools.
Native race, failure and filesystem behavior must still be tested on Windows.
