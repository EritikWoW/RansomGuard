# RansomGuard security boundary

Read [THREAT_MODEL.md](THREAT_MODEL.md) first. It is the canonical statement of current attacker capabilities, fail-open/fail-closed behavior and production qualification boundaries.

## Current product boundary

The normal RansomGuard product is AuditOnly for ordinary applications. It does not install or load the Engineering LAB minifilter and does not claim production ransomware blocking.

The Engineering LAB minifilter is restricted to disposable test environments and explicit test data. Its current user/kernel wire contract is protocol v15. Its altitude is an unassigned LAB placeholder and its test-signing path is not a production trust anchor.

No claim is made that the current product is tamper-proof against a local administrator, a malicious kernel component/BYOVD path, physical/boot compromise or a compromised signing/build system.

## Administrative boundary

A GUI acknowledgement is not an authentication secret. System-changing UI actions execute through the explicitly elevated same-EXE administration path, while Management independently checks privilege, fixed own-service identity, reviewed inputs, file identity/hashes, ACL/state invariants and operation-specific confirmation.

The live UI transport remains read-only. Administrative mutation is not exposed through the status/incidents/diagnostics/subscribe named-pipe protocol.

The service installer does not silently overwrite an existing registration or treat a path/name match as executable identity. Published UI/service bytes remain hash-paired.

## State-store boundary

Private service/incident state uses ACL and reparse-point checks. Those checks reduce accidental and lower-privilege tampering but are not a security boundary against an arbitrary local administrator or kernel attacker.

State-store recovery is fixed-path and explicit. It does not recursively rewrite child ACLs, import old trust rules or claim that an archived tree is confidential. Previously opened handles and inherited child ACLs can outlive a root operation.

## Scoped trust

Scoped trust is presentation context, not an I/O allow rule or scan exclusion. Detection, risk score and evidence remain intact. A trusted/reviewed image can still produce an incident and suspected content transformation vetoes quieting.

Executable name, location, publisher display name, first-seen count or negative lookup never grants immunity. Hash/signing evidence is revalidated according to the scoped-trust contract.

## Telemetry and monitoring

ETW failure is explicit. The service enters diagnostics-only rather than presenting a false healthy state. SCM Running alone is not proof that filesystem monitoring is available.

Queues/windows are intentionally bounded. Event loss, queue drops, stale evidence and truncated windows prevent the LAB automatic decision path from claiming healthy evidence.

## LAB preservation boundary

For resolved, in-scope ordinary user-mode mutations while the LAB gate is connected and activated, destructive I/O follows preserve-before-allow and failures in preservation/admission/gate handling fail closed.

The current LAB communication path has one Filter Manager client connection and one synchronous GateClient handle. Multiple kernel requests can encounter the bounded admission path, while user-mode reply-required preservation is serialized so each `FilterReplyMessage` completes before the next blocking receive. Configurable message slots bound no-reply evidence/completion work; they are not a claim of parallel preservation decisions.

Important exceptions are explicit in THREAT_MODEL.md:

- unresolved/name-query-failed scope classification currently fails open;
- out-of-root operations are outside the negotiated gate;
- kernel-mode requestors are outside the ordinary observation path;
- paging writes are non-blocking evidence and rely on the conservative pre-preserved CREATE baseline;
- a never-activated driver/session is not protection; after an activated LAB session, unexpected GateClient loss now enters a kernel `DEGRADED_PROTECTED` latch for known in-scope destructive I/O, while explicit maintenance deactivation is required for a clean disconnect;

The degraded disconnect latch does not remove the separate unresolved-path fail-open boundary and does not synchronously block already-existing writable mappings; those mappings rely on their previously committed baseline/pre-image. Current recovery from a degraded latch is driver unload/reload, so this remains Engineering LAB behavior rather than production lifecycle semantics.

Do not deploy the LAB blocking path on primary workstations or real user data.

The 0.7.30 qualification campaign materially increases confidence in this LAB boundary but does not change it into a production claim. On an exact tested head, standard Driver Verifier targeted only `RansomGuardMinifilter.sys`, survived bounded CREATE/RENAME/TRUNCATE/DELETE/mapped-write stress without a recorded bugcheck, observed genuine admission overflow (16 requests against cap 8 -> 8 allowed / 8 denied), then completed `verifier /reset` and a second-reboot CLEAR proof. Completion-loss, low-disk fail-closed and real-reboot reconciliation campaigns also have disposable-VM evidence. ReFS remains unqualified on the current VM because filesystem creation was unsupported there.

0.7.31 adds a manual sustained mixed-workload qualification contract but does not widen the security boundary. One GateClient/rollback session is held across repeated mixed CREATE/RENAME/TRUNCATE/DELETE/mapped-write waves and final evidence must remain fully correlated and pending-free. Source presence or a hosted compile is not treated as endurance evidence; the claim exists only for an exact-head disposable-VM run whose artifact proves all configured rounds, elapsed-time budget, worker/gate health and cleanup.

0.7.32 adds a separate degraded-protection qualification contract. An unexpected loss of an activated LAB GateClient must leave known in-scope destructive operations fail-closed and reject replacement-client connection until driver reset; controlled maintenance shutdown instead uses the explicit deactivation command. Runtime proof requires hard GateClient termination, denied protected-file mutation with unchanged SHA-256, reconnect rejection, bounded driver reset and successful continuation of the existing runtime cleanup matrix. This does not close unresolved-name fail-open semantics or turn already-existing writable mappings into a synchronous policy path.

## Recovery boundary

Rollback recovery is conservative and copy-out oriented. It verifies evidence and writes to new output paths. Restart observations never fabricate authoritative filesystem completion.

Crypto recovery is experimental and format-specific. Unknown formats, missing candidates or failed authentication produce unsupported/not-found/failure states rather than guessed plaintext.

Memory dumps, rollback evidence and recovered plaintext can contain sensitive data. Protect them as incident data. Do not commit dumps, private keys or test-signing certificates to the repository.

## IPC/privacy boundary

The read-only local pipe exposes bounded health/incident metadata and has no mutation commands. This is not equivalent to a privileged forensic channel. Enterprise deployment must explicitly decide which monitored-root/process metadata non-admin local users may read.

## Build and release boundary

Source gates are regression checks, not independent security proofs. Kernel loadability, Filter Manager ordering, filesystem semantics, ACL/UAC behavior and recovery behavior require real Windows/runtime qualification.

The repository now pins the .NET SDK, immutable GitHub Action commits and locked NuGet dependency graphs, and runs dependency/source provenance gates. These controls reduce build drift but do not replace protected-branch policy, independent review, protected production signing keys, SBOM/provenance retention or a trusted build environment.

Release-oriented engineering requires exact build inputs, immutable action references, locked dependency graphs, artifact hashes/provenance, protected branches, enforced review and protected signing keys. Repository settings such as branch/ruleset enforcement are not established merely by files in this tree.

`.github/CODEOWNERS` provides review routing for security-sensitive source, build and documentation paths. It does not itself require approval, create independent review, or prevent direct pushes; enforcement still depends on repository branch/ruleset settings.

## Reporting

When reporting a security issue, include the affected commit/version, whether the issue is in the normal Audit product or Engineering LAB path, the minimal reproduction, expected/actual security invariant and whether real data was used. Do not attach sensitive dumps, private keys or user data to a public issue.
