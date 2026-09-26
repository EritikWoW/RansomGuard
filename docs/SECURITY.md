# RansomGuard security boundary

Read [THREAT_MODEL.md](THREAT_MODEL.md) first. It is the canonical statement of current attacker capabilities, fail-open/fail-closed behavior and production qualification boundaries.

## Current product boundary

The normal RansomGuard package defaults to Audit and does not install or load the Engineering LAB minifilter. Version 0.8.6 retains fail-closed ProductionProtection admission on top of the 0.8.0 Enforce state contract and adds a separate lifecycle that is reachable only for `ReadyForLifecycle`. Admission binds the package to the actual running service image and exact version/protocol/hashes. GateClient and the driver catalog must use the same signer as the running service, and SYS/INF must verify as catalog members of that supplied signed catalog. Missing/rejected admission remains `EnforceUnavailable`; an admitted package may proceed through driver registration/load/single-volume attach and ProductionGate activation, but `Protected` is published only after the activation-readiness handshake.

The current engineering minifilter/GateClient wire contract is protocol v18. It retains protocol-v17 exact protected-volume scope and adds a distinct ProductionGate client profile. ProductionGate cannot use LAB-only containment reply flags, containment/query controls or scope-ambiguity fault injection; DegradedProtected reconnect also requires the retained gate profile in addition to the exact root/volume. The Engineering LAB driver package still uses an unassigned placeholder altitude and test-signing path and remains restricted to disposable test environments. The 0.8.6 service lifecycle consumes ProductionGate only after admitted package verification; exact-head lifecycle VM qualification and external production signing/altitude governance remain separate release gates.

No claim is made that the current product is tamper-proof against a local administrator, a malicious kernel component/BYOVD path, physical/boot compromise or a compromised signing/build system.

Protection-package admission rejects the Engineering LAB provider and placeholder altitude, but a numeric altitude in a local descriptor is not proof that Microsoft assigned it. Production release governance must bind the shipped INF/descriptor to the external Microsoft altitude assignment and controlled production signing identity.

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

For ordinary user-mode destructive mutations while the LAB gate is connected and activated, resolved in-root operations follow preserve-before-allow. Version 0.8.4 also mediates the reviewed data-mutating FSCTL class: zero-data, duplicate-extents/block-clone, offload-write, file-level trim and sparse-state operations cannot bypass the preservation boundary. In protected scope they require an already committed durable stream baseline or fail closed; the FSCTL callback does not synchronously call user mode. If the default normalized-name query is unavailable, the driver first retries from Filter Manager's name cache; a scope that still cannot be classified on the exact bound protected volume is treated as ambiguous and fails closed in kernel. Proven out-of-root operations remain outside the gate.

GateClient identity is kernel-bound in 0.8.5. The minifilter references the actual process that calls `FilterConnectCommunicationPort`, requires the wire `ClientProcessId` to equal that kernel-derived PID, and keeps the exact `PEPROCESS` for connection-lifetime self-I/O exemption. A forged PID cannot create a trusted GateClient identity.

The current LAB communication path has one Filter Manager client connection and one synchronous GateClient handle. Multiple kernel requests can encounter the bounded admission path, while user-mode reply-required preservation is serialized so each `FilterReplyMessage` completes before the next blocking receive. Configurable message slots bound no-reply evidence/completion work; they are not a claim of parallel preservation decisions.

Important exceptions are explicit in THREAT_MODEL.md:

- a pathname proven outside the negotiated root remains outside the gate;
- path/name ambiguity is fail-closed only for destructive ordinary user-mode operations whose callback is on the exact bound protected volume; ambiguity on another volume remains outside this root's gate;
- GateClient's own process identity is excluded from ambiguous-volume denial so the rollback store cannot self-deadlock the policy channel;
- kernel-mode requestors are outside the ordinary observation path;
- paging writes are non-blocking evidence and rely on the conservative pre-preserved CREATE baseline;
- driver presence alone is not protection before a LAB session has activated; after activation, unexpected GateClient loss retains the exact root and protected volume in DegradedProtected, but paging/section caveats, kernel-mode requestors and privileged unload/tamper remain outside that guarantee.

Do not deploy the LAB blocking path on primary workstations or real user data.

The 0.7.30 qualification campaign materially increases confidence in this LAB boundary but does not change it into a production claim. On an exact tested head, standard Driver Verifier targeted only `RansomGuardMinifilter.sys`, survived bounded CREATE/RENAME/TRUNCATE/DELETE/mapped-write stress without a recorded bugcheck, observed genuine admission overflow (16 requests against cap 8 -> 8 allowed / 8 denied), then completed `verifier /reset` and a second-reboot CLEAR proof. Completion-loss, low-disk fail-closed and real-reboot reconciliation campaigns also have disposable-VM evidence. ReFS remains unqualified on the current VM because filesystem creation was unsupported there.

0.7.31 sustained mixed-workload qualification does not widen the security boundary, but it now has exact-head disposable-VM evidence: PR #42 head `184566aa4269d28bf3f7c32aeb9035ceaa8dd25c`, run `35986484214`, completed 60/60 waves (300 mixed mutations), retained healthy gate/workers, re-proved 16-to-8 bounded admission overflow, and finished with correlated/pending-free transaction and mapped-write evidence plus cleanup.

0.7.32 introduced protocol v16 and the GateClient-loss fail-safe foundation. 0.7.33 advanced the wire contract to protocol v17 and bound the protected root to an exact referenced Filter Manager volume. 0.8.2 advances the current engineering contract to protocol v18 and separates LAB from ProductionGate. Version 0.8.3 retains protocol v18 and adds a conservative hard-link alias boundary: activation refuses multi-linked protected regular files and active FileLinkInformation/FileLinkInformationEx topology changes touching the protected root fail closed while retaining that volume-aware protection behavior. Resolved source/destination scope is classified against the root; unresolved or unknown destructive ordinary user-mode scope on that volume fails closed, while a callback on another volume does not inherit the protected root's denial policy. RENAME evaluates both source and destination, closing the outside-to-inside bypass. The v16 disconnect state machine is retained: unexpected port loss keeps root plus volume in `DegradedProtected`, exact-root/same-volume reconnect reruns activation preflight, and clean `DeactivateGate` release occurs only after gate/evidence admission is drained. Those historical runtime qualifications remain Engineering LAB evidence; they do not by themselves qualify the new 0.8.6 service lifecycle. Paging/section semantics remain baseline/evidence based, kernel-mode requestors remain excluded, and Administrator/SYSTEM tamper resistance is still outside the current production lifecycle boundary.

## Recovery boundary

Rollback recovery is conservative and copy-out oriented. It verifies evidence and writes to new output paths. Restart observations never fabricate authoritative filesystem completion.

The production containment recovery contract is documented in [CONTAINMENT_ACTUATOR_RECOVERY.md](CONTAINMENT_ACTUATOR_RECOVERY.md). Production ordinary-process containment uses the qualified Windows process state-change object path: exact process/image identity is revalidated, durable pre/post state-change evidence is hash-chained, normal completion explicitly resumes, and final-handle destruction is the qualified crash-release backstop. There is no production fallback to per-thread suspend-count normalization, `NtSuspendProcess`, kill, or process-tree intervention. The shipped/default configuration remains `AutomaticContainment=false`; an explicitly configured integration must still pass final exact-SHA qualification.

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
