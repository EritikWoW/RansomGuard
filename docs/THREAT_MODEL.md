# RansomGuard threat model

Status: engineering threat model for RansomGuard 0.8.6.x, covering the default Audit product, admitted Production Enforce lifecycle, protocol-v18 LAB/ProductionGate separation, hard-link/FSCTL policy, and the Engineering minifilter.

This document describes what the current implementation protects, what it deliberately does not protect, and how ambiguous I/O is handled. It is not a claim of production readiness. The default normal package remains Audit and excludes SYS/CAT/INF/GateClient. Version 0.8.6 retains the cryptographically bound ProductionProtection package, protocol-v18 ProductionGate separation, hard-link/data-mutating-FSCTL policy and kernel-bound GateClient identity, and adds an admitted production driver/GateClient lifecycle for explicit Enforce. Source implementation is not a release claim: exact-head disposable-VM lifecycle qualification, production signing/altitude governance and the remaining product hardening are still required.

## Security goals

RansomGuard is built around three distinct goals:

1. **Preserve** pre-mutation file state before an allowed destructive mutation.
2. **Contain** further destructive mutations from an explicitly bound process only after a valid containment transition.
3. **Recover** from durable evidence without guessing topology or overwriting live source data.

The strongest current guarantee is the LAB preservation invariant: for a resolved, in-scope, ordinary user-mode mutation while the LAB gate is connected and activated, the operation is allowed only after the required preservation/evidence commit succeeds. This guarantee does not extend to every Windows I/O path.

## Assets

Security-sensitive assets include:

- protected file contents and file identity;
- rollback pre-images, range-COW blocks and original-length baselines;
- CREATE/RENAME/TRUNCATE/DELETE intent, completion and restart/finalization journals;
- activation, paging-write, writable-section and containment evidence;
- rollback repository lifecycle/retention state;
- service state and incident evidence under the private application-data store;
- the GateClient/minifilter communication channel and negotiated protected root;
- LAB signing certificate private key on the disposable test VM;
- future production signing identity and Microsoft-assigned minifilter altitude.

## Trust boundaries

### Ordinary product / Enforce lifecycle

The normal service obtains filesystem telemetry through ETW and publishes bounded read-only status through the local named pipe. Audit is the default mode and remains non-blocking. Schema 4 may explicitly request Enforce. Version 0.8.6 first inspects the fixed ProductionProtection package: the actual running service image anchors the signer identity; GateClient and the driver catalog must use the same signer; SYS/INF must verify as catalog members; LAB provider/placeholder altitude are rejected. A rejected or missing package is published as `EnforceUnavailable` and no production lifecycle mutation is performed.

A `ReadyForLifecycle` package allows the separate 0.8.6 lifecycle to proceed only after rollback repository validation. The service verifies/registers the demand-start driver, validates registered altitude/flags and installed SYS identity, loads it, requires exactly one minifilter instance on the configured protected-root volume, and starts the exact admitted ProductionGate client. Pre-existing unrelated or multiple volume attachments are rejected. Initial `Protected` is published only after ProductionGate completes activation preflight and emits the bounded readiness handshake. Unexpected GateClient loss publishes `DegradedProtected` while the kernel fail-safe latch remains active; service reconnect must rerun activation preflight before returning to `Protected`. A reconnect child that does not emit the post-preflight `READY` signal within the bounded startup window is terminated abruptly and is never sent the maintenance-authorizing `shutdown` command, so a late/uncertain activation cannot race into `DeactivateGate`. Loss of the supervising Service control pipe is likewise never accepted as a maintenance request: ProductionGate exits without `DeactivateGate`, leaving the kernel fail-safe latch for a later Service/ProductionGate reconnect. Clean detach/unload is allowed only after an explicit service shutdown command issued to a previously `READY` ProductionGate, kernel-confirmed `Maintenance`, a durable post-Maintenance `Completed` rollback lifecycle record, and the matching clean STOPPED signal. Service stop while a child is still unready terminates that child without maintenance authorization and intentionally leaves any uncertain retained gate fail-safe. Windows lifecycle helper processes are also killed on cancellation so driver-registration/load/attach mutations cannot continue orphaned after the host stops. If an authorized maintenance command was sent but the acknowledgement is lost, the service refuses driver unload and publishes no active-enforcement claim because the kernel outcome is unconfirmed. If kernel `Maintenance` was confirmed and only later detach/unload cleanup fails, the state remains `Maintenance` and the cleanup failure is recorded separately.

A retained production protection epoch and its rollback evidence namespace are treated as one lifecycle. Active root-bound sessions are resumed; multiple/foreign Active sessions fail closed. Faulted or legacy-unmanaged service-owned production sessions require explicit recovery and block creation of a new Enforce evidence namespace. A clean session is not marked Completed until kernel Maintenance has actually been confirmed.

The protection state machine is the only source of a kernel-enforcement claim. SCM `Running`, driver installation, a live UI, a spawned GateClient, or a connected-but-not-activated kernel channel cannot set `KernelEnforcementActive=true`. Rollback repository validation must complete before any kernel-start transition.

A detector result is evidence for review; it is not yet an authorization to block a normal process. The UI does not turn SCM Running into proof that ETW monitoring is healthy. ETW startup/runtime failure enters an explicit diagnostics-only state.

### Engineering LAB gate

The LAB path consists of:

`user-mode requestor -> Filter Manager/minifilter -> synchronous GateClient decision -> durable rollback store -> allow/deny`

The minifilter and GateClient trust each other only inside the explicitly negotiated protocol/session. The current wire contract is protocol v18; protocol drift is a compatibility/security boundary, not a best-effort condition. v18 retains the v17 exact protected-root/volume scope and adds distinct `LabGate` and `ProductionGate` profiles. ProductionGate cannot request LAB containment/scope-fault controls or set the containment reply flag, and a degraded session retains its original profile for reconnect. The gate is scoped to one explicit protected root plus the exact local Filter Manager volume object that contains that root. The rollback store must be outside the protected root; ProductionGate fixes it to the service-managed ProgramData rollback repository.

The connection identity itself is kernel-derived. The connect callback references `PsGetCurrentProcess()`, derives its PID with `PsGetProcessId`, and rejects a `ClientProcessId` mismatch. The referenced `PEPROCESS` is retained for the live connection and exact-object requestor comparison is used for GateClient self-I/O exemption. The wire PID is therefore not a trust anchor.

The Filter Manager server port currently permits one client connection. GateClient uses one synchronous communication handle. Kernel admission may have multiple blocking requests waiting, but user-mode reply-required preservation is deliberately serialized: the worker handling a gate request must send its reply before the receive loop issues the next blocking `FilterGetMessage`. Configurable GateClient slots bound no-reply completion/evidence processing; they are not a claim of multiple simultaneous preservation replies. This distinction is part of the availability model and must not be blurred in performance or security claims.

The runtime test certificate, TESTSIGNING configuration and unassigned LAB altitude are test infrastructure, not production trust anchors.

### Recovery

Recovery consumes validated evidence and writes copy-out results to new paths. It does not automatically rename, delete, recreate or overwrite live topology. Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion.

## Attacker model

| Actor/capability | Current scope | Boundary |
|---|---|---|
| Ordinary user-mode process mutating a resolved file inside the activated LAB root | In scope for LAB preservation | Must pass preserve-before-allow or be denied |
| Explicitly authorized LAB process after durable containment transition | In scope for LAB containment | Future destructive in-root mutations are denied by process-object identity |
| Ordinary process under the default Audit installation | Detection/audit only | No kernel blocking claim; the default bundle excludes the ProductionProtection package |
| Ordinary user-mode process inside an explicitly activated 0.8.6 Production Enforce root | In scope for preserve-before-allow / fail-safe gate policy | Protection claim exists only after admitted lifecycle activation; detector-driven containment is still disabled |
| Process operating outside the negotiated LAB root | Out of preservation scope | Allowed by this gate |
| Ordinary user-mode destructive request whose pathname cannot be resolved/classified and whose callback is on the bound protected volume | In scope for fail-safe scope handling | Denied in kernel as ambiguous; unknown is not reinterpreted as outside |
| Kernel-mode requestor / compromised kernel component / BYOVD path | Out of scope | `RequestorMode == KernelMode` is not observed by the ordinary gate path |
| Local administrator able to modify binaries/security state | Out of scope as a tamper-resistant boundary | No claim of protection from equal/higher privilege |
| Physical/boot/firmware attacker | Out of scope | No measured-boot or physical isolation claim |
| Compromised signing key/build system | Supply-chain threat, not runtime-detected | Requires repository/release governance controls |
| Network/UNC/remote filesystem semantics | Not qualified | Current LAB/recovery assumptions are local filesystem oriented |

## Enforcement state machine

The current driver does not mean "driver loaded = protected".

| State/condition | Current behavior | Security interpretation |
|---|---|---|
| No gate-profile GateClient has activated a session, or driver is unloading | Observation path can return without enforcement | No preservation guarantee |
| Client in Audit mode | Event may be queued; operation continues | Telemetry only |
| Client mode unknown/not a LAB/Production gate without a retained protection latch | Operation continues | No blocking guarantee |
| LAB/Production gate, pathname proven outside root | Operation continues | Explicitly out of scope |
| LAB/Production gate/degraded state, destructive ordinary user-mode pathname is unresolved/unknown and callback volume equals the bound protected volume | Denied in kernel | Ambiguous protected-volume scope fails safe |
| LAB/Production gate/degraded state, unresolved/unknown pathname on a different volume | Operation continues | The protected root does not impose a volume-wide/global denial policy elsewhere |
| RENAME with either resolved source or destination inside the protected root | Gated; unsupported cross-boundary preservation is denied by user-mode policy | Destination cannot bypass root scope |
| RENAME with one unresolved side on the bound protected volume and no proven in-root side | Denied in kernel | Ambiguous cross-boundary topology fails safe |
| Protected regular file has `NumberOfLinks != 1` during activation | Activation refused before Protected | Existing outside alias cannot enter the protected session |
| `FileLinkInformation` / `FileLinkInformationEx` touches protected source or destination | Denied in kernel | New hard-link aliases cannot cross the protection boundary |
| Hard-link source/destination both proven outside root | Operation continues | Protected root does not impose volume-wide hard-link denial |
| LAB/Production gate, external in-root mutation before activation completes | Denied | Prevents mutation racing activation preflight |
| LAB gate active, resolved in-root mutation, containment latch matches requestor | Denied before userspace preservation | Containment enforcement |
| ProductionGate receives LAB-only containment/query/fault control or containment reply flag | Rejected with `STATUS_NOT_SUPPORTED` / fail-closed gate decision | Production preservation profile cannot activate LAB test/containment control surface |
| LAB/Production gate active, resolved in-root mutation, preservation/gate decision fails | Denied | Fail-closed preservation path |
| Activated LAB/Production gate loses GateClient unexpectedly | Kernel publishes `DegradedProtected`, retains exact root and denies resolved ordinary user-mode mutation-capable CREATE/non-paging WRITE/RENAME/DELETE/TRUNCATE | Prevents silent active-session protection loss |
| Protocol-v18 GateClient reconnects after degraded loss | Accepted only for the exact retained LAB/Production profile, root and referenced protected volume; returns to Preflight before Protected | Prevents profile substitution and re-establishes user-mode preservation only after activation preflight |
| Clean transaction-complete GateClient requests DeactivateGate | Kernel first enters Maintenance-requested admission closure; only after gate/pending work drains does it authorize release and allow the subsequent port close to clear the retained root | Explicit two-phase release rather than disconnect-as-disable |
| LAB storage admission/quota/free-space check fails | Denied | Preservation integrity wins over availability |
| Paging write on tracked stream | Non-blocking evidence only when the stream context belongs to the current protection generation and current root | Relies on pre-preserved CREATE baseline without leaking stale evidence into a later root/session |
| Writable section creation on tracked stream | Non-blocking attestation only for the current protection generation/root | Attests prior baseline; stale stream contexts are ignored rather than crossing protection sessions |
| Kernel-mode requestor | Not observed by ordinary gate path | Explicit threat-model exclusion |

## Ambiguous-scope analysis

Protocol v18 retains the protected-volume ambiguity policy introduced in v17: ordinary user-mode destructive `name query failed -> allow` is not permitted on the negotiated protected volume, without converting the entire machine into fail-closed I/O. Before classifying a normalized name as unresolved, the driver retries through Filter Manager with `QUERY_ALWAYS_ALLOW_CACHE_LOOKUP`; only residual uncertainty reaches the volume-aware Ambiguous state.

GateClient derives the NT device-volume prefix for the selected local LAB root and sends its byte length in the fixed-size connect context. The kernel resolves that prefix with Filter Manager and retains the referenced `PFLT_VOLUME` for the protected session. Scope classification then uses three states:

- **Inside**: a resolved or truncated source/destination prefix is inside the negotiated root;
- **Outside**: the relevant path is proven outside the root, or an unresolved callback belongs to another volume;
- **Ambiguous**: the destructive ordinary user-mode request cannot be classified by name and the callback belongs to the exact bound protected volume.

Ambiguous mutation-capable CREATE, non-paging WRITE, RENAME, DELETE and TRUNCATE are denied in kernel. Read-only CREATE remains available because it cannot perform the destructive mutation being protected. RENAME evaluates both source and destination: either side inside makes the operation in-scope; both sides proven outside remain out-of-scope; an unresolved side on the protected volume fails safe.

0.8.4 adds a separate mediation rule for known data-mutating filesystem controls that can change file content or extent layout without ordinary `IRP_MJ_WRITE` delivery. `FSCTL_SET_ZERO_DATA`, duplicate-extents/block-clone, offload-write, file-level trim and sparse-state operations are classified against the same protected root/volume scope. Proven outside operations remain outside; protected-volume ambiguity fails closed. In-scope execution requires an existing stream context whose mutation-capable CREATE already received `SnapshotCommitted` or `BaselineCommitted`. Missing context, Preflight, Maintenance, DegradedProtected or contained requestors are denied. No synchronous user-mode preservation is attempted from `IRP_MJ_FILE_SYSTEM_CONTROL`.

0.8.3 applies the same source+destination rule to hard-link creation without adding a new user-mode transaction type. Activation also checks `FileStandardInfo.NumberOfLinks` on the exact frozen handle after FILE_ID equality and requires exactly one link. This deliberately keeps protected regular files single-named for the current recovery model: pre-existing aliases refuse activation, new inside↔outside aliases are denied, and proven outside↔outside links remain allowed.

GateClient's own process identity is excluded from ambiguous-volume denial because the rollback store and protocol activity must not become dependent on the synchronous gate they service. This is an explicit trusted-component exception, not a general process allow-list.

Protocol v18 retains the LAB-only negative fault-injection control used for qualification, but ProductionGate rejects that control in kernel. `ArmScopeAmbiguity` references one already-running non-system target process object and forces only that process's next destructive callback to `PathStatus=QueryFailed`. It cannot manufacture an allow decision or disable scope enforcement, is consumed one-shot, and the referenced process object is cleared on successful deactivation, disconnect and unload. It is test infrastructure, not a production policy command.

The production design rule remains:

`failure condition -> attacker influence -> certainty request is in protected namespace -> permit/deny/degrade -> telemetry/operator action`

Protocol v18 therefore retains the v17 rule that "unable to prove in scope" is not silently interpreted as "proven out of scope" for ordinary destructive user-mode operations on the protected volume. It does not claim that all Windows namespace aliases, paging paths or malicious kernel requestors are now covered.

### Kernel requestors

The ordinary observation predicate rejects `RequestorMode == KernelMode`. This is acceptable only while kernel compromise/BYOVD is explicitly outside the supported threat model. Product claims must not imply protection against a malicious kernel component.

### Gate disconnect/unavailable state

Protocol v18 retains the v16/v17 fail-safe disconnect behavior and additionally retains the exact LAB/Production gate profile with the protected root and referenced volume. Once activation succeeds, the kernel sets a protection-required latch. If GateClient disappears without an authorized whole-gate deactivation, the driver publishes `DegradedProtected` before publishing client loss, retains the exact negotiated root and volume reference, denies resolved in-root destructive operations, and also denies ambiguous destructive ordinary user-mode operations on that protected volume. A replacement v18 GateClient may reconnect only with the same retained gate profile, root and Filter Manager volume and begins again in Preflight.

A clean shutdown is a distinct two-phase maintenance transition. GateClient first requires a clean durable transaction/lifecycle state and then sends `DeactivateGate`. The kernel immediately publishes a maintenance-requested latch that closes new synchronous gate admission, closes new queued evidence admission, and causes any already-replied request racing the transition to be denied. That latch is **not** release authorization: while blocking gate sends or queued evidence work remain, the command returns busy and the protection-required latch stays armed. If GateClient dies during this drain, disconnect still enters `DegradedProtected`. Only after gate/pending work reaches zero does the kernel clear the protection-required latch, authorize graceful disconnect and report Maintenance; the subsequent port close may then clear the root.

This is a fail-safe foundation, not production self-protection. Ordinary destructive user-mode unresolved/scope-ambiguous requests on the bound protected volume now fail closed, but paging/section callbacks retain the existing non-blocking pre-preserved-baseline model, kernel-mode requestors remain excluded, GateClient is a trusted exception for ambiguous-volume classification, driver unload explicitly clears the latch, and an Administrator/SYSTEM attacker that can control the driver/service lifecycle is not yet contained by this boundary.

## Fail-closed analysis and availability risk

Several current LAB paths deliberately fail closed:

- external in-root mutation during activation preflight;
- preservation or synchronous gate failure for a resolved in-root destructive operation;
- ambiguous/truncated in-root pathname after an already verified protected prefix;
- unsafe rename/topology cases;
- rollback quota/free-space admission failure;
- containment-bound mutations.

These choices protect evidence integrity but can deny application writes. Production qualification must therefore measure latency, storage amplification, low-disk behavior, timeout behavior and recovery from service/gate failure. The kernel admission cap is backpressure, not a throughput guarantee: with the current single synchronous GateClient handle, reply-required preservation remains serial even when several kernel requests are admitted and no-reply evidence work uses bounded user-mode slots. Availability is part of the security model, not a secondary concern.

## Identity and race assumptions

Path strings are not treated as sufficient identity for preserved existing files. Current LAB evidence uses Windows `FILE_ID_INFO` (volume serial + 128-bit file ID) and binds operation evidence to exact request sequences and intent hashes where applicable.

CREATE/RENAME/TRUNCATE/DELETE completion/restart logic must remain conservative:

- intent-before-allow is not completion;
- restart observation is not authoritative kernel completion;
- conflicting, ambiguous or indeterminate observations remain unresolved;
- DELETE cleanup is handle-lifecycle evidence, not proof that a pathname disappeared;
- topology/length review actions do not become automatic live mutations.

## Memory-mapped I/O

Writable mappings are handled through a conservative pre-preservation rule: write-capable CREATE of an existing file must commit a full pre-image before the handle returns. Writable-section and paging-write callbacks then provide evidence without turning Memory Manager callbacks into blocking userspace policy gates.

Stream contexts are bound to a kernel protection generation and revalidated against the currently retained root before paging/section evidence or mutating-FSCTL preservation credit is accepted. Every queued asynchronous event is also bound to the exact GateClient connection generation; post-operation and DELETE handle evidence retain the generation that authorized the operation. This prevents delayed paging, section, completion, or cleanup evidence from one LAB/ProductionGate session from being delivered to a later same-mode connection or a different protected root.

This model does not justify treating an arbitrary pre-existing mapping as safe. Activation preflight checks for pre-existing writable references and prevents activation when a hazard is detected.

## Detection and containment boundary

ETW/RiskEngine is a trigger and evidence source, not the preservation guarantee.

The normal service does not actuate detector-driven containment for ordinary applications, including suspicious/canary cases. Audit mode stays non-blocking. Production Enforce can activate the admitted preservation lifecycle, but `AutomaticContainment=true` remains rejected. The existing suspend primitive is LAB-only and can bind one explicitly authorized process to a referenced kernel process object.

0.8.7 adds an **authorization-only** production contract. After the incident archive is successfully created, the service evaluates an immutable containment-authorization snapshot and durably writes `authorization.json`. The decision is also exposed through read-only runtime/incident diagnostics as exactly `Eligible`, `Denied`, or `DisabledByConfiguration` with explicit veto reasons. `Eligible` means only that the evidence snapshot satisfied the policy contract; it is not evidence that an actuator ran and it does not authorize the current build to suspend, kill, quarantine, or otherwise mutate an ordinary process. The ordinary response path records `ActuationAttempted=false` and returns before the LAB-only actuator path.

Authorization is fail-closed unless the snapshot proves Enforce + Protected, rollback readiness, active kernel enforcement, a Running monitor, zero telemetry/queue/window-loss counters, durable incident persistence, stable live process identity, fresh valid SHA-256 image inspection, resolved protected scope, non-LAB identity, no scoped-trust veto, and the configured risk criterion. Startup, pre-activation, degraded, maintenance, failed, stopped, invalid or ambiguous states deny authorization.

The first actuator milestone adds only a **non-actuating binding/revalidation contract**. A short-lived binding carries a unique authorization id, incident id, exact `ProcessKey`, normalized image path/SHA-256, the protection snapshot observation time, and an explicit expiry. Revalidation must reject expiry/replay, PID reuse, image drift, protection transitions, degraded telemetry, critical/unknown process state, RansomGuard itself, and protected service processes. The current `GuardWorker` is source-gated against referencing this actuation policy or any production suspend/kill primitive; the contract can produce only `Ready` or `Denied` evidence until a separate actuator is implemented and VM-qualified.

The next foundation layer is still non-actuating: `ContainmentActuationLedger` durably consumes one authorization id into one immutable request, hash-chains every state transition with write-through flush semantics, and tracks suspension ownership per thread id. A resume record is accepted only for an increment that RansomGuard previously recorded as owned; completion refuses stranded increments. Partial failure can therefore be followed by durable owned-only recovery evidence without normalizing arbitrary pre-existing suspend counts. The ledger itself contains no Win32/NT suspension, resume or termination primitive and is not reachable from ordinary incident handling while `AutomaticContainment=false`.

`ContainmentSuspendCoordinator` is a second platform-neutral safety layer. It requires an exact live-target session that retains one process instance, reruns actuation validation from live process/image/protection/telemetry state, writes durable preparation before the first intervention operation, bounds thread count/enumeration passes/time, and records each successfully owned thread increment immediately. Any cancellation, operation failure or unstable thread set attempts owned-only rollback and refuses successful completion while an owned increment remains outstanding. The coordinator contains no Windows suspension API and remains unreachable from `GuardWorker`; its fake-platform tests are orchestration evidence only, not production VM qualification. A Windows adapter and disposable-VM proof are separate prerequisites before any ordinary-process actuation can be enabled.

Before production containment actuation is enabled, the chain must be extended and separately qualified end-to-end:

`incident evidence -> live process identity -> preservation health -> authorization decision -> separately qualified actuator -> exact kernel/user-mode receipt -> post-containment audit -> safe deactivation/recovery`

No LAB fast-path threshold or `Eligible` authorization result may be promoted directly into a production blocking action.

## Recovery boundary

Verified rollback is the primary recovery mechanism. It favors copy-out over in-place mutation and verifies hashes before applying captured bytes.

Crypto recovery is experimental and format-specific. Current documented recovery support for the simulator format must not be marketed as generic ransomware decryption.

## State, IPC and local privilege

The service state store uses ACL and reparse protections, but no claim is made that it survives a malicious local administrator. The read-only UI pipe exposes bounded status/incident metadata to permitted local users and does not expose mutation commands.

A future enterprise privacy policy should explicitly decide which path/process metadata non-admin users may read and whether a dedicated local reader group is required.

## Supply-chain assumptions

Source correctness is insufficient if the build inputs can drift. The repository now pins the exact .NET SDK, uses reviewed full-SHA GitHub Action references, commits NuGet lock graphs, restores in locked mode, runs dependency vulnerability auditing, and emits release hashes. Those controls reduce accidental build drift; they do not establish trusted release governance by themselves.

Production release governance still requires:

- protected main branch and required checks/reviews enforced in repository settings;
- independent review of kernel/security-sensitive changes;
- protected production signing keys and a production signing workflow;
- release SBOM/provenance and retained build attestations;
- controlled dependency/action update review.

Repository policy settings are external to source control. A CODEOWNERS file can route review but does not itself enforce approvals or prevent direct pushes. Exact inputs also do not protect against a compromised trusted dependency, action commit, build runner or signing identity.

## Current qualification evidence

The repository has stronger Engineering LAB evidence than a source-only prototype, but the evidence remains narrow and does not expand the supported threat model.

For the exact 0.7.30 Driver Verifier qualification head, a disposable Windows VM completed ARM -> real reboot -> runtime -> real reboot -> CLEAR with standard Driver Verifier checks targeted only at `RansomGuardMinifilter.sys`. Runtime observed the target under Verifier, completed bounded concurrency stress with an overflow width of 16 against a kernel admission cap of 8 (8 allowed / 8 denied), exercised CREATE/RENAME/TRUNCATE/DELETE/mapped-write preservation paths, observed no Windows bugcheck in the qualification window, executed `verifier /reset`, and proved clear verifier state after the second reboot. Persisted reboot timestamps are SHA-bound and parsed from raw offset-bearing JSON so non-UTC runner locale cannot weaken reboot proof.

Separate disposable-VM fault evidence covers completion loss, low-disk fail-closed storage admission, and one real-reboot TRUNCATE reconciliation campaign. NTFS runtime coverage exists. ReFS creation was unsupported on the qualification VM and therefore remains unqualified rather than implicitly passed.

These results are regression/qualification evidence for the tested build and environment. They do not establish production signing, broad Windows/Server compatibility, kernel-compromise resistance, third-party filter interoperability, performance suitability, or safe production blocking policy.

0.7.31 sustained mixed-workload qualification is now backed by exact-head disposable-VM evidence. PR #42 head `184566aa4269d28bf3f7c32aeb9035ceaa8dd25c` completed manual run #1 (`35986484214`) with 60/60 waves and 300 mixed CREATE/RENAME/TRUNCATE/DELETE/mapped-write operations. The run also re-proved bounded overflow at 16 requests against kernel cap 8 (8 allowed / 8 denied), worker/gate health, durable transaction correlation, zero pending metadata transactions, mapped pre-image/section/paging evidence and cleanup. This remains evidence for that tested LAB build/environment, not a production prevention claim.

0.7.32 introduced the protocol-v16 disconnect fail-safe state and is now backed by exact-head disposable-VM evidence: PR #45 head `9efa20727408a1a09c730149649822bc642ab4d0`, runtime run #49 (`36019325665`). That run proved abrupt GateClient-loss denial with hash preservation, read-only access while degraded, out-of-root availability, wrong-root rejection, same-root preflight recovery, clean Maintenance release, containment regressions, NTFS filesystem-matrix coverage and bounded cleanup.

0.7.33 protocol-v17 protected-volume scope classification is backed by exact-head disposable-VM evidence: PR #46 head `58b870349d6a645c73f84f2d1add15b783eb0936`, runtime run #50 (`36030318084`). The run proved destructive same-volume ambiguity is denied with hash preservation, outside-to-inside RENAME is denied with source preserved/destination absent, and forced ambiguity on a separately attached NTFS volume remains outside/allowed. Existing disconnect/reconnect/containment/mapping scenarios and cleanup also passed; ReFS creation remained unsupported on that VM.

## Required production qualification

The project must remain non-production until, at minimum:

- Microsoft assigns the production minifilter altitude and the release driver uses the production signing path;
- target Windows/Server and security-feature compatibility is qualified; NTFS has disposable-VM runtime evidence, while the current runner reported ReFS creation unsupported, so ReFS remains unqualified rather than implicitly passed;
- protocol-v18 retained ambiguous-scope policy is adversarially tested across source/destination rename boundaries, namespace aliases and supported local filesystem behavior;
- the existing completion-loss, low-disk and reboot campaigns are extended into a broader fault matrix that includes GateClient/service death, timeout, torn-journal/power-loss conditions and repeated campaign recovery;
- sustained pressure/queueing, rename/mapped-write storms and large/sparse/compressed/encrypted file cases pass; any concurrency claim distinguishes kernel admission from the serialized single-handle reply-required path;
- the existing exact-head Driver Verifier qualification is repeated across the supported Windows/Server/filesystem matrix, and native static-analysis/SDV-style findings are reviewed to an explicit release threshold;
- antivirus/EDR, VSS/backup and BitLocker coexistence is tested;
- detector-to-containment orchestration is authorized and validated for ordinary applications;
- release governance, independent review and provenance controls are enforced.

## Claim discipline

Until those conditions are met, use these descriptions:

- normal product: **Audit by default, plus an explicit non-active Production Enforce state/config foundation**;
- minifilter: **Engineering LAB preservation/containment prototype**;
- rollback: **verified conservative copy-out recovery**;
- crypto recovery: **experimental, format-specific research path**.

Do not describe the current normal bundle as production ransomware blocking, endpoint tamper protection, kernel-compromise protection or universal ransomware decryption.
