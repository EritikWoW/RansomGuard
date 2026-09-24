# RansomGuard threat model

Status: engineering threat model for RansomGuard 0.7.32.x, covering the current Audit product and Engineering LAB minifilter.

This document describes what the current implementation protects, what it deliberately does not protect, and how ambiguous I/O is handled. It is not a claim of production readiness. The ordinary product remains AuditOnly; the blocking minifilter path is Engineering LAB only.

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

### Ordinary product

The normal service obtains filesystem telemetry through ETW and publishes bounded read-only status through the local named pipe. Ordinary applications are always AuditOnly. A detector result is evidence for review; it is not an authorization to block a normal process.

The UI does not turn SCM Running into proof that ETW monitoring is healthy. ETW startup/runtime failure enters an explicit diagnostics-only state.

### Engineering LAB gate

The LAB path consists of:

`user-mode requestor -> Filter Manager/minifilter -> synchronous GateClient decision -> durable rollback store -> allow/deny`

The minifilter and GateClient trust each other only inside the explicitly negotiated LAB protocol/session. The current wire contract is protocol v16; protocol drift is a compatibility/security boundary, not a best-effort condition. The gate is scoped to one explicit protected root. The rollback store must be outside that root.

The Filter Manager server port currently permits one client connection. GateClient uses one synchronous communication handle. Kernel admission may have multiple blocking requests waiting, but user-mode reply-required preservation is deliberately serialized: the worker handling a gate request must send its reply before the receive loop issues the next blocking `FilterGetMessage`. Configurable GateClient slots bound no-reply completion/evidence processing; they are not a claim of multiple simultaneous preservation replies. This distinction is part of the availability model and must not be blurred in performance or security claims.

The runtime test certificate, TESTSIGNING configuration and unassigned LAB altitude are test infrastructure, not production trust anchors.

### Recovery

Recovery consumes validated evidence and writes copy-out results to new paths. It does not automatically rename, delete, recreate or overwrite live topology. Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion.

## Attacker model

| Actor/capability | Current scope | Boundary |
|---|---|---|
| Ordinary user-mode process mutating a resolved file inside the activated LAB root | In scope for LAB preservation | Must pass preserve-before-allow or be denied |
| Explicitly authorized LAB process after durable containment transition | In scope for LAB containment | Future destructive in-root mutations are denied by process-object identity |
| Ordinary process in the normal installed product | Detection/audit only | No production blocking claim |
| Process operating outside the negotiated LAB root | Out of preservation scope | Allowed by this gate |
| Request whose pathname cannot be resolved/classified as in-scope | Not covered by preservation guarantee | Intentionally fail-open today |
| Kernel-mode requestor / compromised kernel component / BYOVD path | Out of scope | `RequestorMode == KernelMode` is not observed by the ordinary gate path |
| Local administrator able to modify binaries/security state | Out of scope as a tamper-resistant boundary | No claim of protection from equal/higher privilege |
| Physical/boot/firmware attacker | Out of scope | No measured-boot or physical isolation claim |
| Compromised signing key/build system | Supply-chain threat, not runtime-detected | Requires repository/release governance controls |
| Network/UNC/remote filesystem semantics | Not qualified | Current LAB/recovery assumptions are local filesystem oriented |

## Enforcement state machine

The current driver does not mean "driver loaded = protected".

| State/condition | Current behavior | Security interpretation |
|---|---|---|
| No GateClient has activated a LAB session, or driver is unloading | Observation path can return without enforcement | No preservation guarantee |
| Client in Audit mode | Event may be queued; operation continues | Telemetry only |
| Client mode unknown/not LAB gate without a retained protection latch | Operation continues | No blocking guarantee |
| LAB gate, pathname resolved outside root | Operation continues | Explicitly out of scope |
| LAB gate or degraded state, pathname/name query cannot establish in-root scope | Operation continues | Intentional fail-open gap remains |
| LAB gate, external in-root mutation before activation completes | Denied | Prevents mutation racing activation preflight |
| LAB gate active, resolved in-root mutation, containment latch matches requestor | Denied before userspace preservation | Containment enforcement |
| LAB gate active, resolved in-root mutation, preservation/gate decision fails | Denied | Fail-closed preservation path |
| Activated LAB gate loses GateClient unexpectedly | Kernel publishes `DegradedProtected`, retains exact root and denies resolved ordinary user-mode mutation-capable CREATE/non-paging WRITE/RENAME/DELETE/TRUNCATE | Prevents silent active-session protection loss |
| Protocol-v16 GateClient reconnects after degraded loss | Accepted only for exact retained root; returns to Preflight before Protected | Re-establishes user-mode preservation only after activation preflight |
| Clean transaction-complete GateClient requests DeactivateGate | Kernel first enters Maintenance-requested admission closure; only after gate/pending work drains does it authorize release and allow the subsequent port close to clear the retained root | Explicit two-phase release rather than disconnect-as-disable |
| LAB storage admission/quota/free-space check fails | Denied | Preservation integrity wins over availability |
| Paging write on tracked stream | Non-blocking evidence only | Relies on pre-preserved CREATE baseline; paging path is not a synchronous policy gate |
| Writable section creation on tracked stream | Non-blocking attestation | Attests prior baseline; does not itself preserve/block |
| Kernel-mode requestor | Not observed by ordinary gate path | Explicit threat-model exclusion |

## Fail-open analysis

Fail-open behavior exists to avoid turning an unresolved filesystem state into operating-system-wide denial of service. It is nevertheless a production blocker until every adversarially reachable ambiguous state is either eliminated, bounded by another invariant, or handled by a reviewed production policy.

### Name/path resolution failure

CREATE and WRITE paths currently return success without enforcement when the driver cannot establish that the request belongs to the negotiated root. Similar scope classification applies to protected metadata operations.

Production work must answer, for each failure mode:

`failure condition -> attacker influence -> certainty request is in protected namespace -> permit/deny/degrade -> telemetry/operator action`

A production design must not silently reinterpret "unable to prove in scope" as "proven out of scope".

### Kernel requestors

The ordinary observation predicate rejects `RequestorMode == KernelMode`. This is acceptable only while kernel compromise/BYOVD is explicitly outside the supported threat model. Product claims must not imply protection against a malicious kernel component.

### Gate disconnect/unavailable state

Protocol v16 removes the previous silent active-session `client died -> protection off` transition for the Engineering LAB root. Once activation succeeds, the kernel sets a protection-required latch. If GateClient disappears without an authorized whole-gate deactivation, the driver publishes `DegradedProtected` before publishing client loss, retains the exact negotiated root, and denies resolved ordinary user-mode mutation-capable CREATE, non-paging WRITE, RENAME, DELETE and TRUNCATE operations in that root. A replacement v16 GateClient may reconnect only to that same retained root and begins again in Preflight.

A clean shutdown is a distinct two-phase maintenance transition. GateClient first requires a clean durable transaction/lifecycle state and then sends `DeactivateGate`. The kernel immediately publishes a maintenance-requested latch that closes new synchronous gate admission and causes any already-replied request racing the transition to be denied. That latch is **not** release authorization: while blocking gate sends or queued evidence work remain, the command returns busy and the protection-required latch stays armed. If GateClient dies during this drain, disconnect still enters `DegradedProtected`. Only after gate/pending work reaches zero does the kernel clear the protection-required latch, authorize graceful disconnect and report Maintenance; the subsequent port close may then clear the root.

This is a fail-safe foundation, not production self-protection. Unresolved/scope-ambiguous paths still fail open, paging/section callbacks retain the existing non-blocking pre-preserved-baseline model, kernel-mode requestors remain excluded, driver unload explicitly clears the latch, and an Administrator/SYSTEM attacker that can control the driver/service lifecycle is not yet contained by this boundary.

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

This model does not justify treating an arbitrary pre-existing mapping as safe. Activation preflight checks for pre-existing writable references and prevents activation when a hazard is detected.

## Detection and containment boundary

ETW/RiskEngine is a trigger and evidence source, not the preservation guarantee.

The current normal service deliberately returns AuditOnly for ordinary applications, including suspicious/canary cases. The existing containment primitive is LAB-only and can bind one explicitly authorized process to a referenced kernel process object. Production detector-to-containment orchestration remains unimplemented.

Before production containment is enabled, the authorization chain must prove at least:

`incident evidence -> live process identity -> preservation health -> containment request -> exact kernel receipt -> post-containment audit -> safe deactivation/recovery`

No LAB fast-path threshold should be promoted directly into a production blocking rule.

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

0.7.32 introduces the protocol-v16 disconnect fail-safe state described above. Source invariants and hosted compile/build are necessary but are not runtime evidence that process death, exact-root reconnect and graceful release behave correctly under Filter Manager. The milestone remains unqualified until an exact-head disposable-VM campaign kills GateClient after activation, proves in-root destructive I/O is denied while degraded, proves an incompatible/wrong-root recovery path cannot silently release the retained scope, proves same-root preflight recovery, and proves an explicit clean deactivation releases the root.

## Required production qualification

The project must remain non-production until, at minimum:

- Microsoft assigns the production minifilter altitude and the release driver uses the production signing path;
- target Windows/Server and security-feature compatibility is qualified; NTFS has disposable-VM runtime evidence, while the current runner reported ReFS creation unsupported, so ReFS remains unqualified rather than implicitly passed;
- unresolved/name-query failure policy is reviewed and adversarially tested;
- the existing completion-loss, low-disk and reboot campaigns are extended into a broader fault matrix that includes GateClient/service death, timeout, torn-journal/power-loss conditions and repeated campaign recovery;
- sustained pressure/queueing, rename/mapped-write storms and large/sparse/compressed/encrypted file cases pass; any concurrency claim distinguishes kernel admission from the serialized single-handle reply-required path;
- the existing exact-head Driver Verifier qualification is repeated across the supported Windows/Server/filesystem matrix, and native static-analysis/SDV-style findings are reviewed to an explicit release threshold;
- antivirus/EDR, VSS/backup and BitLocker coexistence is tested;
- detector-to-containment orchestration is authorized and validated for ordinary applications;
- release governance, independent review and provenance controls are enforced.

## Claim discipline

Until those conditions are met, use these descriptions:

- normal product: **audit/telemetry + recovery foundations**;
- minifilter: **Engineering LAB preservation/containment prototype**;
- rollback: **verified conservative copy-out recovery**;
- crypto recovery: **experimental, format-specific research path**.

Do not describe the current normal bundle as production ransomware blocking, endpoint tamper protection, kernel-compromise protection or universal ransomware decryption.
