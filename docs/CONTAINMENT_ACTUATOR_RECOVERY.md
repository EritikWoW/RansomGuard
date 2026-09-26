# Production containment actuator recovery runbook

Status: pre-enable recovery contract for RansomGuard 0.8.7. The crash-safe Windows process state-change backend is VM-qualified, but ordinary-process production actuation remains unreachable while `AutomaticContainment=false`.

## Qualified safety model

Production containment must use the qualified process state-change object path, not the older per-thread `SuspendThread` executor.

The ownership primitive is one live Windows process state-change object bound to:

- one short-lived immutable containment authorization/binding;
- one exact `ProcessKey` (PID + process creation FILETIME);
- one freshly revalidated image path and SHA-256;
- one exact healthy Enforce/Protected protection snapshot;
- one retained process handle and one retained state-change handle.

Normal completion must explicitly resume the state change before releasing the session. Cancellation and controlled failure must also attempt explicit resume.

The crash-safety backstop is handle lifetime: disposable-VM qualification proved that hard termination of the helper holding the final state-change handle released the suspended target and its heartbeat resumed. RansomGuard must not fabricate a successful explicit-resume record after such a crash; absence of normal post-actuation evidence remains an abnormal/incomplete session for review.

The legacy per-thread actuator and its exact-thread ownership ledger remain useful engineering qualification evidence, but they are not a production fallback for a platform that lacks the process state-change API.

## Mandatory startup/recovery order

1. Keep new automatic containment admission disabled until recovery review is complete.
2. Open the existing protected state generation; never create a replacement state root to hide missing or corrupt evidence.
3. Validate incident, authorization, binding and actuation evidence that was durably written before the state change.
4. Classify every incomplete actuation session as abnormal/incomplete; never infer that an explicit resume occurred merely because the service restarted.
5. Re-establish current protection health independently. A restarted service must again prove Enforce + Protected, rollback readiness, kernel connectivity/enforcement and healthy telemetry before any new authorization can become actionable.
6. Verify that the process state-change API required by the qualified backend is available. Unsupported platforms fail closed.
7. Do not recover an old process suspension by PID alone. PID reuse or process-creation mismatch invalidates the old target identity.
8. Do not call `ResumeThread`, `NtResumeProcess`, terminate the process, or normalize suspend counts as a recovery shortcut.
9. If an incomplete pre-crash session exists, record recovery review evidence. The qualified safety expectation is that final state-change handle destruction already released the live state change.
10. If the exact target still appears non-progressing after service/helper loss, treat that as a failed safety assumption: keep automatic containment disabled and escalate for operator/security review rather than guessing a resume primitive.
11. Admit a new actuation request only after current evidence is healthy and the new request receives a fresh one-shot authorization/binding.

## Normal bounded session

A future production-wired containment session must follow this ordering:

1. persist incident evidence;
2. evaluate authorization;
3. create the strict immutable capability binding;
4. persist pre-actuation/binding evidence before intervention;
5. open the exact process and state-change object;
6. revalidate process identity, image identity, critical-process state, protection state and telemetry immediately before suspend;
7. apply one process state-change suspend;
8. perform only the bounded response work allowed by the actuator session;
9. explicitly resume on normal completion, timeout, cancellation or handled failure;
10. persist the explicit result/resume outcome;
11. dispose the state-change handle, then the process handle.

Handle destruction is a crash-release safety net, not the normal success path.

## Prohibited fallbacks

Production containment must not fall back to:

- per-thread `SuspendThread` / `ResumeThread`;
- `NtSuspendProcess` / `NtResumeProcess`;
- process-tree suspend/resume/kill;
- repeated resume calls until a process or thread appears runnable;
- PID-only ownership;
- kill/quarantine as a substitute for reversible containment;
- reconstructed evidence after protected-state corruption.

If the process state-change API is unavailable or any exact binding/revalidation check cannot be proved, the actuation request is denied.

## Service-crash case

If the service or helper terminates while holding the active state-change object:

- no user-mode cleanup callback is assumed to run;
- the final state-change handle is expected to close with the process;
- disposable-VM run `36225304884` proved target heartbeat recovery after hard helper termination on the tested Windows build;
- on restart, RansomGuard records the prior session as abnormal/incomplete rather than pretending an explicit resume was durably acknowledged;
- new automatic containment admission stays closed until current protection health and the recovery review are complete.

This contract deliberately distinguishes live safety from evidence completeness: the kernel-object lifetime prevents a durable stranded freeze in the qualified scenario, while the audit trail must still show that normal explicit completion was not observed.

## Operator procedure

If future production automatic containment is enabled and startup finds incomplete actuation evidence:

1. stop new automatic containment admission;
2. preserve the incident archive, authorization/binding evidence and actuation records;
3. restart only the RansomGuard service/recovery path;
4. confirm current protection state independently;
5. confirm the qualified state-change API is available;
6. do not use Task Manager or third-party tooling to normalize suspend counts as part of RansomGuard recovery;
7. record whether the exact prior process instance still exists and whether it is progressing;
8. if the target is not progressing or evidence integrity is uncertain, keep automatic containment disabled and escalate for manual security review;
9. only after recovery review succeeds may later incidents receive fresh authorizations.

## Qualification evidence

Exact-SHA disposable-VM run `36225304884` qualified source:

`8983455fde991a2a85682058a45ed9f8773fc03d`

Evidence artifact:

`ransomguard-containment-actuator-8983455fde991a2a85682058a45ed9f8773fc03d`

Artifact digest:

`sha256:6f73539191cb6bd466a210fc2774c16ff81710f1e5ab2656958376bc57b14a26`

The run reported `passed=true` on `Microsoft Windows NT 10.0.28000.0` and proved:

- exact process/thread identity and immutable binding;
- replay, PID-reuse, image-drift, lifecycle, telemetry, critical/self/protected-service vetoes;
- unrelated-process isolation;
- partial-failure rollback;
- restart-recovery exact-thread qualification for the legacy executor;
- timeout and cancellation rollback;
- process state-change API availability;
- explicit state-change resume;
- hard helper-process termination followed by automatic target heartbeat recovery.

This is evidence for that exact source and tested Windows environment. It is not a claim that every Windows or Windows Server version supports the state-change API.

## Enablement status

The recovery/qualification gate is satisfied for the exact pre-enable source above, but production automatic containment is still disabled.

`AutomaticContainment=true` may be considered only after the separately reviewed ordinary-process integration:

- uses the strict one-shot capability binding;
- uses the qualified state-change backend;
- persists pre/post actuation evidence;
- preserves all authorization and revalidation vetoes;
- has no crash-unsafe fallback;
- passes final hosted and disposable-VM exact-SHA qualification after the integration is wired.

This runbook is a safety contract, not a claim that production automatic containment is currently enabled.
