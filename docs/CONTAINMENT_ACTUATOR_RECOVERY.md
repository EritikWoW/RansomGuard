# Production containment actuator recovery runbook

Status: pre-enable recovery contract for RansomGuard 0.8.7. The production containment actuator remains unreachable while `AutomaticContainment=false`. This runbook defines the recovery behavior that must be implemented and VM-qualified before enablement.

## Safety objective

A service restart, cancellation, timeout, partial actuator failure, or operator recovery must never normalize arbitrary Windows suspend counts or resume a process/thread that RansomGuard cannot prove it suspended.

The only resumable unit is one durable RansomGuard-owned suspend increment bound to:

- one actuation request id;
- one authorization id;
- exact process identity: PID + process creation FILETIME;
- exact thread identity: TID + thread creation FILETIME;
- the immutable image/protection binding stored in the actuation ledger.

## Mandatory recovery order

1. Keep new production actuation admission disabled while recovery is unresolved.
2. Open the existing containment actuation ledger without creating a replacement state root.
3. Verify the complete write-through hash chain and transition graph. If validation fails, stop recovery and require security review; do not guess ownership.
4. Identify requests that have durable `SuspendOwned` records without matching `ResumeOwned` records.
5. Re-open only the exact recorded process instance. PID reuse or creation-time mismatch means the old process identity is gone; never treat the new PID occupant as the suspended target.
6. For every outstanding owned thread, open the exact TID and verify both owner PID and thread creation FILETIME before calling `ResumeThread`.
7. Call `ResumeThread` at most once for each outstanding owned increment. Never loop until the suspend count becomes zero.
8. After a successful exact resume, append durable `ResumeOwned` evidence immediately.
9. Append `ResumeCompleted` only when no owned increment remains outstanding for the request.
10. Verify the ledger again before allowing any new actuation admission.

## Prohibited recovery shortcuts

Recovery must not use:

- `NtResumeProcess` / whole-process resume normalization;
- process-tree resume or termination;
- repeated `ResumeThread` calls until a thread becomes runnable;
- TID-only ownership;
- PID-only process identity;
- a reconstructed or replacement ledger after ledger corruption;
- kill/quarantine as a substitute for owned-suspend recovery.

If exact identity cannot be re-established, recovery must fail closed and preserve the evidence for operator review.

## Process-exited case

If the exact recorded process instance no longer exists, its Windows thread objects can no longer remain as a live suspended workload. The ledger must still preserve that the request ended without a normal owned-resume completion. A future production recovery implementation must record an explicit terminal recovery outcome for this case rather than pretending that `ResumeOwned` occurred.

Until that terminal outcome exists and is qualified, automatic production containment must remain disabled.

## Operator procedure before enablement

If future production actuation is enabled and the service reports outstanding owned suspension evidence:

1. Disable further automatic containment admission.
2. Preserve the incident archive and containment actuation ledger.
3. Restart only the RansomGuard service/recovery path; do not use Task Manager or third-party tools to normalize suspend counts.
4. Require startup recovery to validate the ledger and attempt exact owned-only resume before the service accepts new actuation requests.
5. Confirm that every recoverable request reaches `ResumeCompleted` with zero outstanding owned increments.
6. If recovery reports identity mismatch, corrupt ledger, inaccessible thread, or remaining owned increments, keep automatic containment disabled and escalate for manual security review.

## Qualification requirements

Before `AutomaticContainment=true` is accepted by product configuration, disposable-VM evidence must prove at minimum:

- a healthy authorization suspends only after durable `Prepared` evidence;
- partial thread failure rolls back only owned increments;
- cancellation rolls back only owned increments;
- timeout after at least one owned increment rolls back to zero outstanding ownership;
- reopening the durable ledger as a service-restart simulation can resume only the recorded exact thread identities;
- unrelated processes continue running;
- replay, PID reuse, image drift, protection-state drift and telemetry-loss vetoes fail closed;
- the evidence artifact is bound to an exact source SHA.

Automatic production containment remains disabled until disposable-VM restart/recovery qualification passes.

This runbook is a safety contract, not a claim that production automatic containment is currently enabled.
