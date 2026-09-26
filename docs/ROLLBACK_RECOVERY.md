# Verified rollback recovery — current through v0.8.7

RansomGuard 0.7.16 introduced deterministic recovery planning for Engineering LAB rollback sessions. 0.7.19 extends that planner with conservative review-only use of durable restart reconciliation evidence.

This is **copy-out recovery only**. It does not overwrite, rename or delete live source/evidence paths.

## Commands

The Engineering LAB bundle contains:

`rollback_recovery.cmd`

Generate a plan:

```cmd
rollback_recovery.cmd plan --repository "C:\RansomGuard-Rollback" --session SESSION_ID --output "C:\Recovery\plan.json"
```

Execute the plan:

```cmd
rollback_recovery.cmd execute --repository "C:\RansomGuard-Rollback" --plan "C:\Recovery\plan.json" --output "D:\RansomGuard-Recovered"
```

The output directory must not already exist and must remain outside the rollback repository.

## Recovery states

The planner classifies every relevant durable record:

- **Ready** — safe copy-out action can be executed.
- **Review** — topology needs a human decision. This includes authoritative completion evidence and, starting in 0.7.19, exact fully-consistent restart evidence that supports one crash outcome without claiming authoritative completion.
- **Blocked** — authoritative completion/name/identity evidence is missing or unresolved and restart evidence is absent, ambiguous, indeterminate, or conflicting.
- **Informational** — no recovery action is necessary, or a stronger recovery source supersedes it.

Only two action kinds may ever be `Ready`:

1. `RestoreFullPreimageCopy`
2. `RestoreRangeCowCopy`

CREATE/RENAME/TRUNCATE/DELETE/topology actions are never executed automatically.

## Full pre-image recovery

A committed full pre-image is restored through the existing verified full-file store.

The executor:

1. validates the repository;
2. validates the requested session;
3. re-builds the current recovery plan;
4. verifies plan ID and evidence digest;
5. verifies the exact committed capture record;
6. writes a new `.ransomguard-recovered` file into a new action directory;
7. records the recovered file length and SHA-256.

The damaged/live source is never overwritten.

## Range-COW recovery

Range recovery reconstructs a new file from:

- the current damaged source as the base;
- committed original blocks;
- the recorded original length.

If a full pre-image exists for the same path, the range action is marked `Informational`; the full pre-image is preferred.

Range recovery requires the damaged source to still exist and be at least as long as the recorded original baseline. If that condition is not met, execution fails closed.

## Originally absent paths

A path recorded as originally absent is marked `Review`.

RansomGuard does **not** automatically delete the current file. A file created during the incident may now contain user data, application state, forensic evidence, or another legitimate object.

## CREATE and RENAME transactions

Authoritative kernel completion remains the strongest evidence. Successful CREATE on an originally absent path remains `Review`, successful RENAME remains `Review`, unresolved final name/identity remains `Blocked`, and failed filesystem operations are `Informational`.

For a pending CREATE/RENAME with no authoritative completion, 0.7.19 checks `restart-reconciliation-journal.jsonl` only for records bound to the exact operation kind, kernel request sequence, and intent-record SHA-256.

- If every matching durable observation is decisive and all observations agree on `SupportsCompleted`, the pending topology action becomes `Review`.
- If every matching durable observation is decisive and all observations agree on `SupportsNotCompleted`, the pending topology action becomes `Review`.
- If there is no matching evidence, or any matching observation is `Indeterminate` / `Ambiguous`, or observations conflict, the action remains `Blocked`.

Protocol v14 applies the same boundary to TRUNCATE through its separate truncate-state restart journal. Exact EOF evidence can make a pending transaction Review-only; allocation-size/VDL loss stays unresolved. The executor never changes a live EOF/allocation/VDL value.

Protocol v15 applies an additional lifecycle boundary to DELETE. `DeleteDispositionResult` is authoritative only for the SetInformation result. Exact-handle `CleanupObserved` is persisted separately and does not prove pathname deletion. A bounded live topology probe, or a later restart probe for an unsettled transaction, may observe the original pathname missing, the same FILE_ID still present, or ambiguous/replacement topology. Consistent evidence can make `ReviewDeleteTransaction` reviewable, while cleanup-only or conflicting evidence stays Blocked. No probe writes the DELETE completion journal.

This assessment never writes a CREATE/RENAME/DELETE authoritative completion journal entry and never turns a topology action into `Ready`. The executor therefore still cannot delete incident-created paths, recreate deleted paths, reverse renames, overwrite live objects, or restore in place.

## Plan identity and stale-plan refusal

The planner computes:

- a SHA-256 digest over all validated session `*.jsonl` evidence;
- a deterministic `PlanId` over the session, evidence digest and canonical actions.

The executor does not trust actions from the supplied JSON file. It re-builds a fresh plan from the rollback repository and requires the supplied `PlanId` and evidence digest to match.

If new evidence appears after the plan was generated—including another restart observation or a later authoritative completion—execution is refused before the output directory is created.

## Output

Successful execution creates a new output root containing:

- `recovery-plan.json` — the freshly revalidated plan actually used;
- `recovery-execution.json` — per-action result, output path, length and SHA-256;
- one subdirectory per executed Ready action.

Review/Blocked actions produce no filesystem mutation.

## Path safety

Recovery output and plan paths reject existing reparse-point/junction ancestors.

The recovery output root must be new and outside the rollback repository.

The executor contains no automatic topology mutation path and does not expose delete, rename, overwrite-in-place or restore-in-place verbs.

## Current limitations

0.8.7 adds a separate production administration boundary around the same verified copy-out executor.

## Production copy-out boundary (0.8.7)

Production execution is available only through the short-lived UAC-elevated administration surface. It is not an ordinary `RansomGuard.ReadOnly.v2` command.

Before output creation, production execution requires:

- a canonical `production-*` terminal session;
- Administrator/UAC elevation;
- the RansomGuard service and audit engine to be stopped;
- the exact operator-reviewed `PlanId`;
- the exact journal evidence SHA-256;
- the exact lifecycle-record SHA-256;
- a local, absolute, canonical output path that does not already exist;
- the output path to remain outside RansomGuard private state and source evidence directories.

The plan is rebuilt from read-only stores immediately before execution and again after execution. Lifecycle evidence is revalidated before and after copy-out.

Only `Ready` full-preimage/range-COW copy actions can execute. Every emitted file records its evidence record, expected length/SHA-256, and actual length/SHA-256. Range-COW computes the expected digest before output creation from the validated live base plus committed original blocks, so source drift during copy-out fails verification.

The output root includes `recovery-plan.json`, `recovery-execution.json`, and `production-recovery-execution.json`. Partial failures remain explicit; already completed copies are not represented as rolled back.

### Elevated operator workflow

The same-EXE UAC-elevated recovery window can now invoke this boundary after an explicit review step. The operator must build the current plan, review its Ready/Review/Blocked/Informational actions, type a fully qualified new local output root, and acknowledge that the operation creates recovered copies only. The UI passes only the exact reviewed session/PlanId/evidence/lifecycle tuple to the Management API; it performs no direct filesystem or service mutation itself.

After any execution attempt—success, partial failure, stale-plan refusal, or other error—the UI clears the reviewed plan and approval. A new attempt therefore requires a fresh plan rebuild/review.

Preview/UI-smoke mode remains synthetic and never calls the production executor or queries ProgramData/SCM.

0.8.7 still does not provide:


- automatic directory-tree rollback;
- automatic removal of incident-created paths;
- automatic rename reversal;
- recovery from a missing live source when only range-COW evidence exists;
- incident-wide merge with adaptive crypto recovery;
- production minifilter certification/signing.

Those require additional recovery policy and runtime validation.
