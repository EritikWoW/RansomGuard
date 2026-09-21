# Verified rollback recovery — v0.7.16.0

RansomGuard 0.7.16 adds a deterministic recovery-planning layer for Engineering LAB rollback sessions.

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
- **Review** — evidence is authoritative enough to describe the topology event, but RansomGuard will not mutate live topology automatically.
- **Blocked** — authoritative completion/name/identity evidence is missing or unresolved.
- **Informational** — no recovery action is necessary, or a stronger recovery source supersedes it.

Only two action kinds may ever be `Ready`:

1. `RestoreFullPreimageCopy`
2. `RestoreRangeCowCopy`

CREATE/RENAME/topology actions are never executed automatically.

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

Pending CREATE/RENAME intents are `Blocked`.

Successful CREATE on an originally absent path remains `Review`.

Successful RENAME remains `Review`: the plan records source/destination evidence, but the executor never renames live objects.

Unresolved final name or identity remains `Blocked`.

Failed filesystem operations are `Informational`.

## Plan identity and stale-plan refusal

The planner computes:

- a SHA-256 digest over all validated session `*.jsonl` evidence;
- a deterministic `PlanId` over the session, evidence digest and canonical actions.

The executor does not trust actions from the supplied JSON file. It re-builds a fresh plan from the rollback repository and requires the supplied `PlanId` and evidence digest to match.

If new evidence appears after the plan was generated, execution is refused before the output directory is created.

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

0.7.16 does not yet provide:

- automatic directory-tree rollback;
- automatic removal of incident-created paths;
- automatic rename reversal;
- recovery from a missing live source when only range-COW evidence exists;
- production UI orchestration;
- incident-wide merge with adaptive crypto recovery;
- production minifilter certification/signing.

Those require additional recovery policy and runtime validation.
