# Safe rollback retention — v0.7.18.0

RansomGuard 0.7.18 adds explicit retention planning and single-session purge for Engineering LAB rollback repositories.

Retention is deliberately conservative. A rollback session is never purge-eligible merely because it is old or large.

## Safety model

A session becomes purge-eligible only when all of the following are true:

1. the session has a valid durable lifecycle journal;
2. lifecycle is exactly `Opened -> ClosedCleanly`;
3. there are no pending CREATE transactions;
4. there are no pending RENAME transactions;
5. the current verified recovery plan contains no Blocked actions;
6. the user explicitly released the exact current `RecoveryPlanId`;
7. the configured minimum age since `ClosedCleanly` has elapsed.

Legacy sessions without lifecycle evidence are never automatically purgeable.

A release becomes stale automatically when session evidence changes and therefore produces a different recovery `PlanId`.

## LAB commands

The Engineering LAB bundle contains:

`rollback_retention.cmd`

### 1. Build a retention plan

```cmd
rollback_retention.cmd plan --repository "C:\RansomGuard-Rollback" --output "C:\Recovery\retention-plan.json"
```

Default minimum age: **168 hours / 7 days**.

The CLI allows:

```cmd
--min-age-hours <24..87600>
```

The executable does not expose a force/all/wildcard/disable-age purge switch.

### 2. Release one recovery plan

First create and review the session's verified recovery plan with `rollback_recovery.cmd plan`.

Then explicitly release that exact recovery plan:

```cmd
rollback_retention.cmd release ^
  --repository "C:\RansomGuard-Rollback" ^
  --session "gate-..." ^
  --recovery-plan "C:\Recovery\recovery-plan.json" ^
  --confirm "RELEASE:gate-..."
```

The release is stored in the repository-level hash-chained:

`Retention\retention-release-journal.jsonl`

It is outside `Sessions`, so the acknowledgement does not alter the rollback/recovery evidence digest it approves.

Release is refused when the session is not closed cleanly, has pending CREATE/RENAME transactions, contains Blocked recovery actions, or when the supplied recovery plan is stale.

### 3. Purge exactly one eligible session

Generate a fresh retention plan after release, then:

```cmd
rollback_retention.cmd purge ^
  --repository "C:\RansomGuard-Rollback" ^
  --session "gate-..." ^
  --retention-plan "C:\Recovery\retention-plan.json" ^
  --confirm "PURGE:gate-..."
```

The executor does not trust the session entries from the supplied JSON. It rebuilds the current retention plan and requires the same `PlanId`.

Only the named session may be purged.

## Quarantine-first delete

A validated purge uses this durable sequence:

1. append `Intent` to `Retention\retention-purge-journal.jsonl`;
2. atomically move the exact session directory from `Sessions\<id>` to `Retention\PurgeQuarantine\...`;
3. append `Quarantined`;
4. re-check the quarantine tree for reparse points;
5. recursively delete the quarantine directory;
6. append `Completed`.

If the process stops after the atomic move but before deletion, rollback evidence remains in `PurgeQuarantine` rather than being partially deleted from the session tree.

The purge journal is SHA-256 hash chained and write-through.

## Session lifecycle

New LAB gate sessions commit:

`session-lifecycle.jsonl`

with exactly:

`Opened -> ClosedCleanly`

`Opened` is recorded before activation preflight.

`ClosedCleanly` is written only after all GateClient workers finish during normal shutdown.

A crash, activation failure, abrupt termination, storage-budget refusal during close, or other incomplete shutdown leaves no `ClosedCleanly` record and therefore blocks retention purge.

## Relationship to storage budget

0.7.17 prevents one active session from silently exhausting rollback storage.

0.7.18 addresses completed-session retention.

The two policies are separate:

- storage budget controls new writes;
- retention controls when old evidence may be explicitly removed.

There is no automatic scheduled purge.

## Current limitations

0.7.18 does not yet provide:

- automatic retention scheduling;
- bulk/wildcard purge;
- automatic cleanup of incomplete quarantine operations;
- production UI for review/release/purge;
- retention decisions across external/offloaded archives;
- cryptographic signing of retention approvals;
- production incident-close workflow.

Those remain future work.
