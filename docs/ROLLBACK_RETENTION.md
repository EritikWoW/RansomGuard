# Rollback retention and cleanup — v0.7.18.0

RansomGuard 0.7.18 adds explicit, crash-resumable retention for Engineering LAB rollback repositories.

Retention is manual. GateClient never executes cleanup automatically.

## Session lifecycle

Every new rollback session receives a tamper-evident lifecycle journal:

`lifecycle-state/session-lifecycle.jsonl`

Lifecycle events:

- `Created`
- `Completed`
- `Faulted`
- `HoldSet`
- `HoldReleased`

A GateClient session becomes `Completed` only after:

- all active gate workers have drained;
- repository verification succeeds;
- no gate worker failure was recorded;
- CREATE has no pending intent;
- RENAME has no pending intent.

Otherwise the graceful shutdown is marked `Faulted`. A crash before terminal lifecycle commit leaves the session `Active`.

Legacy sessions that predate lifecycle metadata are treated as `LegacyUnmanaged` and are never automatically selected by retention.

## Hold

Use a hold to protect a managed session from cleanup:

```cmd
rollback_maintenance.cmd hold --repository "C:\RansomGuard-Rollback" --session SESSION_ID --reason "incident investigation"
```

Release it explicitly:

```cmd
rollback_maintenance.cmd release-hold --repository "C:\RansomGuard-Rollback" --session SESSION_ID --reason "investigation complete"
```

Hold changes are appended to the same lifecycle hash chain. An existing retention plan becomes stale after a hold change.

## Default retention policy

The default Engineering LAB policy is:

- maximum completed-session age: **30 days**;
- maximum managed completed storage: **32 GiB**;
- capacity-pressure purge may only select sessions at least **24 hours** old.

Completed `Held` and completed pending-transaction sessions still count toward the retained completed-byte total but are not purge candidates. If protected evidence prevents the repository from reaching the configured byte cap, the plan reports `UnresolvedExcessBytes`.

## Plan

Generate a plan:

```cmd
rollback_maintenance.cmd retention-plan ^
  --repository "C:\RansomGuard-Rollback" ^
  --output "C:\Recovery\retention-plan.json"
```

Optional policy tuning:

```text
--max-age-days <1..3650>
--max-completed-mib <1..10485760>
--min-pressure-hours <0..max-age-days*24>
```

The planner is read-only.

It excludes:

- Active sessions;
- Faulted sessions;
- Held sessions;
- LegacyUnmanaged sessions;
- sessions with pending CREATE/RENAME/TRUNCATE transactions;
- sessions with unsettled DELETE lifecycle evidence, including missing disposition completion, cleanup-only state, same-FILE_ID presence, or ambiguous/conflicting topology.

Selection reasons are:

- age expiry;
- completed-storage capacity pressure;
- continuation of an already-started purge.

The plan binds current lifecycle/evidence state into SHA-256 inventory/session digests and a deterministic PlanId.

## Execute

Execute only a saved plan:

```cmd
rollback_maintenance.cmd retention-execute ^
  --repository "C:\RansomGuard-Rollback" ^
  --plan "C:\Recovery\retention-plan.json" ^
  --report "C:\Recovery\retention-report.json"
```

The executor first acquires the repository-wide cross-process maintenance lease, then rebuilds the current plan. `hold` and `release-hold` acquire the same lease, so a Hold cannot race the final purge revalidation. If inventory/PlanId changed, execution is refused.

## Purge ordering

A new purge is not deleted directly from `Sessions`.

The required order is:

1. validate completed/unheld lifecycle, pending transactions and session digest;
2. append repository-level `PurgeStarted`;
3. atomically move `Sessions\SESSION_ID` to `Retired\SESSION_ID`;
4. append `Quarantined`;
5. delete the quarantined tree using reparse-safe traversal;
6. append `PurgeCompleted`.

Repository-level audit lives at:

`retention-state/retention-journal.jsonl`

The journal is write-through and SHA-256 hash chained.

## Crash resume

If maintenance stops after `PurgeStarted` or `Quarantined`, the next retention plan recognizes the incomplete chain.

Supported recovery paths include:

- resume while the session is still under `Sessions`;
- resume after it has moved to `Retired`;
- finalize a missing quarantine when deletion completed but the final receipt was not written.

Before the `Quarantined` receipt, the session digest must still match the original purge intent.

After `Quarantined`, partial deletion can be resumed, but every remaining path is still checked for reparse points before deletion.

## What retention never does

Retention never automatically deletes:

- Active evidence;
- Faulted evidence;
- Held evidence;
- legacy unmanaged evidence;
- sessions with unresolved CREATE/RENAME/TRUNCATE transactions;
- sessions with unsettled DELETE lifecycle evidence.

There is no force-delete or ignore-hold command.

Retention cleanup is not run by GateClient, normal Audit startup, or normal CI.

## Current limitations

0.7.18 is an Engineering LAB lifecycle/retention foundation. Production work still includes:

- user-facing retention UI and policy management;
- incident-aware automatic hold placement;
- long-running repository telemetry;
- broader fault injection during move/delete phases;
- backup/export integration before purge;
- enterprise retention/legal-hold policy integration.
