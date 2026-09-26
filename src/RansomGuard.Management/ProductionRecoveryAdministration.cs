using System.Diagnostics;
using RansomGuard.Core;
using RansomGuard.Rollback;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record ProductionRecoverySessionSummary(
    string SessionId,
    string LifecycleState,
    bool IsHeld,
    DateTime? CreatedUtc,
    DateTime? CompletedUtc,
    DateTime? FaultedUtc,
    string LastRecordSha256,
    bool CanPlan,
    string Note);

public sealed record ProductionRecoveryActionSummary(
    int Index,
    string Kind,
    string State,
    string PrimaryPath,
    string RelatedPath,
    string EvidenceRecordSha256,
    ulong EvidenceSequence,
    bool RequiresLiveSource,
    string Reason);

public sealed record ProductionRecoveryPlanSummary(
    string SessionId,
    string LifecycleState,
    string PlanId,
    string JournalEvidenceSha256,
    DateTime PlannedUtc,
    int ReadyCount,
    int ReviewCount,
    int BlockedCount,
    int InformationalCount,
    int TotalActions,
    bool ActionsTruncated,
    ProductionRecoveryActionSummary[] Actions,
    string SafetyNote);

/// <summary>
/// Read-only production recovery administration foundation.
///
/// This type deliberately does not execute recovery actions. It validates the fixed private
/// RansomGuard state store, requires an idle service/process boundary, validates rollback
/// evidence, and exposes deterministic plan summaries for the short-lived elevated UI.
/// </summary>
public static class ProductionRecoveryAdministration
{
    private const int MaxSessions = 128;
    private const int MaxActions = 200;
    private const string ProductionPrefix = "production-";

    public static ProductionRecoverySessionSummary[] ListSessions()
    {
        RuleAdministration.DemandAdministrator();
        using var maintenance = StateMaintenanceGate.Acquire();
        EnsureIdle();

        var rollbackRoot = ValidateStateAndGetRollbackRoot(allowMissing: true);
        if (rollbackRoot is null)
            return [];

        var repository = new RollbackRepository(rollbackRoot, createIfMissing: false);

        var ids = repository.SessionIds()
            .Where(IsProductionSessionId)
            .OrderByDescending(x => x, StringComparer.Ordinal)
            .ToArray();

        if (ids.Length > MaxSessions)
            throw new IOException($"Recovery inventory exceeds the bounded session limit ({MaxSessions}). Run reviewed retention/archive maintenance before planning recovery.");

        return ids.Select(id =>
        {
            repository.VerifySession(id);
            return BuildSessionSummary(repository, id);
        }).ToArray();
    }

    public static ProductionRecoveryPlanSummary BuildPlan(string sessionId)
    {
        RuleAdministration.DemandAdministrator();
        ValidateProductionSessionId(sessionId);
        using var maintenance = StateMaintenanceGate.Acquire();
        EnsureIdle();

        var rollbackRoot = ValidateStateAndGetRollbackRoot(allowMissing: false)
            ?? throw new DirectoryNotFoundException("Rollback repository does not exist.");

        var repository = new RollbackRepository(rollbackRoot, createIfMissing: false);

        if (!repository.SessionIds().Contains(sessionId, StringComparer.Ordinal))
            throw new DirectoryNotFoundException("Production rollback session not found: " + sessionId);

        repository.VerifySession(sessionId);
        var session = repository.OpenSession(sessionId);
        var lifecycle = new RollbackSessionLifecycleStore(session.Root);
        lifecycle.VerifyAll();
        var snapshot = lifecycle.Snapshot;

        if (snapshot.State is not (RollbackSessionLifecycleState.Completed or RollbackSessionLifecycleState.Faulted))
            throw new InvalidOperationException(
                $"Recovery planning is refused for lifecycle state '{snapshot.State}'. Resume/resolve the production session before operator recovery planning.");

        var plan = RollbackRecoveryPlanner.Build(rollbackRoot, sessionId, createIfMissing: false, verifyRepositoryAll: false);
        var actions = plan.Actions
            .Take(MaxActions)
            .Select(x => new ProductionRecoveryActionSummary(
                x.Index,
                x.Kind.ToString(),
                x.State.ToString(),
                x.PrimaryPath,
                x.RelatedPath,
                x.EvidenceRecordSha256,
                x.EvidenceSequence,
                x.RequiresLiveSource,
                x.Reason))
            .ToArray();

        var informational = plan.Actions.Count(x => x.State == RecoveryActionState.Informational);

        return new ProductionRecoveryPlanSummary(
            sessionId,
            snapshot.State.ToString(),
            plan.PlanId,
            plan.JournalEvidenceSha256,
            plan.PlannedUtc,
            plan.ReadyCount,
            plan.ReviewCount,
            plan.BlockedCount,
            informational,
            plan.Actions.Count,
            plan.Actions.Count > MaxActions,
            actions,
            "READ-ONLY PLAN. No recovery action was executed. Ready actions remain copy-out-only in the existing executor; live overwrite, rename and delete are not authorized by this administration foundation.");
    }

    public static bool IsProductionSessionId(string? value) =>
        value is not null &&
        value.StartsWith(ProductionPrefix, StringComparison.Ordinal) &&
        value.Length <= 80 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    internal static void ValidateProductionSessionId(string sessionId)
    {
        if (!IsProductionSessionId(sessionId))
            throw new ArgumentException("A canonical production rollback session id is required.", nameof(sessionId));
    }

    private static ProductionRecoverySessionSummary BuildSessionSummary(
        RollbackRepository repository,
        string sessionId)
    {
        var session = repository.OpenSession(sessionId);
        var lifecycle = new RollbackSessionLifecycleStore(session.Root);
        lifecycle.VerifyAll();
        var snapshot = lifecycle.Snapshot;
        var canPlan = snapshot.State is RollbackSessionLifecycleState.Completed or RollbackSessionLifecycleState.Faulted;
        var note = snapshot.State switch
        {
            RollbackSessionLifecycleState.Completed =>
                "Completed production evidence is eligible for deterministic recovery planning.",
            RollbackSessionLifecycleState.Faulted =>
                "Faulted production evidence may be planned for operator review; no action executes automatically.",
            RollbackSessionLifecycleState.Active =>
                "Active production evidence must be resumed/resolved before recovery planning.",
            _ =>
                "Legacy/unmanaged production evidence is not eligible for automatic planning."
        };

        return new ProductionRecoverySessionSummary(
            sessionId,
            snapshot.State.ToString(),
            snapshot.IsHeld,
            snapshot.CreatedUtc,
            snapshot.CompletedUtc,
            snapshot.FaultedUtc,
            snapshot.LastRecordSha256,
            canPlan,
            note);
    }

    internal static string? ValidateStateAndGetRollbackRoot(bool allowMissing)
    {
        var state = StateStoreAdministration.Inspect();
        if (!state.Exists)
        {
            if (allowMissing) return null;
            throw new DirectoryNotFoundException("RansomGuard private state store does not exist.");
        }

        if (!state.PrivateAcl || state.LegacyUntrusted)
            throw new UnauthorizedAccessException("Recovery planning requires the current trusted private RansomGuard state store.");

        var rollbackRoot = Path.Combine(StateStoreAdministration.Root, "Rollback");
        if (!Directory.Exists(rollbackRoot))
        {
            if (allowMissing) return null;
            throw new DirectoryNotFoundException("Rollback repository does not exist.");
        }

        FileSafety.NoReparse(rollbackRoot);
        var sessionsRoot = Path.Combine(rollbackRoot, "Sessions");
        if (!Directory.Exists(sessionsRoot))
        {
            if (File.Exists(sessionsRoot))
                throw new IOException("Rollback Sessions path is not a directory.");
            if (allowMissing) return null;
            throw new DirectoryNotFoundException("Rollback Sessions directory does not exist; read-only recovery planning will not create it.");
        }

        FileSafety.NoReparse(sessionsRoot);
        return rollbackRoot;
    }

    internal static void EnsureIdle()
    {
        var status = ServiceAdministration.Query();
        if (!status.QuerySucceeded)
            throw new IOException("RecoveryBusy: cannot confirm RansomGuard service state. " + status.Error);
        if (status.Installed && !string.Equals(status.State, "Stopped", StringComparison.Ordinal))
            throw new IOException("RecoveryBusy: stop the RansomGuard service before recovery planning.");

        var processes = Process.GetProcessesByName("RansomGuard.Service");
        try
        {
            if (processes.Length != 0)
                throw new IOException("RecoveryBusy: stop RansomGuard service/audit engine processes before recovery planning.");
        }
        finally
        {
            foreach (var process in processes) process.Dispose();
        }
    }
}
