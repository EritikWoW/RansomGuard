using System.Text.Json;

namespace RansomGuard.Rollback;

public static class RollbackRetentionExecutor
{
    public static async Task<RollbackRetentionExecutionReport> ExecuteAsync(
        string repositoryRoot,
        RollbackRetentionPlan requestedPlan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestedPlan);
        var repositoryFull = Path.GetFullPath(repositoryRoot);

        var current = RollbackRetentionPlanner.Build(
            repositoryFull,
            requestedPlan.Policy,
            DateTime.UtcNow);

        ValidateRequestedPlan(requestedPlan, current, repositoryFull);

        var repository = new RollbackRepository(repositoryFull);
        repository.VerifyAll();

        var sessionsRoot = Path.Combine(repositoryFull, "Sessions");
        var retiredRoot = Path.Combine(repositoryFull, "Retired");
        Directory.CreateDirectory(retiredRoot);
        RejectReparse(retiredRoot);

        var retention = new RollbackRetentionStore(repositoryFull);
        retention.VerifyAll();

        var startedUtc = DateTime.UtcNow;
        var results = new List<RollbackRetentionExecutionItem>();

        foreach (var action in current.Actions.OrderBy(x => x.Index))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                switch (action.Kind)
                {
                    case RollbackRetentionActionKind.PurgeCompletedSession:
                        await ExecuteNewPurgeAsync(
                            action,
                            current.PlanId,
                            sessionsRoot,
                            retiredRoot,
                            retention,
                            cancellationToken).ConfigureAwait(false);
                        break;

                    case RollbackRetentionActionKind.ResumePurgeFromSessions:
                        await ResumeFromSessionsAsync(
                            action,
                            sessionsRoot,
                            retiredRoot,
                            retention,
                            cancellationToken).ConfigureAwait(false);
                        break;

                    case RollbackRetentionActionKind.ResumePurgeFromRetired:
                        await ResumeFromRetiredAsync(
                            action,
                            retiredRoot,
                            retention,
                            cancellationToken).ConfigureAwait(false);
                        break;

                    case RollbackRetentionActionKind.FinalizeMissingQuarantine:
                        await FinalizeMissingQuarantineAsync(
                            action,
                            retention,
                            cancellationToken).ConfigureAwait(false);
                        break;

                    default:
                        throw new InvalidDataException(
                            $"Unsupported retention action kind: {action.Kind}.");
                }

                results.Add(new RollbackRetentionExecutionItem(
                    action.Index,
                    action.Kind,
                    action.SessionId,
                    RollbackRetentionExecutionState.Succeeded,
                    action.SessionBytes,
                    action.Reason,
                    string.Empty));
            }
            catch (Exception ex) when (
                ex is IOException or InvalidDataException or UnauthorizedAccessException
                    or InvalidOperationException or ArgumentException)
            {
                results.Add(new RollbackRetentionExecutionItem(
                    action.Index,
                    action.Kind,
                    action.SessionId,
                    RollbackRetentionExecutionState.Failed,
                    0,
                    action.Reason,
                    ex.Message));

                return new RollbackRetentionExecutionReport(
                    Schema: 1,
                    PlanId: current.PlanId,
                    RepositoryRoot: repositoryFull,
                    StartedUtc: startedUtc,
                    CompletedUtc: DateTime.UtcNow,
                    RequestedActions: current.Actions.Count,
                    SucceededActions: results.Count(x =>
                        x.State == RollbackRetentionExecutionState.Succeeded),
                    FailedActions: 1,
                    ReclaimedBytes: results
                        .Where(x => x.State == RollbackRetentionExecutionState.Succeeded)
                        .Sum(x => x.ReclaimedBytes),
                    Succeeded: false,
                    Items: results);
            }
        }

        return new RollbackRetentionExecutionReport(
            Schema: 1,
            PlanId: current.PlanId,
            RepositoryRoot: repositoryFull,
            StartedUtc: startedUtc,
            CompletedUtc: DateTime.UtcNow,
            RequestedActions: current.Actions.Count,
            SucceededActions: results.Count,
            FailedActions: 0,
            ReclaimedBytes: results.Sum(x => x.ReclaimedBytes),
            Succeeded: true,
            Items: results);
    }

    private static async Task ExecuteNewPurgeAsync(
        RollbackRetentionAction action,
        string currentPlanId,
        string sessionsRoot,
        string retiredRoot,
        RollbackRetentionStore retention,
        CancellationToken cancellationToken)
    {
        var source = Path.Combine(sessionsRoot, action.SessionId);
        if (!Directory.Exists(source))
            throw new DirectoryNotFoundException(
                "Retention source session disappeared before purge: " + source);

        VerifySessionDigest(source, action.SessionEvidenceSha256);
        VerifyCompletedAndUnheld(source);

        var destination = Path.Combine(retiredRoot, action.SessionId);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Retention quarantine destination already exists: " + destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.PurgeStarted,
            currentPlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);

        Directory.Move(source, destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.Quarantined,
            currentPlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);

        SafeDeleteTree(destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.PurgeCompleted,
            currentPlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task ResumeFromSessionsAsync(
        RollbackRetentionAction action,
        string sessionsRoot,
        string retiredRoot,
        RollbackRetentionStore retention,
        CancellationToken cancellationToken)
    {
        var source = Path.Combine(sessionsRoot, action.SessionId);
        var destination = Path.Combine(retiredRoot, action.SessionId);

        if (!Directory.Exists(source))
            throw new DirectoryNotFoundException(
                "Incomplete retention purge no longer has its Sessions source: " + source);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException(
                "Incomplete retention purge has conflicting Retired destination: " + destination);

        VerifySessionDigest(source, action.SessionEvidenceSha256);

        var latest = RequireLatest(retention, action.SessionId);
        if (latest.EventType != RollbackRetentionEventType.PurgeStarted)
            throw new InvalidDataException(
                "Resume-from-Sessions requires latest retention event PurgeStarted.");

        Directory.Move(source, destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.Quarantined,
            latest.PlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);

        SafeDeleteTree(destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.PurgeCompleted,
            latest.PlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task ResumeFromRetiredAsync(
        RollbackRetentionAction action,
        string retiredRoot,
        RollbackRetentionStore retention,
        CancellationToken cancellationToken)
    {
        var destination = Path.Combine(retiredRoot, action.SessionId);
        if (!Directory.Exists(destination))
            throw new DirectoryNotFoundException(
                "Incomplete retention purge no longer has its Retired source: " + destination);

        var latest = RequireLatest(retention, action.SessionId);
        if (latest.EventType == RollbackRetentionEventType.PurgeStarted)
        {
            VerifySessionDigest(destination, action.SessionEvidenceSha256);
            _ = await retention.RecordAsync(
                RollbackRetentionEventType.Quarantined,
                latest.PlanId,
                action.SessionId,
                action.SessionEvidenceSha256,
                action.SessionBytes,
                action.Reason,
                cancellationToken).ConfigureAwait(false);

            latest = RequireLatest(retention, action.SessionId);
        }

        if (latest.EventType != RollbackRetentionEventType.Quarantined)
            throw new InvalidDataException(
                "Resume-from-Retired requires latest retention event PurgeStarted or Quarantined.");

        RollbackRetentionPlanner.ValidateTreeHasNoReparse(destination);
        SafeDeleteTree(destination);

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.PurgeCompleted,
            latest.PlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task FinalizeMissingQuarantineAsync(
        RollbackRetentionAction action,
        RollbackRetentionStore retention,
        CancellationToken cancellationToken)
    {
        var latest = RequireLatest(retention, action.SessionId);
        if (latest.EventType != RollbackRetentionEventType.Quarantined)
            throw new InvalidDataException(
                "Finalize-missing-quarantine requires latest retention event Quarantined.");

        _ = await retention.RecordAsync(
            RollbackRetentionEventType.PurgeCompleted,
            latest.PlanId,
            action.SessionId,
            action.SessionEvidenceSha256,
            action.SessionBytes,
            action.Reason,
            cancellationToken).ConfigureAwait(false);
    }

    private static RollbackRetentionRecord RequireLatest(
        RollbackRetentionStore retention,
        string sessionId) =>
        retention.LatestForSession(sessionId)
        ?? throw new InvalidDataException(
            "Retention journal has no record for incomplete purge session: " + sessionId);

    private static void VerifyCompletedAndUnheld(string sessionRoot)
    {
        var lifecycle = new RollbackSessionLifecycleStore(sessionRoot);
        lifecycle.VerifyAll();
        var snapshot = lifecycle.Snapshot;

        if (snapshot.State != RollbackSessionLifecycleState.Completed)
            throw new InvalidDataException(
                "Retention purge requires lifecycle state Completed.");
        if (snapshot.IsHeld)
            throw new InvalidDataException(
                "Retention purge refuses a session that is on Hold.");

        var createRoot = Path.Combine(sessionRoot, "create-state");
        if (Directory.Exists(createRoot) &&
            new CreateOperationStore(createRoot).PendingIntents.Count != 0)
            throw new InvalidDataException(
                "Retention purge refuses pending CREATE transactions.");

        var renameRoot = Path.Combine(sessionRoot, "rename-state");
        if (Directory.Exists(renameRoot) &&
            new RenameRollbackStore(renameRoot).PendingIntents.Count != 0)
            throw new InvalidDataException(
                "Retention purge refuses pending RENAME transactions.");
    }

    private static void VerifySessionDigest(string root, string expectedSha256)
    {
        var actual = RollbackRetentionPlanner.ComputeSessionDigest(root);
        if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Retention session evidence changed after plan creation.");
    }

    private static void ValidateRequestedPlan(
        RollbackRetentionPlan requested,
        RollbackRetentionPlan current,
        string repositoryRoot)
    {
        if (requested.Schema != RollbackRetentionPlanner.Schema)
            throw new InvalidDataException("Unsupported retention plan schema.");
        if (!Path.GetFullPath(requested.RepositoryRoot)
                .Equals(repositoryRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Retention plan belongs to a different rollback repository.");
        if (requested.Policy != current.Policy)
            throw new InvalidDataException("Retention policy changed after plan creation.");
        if (!requested.InventorySha256.Equals(
                current.InventorySha256, StringComparison.OrdinalIgnoreCase) ||
            !requested.PlanId.Equals(current.PlanId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Retention plan is stale or does not match the current rollback inventory.");
    }

    private static void SafeDeleteTree(string root)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full))
            return;

        RollbackRetentionPlanner.ValidateTreeHasNoReparse(full);

        var directories = Directory.EnumerateDirectories(full, "*", SearchOption.AllDirectories)
            .OrderByDescending(x => x.Length)
            .ToArray();

        foreach (var file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories))
        {
            RejectReparse(file);
            File.SetAttributes(file, FileAttributes.Normal);
            File.Delete(file);
        }

        foreach (var directory in directories)
        {
            RejectReparse(directory);
            Directory.Delete(directory, recursive: false);
        }

        RejectReparse(full);
        Directory.Delete(full, recursive: false);
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException(
                "Retention cleanup refuses reparse-point paths: " + path);
    }
}

public enum RollbackRetentionExecutionState
{
    Succeeded = 1,
    Failed = 2
}

public sealed record RollbackRetentionExecutionItem(
    int ActionIndex,
    RollbackRetentionActionKind Kind,
    string SessionId,
    RollbackRetentionExecutionState State,
    long ReclaimedBytes,
    string Reason,
    string Error);

public sealed record RollbackRetentionExecutionReport(
    int Schema,
    string PlanId,
    string RepositoryRoot,
    DateTime StartedUtc,
    DateTime CompletedUtc,
    int RequestedActions,
    int SucceededActions,
    int FailedActions,
    long ReclaimedBytes,
    bool Succeeded,
    IReadOnlyList<RollbackRetentionExecutionItem> Items);
