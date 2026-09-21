using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Builds a deterministic, non-destructive retention plan from validated rollback/recovery evidence.
/// A session is purge-eligible only after clean close and an explicit release bound to the current RecoveryPlanId.
/// </summary>
public static class RollbackRetentionPlanner
{
    public const int Schema = 1;

    public static RollbackRetentionPlan Build(
        string repositoryRoot,
        int minimumAgeHours = 168,
        DateTime? nowUtc = null)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));
        if (minimumAgeHours < 0 || minimumAgeHours > 24 * 3650)
            throw new ArgumentOutOfRangeException(nameof(minimumAgeHours));

        var repository = new RollbackRepository(repositoryRoot);
        repository.VerifyAll();

        var releases = new RollbackRetentionReleaseStore(repository.Root);
        releases.VerifyAll();

        var now = (nowUtc ?? DateTime.UtcNow).ToUniversalTime();
        var minimumAge = TimeSpan.FromHours(minimumAgeHours);
        var items = new List<RollbackRetentionItem>();

        foreach (var sessionId in repository.SessionIds())
        {
            var session = repository.OpenSession(sessionId);
            var sessionRoot = session.Root;
            var sizeBytes = MeasureSessionBytes(sessionRoot);

            var lifecyclePath = Path.Combine(sessionRoot, "session-lifecycle.jsonl");
            RollbackSessionLifecycleStore? lifecycle = null;
            if (File.Exists(lifecyclePath))
            {
                lifecycle = new RollbackSessionLifecycleStore(sessionRoot);
                lifecycle.VerifyAll();
            }

            var pendingCreate = 0;
            var createRoot = Path.Combine(sessionRoot, "create-state");
            if (Directory.Exists(createRoot))
            {
                var createOperations = new CreateOperationStore(createRoot);
                createOperations.VerifyAll();
                pendingCreate = createOperations.PendingIntents.Count;
            }

            var pendingRename = 0;
            var renameRoot = Path.Combine(sessionRoot, "rename-state");
            if (Directory.Exists(renameRoot))
            {
                var renames = new RenameRollbackStore(renameRoot);
                renames.VerifyAll();
                pendingRename = renames.PendingIntents.Count;
            }

            RollbackRecoveryPlan? recoveryPlan = null;
            if (lifecycle is not null && lifecycle.IsClosedCleanly)
                recoveryPlan = RollbackRecoveryPlanner.Build(repository.Root, sessionId);

            releases.TryGetLatestRelease(sessionId, out var release);

            var decision = Decide(
                lifecycle,
                pendingCreate,
                pendingRename,
                recoveryPlan,
                release,
                minimumAge,
                now,
                out var reason);

            var closedUtc = lifecycle?.ClosedUtc;
            var ageHours = closedUtc is null
                ? (double?)null
                : Math.Max(0, (now - closedUtc.Value.ToUniversalTime()).TotalHours);

            items.Add(new RollbackRetentionItem(
                sessionId,
                sessionRoot,
                sizeBytes,
                lifecycle is null
                    ? RollbackRetentionLifecycle.LegacyUnmarked
                    : lifecycle.IsClosedCleanly
                        ? RollbackRetentionLifecycle.ClosedCleanly
                        : RollbackRetentionLifecycle.OpenOrUnclean,
                lifecycle?.OpenedUtc,
                closedUtc,
                ageHours,
                pendingCreate,
                pendingRename,
                recoveryPlan?.PlanId ?? string.Empty,
                recoveryPlan?.BlockedCount ?? 0,
                recoveryPlan?.ReadyCount ?? 0,
                recoveryPlan?.ReviewCount ?? 0,
                release?.RecoveryPlanId ?? string.Empty,
                release?.RecordSha256 ?? string.Empty,
                decision,
                reason));
        }

        var ordered = items.OrderBy(x => x.SessionId, StringComparer.Ordinal).ToArray();
        var planId = ComputePlanId(repository.Root, minimumAgeHours, ordered);

        return new RollbackRetentionPlan(
            Schema,
            planId,
            repository.Root,
            minimumAgeHours,
            now,
            ordered.Sum(x => x.SizeBytes),
            ordered.Where(x => x.Decision == RollbackRetentionDecision.Eligible).Sum(x => x.SizeBytes),
            ordered);
    }

    public static async Task<RollbackRetentionReleaseRecord> ReleaseAsync(
        string repositoryRoot,
        string sessionId,
        string expectedRecoveryPlanId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(expectedRecoveryPlanId) ||
            expectedRecoveryPlanId.Length != 64 ||
            !expectedRecoveryPlanId.All(char.IsAsciiHexDigit))
            throw new ArgumentException("Expected recovery plan id must be SHA-256.", nameof(expectedRecoveryPlanId));

        var repository = new RollbackRepository(repositoryRoot);
        repository.VerifyAll();
        var session = repository.OpenSession(sessionId);

        var lifecyclePath = Path.Combine(session.Root, "session-lifecycle.jsonl");
        if (!File.Exists(lifecyclePath))
            throw new InvalidDataException("Legacy/unmarked rollback session cannot be released for retention purge.");

        var lifecycle = new RollbackSessionLifecycleStore(session.Root);
        lifecycle.VerifyAll();
        if (!lifecycle.IsClosedCleanly)
            throw new InvalidDataException("Rollback session is not closed cleanly.");

        var createRoot = Path.Combine(session.Root, "create-state");
        if (Directory.Exists(createRoot))
        {
            var createOperations = new CreateOperationStore(createRoot);
            createOperations.VerifyAll();
            if (createOperations.PendingIntents.Count != 0)
                throw new InvalidDataException("Rollback session still has pending CREATE transactions.");
        }

        var renameRoot = Path.Combine(session.Root, "rename-state");
        if (Directory.Exists(renameRoot))
        {
            var renames = new RenameRollbackStore(renameRoot);
            renames.VerifyAll();
            if (renames.PendingIntents.Count != 0)
                throw new InvalidDataException("Rollback session still has pending RENAME transactions.");
        }

        var recoveryPlan = RollbackRecoveryPlanner.Build(repository.Root, sessionId);
        if (recoveryPlan.BlockedCount != 0)
            throw new InvalidDataException("Rollback session recovery plan still contains blocked actions.");
        if (!recoveryPlan.PlanId.Equals(expectedRecoveryPlanId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Recovery plan changed; retention release requires the current RecoveryPlanId.");

        var releases = new RollbackRetentionReleaseStore(repository.Root);
        releases.VerifyAll();
        return await releases.RecordReleaseAsync(
            sessionId,
            recoveryPlan.PlanId,
            cancellationToken).ConfigureAwait(false);
    }

    private static RollbackRetentionDecision Decide(
        RollbackSessionLifecycleStore? lifecycle,
        int pendingCreate,
        int pendingRename,
        RollbackRecoveryPlan? recoveryPlan,
        RollbackRetentionReleaseRecord? release,
        TimeSpan minimumAge,
        DateTime nowUtc,
        out string reason)
    {
        if (lifecycle is null)
        {
            reason = "Session predates durable lifecycle evidence and is never automatically purgeable.";
            return RollbackRetentionDecision.LegacyUnmarked;
        }

        if (!lifecycle.IsClosedCleanly || lifecycle.ClosedUtc is null)
        {
            reason = "Session has no durable ClosedCleanly terminal record.";
            return RollbackRetentionDecision.NotClosedCleanly;
        }

        if (pendingCreate != 0 || pendingRename != 0)
        {
            reason = "Session still contains pending CREATE/RENAME transactions.";
            return RollbackRetentionDecision.PendingTransactions;
        }

        if (recoveryPlan is null || recoveryPlan.BlockedCount != 0)
        {
            reason = "Current recovery plan contains blocked or unresolved actions.";
            return RollbackRetentionDecision.RecoveryBlocked;
        }

        if (release is null)
        {
            reason = "Current recovery plan has not been explicitly released for retention purge.";
            return RollbackRetentionDecision.NotReleased;
        }

        if (!release.RecoveryPlanId.Equals(recoveryPlan.PlanId, StringComparison.OrdinalIgnoreCase))
        {
            reason = "Retention release references an older RecoveryPlanId.";
            return RollbackRetentionDecision.ReleaseStale;
        }

        var age = nowUtc - lifecycle.ClosedUtc.Value.ToUniversalTime();
        if (age < minimumAge)
        {
            reason = $"Session is younger than the configured minimum age of {minimumAge.TotalHours:F0} hours.";
            return RollbackRetentionDecision.TooYoung;
        }

        reason = "Cleanly closed session has no pending/blocked recovery state and its current RecoveryPlanId was explicitly released.";
        return RollbackRetentionDecision.Eligible;
    }

    private static string ComputePlanId(
        string repositoryRoot,
        int minimumAgeHours,
        IReadOnlyList<RollbackRetentionItem> items)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            schema = Schema,
            repositoryRoot = Path.GetFullPath(repositoryRoot),
            minimumAgeHours,
            sessions = items.Select(x => new
            {
                x.SessionId,
                x.SessionRoot,
                x.SizeBytes,
                x.Lifecycle,
                x.OpenedUtc,
                x.ClosedUtc,
                x.PendingCreateCount,
                x.PendingRenameCount,
                x.RecoveryPlanId,
                x.RecoveryBlockedCount,
                x.RecoveryReadyCount,
                x.RecoveryReviewCount,
                x.ReleaseRecoveryPlanId,
                x.ReleaseRecordSha256,
                x.Decision,
                x.Reason
            })
        });

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static long MeasureSessionBytes(string sessionRoot)
    {
        var root = Path.GetFullPath(sessionRoot);
        RejectReparse(root);

        long total = 0;
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count != 0)
        {
            var directory = pending.Pop();
            RejectReparse(directory);

            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(file);
                total = checked(total + new FileInfo(file).Length);
            }

            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(child);
                pending.Push(child);
            }
        }

        return total;
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback retention planner refuses reparse-point evidence: " + path);
    }
}

public enum RollbackRetentionLifecycle
{
    LegacyUnmarked = 1,
    OpenOrUnclean = 2,
    ClosedCleanly = 3
}

public enum RollbackRetentionDecision
{
    Eligible = 1,
    LegacyUnmarked = 2,
    NotClosedCleanly = 3,
    PendingTransactions = 4,
    RecoveryBlocked = 5,
    NotReleased = 6,
    ReleaseStale = 7,
    TooYoung = 8
}

public sealed record RollbackRetentionItem(
    string SessionId,
    string SessionRoot,
    long SizeBytes,
    RollbackRetentionLifecycle Lifecycle,
    DateTime? OpenedUtc,
    DateTime? ClosedUtc,
    double? AgeHours,
    int PendingCreateCount,
    int PendingRenameCount,
    string RecoveryPlanId,
    int RecoveryBlockedCount,
    int RecoveryReadyCount,
    int RecoveryReviewCount,
    string ReleaseRecoveryPlanId,
    string ReleaseRecordSha256,
    RollbackRetentionDecision Decision,
    string Reason);

public sealed record RollbackRetentionPlan(
    int Schema,
    string PlanId,
    string RepositoryRoot,
    int MinimumAgeHours,
    DateTime PlannedUtc,
    long TotalSessionBytes,
    long EligibleBytes,
    IReadOnlyList<RollbackRetentionItem> Sessions);
