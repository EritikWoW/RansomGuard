using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

public static class RollbackRetentionPlanner
{
    public const int Schema = 1;
    public static RollbackRetentionPolicy DefaultPolicy { get; } = new(
        MaxCompletedAge: TimeSpan.FromDays(30),
        MaxCompletedBytes: 32L * 1024 * 1024 * 1024,
        MinPressureAge: TimeSpan.FromHours(24));

    public static RollbackRetentionPlan Build(
        string repositoryRoot,
        RollbackRetentionPolicy? policy = null,
        DateTime? nowUtc = null)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));

        var effectivePolicy = policy ?? DefaultPolicy;
        ValidatePolicy(effectivePolicy);

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        var repository = new RollbackRepository(repositoryFull);
        repository.VerifyAll();

        var retention = new RollbackRetentionStore(repositoryFull, createIfMissing: false);
        retention.VerifyAll();

        var now = (nowUtc ?? DateTime.UtcNow).ToUniversalTime();
        var sessionsRoot = Path.Combine(repositoryFull, "Sessions");
        var retiredRoot = Path.Combine(repositoryFull, "Retired");
        var actions = new List<RollbackRetentionAction>();
        var issues = new List<RollbackRetentionIssue>();
        var inventory = new List<RetentionInventoryItem>();
        var managedCompleted = new List<RetentionCompletedCandidate>();
        var protectedCount = 0;
        var heldCount = 0;
        var legacyCount = 0;

        var latestRetention = retention.Records
            .GroupBy(x => x.SessionId, StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.OrderBy(y => y.Sequence).Last(), StringComparer.Ordinal);

        foreach (var pair in latestRetention.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (pair.Value.EventType == RollbackRetentionEventType.PurgeCompleted)
                continue;

            var sessionId = pair.Key;
            var sessionPath = Path.Combine(sessionsRoot, sessionId);
            var retiredPath = Path.Combine(retiredRoot, sessionId);
            var sessionExists = Directory.Exists(sessionPath);
            var retiredExists = Directory.Exists(retiredPath);

            if (sessionExists && retiredExists)
            {
                issues.Add(new RollbackRetentionIssue(
                    sessionId, "Both Sessions and Retired copies exist for an incomplete purge."));
                continue;
            }

            if (sessionExists)
            {
                var digest = ComputeSessionDigest(sessionPath);
                if (!digest.Equals(pair.Value.SessionEvidenceSha256, StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new RollbackRetentionIssue(
                        sessionId, "Incomplete purge source no longer matches its recorded evidence digest."));
                    continue;
                }

                actions.Add(new RollbackRetentionAction(
                    actions.Count + 1,
                    RollbackRetentionActionKind.ResumePurgeFromSessions,
                    sessionId,
                    sessionPath,
                    pair.Value.SessionBytes,
                    pair.Value.SessionEvidenceSha256,
                    null,
                    "resume-incomplete-purge",
                    pair.Value.PlanId));
                continue;
            }

            if (retiredExists)
            {
                if (pair.Value.EventType == RollbackRetentionEventType.PurgeStarted)
                {
                    var digest = ComputeSessionDigest(retiredPath);
                    if (!digest.Equals(pair.Value.SessionEvidenceSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add(new RollbackRetentionIssue(
                            sessionId, "Moved purge source changed before Quarantined receipt was committed."));
                        continue;
                    }
                }
                else
                {
                    ValidateTreeHasNoReparse(retiredPath);
                }

                actions.Add(new RollbackRetentionAction(
                    actions.Count + 1,
                    RollbackRetentionActionKind.ResumePurgeFromRetired,
                    sessionId,
                    retiredPath,
                    pair.Value.SessionBytes,
                    pair.Value.SessionEvidenceSha256,
                    null,
                    "resume-incomplete-purge",
                    pair.Value.PlanId));
                continue;
            }

            if (pair.Value.EventType == RollbackRetentionEventType.Quarantined)
            {
                actions.Add(new RollbackRetentionAction(
                    actions.Count + 1,
                    RollbackRetentionActionKind.FinalizeMissingQuarantine,
                    sessionId,
                    string.Empty,
                    pair.Value.SessionBytes,
                    pair.Value.SessionEvidenceSha256,
                    null,
                    "finalize-purge-receipt-after-delete",
                    pair.Value.PlanId));
            }
            else
            {
                issues.Add(new RollbackRetentionIssue(
                    sessionId, "PurgeStarted exists but neither Sessions nor Retired copy is present."));
            }
        }

        var incompleteIds = latestRetention
            .Where(x => x.Value.EventType != RollbackRetentionEventType.PurgeCompleted)
            .Select(x => x.Key)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var sessionId in repository.SessionIds())
        {
            if (incompleteIds.Contains(sessionId))
                continue;

            var store = repository.OpenSession(sessionId);
            var lifecycleRoot = Path.Combine(store.Root, "lifecycle-state");
            if (!Directory.Exists(lifecycleRoot))
            {
                legacyCount++;
                protectedCount++;
                inventory.Add(new RetentionInventoryItem(
                    sessionId, RollbackSessionLifecycleState.LegacyUnmanaged,
                    false, null, 0, string.Empty, string.Empty));
                continue;
            }

            var lifecycle = new RollbackSessionLifecycleStore(store.Root);
            lifecycle.VerifyAll();
            var snapshot = lifecycle.Snapshot;

            if (snapshot.IsHeld) heldCount++;

            if (snapshot.State != RollbackSessionLifecycleState.Completed || snapshot.IsHeld)
            {
                protectedCount++;
                inventory.Add(new RetentionInventoryItem(
                    sessionId, snapshot.State, snapshot.IsHeld, snapshot.CompletedUtc,
                    0, string.Empty, snapshot.LastRecordSha256));
                continue;
            }

            if (HasPendingTransactions(store.Root))
            {
                protectedCount++;
                issues.Add(new RollbackRetentionIssue(
                    sessionId, "Completed lifecycle has pending CREATE/RENAME transaction evidence; protected from retention."));
                inventory.Add(new RetentionInventoryItem(
                    sessionId, snapshot.State, false, snapshot.CompletedUtc,
                    0, string.Empty, snapshot.LastRecordSha256));
                continue;
            }

            var sessionBytes = MeasureTreeBytes(store.Root);
            var digest = ComputeSessionDigest(store.Root);
            var completedUtc = snapshot.CompletedUtc
                ?? throw new InvalidDataException("Completed lifecycle is missing CompletedUtc.");

            managedCompleted.Add(new RetentionCompletedCandidate(
                sessionId, store.Root, completedUtc, sessionBytes,
                digest, snapshot.LastRecordSha256));
            inventory.Add(new RetentionInventoryItem(
                sessionId, snapshot.State, false, completedUtc,
                sessionBytes, digest, snapshot.LastRecordSha256));
        }

        var selected = new Dictionary<string, (RollbackRetentionPurgeReason Reason, RetentionCompletedCandidate Candidate)>(
            StringComparer.Ordinal);

        foreach (var candidate in managedCompleted
                     .Where(x => now - x.CompletedUtc >= effectivePolicy.MaxCompletedAge)
                     .OrderBy(x => x.CompletedUtc)
                     .ThenBy(x => x.SessionId, StringComparer.Ordinal))
        {
            selected[candidate.SessionId] = (RollbackRetentionPurgeReason.AgeExpired, candidate);
        }

        var totalCompletedBytes = managedCompleted.Sum(x => x.SessionBytes);
        var plannedReclaimBytes = selected.Values.Sum(x => x.Candidate.SessionBytes);
        var remainingBytes = totalCompletedBytes - plannedReclaimBytes;

        if (remainingBytes > effectivePolicy.MaxCompletedBytes)
        {
            foreach (var candidate in managedCompleted
                         .Where(x => !selected.ContainsKey(x.SessionId) &&
                                     now - x.CompletedUtc >= effectivePolicy.MinPressureAge)
                         .OrderBy(x => x.CompletedUtc)
                         .ThenBy(x => x.SessionId, StringComparer.Ordinal))
            {
                if (remainingBytes <= effectivePolicy.MaxCompletedBytes)
                    break;

                selected[candidate.SessionId] = (RollbackRetentionPurgeReason.CapacityPressure, candidate);
                plannedReclaimBytes = checked(plannedReclaimBytes + candidate.SessionBytes);
                remainingBytes -= candidate.SessionBytes;
            }
        }

        foreach (var item in selected.Values
                     .OrderBy(x => x.Candidate.CompletedUtc)
                     .ThenBy(x => x.Candidate.SessionId, StringComparer.Ordinal))
        {
            actions.Add(new RollbackRetentionAction(
                actions.Count + 1,
                RollbackRetentionActionKind.PurgeCompletedSession,
                item.Candidate.SessionId,
                item.Candidate.SessionRoot,
                item.Candidate.SessionBytes,
                item.Candidate.SessionEvidenceSha256,
                item.Candidate.CompletedUtc,
                item.Reason == RollbackRetentionPurgeReason.AgeExpired
                    ? "completed-session-age-expired"
                    : "completed-storage-capacity-pressure",
                string.Empty));
        }

        var unresolvedExcessBytes = Math.Max(
            0,
            totalCompletedBytes - plannedReclaimBytes - effectivePolicy.MaxCompletedBytes);

        var inventorySha = ComputeInventoryDigest(inventory, retention.Records);
        var provisional = actions.ToArray();
        var planId = ComputePlanId(effectivePolicy, inventorySha, provisional, issues);

        return new RollbackRetentionPlan(
            Schema,
            planId,
            repositoryFull,
            now,
            effectivePolicy,
            inventorySha,
            totalCompletedBytes,
            plannedReclaimBytes,
            unresolvedExcessBytes,
            managedCompleted.Count,
            protectedCount,
            heldCount,
            legacyCount,
            provisional,
            issues.ToArray());
    }

    public static long MeasureTreeBytes(string root)
    {
        long total = 0;
        foreach (var file in EnumerateFilesSafe(root))
            total = checked(total + new FileInfo(file).Length);
        return total;
    }

    public static string ComputeSessionDigest(string root)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in EnumerateFilesSafe(root)
                     .OrderBy(x => Path.GetRelativePath(root, x), StringComparer.OrdinalIgnoreCase))
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            var fileHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
            aggregate.AppendData(Encoding.UTF8.GetBytes(relative + "\0" + fileHash + "\n"));
        }
        return Convert.ToHexString(aggregate.GetHashAndReset());
    }

    private static bool HasPendingTransactions(string sessionRoot)
    {
        var createRoot = Path.Combine(sessionRoot, "create-state");
        if (Directory.Exists(createRoot) &&
            new CreateOperationStore(createRoot).PendingIntents.Count != 0)
            return true;

        var renameRoot = Path.Combine(sessionRoot, "rename-state");
        if (Directory.Exists(renameRoot) &&
            new RenameRollbackStore(renameRoot).PendingIntents.Count != 0)
            return true;

        return false;
    }

    public static void ValidateTreeHasNoReparse(string root)
    {
        _ = EnumerateFilesSafe(root).Count();
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException(full);

        var pending = new Stack<string>();
        pending.Push(full);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            RejectReparse(directory);

            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(file);
                yield return file;
            }

            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(child);
                pending.Push(child);
            }
        }
    }

    private static string ComputeInventoryDigest(
        IReadOnlyList<RetentionInventoryItem> inventory,
        IReadOnlyList<RollbackRetentionRecord> retentionRecords)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            sessions = inventory.OrderBy(x => x.SessionId, StringComparer.Ordinal),
            retention = retentionRecords.OrderBy(x => x.Sequence).Select(x => new
            {
                x.Sequence,
                x.EventType,
                x.PlanId,
                x.SessionId,
                x.SessionEvidenceSha256,
                x.SessionBytes,
                x.RecordSha256
            })
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string ComputePlanId(
        RollbackRetentionPolicy policy,
        string inventorySha,
        IReadOnlyList<RollbackRetentionAction> actions,
        IReadOnlyList<RollbackRetentionIssue> issues)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            schema = Schema,
            policy,
            inventorySha,
            actions = actions.Select(x => new
            {
                x.Index,
                x.Kind,
                x.SessionId,
                x.SessionBytes,
                x.SessionEvidenceSha256,
                x.CompletedUtc,
                x.Reason,
                x.RetentionChainPlanId
            }),
            issues = issues.OrderBy(x => x.SessionId, StringComparer.Ordinal)
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static void ValidatePolicy(RollbackRetentionPolicy policy)
    {
        if (policy.MaxCompletedAge <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(policy.MaxCompletedAge));
        if (policy.MinPressureAge < TimeSpan.Zero ||
            policy.MinPressureAge > policy.MaxCompletedAge)
            throw new ArgumentOutOfRangeException(nameof(policy.MinPressureAge));
        if (policy.MaxCompletedBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(policy.MaxCompletedBytes));
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback retention refuses reparse-point paths: " + path);
    }

    private sealed record RetentionCompletedCandidate(
        string SessionId,
        string SessionRoot,
        DateTime CompletedUtc,
        long SessionBytes,
        string SessionEvidenceSha256,
        string LifecycleRecordSha256);

    private sealed record RetentionInventoryItem(
        string SessionId,
        RollbackSessionLifecycleState State,
        bool IsHeld,
        DateTime? CompletedUtc,
        long SessionBytes,
        string SessionEvidenceSha256,
        string LifecycleRecordSha256);
}

public sealed record RollbackRetentionPolicy(
    TimeSpan MaxCompletedAge,
    long MaxCompletedBytes,
    TimeSpan MinPressureAge);

public enum RollbackRetentionPurgeReason
{
    AgeExpired = 1,
    CapacityPressure = 2
}

public enum RollbackRetentionActionKind
{
    PurgeCompletedSession = 1,
    ResumePurgeFromSessions = 2,
    ResumePurgeFromRetired = 3,
    FinalizeMissingQuarantine = 4
}

public sealed record RollbackRetentionAction(
    int Index,
    RollbackRetentionActionKind Kind,
    string SessionId,
    string SourcePath,
    long SessionBytes,
    string SessionEvidenceSha256,
    DateTime? CompletedUtc,
    string Reason,
    string RetentionChainPlanId);

public sealed record RollbackRetentionIssue(
    string SessionId,
    string Reason);

public sealed record RollbackRetentionPlan(
    int Schema,
    string PlanId,
    string RepositoryRoot,
    DateTime PlannedUtc,
    RollbackRetentionPolicy Policy,
    string InventorySha256,
    long TotalManagedCompletedBytes,
    long PlannedReclaimBytes,
    long UnresolvedExcessBytes,
    int ManagedCompletedSessions,
    int ProtectedSessions,
    int HeldSessions,
    int LegacySessions,
    IReadOnlyList<RollbackRetentionAction> Actions,
    IReadOnlyList<RollbackRetentionIssue> Issues);
