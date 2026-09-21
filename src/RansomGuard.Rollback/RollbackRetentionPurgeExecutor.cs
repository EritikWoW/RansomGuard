namespace RansomGuard.Rollback;

/// <summary>
/// Explicit retention purge executor. It revalidates the full retention plan and only purges
/// a freshly Eligible session. Data is atomically quarantined inside the repository before deletion.
/// </summary>
public static class RollbackRetentionPurgeExecutor
{
    public static async Task<RollbackRetentionPurgeReport> PurgeSessionAsync(
        string repositoryRoot,
        RollbackRetentionPlan requestedPlan,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestedPlan);
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));
        if (string.IsNullOrWhiteSpace(sessionId))
            throw new ArgumentException("Rollback session id is required.", nameof(sessionId));

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        if (requestedPlan.Schema != RollbackRetentionPlanner.Schema)
            throw new InvalidDataException("Unsupported rollback retention plan schema.");
        if (!Path.GetFullPath(requestedPlan.RepositoryRoot)
                .Equals(repositoryFull, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Retention plan belongs to a different rollback repository.");

        var current = RollbackRetentionPlanner.Build(
            repositoryFull,
            requestedPlan.MinimumAgeHours);

        if (!requestedPlan.PlanId.Equals(current.PlanId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Retention plan is stale or does not match the currently validated rollback repository.");

        var item = current.Sessions.SingleOrDefault(x =>
            x.SessionId.Equals(sessionId, StringComparison.Ordinal))
            ?? throw new InvalidDataException("Requested session is not present in the current retention plan.");

        if (item.Decision != RollbackRetentionDecision.Eligible)
            throw new InvalidDataException(
                $"Requested session is not purge-eligible: {item.Decision}. {item.Reason}");

        if (string.IsNullOrWhiteSpace(item.RecoveryPlanId) ||
            string.IsNullOrWhiteSpace(item.ReleaseRecordSha256))
            throw new InvalidDataException("Eligible retention item is missing recovery/release evidence.");

        var expectedSessionRoot = Path.GetFullPath(
            Path.Combine(repositoryFull, "Sessions", sessionId));
        if (!Path.GetFullPath(item.SessionRoot)
                .Equals(expectedSessionRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Retention session root does not match the canonical repository path.");
        if (!Directory.Exists(expectedSessionRoot))
            throw new DirectoryNotFoundException("Retention session disappeared before purge.");

        VerifyTreeNoReparse(expectedSessionRoot);

        var operationId = Guid.NewGuid().ToString("N");
        var quarantineRelative = Path.Combine(
            "Retention",
            "PurgeQuarantine",
            $"{sessionId}-{current.PlanId[..12]}-{operationId}");
        var quarantineFull = Path.GetFullPath(Path.Combine(repositoryFull, quarantineRelative));
        EnsureUnderRepository(quarantineFull, repositoryFull);

        var purgeStore = new RollbackRetentionPurgeStore(repositoryFull);
        purgeStore.VerifyAll();

        var intent = await purgeStore.RecordIntentAsync(
            operationId,
            sessionId,
            current.PlanId,
            item.RecoveryPlanId,
            item.ReleaseRecordSha256,
            item.SizeBytes,
            quarantineRelative,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        var quarantineParent = Path.GetDirectoryName(quarantineFull)
            ?? throw new InvalidDataException("Retention quarantine path has no parent.");
        RejectExistingReparseAncestors(quarantineParent);
        Directory.CreateDirectory(quarantineParent);
        RejectReparse(quarantineParent);

        if (Directory.Exists(quarantineFull) || File.Exists(quarantineFull))
            throw new IOException("Retention quarantine target already exists: " + quarantineFull);

        Directory.Move(expectedSessionRoot, quarantineFull);

        _ = await purgeStore.RecordQuarantinedAsync(intent, CancellationToken.None)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        VerifyTreeNoReparse(quarantineFull);

        Directory.Delete(quarantineFull, recursive: true);

        var completed = await purgeStore.RecordCompletedAsync(intent, CancellationToken.None)
            .ConfigureAwait(false);

        return new RollbackRetentionPurgeReport(
            Schema: 1,
            OperationId: operationId,
            SessionId: sessionId,
            RetentionPlanId: current.PlanId,
            RecoveryPlanId: item.RecoveryPlanId,
            ReleaseRecordSha256: item.ReleaseRecordSha256,
            PurgedBytes: item.SizeBytes,
            QuarantineRelativePath: quarantineRelative.Replace('\\', '/'),
            CompletedUtc: completed.ObservedUtc,
            CompletedRecordSha256: completed.RecordSha256);
    }

    private static void VerifyTreeNoReparse(string root)
    {
        var full = Path.GetFullPath(root);
        RejectReparse(full);

        var pending = new Stack<string>();
        pending.Push(full);
        while (pending.Count != 0)
        {
            var directory = pending.Pop();
            RejectReparse(directory);

            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
                RejectReparse(file);

            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(child);
                pending.Push(child);
            }
        }
    }

    private static void RejectExistingReparseAncestors(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        if (!current.Exists) current = current.Parent;
        while (current is not null)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException(
                    "Retention purge path must not traverse a reparse point: " + current.FullName);
            current = current.Parent;
        }
    }

    private static void EnsureUnderRepository(string path, string repositoryRoot)
    {
        var candidate = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetFullPath(repositoryRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Retention quarantine escaped the rollback repository.");
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Retention purge refuses reparse-point paths: " + path);
    }
}

public sealed record RollbackRetentionPurgeReport(
    int Schema,
    string OperationId,
    string SessionId,
    string RetentionPlanId,
    string RecoveryPlanId,
    string ReleaseRecordSha256,
    long PurgedBytes,
    string QuarantineRelativePath,
    DateTime CompletedUtc,
    string CompletedRecordSha256);
