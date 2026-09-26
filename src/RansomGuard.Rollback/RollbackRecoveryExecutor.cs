using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Executes only copy-out actions from a freshly revalidated recovery plan.
/// Live source/evidence paths are never overwritten, renamed or deleted.
/// </summary>
public static class RollbackRecoveryExecutor
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static async Task<RollbackRecoveryExecutionReport> ExecuteReadyAsync(
        string repositoryRoot,
        RollbackRecoveryPlan requestedPlan,
        string outputRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestedPlan);
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));
        if (string.IsNullOrWhiteSpace(outputRoot))
            throw new ArgumentException("Recovery output root is required.", nameof(outputRoot));

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        var current = RollbackRecoveryPlanner.Build(
            repositoryFull, requestedPlan.SessionId, createIfMissing: false, verifyRepositoryAll: false);
        ValidateRequestedPlan(requestedPlan, current, repositoryFull);

        var outputFull = Path.GetFullPath(outputRoot);
        if (Directory.Exists(outputFull) || File.Exists(outputFull))
            throw new IOException("Recovery output root already exists: " + outputFull);
        if (IsSameOrUnder(outputFull, repositoryFull))
            throw new IOException("Recovery output root must remain outside the rollback repository.");

        RejectExistingReparseAncestors(outputFull);
        Directory.CreateDirectory(outputFull);
        RejectReparse(outputFull);

        var planPath = Path.Combine(outputFull, "recovery-plan.json");
        WriteNewJson(planPath, current);

        var repository = new RollbackRepository(repositoryFull, createIfMissing: false);
        repository.VerifySession(current.SessionId);
        var store = repository.OpenSession(current.SessionId);
        store.VerifyAll();

        var rangeRoot = Path.Combine(store.Root, "write-cow");
        RangeRollbackStore? range = Directory.Exists(rangeRoot)
            ? new RangeRollbackStore(rangeRoot, createIfMissing: false)
            : null;
        range?.VerifyAll();

        var results = new List<RollbackRecoveryExecutionItem>();
        var startedUtc = DateTime.UtcNow;
        var success = true;

        foreach (var action in current.Actions.Where(x => x.State == RecoveryActionState.Ready).OrderBy(x => x.Index))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var actionDirectory = Path.Combine(
                outputFull,
                $"{action.Index:D4}-{action.Kind.ToString().ToLowerInvariant()}");
            Directory.CreateDirectory(actionDirectory);
            RejectReparse(actionDirectory);

            var expectedLength = 0L;
            var expectedSha256 = string.Empty;
            try
            {
                string recoveredPath;
                switch (action.Kind)
                {
                    case RecoveryActionKind.RestoreFullPreimageCopy:
                    {
                        var capture = store.Captures.SingleOrDefault(x =>
                            Path.GetFullPath(x.OriginalPath).Equals(
                                Path.GetFullPath(action.PrimaryPath),
                                StringComparison.OrdinalIgnoreCase) &&
                            x.RecordSha256.Equals(
                                action.EvidenceRecordSha256,
                                StringComparison.OrdinalIgnoreCase))
                            ?? throw new InvalidDataException(
                                "Recovery action no longer matches a committed full pre-image.");
                        expectedLength = capture.OriginalLength;
                        expectedSha256 = capture.OriginalSha256;
                        recoveredPath = await store.RestoreToNewCopyAsync(
                            capture, actionDirectory, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case RecoveryActionKind.RestoreRangeCowCopy:
                    {
                        if (range is null)
                            throw new InvalidDataException("Recovery action requires a missing range-COW store.");
                        var baseline = range.Baselines.SingleOrDefault(x =>
                            Path.GetFullPath(x.OriginalPath).Equals(
                                Path.GetFullPath(action.PrimaryPath),
                                StringComparison.OrdinalIgnoreCase) &&
                            x.RecordSha256.Equals(
                                action.EvidenceRecordSha256,
                                StringComparison.OrdinalIgnoreCase))
                            ?? throw new InvalidDataException(
                                "Recovery action no longer matches a committed range-COW baseline.");
                        var expectation = await range.ComputeExpectedRecoveryAsync(
                            action.PrimaryPath, cancellationToken).ConfigureAwait(false);
                        if (expectation.ExpectedLength != baseline.OriginalLength)
                            throw new InvalidDataException(
                                "Range recovery expectation length does not match the committed baseline.");
                        expectedLength = expectation.ExpectedLength;
                        expectedSha256 = expectation.ExpectedSha256;
                        recoveredPath = await range.RestoreToNewCopyAsync(
                            action.PrimaryPath, actionDirectory, expectation, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    default:
                        throw new InvalidDataException(
                            $"Ready recovery action kind '{action.Kind}' is not a copy-out operation.");
                }

                var info = new FileInfo(recoveredPath);
                var sha = await HashFileAsync(recoveredPath, cancellationToken).ConfigureAwait(false);
                if (info.Length != expectedLength)
                    throw new InvalidDataException(
                        $"Recovered copy length mismatch. expected={expectedLength} actual={info.Length}");
                if (!sha.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        "Recovered copy SHA-256 does not match the pre-output evidence expectation.");

                results.Add(new RollbackRecoveryExecutionItem(
                    action.Index,
                    action.Kind,
                    action.PrimaryPath,
                    action.EvidenceRecordSha256,
                    recoveredPath,
                    RollbackRecoveryExecutionState.Succeeded,
                    expectedLength,
                    expectedSha256,
                    info.Length,
                    sha,
                    string.Empty));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
            {
                success = false;
                results.Add(new RollbackRecoveryExecutionItem(
                    action.Index,
                    action.Kind,
                    action.PrimaryPath,
                    action.EvidenceRecordSha256,
                    string.Empty,
                    RollbackRecoveryExecutionState.Failed,
                    expectedLength,
                    expectedSha256,
                    0,
                    string.Empty,
                    ex.Message));
                break;
            }
        }

        var report = new RollbackRecoveryExecutionReport(
            Schema: 2,
            PlanId: current.PlanId,
            SessionId: current.SessionId,
            RepositoryRoot: repositoryFull,
            OutputRoot: outputFull,
            StartedUtc: startedUtc,
            CompletedUtc: DateTime.UtcNow,
            JournalEvidenceSha256: current.JournalEvidenceSha256,
            RequestedReadyActions: current.ReadyCount,
            SucceededActions: results.Count(x => x.State == RollbackRecoveryExecutionState.Succeeded),
            FailedActions: results.Count(x => x.State == RollbackRecoveryExecutionState.Failed),
            ReviewActionsNotExecuted: current.ReviewCount,
            BlockedActionsNotExecuted: current.BlockedCount,
            AutomaticTopologyMutationPerformed: false,
            Succeeded: success &&
                       results.Count == current.ReadyCount &&
                       results.All(x => x.State == RollbackRecoveryExecutionState.Succeeded),
            Items: results);

        WriteNewJson(Path.Combine(outputFull, "recovery-execution.json"), report);
        return report;
    }

    private static void ValidateRequestedPlan(
        RollbackRecoveryPlan requested,
        RollbackRecoveryPlan current,
        string repositoryRoot)
    {
        if (requested.Schema != RollbackRecoveryPlanner.Schema)
            throw new InvalidDataException("Unsupported recovery plan schema.");
        if (!Path.GetFullPath(requested.RepositoryRoot).Equals(repositoryRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Recovery plan belongs to a different rollback repository.");
        if (!requested.SessionId.Equals(current.SessionId, StringComparison.Ordinal))
            throw new InvalidDataException("Recovery plan session mismatch.");
        if (!requested.PlanId.Equals(current.PlanId, StringComparison.OrdinalIgnoreCase) ||
            !requested.JournalEvidenceSha256.Equals(current.JournalEvidenceSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Recovery plan is stale or does not match the currently validated rollback evidence.");
        if (current.AutomaticTopologyMutationAllowed)
            throw new InvalidDataException("Recovery plan unexpectedly allows topology mutation.");
    }

    private static void WriteNewJson<T>(string path, T value)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, Json));
        using var stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(true);
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            hash.AppendData(buffer, 0, read);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static bool IsSameOrUnder(string candidate, string parent)
    {
        var c = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var p = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return c.Equals(p, StringComparison.OrdinalIgnoreCase) ||
               c.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RejectExistingReparseAncestors(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        if (!current.Exists) current = current.Parent;
        while (current is not null)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Recovery output path must not traverse a reparse point: " + current.FullName);
            current = current.Parent;
        }
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Recovery output must not be a reparse point: " + path);
    }
}

public enum RollbackRecoveryExecutionState
{
    Succeeded = 1,
    Failed = 2
}

public sealed record RollbackRecoveryExecutionItem(
    int ActionIndex,
    RecoveryActionKind Kind,
    string SourcePath,
    string EvidenceRecordSha256,
    string RecoveredPath,
    RollbackRecoveryExecutionState State,
    long ExpectedLength,
    string ExpectedSha256,
    long RecoveredLength,
    string RecoveredSha256,
    string Error);

public sealed record RollbackRecoveryExecutionReport(
    int Schema,
    string PlanId,
    string SessionId,
    string RepositoryRoot,
    string OutputRoot,
    DateTime StartedUtc,
    DateTime CompletedUtc,
    string JournalEvidenceSha256,
    int RequestedReadyActions,
    int SucceededActions,
    int FailedActions,
    int ReviewActionsNotExecuted,
    int BlockedActionsNotExecuted,
    bool AutomaticTopologyMutationPerformed,
    bool Succeeded,
    IReadOnlyList<RollbackRecoveryExecutionItem> Items);
