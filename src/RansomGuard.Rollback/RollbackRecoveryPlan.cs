using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Builds a deterministic, read-only recovery plan from one validated rollback session.
/// The plan never instructs the caller to overwrite, rename or delete live evidence.
/// </summary>
public static class RollbackRecoveryPlanner
{
    public const int Schema = 1;

    public static RollbackRecoveryPlan Build(string repositoryRoot, string sessionId)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));
        if (string.IsNullOrWhiteSpace(sessionId))
            throw new ArgumentException("Rollback session id is required.", nameof(sessionId));

        var repository = new RollbackRepository(repositoryRoot);
        repository.VerifyAll();
        var store = repository.OpenSession(sessionId);
        store.VerifyAll();

        var sessionRoot = store.Root;
        var actions = new List<RollbackRecoveryAction>();
        var fullByPath = store.Captures.ToDictionary(
            x => Path.GetFullPath(x.OriginalPath),
            StringComparer.OrdinalIgnoreCase);

        foreach (var capture in store.Captures.OrderBy(x => x.Sequence))
        {
            actions.Add(NewAction(
                actions.Count + 1,
                RecoveryActionKind.RestoreFullPreimageCopy,
                RecoveryActionState.Ready,
                capture.OriginalPath,
                null,
                capture.RecordSha256,
                checked((ulong)capture.Sequence),
                false,
                "Verified full pre-image can be restored only to a new recovery copy."));
        }

        var rangeRoot = Path.Combine(sessionRoot, "write-cow");
        if (Directory.Exists(rangeRoot))
        {
            var range = new RangeRollbackStore(rangeRoot);
            range.VerifyAll();
            foreach (var baseline in range.Baselines.OrderBy(x => x.Sequence))
            {
                var full = Path.GetFullPath(baseline.OriginalPath);
                var hasFull = fullByPath.ContainsKey(full);
                actions.Add(NewAction(
                    actions.Count + 1,
                    RecoveryActionKind.RestoreRangeCowCopy,
                    hasFull ? RecoveryActionState.Informational : RecoveryActionState.Ready,
                    full,
                    null,
                    baseline.RecordSha256,
                    checked((ulong)baseline.Sequence),
                    true,
                    hasFull
                        ? "A full pre-image exists for the same path and supersedes range-COW recovery."
                        : "Range-COW can reconstruct a new copy from the current damaged source plus committed original blocks."));
            }
        }

        var restartRoot = Path.Combine(sessionRoot, "restart-state");
        RestartReconciliationStore? restartEvidence = null;
        if (Directory.Exists(restartRoot))
        {
            restartEvidence = new RestartReconciliationStore(restartRoot);
            restartEvidence.VerifyAll();
        }

        var createRoot = Path.Combine(sessionRoot, "create-state");
        if (Directory.Exists(createRoot))
        {
            var baselines = new CreateRollbackStore(createRoot);
            var operations = new CreateOperationStore(createRoot);
            baselines.VerifyAll();
            operations.VerifyAll();

            foreach (var baseline in baselines.Baselines.OrderBy(x => x.Sequence))
            {
                actions.Add(NewAction(
                    actions.Count + 1,
                    RecoveryActionKind.ReviewOriginallyAbsentPath,
                    RecoveryActionState.Review,
                    baseline.OriginalPath,
                    null,
                    baseline.RecordSha256,
                    checked((ulong)baseline.Sequence),
                    false,
                    "Path was originally absent. Recovery must not delete a current file automatically."));
            }

            foreach (var intent in operations.Intents.OrderBy(x => x.Sequence))
            {
                if (!operations.TryGetCompletion(intent.RequestSequence, out var completion) || completion is null)
                {
                    var assessment = restartEvidence?.Assess(
                        RestartOperationKind.Create,
                        intent.RequestSequence,
                        intent.RecordSha256)
                        ?? new RestartEvidenceAssessment(
                            RestartEvidenceAssessmentState.NoEvidence,
                            0,
                            string.Empty);
                    var reviewable = assessment.State is
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted or
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted;
                    var crashReason = assessment.State switch
                    {
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted =>
                            "CREATE intent has no authoritative kernel completion, but all durable restart observations consistently support completion. Manual review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted =>
                            "CREATE intent has no authoritative kernel completion, but all durable restart observations consistently support non-completion. Manual review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.Unresolved =>
                            "CREATE intent has no authoritative kernel completion and restart evidence is ambiguous, indeterminate, or conflicting.",
                        _ =>
                            "CREATE intent has no authoritative kernel completion."
                    };
                    actions.Add(NewAction(
                        actions.Count + 1,
                        RecoveryActionKind.ReviewCreateTransaction,
                        reviewable ? RecoveryActionState.Review : RecoveryActionState.Blocked,
                        intent.OriginalPath,
                        null,
                        reviewable ? assessment.LatestRecordSha256 : intent.RecordSha256,
                        intent.RequestSequence,
                        false,
                        crashReason));
                    continue;
                }

                var state = completion.State switch
                {
                    CreateCompletionState.Failed => RecoveryActionState.Informational,
                    CreateCompletionState.Succeeded => intent.PreservationAction == CreatePreservationAction.RecordOriginallyAbsent
                        ? RecoveryActionState.Review
                        : RecoveryActionState.Informational,
                    _ => RecoveryActionState.Blocked
                };
                var reason = completion.State switch
                {
                    CreateCompletionState.Failed =>
                        "Filesystem CREATE failed; no topology recovery is required for this operation.",
                    CreateCompletionState.Succeeded when intent.PreservationAction == CreatePreservationAction.RecordOriginallyAbsent =>
                        "CREATE succeeded on a path that was originally absent. Automatic deletion is forbidden; review current data manually.",
                    CreateCompletionState.Succeeded =>
                        "CREATE completed authoritatively; content recovery, when required, is represented by the pre-image copy action.",
                    _ =>
                        "CREATE completed with unresolved final name and/or identity; automatic topology recovery is blocked."
                };
                actions.Add(NewAction(
                    actions.Count + 1,
                    RecoveryActionKind.ReviewCreateTransaction,
                    state,
                    intent.OriginalPath,
                    string.IsNullOrWhiteSpace(completion.FinalPath) ? null : completion.FinalPath,
                    completion.RecordSha256,
                    intent.RequestSequence,
                    false,
                    reason));
            }
        }

        var renameRoot = Path.Combine(sessionRoot, "rename-state");
        if (Directory.Exists(renameRoot))
        {
            var renames = new RenameRollbackStore(renameRoot);
            renames.VerifyAll();

            foreach (var intent in renames.Intents.OrderBy(x => x.Sequence))
            {
                if (!renames.TryGetCompletion(intent.RequestSequence, out var completion) || completion is null)
                {
                    var assessment = restartEvidence?.Assess(
                        RestartOperationKind.Rename,
                        intent.RequestSequence,
                        intent.RecordSha256)
                        ?? new RestartEvidenceAssessment(
                            RestartEvidenceAssessmentState.NoEvidence,
                            0,
                            string.Empty);
                    var reviewable = assessment.State is
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted or
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted;
                    var crashReason = assessment.State switch
                    {
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted =>
                            "RENAME intent has no authoritative kernel completion, but all durable restart observations consistently support completion. Manual topology review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted =>
                            "RENAME intent has no authoritative kernel completion, but all durable restart observations consistently support non-completion. Manual topology review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.Unresolved =>
                            "RENAME intent has no authoritative kernel completion and restart evidence is ambiguous, indeterminate, or conflicting.",
                        _ =>
                            "RENAME intent has no authoritative kernel completion."
                    };
                    actions.Add(NewAction(
                        actions.Count + 1,
                        RecoveryActionKind.ReviewRenameTopology,
                        reviewable ? RecoveryActionState.Review : RecoveryActionState.Blocked,
                        intent.SourcePath,
                        intent.DestinationPath,
                        reviewable ? assessment.LatestRecordSha256 : intent.RecordSha256,
                        intent.RequestSequence,
                        false,
                        crashReason));
                    continue;
                }

                var state = completion.State switch
                {
                    RenameCompletionState.Failed => RecoveryActionState.Informational,
                    RenameCompletionState.Succeeded => RecoveryActionState.Review,
                    _ => RecoveryActionState.Blocked
                };
                var reason = completion.State switch
                {
                    RenameCompletionState.Failed =>
                        "Filesystem RENAME failed; pre-operation names remain authoritative.",
                    RenameCompletionState.Succeeded =>
                        "RENAME succeeded authoritatively. Copy-out recovery is safe, but live topology is never renamed automatically.",
                    _ =>
                        "RENAME completed with unresolved final name and/or identity; topology recovery is blocked."
                };
                actions.Add(NewAction(
                    actions.Count + 1,
                    RecoveryActionKind.ReviewRenameTopology,
                    state,
                    intent.SourcePath,
                    string.IsNullOrWhiteSpace(completion.FinalDestinationPath)
                        ? intent.DestinationPath
                        : completion.FinalDestinationPath,
                    completion.RecordSha256,
                    intent.RequestSequence,
                    false,
                    reason));
            }
        }

        var truncateRoot = Path.Combine(sessionRoot, "truncate-state");
        if (Directory.Exists(truncateRoot))
        {
            var truncates = new TruncateOperationStore(truncateRoot);
            truncates.VerifyAll();

            foreach (var intent in truncates.Intents.OrderBy(x => x.Sequence))
            {
                if (!truncates.TryGetCompletion(intent.RequestSequence, out var completion) || completion is null)
                {
                    var assessment = truncates.AssessRestart(intent);
                    var reviewable = assessment.State is
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted or
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted;
                    var restartReason = assessment.State switch
                    {
                        RestartEvidenceAssessmentState.ConsistentSupportsCompleted =>
                            "TRUNCATE intent has no authoritative kernel completion, but durable restart evidence consistently supports completion. Manual review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted =>
                            "TRUNCATE intent has no authoritative kernel completion, but durable restart evidence consistently supports non-completion. Manual review is allowed; restart evidence never becomes a kernel completion.",
                        RestartEvidenceAssessmentState.Unresolved =>
                            "TRUNCATE intent has no authoritative kernel completion and restart evidence is ambiguous, indeterminate, or conflicting.",
                        _ =>
                            "TRUNCATE intent has no authoritative kernel completion."
                    };
                    actions.Add(NewAction(
                        actions.Count + 1,
                        RecoveryActionKind.ReviewTruncateTransaction,
                        reviewable ? RecoveryActionState.Review : RecoveryActionState.Blocked,
                        intent.OriginalPath,
                        null,
                        reviewable ? assessment.LatestRecordSha256 : intent.RecordSha256,
                        intent.RequestSequence,
                        false,
                        restartReason));
                    continue;
                }

                var state = completion.State switch
                {
                    TruncateCompletionState.Failed => RecoveryActionState.Informational,
                    TruncateCompletionState.Succeeded => RecoveryActionState.Informational,
                    _ => RecoveryActionState.Review
                };
                var completionReason = completion.State switch
                {
                    TruncateCompletionState.Failed =>
                        "Filesystem TRUNCATE failed; no length mutation recovery decision is required.",
                    TruncateCompletionState.Succeeded =>
                        "TRUNCATE succeeded authoritatively. Verified content recovery is represented separately by copy-out pre-image evidence; live length is never modified automatically.",
                    _ =>
                        "TRUNCATE succeeded authoritatively but post-operation metric and/or identity was unresolved. Copy-out evidence remains separate; manual review is required."
                };
                actions.Add(NewAction(
                    actions.Count + 1,
                    RecoveryActionKind.ReviewTruncateTransaction,
                    state,
                    intent.OriginalPath,
                    null,
                    completion.RecordSha256,
                    intent.RequestSequence,
                    false,
                    completionReason));
            }
        }

        var evidenceSha = ComputeJournalEvidenceDigest(sessionRoot);
        var ordered = actions
            .OrderBy(x => x.Index)
            .ToArray();
        var planId = ComputePlanId(sessionId, evidenceSha, ordered);

        return new RollbackRecoveryPlan(
            Schema,
            planId,
            sessionId,
            Path.GetFullPath(repositoryRoot),
            sessionRoot,
            DateTime.UtcNow,
            evidenceSha,
            ordered,
            ordered.Count(x => x.State == RecoveryActionState.Ready),
            ordered.Count(x => x.State == RecoveryActionState.Review),
            ordered.Count(x => x.State == RecoveryActionState.Blocked),
            AutomaticTopologyMutationAllowed: false);
    }

    private static RollbackRecoveryAction NewAction(
        int index,
        RecoveryActionKind kind,
        RecoveryActionState state,
        string primaryPath,
        string? relatedPath,
        string evidenceRecordSha256,
        ulong evidenceSequence,
        bool requiresLiveSource,
        string reason) =>
        new(
            index,
            kind,
            state,
            Path.GetFullPath(primaryPath),
            string.IsNullOrWhiteSpace(relatedPath) ? string.Empty : Path.GetFullPath(relatedPath),
            evidenceRecordSha256,
            evidenceSequence,
            requiresLiveSource,
            reason);

    private static string ComputeJournalEvidenceDigest(string sessionRoot)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in Directory.EnumerateFiles(sessionRoot, "*.jsonl", SearchOption.AllDirectories)
                     .OrderBy(x => Path.GetRelativePath(sessionRoot, x), StringComparer.OrdinalIgnoreCase))
        {
            RejectReparse(path);
            var relative = Path.GetRelativePath(sessionRoot, path).Replace('\\', '/');
            var fileHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            var line = Encoding.UTF8.GetBytes(relative + "\0" + fileHash + "\n");
            aggregate.AppendData(line);
        }
        return Convert.ToHexString(aggregate.GetHashAndReset());
    }

    private static string ComputePlanId(
        string sessionId,
        string evidenceSha256,
        IReadOnlyList<RollbackRecoveryAction> actions)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            schema = Schema,
            sessionId,
            evidenceSha256,
            actions = actions.Select(x => new
            {
                x.Index,
                x.Kind,
                x.State,
                x.PrimaryPath,
                x.RelatedPath,
                x.EvidenceRecordSha256,
                x.EvidenceSequence,
                x.RequiresLiveSource,
                x.Reason
            })
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Recovery planning refuses reparse-point evidence: " + path);
    }
}

public enum RecoveryActionKind
{
    RestoreFullPreimageCopy = 1,
    RestoreRangeCowCopy = 2,
    ReviewOriginallyAbsentPath = 3,
    ReviewCreateTransaction = 4,
    ReviewRenameTopology = 5,
    ReviewTruncateTransaction = 6
}

public enum RecoveryActionState
{
    Ready = 1,
    Review = 2,
    Blocked = 3,
    Informational = 4
}

public sealed record RollbackRecoveryAction(
    int Index,
    RecoveryActionKind Kind,
    RecoveryActionState State,
    string PrimaryPath,
    string RelatedPath,
    string EvidenceRecordSha256,
    ulong EvidenceSequence,
    bool RequiresLiveSource,
    string Reason);

public sealed record RollbackRecoveryPlan(
    int Schema,
    string PlanId,
    string SessionId,
    string RepositoryRoot,
    string SessionRoot,
    DateTime PlannedUtc,
    string JournalEvidenceSha256,
    IReadOnlyList<RollbackRecoveryAction> Actions,
    int ReadyCount,
    int ReviewCount,
    int BlockedCount,
    bool AutomaticTopologyMutationAllowed);
