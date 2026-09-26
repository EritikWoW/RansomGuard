using System.Text;
using System.Text.Json;
using RansomGuard.Core;
using RansomGuard.Rollback;

namespace RansomGuard.Management;

public sealed record ProductionRecoveryExecutionRequest(
    string SessionId,
    string PlanId,
    string JournalEvidenceSha256,
    string LifecycleRecordSha256,
    string OutputRoot);

public sealed record ProductionRecoveryExecutionManifest(
    int Schema,
    string SessionId,
    string PlanId,
    string JournalEvidenceSha256,
    string LifecycleRecordSha256,
    string OutputRoot,
    DateTime StartedUtc,
    DateTime CompletedUtc,
    bool ServiceIdleBefore,
    bool ServiceIdleAfter,
    bool SourceOrTopologyMutationPerformed,
    bool Succeeded,
    RollbackRecoveryExecutionReport Report);

/// <summary>
/// Explicit production copy-out boundary.
///
/// The ordinary read-only pipe never calls this type. The caller must already be the
/// short-lived elevated administration process and must provide the exact plan/evidence
/// identity reviewed by the operator. Only planner-classified Ready copy actions execute.
/// </summary>
public static class ProductionRecoveryExecutionAdministration
{
    private const int MaxExecutionActions = 200;
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static Task<ProductionRecoveryExecutionManifest> ExecuteCopyOutAsync(
        ProductionRecoveryExecutionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.Run(
            () => ExecuteCopyOut(request, cancellationToken),
            cancellationToken);
    }

    private static ProductionRecoveryExecutionManifest ExecuteCopyOut(
        ProductionRecoveryExecutionRequest request,
        CancellationToken cancellationToken)
    {
        RuleAdministration.DemandAdministrator();
        ValidateRequest(request);

        // StateMaintenanceGate is a named Mutex and is deliberately thread-affine.
        // The entire copy-out body therefore stays synchronous on this worker thread;
        // async I/O is joined here rather than retaining the Mutex across an await.
        using var maintenance = StateMaintenanceGate.Acquire();
        ProductionRecoveryAdministration.EnsureIdle();

        var rollbackRoot = ProductionRecoveryAdministration.ValidateStateAndGetRollbackRoot(allowMissing: false)
            ?? throw new DirectoryNotFoundException("Rollback repository does not exist.");

        var repository = new RollbackRepository(rollbackRoot, createIfMissing: false);
        if (!repository.SessionIds().Contains(request.SessionId, StringComparer.Ordinal))
            throw new DirectoryNotFoundException("Production rollback session not found: " + request.SessionId);

        repository.VerifySession(request.SessionId);
        var session = repository.OpenSession(request.SessionId);
        var lifecycle = new RollbackSessionLifecycleStore(session.Root);
        lifecycle.VerifyAll();
        var lifecycleBefore = lifecycle.Snapshot;
        RequireTerminalLifecycle(lifecycleBefore);

        if (!lifecycleBefore.LastRecordSha256.Equals(
                request.LifecycleRecordSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Production recovery lifecycle revision changed after operator review. Rebuild the plan before execution.");

        var currentPlan = RollbackRecoveryPlanner.Build(
            rollbackRoot, request.SessionId, createIfMissing: false, verifyRepositoryAll: false);
        ValidateReviewedPlan(request, currentPlan);

        if (currentPlan.Actions.Count > MaxExecutionActions || currentPlan.ReadyCount > MaxExecutionActions)
            throw new IOException(
                $"Production recovery execution exceeds the bounded action limit ({MaxExecutionActions}).");

        var outputFull = ValidateOutputRoot(request.OutputRoot, rollbackRoot, currentPlan);
        var startedUtc = DateTime.UtcNow;

        var report = RollbackRecoveryExecutor.ExecuteReadyAsync(
            rollbackRoot,
            currentPlan,
            outputFull,
            cancellationToken).GetAwaiter().GetResult();

        // Prove that the service stayed idle and the exact lifecycle/evidence revision did
        // not move underneath the copy-out. The executor itself never writes the repository.
        ProductionRecoveryAdministration.EnsureIdle();
        repository.VerifySession(request.SessionId);

        var lifecycleAfterStore = new RollbackSessionLifecycleStore(session.Root);
        lifecycleAfterStore.VerifyAll();
        var lifecycleAfter = lifecycleAfterStore.Snapshot;
        RequireTerminalLifecycle(lifecycleAfter);
        if (!lifecycleAfter.LastRecordSha256.Equals(
                request.LifecycleRecordSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Production recovery lifecycle revision changed during copy-out.");

        var planAfter = RollbackRecoveryPlanner.Build(
            rollbackRoot, request.SessionId, createIfMissing: false, verifyRepositoryAll: false);
        ValidateReviewedPlan(request, planAfter);

        var manifest = new ProductionRecoveryExecutionManifest(
            Schema: 1,
            SessionId: request.SessionId,
            PlanId: request.PlanId,
            JournalEvidenceSha256: request.JournalEvidenceSha256,
            LifecycleRecordSha256: request.LifecycleRecordSha256,
            OutputRoot: outputFull,
            StartedUtc: startedUtc,
            CompletedUtc: DateTime.UtcNow,
            ServiceIdleBefore: true,
            ServiceIdleAfter: true,
            SourceOrTopologyMutationPerformed: false,
            Succeeded: report.Succeeded,
            Report: report);

        WriteNewManifest(Path.Combine(outputFull, "production-recovery-execution.json"), manifest);
        return manifest;
    }

    private static void ValidateRequest(ProductionRecoveryExecutionRequest request)
    {
        ProductionRecoveryAdministration.ValidateProductionSessionId(request.SessionId);
        if (!IsSha256(request.PlanId))
            throw new ArgumentException("A canonical SHA-256 PlanId is required.", nameof(request));
        if (!IsSha256(request.JournalEvidenceSha256))
            throw new ArgumentException("A canonical SHA-256 evidence digest is required.", nameof(request));
        if (!IsSha256(request.LifecycleRecordSha256))
            throw new ArgumentException("A canonical SHA-256 lifecycle revision is required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.OutputRoot))
            throw new ArgumentException("An explicit recovery output root is required.", nameof(request));
    }

    private static void ValidateReviewedPlan(
        ProductionRecoveryExecutionRequest request,
        RollbackRecoveryPlan current)
    {
        if (!current.PlanId.Equals(request.PlanId, StringComparison.OrdinalIgnoreCase) ||
            !current.JournalEvidenceSha256.Equals(
                request.JournalEvidenceSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Production recovery plan/evidence is stale. Rebuild and review the plan before execution.");
        if (current.AutomaticTopologyMutationAllowed)
            throw new InvalidDataException("Production recovery plan unexpectedly authorizes topology mutation.");
        if (current.Actions.Any(x =>
                x.State == RecoveryActionState.Ready &&
                x.Kind is not (
                    RecoveryActionKind.RestoreFullPreimageCopy or
                    RecoveryActionKind.RestoreRangeCowCopy)))
            throw new InvalidDataException(
                "Production recovery contains a Ready action that is not copy-out-only.");
    }

    private static string ValidateOutputRoot(
        string requested,
        string rollbackRoot,
        RollbackRecoveryPlan plan)
    {
        if (!Path.IsPathFullyQualified(requested))
            throw new ArgumentException("Recovery output root must be an absolute local path.", nameof(requested));

        var outputFull = Path.GetFullPath(requested);
        var supplied = requested.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var canonical = outputFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!supplied.Equals(canonical, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Recovery output root must already be canonical.", nameof(requested));
        if (outputFull.StartsWith(@"\\", StringComparison.Ordinal))
            throw new ArgumentException("Network recovery destinations are not supported.", nameof(requested));

        var driveRoot = Path.GetPathRoot(outputFull)
            ?? throw new ArgumentException("Recovery output root has no local drive.", nameof(requested));
        var drive = new DriveInfo(driveRoot);
        if (drive.DriveType is DriveType.Network or DriveType.NoRootDirectory)
            throw new ArgumentException("Network or unavailable recovery destinations are not supported.", nameof(requested));

        if (Directory.Exists(outputFull) || File.Exists(outputFull))
            throw new IOException("Recovery output root already exists: " + outputFull);
        if (IsSameOrUnder(outputFull, rollbackRoot) ||
            IsSameOrUnder(outputFull, StateStoreAdministration.Root))
            throw new IOException("Recovery output root must remain outside RansomGuard private state.");

        foreach (var sourceDirectory in plan.Actions
                     .SelectMany(x => new[] { x.PrimaryPath, x.RelatedPath })
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Select(Path.GetDirectoryName)
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (IsSameOrUnder(outputFull, sourceDirectory!))
                throw new IOException(
                    "Recovery output root must not be created inside a source evidence directory.");
        }

        return outputFull;
    }

    private static void RequireTerminalLifecycle(RollbackSessionLifecycleSnapshot snapshot)
    {
        if (snapshot.State is not (
                RollbackSessionLifecycleState.Completed or
                RollbackSessionLifecycleState.Faulted))
            throw new InvalidOperationException(
                $"Production recovery execution is refused for lifecycle state '{snapshot.State}'.");
        if (!IsSha256(snapshot.LastRecordSha256))
            throw new InvalidDataException("Production recovery lifecycle evidence is incomplete.");
    }

    private static bool IsSameOrUnder(string candidate, string parent)
    {
        var c = Path.GetFullPath(candidate)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var p = Path.GetFullPath(parent)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return c.Equals(p, StringComparison.OrdinalIgnoreCase) ||
               c.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void WriteNewManifest(
        string path,
        ProductionRecoveryExecutionManifest manifest)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest, Json));
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            64 * 1024,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(true);
    }
}
