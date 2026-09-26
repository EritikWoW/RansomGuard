using System.Diagnostics;

namespace RansomGuard.Core;

public sealed record ContainmentSuspendLimits(
    int MaxThreads,
    int MaxEnumerationPasses,
    TimeSpan Timeout)
{
    public static ContainmentSuspendLimits Default { get; } =
        new(128, 4, TimeSpan.FromSeconds(5));

    public void Validate()
    {
        if (MaxThreads < 1 || MaxThreads > 512)
            throw new ArgumentOutOfRangeException(nameof(MaxThreads));
        if (MaxEnumerationPasses < 2 || MaxEnumerationPasses > 8)
            throw new ArgumentOutOfRangeException(nameof(MaxEnumerationPasses));
        if (Timeout < TimeSpan.FromMilliseconds(100) || Timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(Timeout));
    }
}

public sealed record ContainmentSuspendTargetSnapshot(
    ProcessKey Process,
    string? ImagePath,
    string? ImageSha256,
    bool CriticalStateKnown,
    bool IsCritical,
    bool IsSelf,
    bool IsProtectedServiceProcess);

public sealed record ContainmentThreadOperationResult(
    bool Succeeded,
    string ReasonCode)
{
    public static ContainmentThreadOperationResult Success() => new(true, "Success");
    public static ContainmentThreadOperationResult Failure(string reasonCode) => new(false, reasonCode);
}

public interface IContainmentSuspendSession : IDisposable
{
    // The implementation must retain one exact process handle for the session lifetime.
    ContainmentSuspendTargetSnapshot Target { get; }

    // Returned thread ids must belong to Target.Process. Implementations must fail
    // closed when the bounded result cannot be proven complete.
    IReadOnlyList<uint> EnumerateThreadIds(int maxThreads);

    // One successful call means exactly one suspend-count increment was added by
    // RansomGuard to this thread.
    ContainmentThreadOperationResult SuspendOne(uint threadId);

    // One successful call means exactly one previously RansomGuard-owned
    // suspend-count increment was removed from this thread.
    ContainmentThreadOperationResult ResumeOne(uint threadId);
}

public interface IContainmentSuspendPlatform
{
    // Must open/retain the exact process instance before any thread operation.
    IContainmentSuspendSession OpenExact(ProcessKey expectedProcess);
}

public sealed class ContainmentSuspendException : InvalidOperationException
{
    public string ReasonCode { get; }

    public ContainmentSuspendException(string reasonCode, string message)
        : base(message)
    {
        if (string.IsNullOrWhiteSpace(reasonCode) ||
            reasonCode.Length > 64 ||
            reasonCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '_' and not '-'))
            throw new ArgumentException("Invalid containment suspension reason code.", nameof(reasonCode));
        ReasonCode = reasonCode;
    }
}

public sealed class ContainmentSuspendCoordinator
{
    private readonly ContainmentActuationLedger _ledger;
    private readonly IContainmentSuspendPlatform _platform;
    private readonly ContainmentSuspendLimits _limits;

    public ContainmentSuspendCoordinator(
        ContainmentActuationLedger ledger,
        IContainmentSuspendPlatform platform,
        ContainmentSuspendLimits? limits = null)
    {
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
        _limits = limits ?? ContainmentSuspendLimits.Default;
        _limits.Validate();
    }

    public ContainmentActuationResult Suspend(
        ContainmentActuationRequest request,
        ProtectionStatusDto currentProtection,
        bool telemetryHealthy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(currentProtection);

        if (_ledger.IsAuthorizationConsumed(request.Binding.AuthorizationId))
        {
            ContainmentActuationResult existing;
            try
            {
                existing = _ledger.ResultFor(request.RequestId);
            }
            catch (InvalidOperationException ex)
            {
                throw new ContainmentSuspendException(
                    "AuthorizationAlreadyConsumed",
                    "The authorization id was already consumed by another actuation request.") { Source = ex.Source };
            }

            if (existing.State is nameof(ContainmentActuationResultState.Suspended)
                or nameof(ContainmentActuationResultState.Resumed)
                or nameof(ContainmentActuationResultState.Failed)
                or nameof(ContainmentActuationResultState.FailedRecovered))
                return existing;

            throw new ContainmentSuspendException(
                "ActuationRecoveryRequired",
                "A prior actuation request is incomplete and must be recovered before retry.");
        }

        using var session = _platform.OpenExact(request.Binding.Process);
        var target = session.Target;
        var validation = ContainmentActuationPolicy.Evaluate(new(
            request.Binding,
            DateTime.UtcNow,
            target.Process,
            target.ImagePath,
            target.ImageSha256,
            currentProtection,
            telemetryHealthy,
            target.CriticalStateKnown,
            target.IsCritical,
            target.IsSelf,
            target.IsProtectedServiceProcess,
            AuthorizationConsumed: false));

        if (!validation.Ready)
            throw new ContainmentSuspendException(
                "ActuationRevalidationDenied",
                "Live containment actuation revalidation denied: " +
                string.Join(",", validation.Reasons));

        _ledger.Prepare(request, validation);

        var owned = new List<uint>();
        var watch = Stopwatch.StartNew();
        try
        {
            var stablePasses = 0;
            for (var pass = 0; pass < _limits.MaxEnumerationPasses; pass++)
            {
                ThrowIfCancelledOrTimedOut(cancellationToken, watch);

                var threadIds = session.EnumerateThreadIds(_limits.MaxThreads)
                    ?? throw new ContainmentSuspendException(
                        "ThreadEnumerationUnavailable",
                        "Thread enumeration returned no result.");

                var normalized = threadIds
                    .Where(x => x != 0)
                    .Distinct()
                    .OrderBy(x => x)
                    .ToArray();

                if (normalized.Length == 0)
                    throw new ContainmentSuspendException(
                        "NoTargetThreads",
                        "The exact target has no suspendable threads.");
                if (normalized.Length > _limits.MaxThreads)
                    throw new ContainmentSuspendException(
                        "ThreadLimitExceeded",
                        "Thread enumeration exceeded the configured bound.");

                var newlyObserved = normalized.Where(x => !owned.Contains(x)).ToArray();
                if (newlyObserved.Length == 0)
                {
                    stablePasses++;
                    if (stablePasses >= 2)
                        break;
                    continue;
                }

                stablePasses = 0;
                foreach (var threadId in newlyObserved)
                {
                    ThrowIfCancelledOrTimedOut(cancellationToken, watch);
                    var operation = session.SuspendOne(threadId);
                    ValidatePlatformResult(operation, "SuspendThreadFailed");
                    try
                    {
                        _ledger.RecordSuspendOwned(request.RequestId, threadId);
                        owned.Add(threadId);
                    }
                    catch
                    {
                        var immediateResume = session.ResumeOne(threadId);
                        if (!immediateResume.Succeeded)
                            throw new ContainmentSuspendException(
                                "OwnershipPersistAndResumeFailed",
                                "Suspend succeeded, ownership persistence failed, and immediate compensation failed.");
                        throw;
                    }
                }
            }

            ThrowIfCancelledOrTimedOut(cancellationToken, watch);

            // Require the final two bounded snapshots to contain no new threads.
            var finalA = session.EnumerateThreadIds(_limits.MaxThreads)
                .Where(x => x != 0).Distinct().OrderBy(x => x).ToArray();
            var finalB = session.EnumerateThreadIds(_limits.MaxThreads)
                .Where(x => x != 0).Distinct().OrderBy(x => x).ToArray();
            if (finalA.Length == 0 ||
                finalA.Length > _limits.MaxThreads ||
                !finalA.SequenceEqual(finalB) ||
                finalA.Any(x => !owned.Contains(x)))
                throw new ContainmentSuspendException(
                    "ThreadSetNotStable",
                    "The target thread set did not stabilize inside the bounded suspension window.");

            _ledger.RecordSuspendCompleted(request.RequestId);
            return _ledger.ResultFor(request.RequestId);
        }
        catch (Exception ex)
        {
            var reason = ReasonFrom(ex);
            try { _ledger.RecordFailed(request.RequestId, reason); } catch { }

            var rollbackFailures = ResumeOwned(session, request.RequestId, owned);
            if (rollbackFailures.Count == 0 && owned.Count > 0)
            {
                try { _ledger.RecordResumeCompleted(request.RequestId); } catch { }
            }

            if (rollbackFailures.Count != 0)
                throw new ContainmentSuspendException(
                    "OwnedRollbackIncomplete",
                    "Containment suspension failed and owned rollback was incomplete: " +
                    string.Join(",", rollbackFailures));

            if (ex is OperationCanceledException)
                throw;
            if (ex is ContainmentSuspendException)
                throw;
            throw new ContainmentSuspendException(reason, ex.Message);
        }
    }

    public ContainmentActuationResult ResumeOutstanding(string requestId)
    {
        var entries = _ledger.Records
            .Where(x => string.Equals(x.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Sequence)
            .ToArray();

        var prepared = entries.FirstOrDefault(x => x.Phase == ContainmentActuationLedgerPhase.Prepared)
            ?? throw new ContainmentSuspendException(
                "ActuationRequestNotPrepared",
                "No prepared actuation request exists.");

        var owned = entries
            .Where(x => x.Phase == ContainmentActuationLedgerPhase.SuspendOwned)
            .Select(x => x.ThreadId)
            .Distinct()
            .ToArray();
        var resumed = entries
            .Where(x => x.Phase == ContainmentActuationLedgerPhase.ResumeOwned)
            .Select(x => x.ThreadId)
            .ToHashSet();
        var outstanding = owned.Where(x => !resumed.Contains(x)).Reverse().ToArray();

        if (outstanding.Length == 0)
            return _ledger.ResultFor(requestId);

        using var session = _platform.OpenExact(
            new ProcessKey(prepared.ProcessId, prepared.ProcessCreationFileTimeUtc));
        if (session.Target.Process != new ProcessKey(prepared.ProcessId, prepared.ProcessCreationFileTimeUtc))
            throw new ContainmentSuspendException(
                "ProcessIdentityChanged",
                "Recovery opened a different process instance.");

        var failures = ResumeOwned(session, requestId, outstanding);
        if (failures.Count != 0)
            throw new ContainmentSuspendException(
                "OwnedRollbackIncomplete",
                "Owned suspension recovery was incomplete: " + string.Join(",", failures));

        _ledger.RecordResumeCompleted(requestId);
        return _ledger.ResultFor(requestId);
    }

    private List<string> ResumeOwned(
        IContainmentSuspendSession session,
        string requestId,
        IEnumerable<uint> threadIds)
    {
        var failures = new List<string>();
        foreach (var threadId in threadIds.Reverse())
        {
            try
            {
                var result = session.ResumeOne(threadId);
                if (!result.Succeeded)
                {
                    failures.Add($"{threadId}:{NormalizeReason(result.ReasonCode, "ResumeThreadFailed")}");
                    continue;
                }
                _ledger.RecordResumeOwned(requestId, threadId);
            }
            catch (Exception ex)
            {
                failures.Add($"{threadId}:{ReasonFrom(ex)}");
            }
        }
        return failures;
    }

    private void ThrowIfCancelledOrTimedOut(CancellationToken cancellationToken, Stopwatch watch)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (watch.Elapsed > _limits.Timeout)
            throw new ContainmentSuspendException(
                "ActuationTimeout",
                "Containment suspension exceeded the configured timeout.");
    }

    private static void ValidatePlatformResult(
        ContainmentThreadOperationResult result,
        string fallbackReason)
    {
        if (result is null || !result.Succeeded)
            throw new ContainmentSuspendException(
                NormalizeReason(result?.ReasonCode, fallbackReason),
                "Containment thread operation failed.");
    }

    private static string ReasonFrom(Exception ex) =>
        ex switch
        {
            ContainmentSuspendException typed => typed.ReasonCode,
            OperationCanceledException => "ActuationCancelled",
            _ => "ActuationFailed"
        };

    private static string NormalizeReason(string? reason, string fallback)
    {
        if (string.IsNullOrWhiteSpace(reason) ||
            reason.Length > 64 ||
            reason.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '_' and not '-'))
            return fallback;
        return reason;
    }
}
