namespace RansomGuard.Core;

public interface IContainmentProcessActuationLease : IDisposable
{
    ProcessKey Process { get; }
    string? ImagePath { get; }
    string? ImageSha256 { get; }
    bool CriticalStateKnown { get; }
    bool IsCritical { get; }

    IReadOnlyList<ContainmentActuationThreadKey> EnumerateThreads(
        int maxThreads,
        CancellationToken cancellationToken);

    bool TrySuspendThread(
        ContainmentActuationThreadKey thread,
        out string diagnostic);

    bool TryResumeThread(
        ContainmentActuationThreadKey thread,
        out string diagnostic);
}

public interface IContainmentProcessActuationPlatform
{
    IContainmentProcessActuationLease Open(ProcessKey expectedProcess);
}

public sealed record ContainmentActuatorOptions(
    int MaxThreads,
    int MaxPasses,
    TimeSpan Timeout)
{
    public static ContainmentActuatorOptions Default { get; } =
        new(256, 4, TimeSpan.FromSeconds(5));

    public void Validate()
    {
        if (MaxThreads is < 1 or > 1024)
            throw new ArgumentOutOfRangeException(nameof(MaxThreads));
        if (MaxPasses is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(MaxPasses));
        if (Timeout <= TimeSpan.Zero || Timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(Timeout));
    }
}

public sealed class ContainmentActuator
{
    private readonly IContainmentProcessActuationPlatform _platform;

    public ContainmentActuator(IContainmentProcessActuationPlatform platform)
    {
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
    }

    public ContainmentActuationResult Suspend(
        ContainmentActuationRequest request,
        ContainmentActuationLedger ledger,
        Func<IContainmentProcessActuationLease, ContainmentActuationValidationDecision> revalidate,
        ContainmentActuatorOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(ledger);
        ArgumentNullException.ThrowIfNull(revalidate);

        options ??= ContainmentActuatorOptions.Default;
        options.Validate();

        using var lease = _platform.Open(request.Binding.Process);
        if (lease.Process != request.Binding.Process)
            throw new InvalidOperationException("ProcessIdentityChanged");

        var validation = revalidate(lease)
            ?? throw new InvalidOperationException("ActuationRevalidationMissing");
        RequireReadyBinding(request.Binding, validation);

        // This is the durable one-shot consume and pre-actuation audit. It must
        // complete before any thread intervention right is exercised.
        ledger.Prepare(request, validation);

        var started = System.Diagnostics.Stopwatch.StartNew();
        var owned = new HashSet<ContainmentActuationThreadKey>();
        var stable = false;

        try
        {
            for (var pass = 0; pass < options.MaxPasses; pass++)
            {
                ThrowIfBudgetExpired(started, options.Timeout, cancellationToken);

                var snapshot = lease.EnumerateThreads(options.MaxThreads, cancellationToken)
                    ?? throw new InvalidOperationException("ThreadEnumerationMissing");
                var threads = snapshot.Distinct().OrderBy(x => x.ThreadId).ThenBy(x => x.CreationFileTimeUtc).ToArray();

                if (threads.Length == 0)
                    return FailAndRollback(request.RequestId, ledger, lease, owned, "NoTargetThreads");
                if (threads.Length > options.MaxThreads)
                    return FailAndRollback(request.RequestId, ledger, lease, owned, "ThreadLimitExceeded");
                if (threads.Any(x => x.ThreadId == 0 || x.CreationFileTimeUtc <= 0))
                    return FailAndRollback(request.RequestId, ledger, lease, owned, "ThreadIdentityInvalid");

                var pending = threads.Where(x => !owned.Contains(x)).ToArray();
                if (pending.Length == 0)
                {
                    stable = true;
                    break;
                }

                foreach (var thread in pending)
                {
                    ThrowIfBudgetExpired(started, options.Timeout, cancellationToken);

                    if (!lease.TrySuspendThread(thread, out _))
                        return FailAndRollback(request.RequestId, ledger, lease, owned, "SuspendThreadFailed");

                    try
                    {
                        ledger.RecordSuspendOwned(
                            request.RequestId,
                            thread.ThreadId,
                            thread.CreationFileTimeUtc);
                        owned.Add(thread);
                    }
                    catch
                    {
                        // The increment succeeded but durable ownership did not.
                        // Compensate exactly once before propagating the ledger failure.
                        _ = lease.TryResumeThread(thread, out _);
                        if (owned.Count > 0)
                        {
                            try
                            {
                                ledger.RecordFailed(request.RequestId, "OwnershipCommitFailed");
                                RollbackOwned(request.RequestId, ledger, lease, owned);
                            }
                            catch
                            {
                                // Preserve the original durable-ledger exception below.
                            }
                        }
                        throw;
                    }
                }
            }

            if (!stable)
                return FailAndRollback(request.RequestId, ledger, lease, owned, "ThreadSetUnstable");

            ledger.RecordSuspendCompleted(request.RequestId);
            return ledger.ResultFor(request.RequestId);
        }
        catch (OperationCanceledException)
        {
            return FailAndRollback(request.RequestId, ledger, lease, owned, "ActuationCancelled");
        }
        catch (TimeoutException)
        {
            return FailAndRollback(request.RequestId, ledger, lease, owned, "ActuationTimedOut");
        }
    }

    public ContainmentActuationResult ResumeOwned(
        ContainmentActuationRequest request,
        ContainmentActuationLedger ledger)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(ledger);

        using var lease = _platform.Open(request.Binding.Process);
        if (lease.Process != request.Binding.Process)
            throw new InvalidOperationException("ProcessIdentityChanged");

        var outstanding = OutstandingOwned(ledger, request.RequestId);
        if (outstanding.Count == 0)
            return ledger.ResultFor(request.RequestId);

        RollbackOwned(request.RequestId, ledger, lease, outstanding);
        return ledger.ResultFor(request.RequestId);
    }

    private static void RequireReadyBinding(
        ContainmentActuationBinding binding,
        ContainmentActuationValidationDecision validation)
    {
        if (!validation.Ready ||
            !string.Equals(
                validation.State,
                ContainmentActuationValidationState.Ready.ToString(),
                StringComparison.Ordinal) ||
            validation.Reasons is null ||
            validation.Reasons.Length != 0)
            throw new InvalidOperationException(
                "ActuationRevalidationDenied:" +
                string.Join(",", validation.Reasons ?? Array.Empty<string>()));

        var expected = ContainmentActuationPolicy.ComputeBindingFingerprint(binding);
        if (!DecisionPolicy.HashEqual(expected, validation.BindingFingerprint))
            throw new InvalidOperationException("ActuationValidationBindingMismatch");
    }

    private static void ThrowIfBudgetExpired(
        System.Diagnostics.Stopwatch started,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (started.Elapsed > timeout)
            throw new TimeoutException("Containment actuator time budget expired.");
    }

    private static ContainmentActuationResult FailAndRollback(
        string requestId,
        ContainmentActuationLedger ledger,
        IContainmentProcessActuationLease lease,
        IEnumerable<ContainmentActuationThreadKey> owned,
        string reasonCode)
    {
        try
        {
            ledger.RecordFailed(requestId, reasonCode);
        }
        catch (InvalidOperationException ex) when (
            ex.Message is "RequestAlreadyResumed" or "ActuationRequestNotPrepared")
        {
            throw;
        }

        RollbackOwned(requestId, ledger, lease, owned);
        return ledger.ResultFor(requestId);
    }

    private static void RollbackOwned(
        string requestId,
        ContainmentActuationLedger ledger,
        IContainmentProcessActuationLease lease,
        IEnumerable<ContainmentActuationThreadKey> candidates)
    {
        var outstanding = OutstandingOwned(ledger, requestId);
        if (outstanding.Count == 0)
            return;

        var candidateSet = candidates.ToHashSet();
        var toResume = outstanding
            .Where(candidateSet.Contains)
            .OrderByDescending(x => x.ThreadId)
            .ThenByDescending(x => x.CreationFileTimeUtc)
            .ToArray();

        foreach (var thread in toResume)
        {
            // Recovery deliberately ignores caller cancellation. Once RansomGuard
            // owns an increment it must attempt to release every owned increment.
            if (!lease.TryResumeThread(thread, out _))
                continue;

            ledger.RecordResumeOwned(
                requestId,
                thread.ThreadId,
                thread.CreationFileTimeUtc);
        }

        if (OutstandingOwned(ledger, requestId).Count == 0)
            ledger.RecordResumeCompleted(requestId);
    }

    private static HashSet<ContainmentActuationThreadKey> OutstandingOwned(
        ContainmentActuationLedger ledger,
        string requestId)
    {
        var owned = ledger.Records
            .Where(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendOwned &&
                string.Equals(x.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
            .Select(x => new ContainmentActuationThreadKey(x.ThreadId, x.ThreadCreationFileTimeUtc))
            .ToHashSet();
        var resumed = ledger.Records
            .Where(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeOwned &&
                string.Equals(x.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
            .Select(x => new ContainmentActuationThreadKey(x.ThreadId, x.ThreadCreationFileTimeUtc))
            .ToHashSet();
        owned.ExceptWith(resumed);
        return owned;
    }
}
