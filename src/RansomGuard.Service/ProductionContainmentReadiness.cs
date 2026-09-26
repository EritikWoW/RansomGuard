using RansomGuard.Core;

namespace RansomGuard.Service;

internal sealed record ProductionContainmentReadinessDecision(
    bool Ready,
    string Reason,
    int IncompleteSessions);

internal static class ProductionContainmentReadiness
{
    internal static ProductionContainmentReadinessDecision Evaluate(
        GuardSettings settings,
        ContainmentStateChangeJournal journal)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(journal);

        if (!settings.Enforce.AutomaticContainment)
            return new(false, "DisabledByConfiguration", 0);

        journal.VerifyAll();

        if (!WindowsProcessStateChangeLease.IsSupported())
            return new(false, "ProcessStateChangeApiUnavailable", 0);

        var incomplete = journal.IncompleteRequests();
        if (incomplete.Length != 0)
            return new(false, "IncompleteStateChangeSessionsRequireReview", incomplete.Length);

        return new(true, "QualifiedStateChangeBackendReady", 0);
    }
}
