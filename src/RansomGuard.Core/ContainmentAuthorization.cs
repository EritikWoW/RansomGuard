namespace RansomGuard.Core;

public enum ContainmentAuthorizationState
{
    DisabledByConfiguration = 0,
    Denied = 1,
    Eligible = 2
}

public sealed record ContainmentAuthorizationInput(
    bool AutomaticContainmentConfigured,
    ProtectionStatusDto Protection,
    string MonitorState,
    long EtwEventsLost,
    long MonitorQueueDropped,
    long IncidentQueueDropped,
    long WindowEvictions,
    long TruncatedWindows,
    bool IncidentPersisted,
    bool ProcessIdentityVerified,
    bool FreshImageIdentityVerified,
    bool ProtectedScopeResolved,
    bool IsLab,
    bool ScopedTrustApplies,
    int RiskScore,
    int RiskThreshold,
    bool ConfirmedCanary);

public sealed record ContainmentAuthorizationDecision(
    string State,
    bool Eligible,
    string[] Reasons);

public static class ContainmentAuthorizationPolicy
{
    public static ContainmentAuthorizationDecision Evaluate(ContainmentAuthorizationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var reasons = new List<string>();

        if (!input.AutomaticContainmentConfigured)
            reasons.Add("DisabledByConfiguration");

        var protectionValid = true;
        try
        {
            ProtectionStateMachine.ValidateSnapshot(input.Protection);
        }
        catch (InvalidOperationException)
        {
            protectionValid = false;
            reasons.Add("ProtectionSnapshotInvalid");
        }

        if (protectionValid)
        {
            if (!string.Equals(input.Protection.RequestedMode, "Enforce", StringComparison.Ordinal))
                reasons.Add("RequestedModeNotEnforce");
            if (!string.Equals(input.Protection.State, "Protected", StringComparison.Ordinal))
                reasons.Add("ProtectionStateNotProtected");
            if (!input.Protection.RollbackStoreReady)
                reasons.Add("RollbackStoreNotReady");
            if (!input.Protection.KernelChannelConnected)
                reasons.Add("KernelChannelNotConnected");
            if (!input.Protection.KernelEnforcementActive)
                reasons.Add("KernelEnforcementNotActive");
        }

        if (!string.Equals(input.MonitorState, "Running", StringComparison.Ordinal))
            reasons.Add("MonitorNotRunning");

        if (input.EtwEventsLost < 0 ||
            input.MonitorQueueDropped < 0 ||
            input.IncidentQueueDropped < 0 ||
            input.WindowEvictions < 0 ||
            input.TruncatedWindows < 0)
        {
            reasons.Add("TelemetryCounterInvalid");
        }
        else
        {
            if (input.EtwEventsLost != 0)
                reasons.Add("EtwLossObserved");
            if (input.MonitorQueueDropped != 0)
                reasons.Add("MonitorQueueLossObserved");
            if (input.IncidentQueueDropped != 0)
                reasons.Add("IncidentQueueLossObserved");
            if (input.WindowEvictions != 0)
                reasons.Add("WindowEvictionsObserved");
            if (input.TruncatedWindows != 0)
                reasons.Add("TruncatedWindowsObserved");
        }

        if (!input.IncidentPersisted)
            reasons.Add("IncidentNotPersisted");
        if (!input.ProcessIdentityVerified)
            reasons.Add("ProcessIdentityNotVerified");
        if (!input.FreshImageIdentityVerified)
            reasons.Add("FreshImageIdentityNotVerified");
        if (!input.ProtectedScopeResolved)
            reasons.Add("ProtectedScopeUnresolved");
        if (input.IsLab)
            reasons.Add("LabIdentityNotEligible");
        if (input.ScopedTrustApplies)
            reasons.Add("ScopedTrustVeto");

        if (input.RiskThreshold <= 0)
            reasons.Add("RiskThresholdInvalid");
        else if (!input.ConfirmedCanary && input.RiskScore < input.RiskThreshold)
            reasons.Add("RiskBelowAuthorizationThreshold");

        var state = !input.AutomaticContainmentConfigured
            ? ContainmentAuthorizationState.DisabledByConfiguration
            : reasons.Count == 0
                ? ContainmentAuthorizationState.Eligible
                : ContainmentAuthorizationState.Denied;

        return new(
            state.ToString(),
            state == ContainmentAuthorizationState.Eligible,
            reasons.Distinct(StringComparer.Ordinal).ToArray());
    }
}
