using System.Security.Cryptography;
using System.Text.Json;

namespace RansomGuard.Core;

public enum ContainmentActuationValidationState
{
    Denied = 0,
    Ready = 1
}

public sealed record ContainmentActuationBinding(
    string AuthorizationId,
    string CaseId,
    DateTime EvaluatedUtc,
    DateTime ExpiresUtc,
    ProcessKey Process,
    string ImagePath,
    string ImageSha256,
    DateTime ProtectionObservedUtc,
    ContainmentAuthorizationDecision Authorization);

public sealed record ContainmentActuationValidationInput(
    ContainmentActuationBinding Binding,
    DateTime NowUtc,
    ProcessKey LiveProcess,
    string? LiveImagePath,
    string? LiveImageSha256,
    ProtectionStatusDto CurrentProtection,
    bool TelemetryHealthy,
    bool CriticalStateKnown,
    bool IsCritical,
    bool IsSelf,
    bool IsProtectedServiceProcess,
    bool AuthorizationConsumed);

public sealed record ContainmentActuationValidationDecision(
    string State,
    bool Ready,
    string[] Reasons,
    string BindingFingerprint = "");

public static class ContainmentActuationPolicy
{
    public static readonly TimeSpan MaxAuthorizationLifetime = TimeSpan.FromSeconds(10);

    public static ContainmentActuationValidationDecision Evaluate(ContainmentActuationValidationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var reasons = new List<string>();
        var binding = input.Binding;

        if (binding is null)
        {
            reasons.Add("BindingMissing");
            return Denied(reasons);
        }

        if (!Guid.TryParseExact(binding.AuthorizationId, "N", out _))
            reasons.Add("AuthorizationIdInvalid");
        if (string.IsNullOrWhiteSpace(binding.CaseId))
            reasons.Add("CaseIdMissing");
        if (binding.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            binding.ExpiresUtc.Kind != DateTimeKind.Utc ||
            binding.ProtectionObservedUtc.Kind != DateTimeKind.Utc ||
            input.NowUtc.Kind != DateTimeKind.Utc)
            reasons.Add("TimestampNotUtc");
        if (binding.ExpiresUtc <= binding.EvaluatedUtc ||
            binding.ExpiresUtc - binding.EvaluatedUtc > MaxAuthorizationLifetime)
            reasons.Add("AuthorizationLifetimeInvalid");
        if (input.NowUtc < binding.EvaluatedUtc)
            reasons.Add("AuthorizationNotYetValid");
        if (input.NowUtc > binding.ExpiresUtc)
            reasons.Add("AuthorizationExpired");

        if (binding.Authorization is null ||
            !binding.Authorization.Eligible ||
            !string.Equals(binding.Authorization.State, ContainmentAuthorizationState.Eligible.ToString(), StringComparison.Ordinal) ||
            binding.Authorization.Reasons is null ||
            binding.Authorization.Reasons.Length != 0)
            reasons.Add("AuthorizationNotEligible");

        if (input.AuthorizationConsumed)
            reasons.Add("AuthorizationAlreadyConsumed");

        if (binding.Process.Pid <= 4 || binding.Process.CreationFileTimeUtc <= 0)
            reasons.Add("BoundProcessInvalid");
        if (input.LiveProcess != binding.Process)
            reasons.Add("ProcessIdentityChanged");

        var boundPath = WinPaths.Normalize(binding.ImagePath);
        var livePath = WinPaths.Normalize(input.LiveImagePath);
        if (boundPath is null)
            reasons.Add("BoundImagePathInvalid");
        if (livePath is null || boundPath is null || !WinPaths.Equal(boundPath, livePath))
            reasons.Add("ImagePathChanged");
        if (!DecisionPolicy.HashEqual(binding.ImageSha256, binding.ImageSha256))
            reasons.Add("BoundImageHashInvalid");
        if (!DecisionPolicy.HashEqual(binding.ImageSha256, input.LiveImageSha256))
            reasons.Add("ImageHashChanged");

        var protectionValid = true;
        try
        {
            ProtectionStateMachine.ValidateSnapshot(input.CurrentProtection);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentNullException)
        {
            protectionValid = false;
            reasons.Add("ProtectionSnapshotInvalid");
        }

        if (protectionValid)
        {
            if (!string.Equals(input.CurrentProtection.RequestedMode, RequestedProtectionMode.Enforce.ToString(), StringComparison.Ordinal))
                reasons.Add("RequestedModeNotEnforce");
            if (!string.Equals(input.CurrentProtection.State, ProtectionPhase.Protected.ToString(), StringComparison.Ordinal))
                reasons.Add("ProtectionStateNotProtected");
            if (!input.CurrentProtection.RollbackStoreReady)
                reasons.Add("RollbackStoreNotReady");
            if (!input.CurrentProtection.KernelChannelConnected)
                reasons.Add("KernelChannelNotConnected");
            if (!input.CurrentProtection.KernelEnforcementActive)
                reasons.Add("KernelEnforcementNotActive");
            if (input.CurrentProtection.ObservedUtc != binding.ProtectionObservedUtc)
                reasons.Add("ProtectionSnapshotChanged");
        }

        if (!input.TelemetryHealthy)
            reasons.Add("TelemetryNoLongerHealthy");
        if (!input.CriticalStateKnown)
            reasons.Add("CriticalStateUnknown");
        else if (input.IsCritical)
            reasons.Add("CriticalProcess");
        if (input.IsSelf)
            reasons.Add("SelfProcess");
        if (input.IsProtectedServiceProcess)
            reasons.Add("ProtectedServiceProcess");

        if (reasons.Count != 0)
            return Denied(reasons);

        return new(
            ContainmentActuationValidationState.Ready.ToString(),
            true,
            Array.Empty<string>(),
            ComputeBindingFingerprint(binding));
    }

    public static string ComputeBindingFingerprint(ContainmentActuationBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var normalizedPath = WinPaths.Normalize(binding.ImagePath)
            ?? throw new InvalidDataException("Containment actuation binding image path is invalid.");
        if (!DecisionPolicy.HashEqual(binding.ImageSha256, binding.ImageSha256))
            throw new InvalidDataException("Containment actuation binding SHA-256 is invalid.");

        var payload = new ContainmentActuationBindingFingerprintPayload(
            binding.AuthorizationId.ToLowerInvariant(),
            binding.CaseId,
            binding.EvaluatedUtc.Ticks,
            binding.ExpiresUtc.Ticks,
            binding.Process.Pid,
            binding.Process.CreationFileTimeUtc,
            normalizedPath.ToUpperInvariant(),
            binding.ImageSha256.ToUpperInvariant(),
            binding.ProtectionObservedUtc.Ticks,
            binding.Authorization.State,
            binding.Authorization.Eligible,
            binding.Authorization.Reasons ?? Array.Empty<string>());
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload)));
    }

    private static ContainmentActuationValidationDecision Denied(IEnumerable<string> reasons) =>
        new(
            ContainmentActuationValidationState.Denied.ToString(),
            false,
            reasons.Distinct(StringComparer.Ordinal).ToArray(),
            "");
}

internal sealed record ContainmentActuationBindingFingerprintPayload(
    string AuthorizationId,
    string CaseId,
    long EvaluatedUtcTicks,
    long ExpiresUtcTicks,
    int ProcessId,
    long ProcessCreationFileTimeUtc,
    string ImagePath,
    string ImageSha256,
    long ProtectionObservedUtcTicks,
    string AuthorizationState,
    bool AuthorizationEligible,
    string[] AuthorizationReasons);
