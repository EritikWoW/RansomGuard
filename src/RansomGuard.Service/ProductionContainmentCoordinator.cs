using System.ComponentModel;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal sealed record ProductionContainmentLiveState(
    ProtectionStatusDto Protection,
    bool TelemetryHealthy);

internal sealed record ProductionContainmentAttemptResult(
    string Action,
    bool Attempted,
    bool Suspended,
    bool ExplicitResumeApplied,
    bool Completed,
    string Reason,
    string[] Reasons,
    string? RequestId,
    string? AuthorizationId);

internal sealed class ProductionContainmentCoordinator
{
    private static readonly TimeSpan AuthorizationLifetime = TimeSpan.FromSeconds(5);

    private readonly ILogger<ProductionContainmentCoordinator> _log;
    private readonly GuardSettings _settings;
    private readonly SecureStore _store;
    private readonly ImageInspector _images;
    private readonly ContainmentStateChangeJournal _journal;

    internal ProductionContainmentCoordinator(
        ILogger<ProductionContainmentCoordinator> log,
        GuardSettings settings,
        SecureStore store,
        ImageInspector images,
        ContainmentStateChangeJournal journal)
    {
        _log = log;
        _settings = settings;
        _store = store;
        _images = images;
        _journal = journal;
    }

    internal async Task<ProductionContainmentAttemptResult> AttemptAsync(
        string caseDirectory,
        string caseId,
        RiskSignal risk,
        ImageEvidence authorizedImage,
        DateTime authorizationEvaluatedUtc,
        ContainmentAuthorizationInput authorizationInput,
        ContainmentAuthorizationDecision authorization,
        Func<ProductionContainmentLiveState> captureLiveState,
        CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caseDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(caseId);
        ArgumentNullException.ThrowIfNull(risk);
        ArgumentNullException.ThrowIfNull(authorizedImage);
        ArgumentNullException.ThrowIfNull(authorizationInput);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(captureLiveState);

        if (!_settings.Enforce.AutomaticContainment || !authorization.Eligible)
        {
            return new(
                "NotAuthorized",
                false,
                false,
                false,
                false,
                authorization.Eligible ? "DisabledByConfiguration" : "AuthorizationDenied",
                authorization.Reasons ?? Array.Empty<string>(),
                null,
                null);
        }

        if (!string.Equals(authorizedImage.Status, "Hashed", StringComparison.Ordinal) ||
            authorizedImage.Path is null ||
            authorizedImage.Sha256 is null)
        {
            return new(
                "Denied",
                false,
                false,
                false,
                false,
                "FreshImageIdentityUnavailable",
                new[] { "FreshImageIdentityUnavailable" },
                null,
                null);
        }

        var authorizationId = Guid.NewGuid().ToString("N");
        var requestId = Guid.NewGuid().ToString("N");
        ContainmentActuationBinding binding;
        try
        {
            binding = ContainmentActuationBindingFactory.Create(
                authorizationId,
                caseId,
                authorizationEvaluatedUtc,
                AuthorizationLifetime,
                risk.Process,
                authorizedImage.Path,
                authorizedImage.Sha256,
                authorizationInput.Protection,
                authorization);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        {
            return new(
                "Denied",
                false,
                false,
                false,
                false,
                "BindingRejected",
                new[] { ex.Message },
                requestId,
                authorizationId);
        }

        WindowsProcessStateChangeLease? lease = null;
        var prepared = false;
        var suspendApplied = false;
        var explicitResume = false;

        try
        {
            token.ThrowIfCancellationRequested();

            lease = WindowsProcessStateChangeLease.Open(
                binding.Process,
                path =>
                {
                    var fresh = _images.Inspect(path, fresh: true);
                    return string.Equals(fresh.Status, "Hashed", StringComparison.Ordinal)
                        ? fresh.Sha256
                        : null;
                });

            var live = captureLiveState();
            var protectedService = IsProtectedRansomGuardProcess(lease.ImagePath);
            var self = lease.Process.Pid == Environment.ProcessId;
            var validation = ContainmentActuationPolicy.Evaluate(
                new(
                    binding,
                    DateTime.UtcNow,
                    lease.Process,
                    lease.ImagePath,
                    lease.ImageSha256,
                    live.Protection,
                    live.TelemetryHealthy,
                    lease.CriticalStateKnown,
                    lease.IsCritical,
                    self,
                    protectedService,
                    _journal.IsAuthorizationConsumed(binding.AuthorizationId)));

            if (!validation.Ready)
            {
                return new(
                    "Denied",
                    false,
                    false,
                    false,
                    false,
                    "RevalidationDenied",
                    validation.Reasons,
                    requestId,
                    authorizationId);
            }

            var request = new ContainmentActuationRequest(
                requestId,
                binding,
                DateTime.UtcNow);

            var preparedEntry = _journal.Prepare(request, validation);
            prepared = true;

            _store.WriteJson(
                Path.Combine(caseDirectory, "containment-actuation-pre.json"),
                new
                {
                    SchemaVersion = 1,
                    Version = ProductInfo.Version,
                    Utc = DateTime.UtcNow,
                    Request = request,
                    Validation = validation,
                    Journal = preparedEntry,
                    Backend = "WindowsProcessStateChange",
                    HoldMilliseconds = _settings.Enforce.ContainmentHoldMilliseconds,
                    Note = "Durable pre-actuation evidence. No successful suspend is implied until SuspendApplied exists."
                });

            token.ThrowIfCancellationRequested();
            lease.Suspend();
            suspendApplied = true;
            var suspendedEntry = _journal.RecordSuspendApplied(requestId);

            _store.WriteJson(
                Path.Combine(caseDirectory, "containment-actuation-suspended.json"),
                new
                {
                    SchemaVersion = 1,
                    Version = ProductInfo.Version,
                    Utc = DateTime.UtcNow,
                    RequestId = requestId,
                    AuthorizationId = authorizationId,
                    Journal = suspendedEntry,
                    Backend = "WindowsProcessStateChange",
                    Note = "Process state-change suspend applied to the exact bound process instance."
                });

            await Task.Delay(
                TimeSpan.FromMilliseconds(_settings.Enforce.ContainmentHoldMilliseconds),
                token).ConfigureAwait(false);

            lease.Resume();
            explicitResume = true;
            var resumedEntry = _journal.RecordExplicitResumeApplied(requestId);
            var completedEntry = _journal.RecordCompleted(requestId);

            var result = new ProductionContainmentAttemptResult(
                "StateChangeContained",
                true,
                true,
                true,
                true,
                "Completed",
                Array.Empty<string>(),
                requestId,
                authorizationId);

            _store.WriteJson(
                Path.Combine(caseDirectory, "containment-actuation-result.json"),
                new
                {
                    SchemaVersion = 1,
                    Version = ProductInfo.Version,
                    Utc = DateTime.UtcNow,
                    Result = result,
                    Resume = resumedEntry,
                    Completed = completedEntry,
                    Backend = "WindowsProcessStateChange"
                });

            _store.Audit(new
            {
                Utc = DateTime.UtcNow,
                Event = "ProductionContainmentCompleted",
                caseId,
                risk.Process,
                RequestId = requestId,
                AuthorizationId = authorizationId,
                Backend = "WindowsProcessStateChange"
            });

            return result;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            explicitResume = TryExplicitResume(lease, prepared, requestId, explicitResume);
            if (prepared)
                TryRecordAbnormal(requestId, explicitResume ? "ActuationCancelledAfterResume" : "ActuationCancelledCrashRelease");

            return new(
                "Cancelled",
                prepared,
                suspendApplied,
                explicitResume,
                false,
                "ActuationCancelled",
                new[] { "ActuationCancelled" },
                requestId,
                authorizationId);
        }
        catch (Exception ex) when (
            ex is IOException or
            UnauthorizedAccessException or
            Win32Exception or
            InvalidOperationException or
            PlatformNotSupportedException)
        {
            explicitResume = TryExplicitResume(lease, prepared, requestId, explicitResume);
            if (prepared)
                TryRecordAbnormal(requestId, explicitResume ? "HandledFailureAfterResume" : "HandledFailureCrashRelease");

            _log.LogError(
                ex,
                "Production containment failed closed for pid={Pid}; request={RequestId}; explicitResume={ExplicitResume}.",
                risk.Process.Pid,
                requestId,
                explicitResume);

            return new(
                "FailedClosed",
                prepared,
                suspendApplied,
                explicitResume,
                false,
                ex.GetType().Name,
                new[] { ex.Message },
                requestId,
                authorizationId);
        }
        finally
        {
            lease?.Dispose();
        }
    }

    private bool TryExplicitResume(
        WindowsProcessStateChangeLease? lease,
        bool prepared,
        string requestId,
        bool alreadyResumed)
    {
        if (lease is null || !lease.IsSuspended || alreadyResumed)
            return alreadyResumed;

        try
        {
            lease.Resume();
            if (prepared)
                _journal.RecordExplicitResumeApplied(requestId);
            return true;
        }
        catch (Exception ex) when (
            ex is IOException or
            Win32Exception or
            InvalidOperationException or
            ObjectDisposedException)
        {
            _log.LogCritical(
                ex,
                "Explicit state-change resume failed for request={RequestId}; final handle release remains the crash-release safety backstop.",
                requestId);
            return false;
        }
    }

    private void TryRecordAbnormal(string requestId, string reasonCode)
    {
        try
        {
            _journal.RecordAbnormal(requestId, reasonCode);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            _log.LogCritical(
                ex,
                "Unable to append terminal abnormal containment evidence for request={RequestId}.",
                requestId);
        }
    }

    internal static bool IsProtectedRansomGuardProcess(string? imagePath)
    {
        var normalized = WinPaths.Normalize(imagePath);
        if (normalized is null)
            return true;

        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var candidates = new[]
        {
            Environment.ProcessPath,
            Path.Combine(baseDirectory, "RansomGuard.Service.exe"),
            Path.Combine(baseDirectory, "RansomGuard.Management.exe"),
            Path.Combine(baseDirectory, "Protection", "GateClient", "RansomGuard.GateClient.exe")
        };

        return candidates.Any(candidate =>
            candidate is not null &&
            WinPaths.Equal(normalized, candidate));
    }
}
