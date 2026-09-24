namespace RansomGuard.Core;

public enum RequestedProtectionMode
{
    Audit = 0,
    Enforce = 1
}

public enum ProtectionPhase
{
    AuditOnly = 0,
    EnforceStarting = 1,
    EnforceUnavailable = 2,
    KernelConnected = 3,
    Protected = 4,
    DegradedProtected = 5,
    Maintenance = 6,
    Failed = 7,
    Stopped = 8
}

public sealed record ProtectionStatusDto(
    string RequestedMode,
    string State,
    bool RollbackStoreReady,
    bool KernelChannelConnected,
    bool KernelEnforcementActive,
    bool AutomaticContainmentActive,
    string Reason,
    DateTime ObservedUtc);

public sealed class ProtectionStateMachine
{
    private readonly object _gate = new();
    private readonly RequestedProtectionMode _requested;
    private ProtectionPhase _phase;
    private bool _rollbackReady;
    private bool _kernelConnected;
    private bool _automaticContainmentActive;
    private string _reason;
    private DateTime _observedUtc;

    public ProtectionStateMachine(string mode)
    {
        _requested = ParseMode(mode);
        _phase = _requested == RequestedProtectionMode.Audit
            ? ProtectionPhase.AuditOnly
            : ProtectionPhase.EnforceStarting;
        _reason = _requested == RequestedProtectionMode.Audit
            ? "Audit mode requested; kernel enforcement is not enabled."
            : "Enforce mode requested; production kernel lifecycle has not completed.";
        _observedUtc = DateTime.UtcNow;
    }

    public static RequestedProtectionMode ParseMode(string? mode) => mode switch
    {
        "Audit" => RequestedProtectionMode.Audit,
        "Enforce" => RequestedProtectionMode.Enforce,
        _ => throw new InvalidOperationException("Protection mode must be exactly Audit or Enforce.")
    };

    public void MarkRollbackReady()
    {
        lock (_gate)
        {
            _rollbackReady = true;
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void BeginKernelStartup()
    {
        lock (_gate)
        {
            RequireEnforce();
            if (!_rollbackReady)
                throw new InvalidOperationException("Kernel enforcement cannot start before rollback repository validation.");
            _phase = ProtectionPhase.EnforceStarting;
            _kernelConnected = false;
            _automaticContainmentActive = false;
            _reason = "Rollback repository validated; kernel enforcement startup is in progress.";
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkKernelConnected()
    {
        lock (_gate)
        {
            RequireEnforce();
            if (!_rollbackReady || _phase != ProtectionPhase.EnforceStarting)
                throw new InvalidOperationException("Kernel channel can be published only during validated Enforce startup.");
            _phase = ProtectionPhase.KernelConnected;
            _kernelConnected = true;
            _automaticContainmentActive = false;
            _reason = "Kernel channel connected; activation/preflight is not yet complete.";
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkProtected(bool automaticContainmentActive)
    {
        lock (_gate)
        {
            RequireEnforce();
            if (!_rollbackReady || !_kernelConnected || _phase != ProtectionPhase.KernelConnected)
                throw new InvalidOperationException("Protected requires rollback readiness and an activated kernel channel.");
            _phase = ProtectionPhase.Protected;
            _automaticContainmentActive = automaticContainmentActive;
            _reason = automaticContainmentActive
                ? "Kernel enforcement and automatic containment policy are active."
                : "Kernel enforcement is active; automatic containment is not enabled.";
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkDegraded(string reason)
    {
        lock (_gate)
        {
            RequireEnforce();
            if (!_rollbackReady || string.IsNullOrWhiteSpace(reason))
                throw new InvalidOperationException("DegradedProtected requires rollback readiness and an explicit reason.");
            _phase = ProtectionPhase.DegradedProtected;
            _kernelConnected = false;
            _automaticContainmentActive = false;
            _reason = reason;
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void BeginMaintenance(string reason)
    {
        lock (_gate)
        {
            RequireEnforce();
            if (string.IsNullOrWhiteSpace(reason))
                throw new InvalidOperationException("Maintenance requires an explicit reason.");
            _phase = ProtectionPhase.Maintenance;
            _automaticContainmentActive = false;
            _reason = reason;
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkUnavailable(string reason)
    {
        lock (_gate)
        {
            RequireEnforce();
            if (string.IsNullOrWhiteSpace(reason))
                throw new InvalidOperationException("EnforceUnavailable requires an explicit reason.");
            _phase = ProtectionPhase.EnforceUnavailable;
            _kernelConnected = false;
            _automaticContainmentActive = false;
            _reason = reason;
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkFailed(string reason)
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(reason))
                throw new InvalidOperationException("Failed protection state requires an explicit reason.");
            _phase = ProtectionPhase.Failed;
            _kernelConnected = false;
            _automaticContainmentActive = false;
            _reason = reason;
            _observedUtc = DateTime.UtcNow;
        }
    }

    public void MarkStopped()
    {
        lock (_gate)
        {
            _phase = ProtectionPhase.Stopped;
            _kernelConnected = false;
            _automaticContainmentActive = false;
            _reason = "Protection host stopped.";
            _observedUtc = DateTime.UtcNow;
        }
    }

    public ProtectionStatusDto Snapshot()
    {
        lock (_gate)
        {
            var kernelEnforcement = _phase is ProtectionPhase.Protected or ProtectionPhase.DegradedProtected;
            return new(
                _requested.ToString(),
                _phase.ToString(),
                _rollbackReady,
                _kernelConnected,
                kernelEnforcement,
                _automaticContainmentActive,
                _reason,
                _observedUtc);
        }
    }

    private void RequireEnforce()
    {
        if (_requested != RequestedProtectionMode.Enforce)
            throw new InvalidOperationException("Kernel enforcement transitions are invalid while Audit mode is requested.");
    }
}
