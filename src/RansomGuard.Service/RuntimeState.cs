using System.Runtime.InteropServices;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed class RuntimeState
{
    private readonly object _gate = new();
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly string _instanceId = Guid.NewGuid().ToString("N");
    private readonly List<IncidentSummaryDto> _incidents = new();
    private readonly ChangePulse _pulse = new();
    private TelemetryDto _telemetry = new(null,null,0,0,0,0,0,0,0,0,0,0);
    private MonitoringHealthDto _monitor = new("Starting", DateTime.UtcNow, "");
    private KernelComponentStatus _driver = new("Unknown",false,false,"Not queried yet.");
    private ProtectionStatusDto _protection;
    private RecoverySummaryDto _recovery = new("NotStarted",null,false,0,0,0,
        "Offline recovery needs a dump and a supported encrypted file format. Ordinary processes remain audit-only.",DateTime.UtcNow);
    private ScopedRuleSetDto? _scopedRules;
    private ContainmentAuthorizationDecision? _containmentAuthorization;
    private long _revision, _telemetryRevision, _incidentRevision, _recoveryRevision;
    public RuntimeState(ProtectionStatusDto protection)
    {
        ProtectionStateMachine.ValidateSnapshot(protection);
        _protection = protection;
    }
    public DateTime StartedUtc => _startedUtc;
    public ChangePulse.Subscription Subscribe() => _pulse.Subscribe();
    public void UpdateMonitor(MonitoringHealthDto health)
    {
        lock (_gate)
        {
            _monitor = health; _revision++;
            if (!MonitoringHealth.IsRunning(health))
            { _telemetry = new(null,null,0,0,0,0,0,0,0,0,0,0); _telemetryRevision++; }
        }
        _pulse.Signal();
    }
    public void UpdateScopedRules(ScopedRuleSetDto value)
    {
        bool changed;
        lock (_gate)
        {
            var previous=_scopedRules;
            changed=previous is null || value.StoreDigest!=previous.StoreDigest || value.StoreState!=previous.StoreState ||
                !System.Text.Json.JsonSerializer.Serialize(value.Rules).Equals(System.Text.Json.JsonSerializer.Serialize(previous.Rules),StringComparison.Ordinal);
            if(changed){_scopedRules=value;_telemetryRevision++;_revision++;}
        }
        if(changed)_pulse.Signal();
    }
    public void TouchServiceHeartbeat() { } // Live transport sends its own heartbeat.
    public void UpdateTelemetry(TelemetryDto telemetry)
    { lock (_gate) { _telemetry=telemetry; _revision++; _telemetryRevision++; } _pulse.Signal(); }
    public void UpdateRecovery(RecoverySummaryDto value)
    { lock (_gate) { _recovery=value; _revision++; _recoveryRevision++; } _pulse.Signal(); }
    public void UpdateProtection(ProtectionStatusDto value)
    {
        ProtectionStateMachine.ValidateSnapshot(value);
        lock (_gate) { _protection=value; _revision++; _telemetryRevision++; }
        _pulse.Signal();
    }
    public ProtectionStatusDto Protection() { lock(_gate) return _protection; }
    public MonitoringHealthDto Monitor() { lock(_gate) return _monitor; }
    public void UpdateContainmentAuthorization(ContainmentAuthorizationDecision value)
    {
        ArgumentNullException.ThrowIfNull(value);
        lock (_gate)
        {
            _containmentAuthorization=value;
            _revision++;
            _telemetryRevision++;
        }
        _pulse.Signal();
    }
    public void RefreshDriverStatus()
    {
        var result=DriverServiceProbe.Query("RansomGuardMinifilter");
        bool changed;
        lock (_gate) { changed=result!=_driver; if(changed){_driver=result;_revision++;} }
        if(changed)_pulse.Signal();
    }
    public void RecordIncident(IncidentSummaryDto incident)
    {
        lock (_gate)
        {
            var existing=_incidents.FindIndex(x=>x.CaseId==incident.CaseId);
            if(existing>=0)_incidents[existing]=incident; else _incidents.Insert(0,incident);
            if(_incidents.Count>100)_incidents.RemoveRange(100,_incidents.Count-100);
            _incidentRevision++; _revision++;
        }
        _pulse.Signal();
    }
    private GuardStatusDto StatusLocked(GuardSettings settings)
    {
        var mode = string.Equals(_protection.RequestedMode, "Audit", StringComparison.Ordinal)
            ? MonitoringHealth.ProtectionMode(_monitor)
            : _protection.State;
        var note = _protection.KernelEnforcementActive
            ? _protection.Reason
            : "Live connection and a running driver service are not proof of kernel enforcement. " + _protection.Reason;
        return new(
            "RansomGuard",ProductInfo.Version,_startedUtc,Math.Max(0,(DateTime.UtcNow-_startedUtc).TotalSeconds),
            mode,_protection.AutomaticContainmentActive,_protection.KernelEnforcementActive,_driver,settings.ProtectedRoots.Length,
            settings.CanaryFiles.Length,_incidents.Count,DateTime.UtcNow,note,
            settings.ProtectedRoots.ToArray(),_monitor,_protection);
    }
    public GuardStatusDto Status(GuardSettings settings) { lock(_gate)return StatusLocked(settings); }
    public IncidentSummaryDto[] Incidents(int limit)
    { lock(_gate)return _incidents.Take(LocalApiContract.ClampIncidentLimit(limit)).ToArray(); }
    private DiagnosticsDto DiagnosticsLocked() => new(ProductInfo.Version,RuntimeInformation.FrameworkDescription,
        RuntimeInformation.OSDescription,Environment.Is64BitProcess,$@"\\.\pipe\{LocalApiContract.PipeName}",
        "Local read-only framed stream. NETWORK and ANONYMOUS denied. Bounded snapshots; 4 connections; write deadlines.",
        _telemetry,new[]{"Live UI does not remove ETW delivery delay.",
        "The durable rollback repository must validate before production kernel startup may begin.",
        "No key material is sent to the UI. Reconnect receives only the latest 50 incident summaries; the protected archive is separate.",
        "Containment authorization is read-only policy evidence; it does not imply that an actuator ran.",
        "A connected UI or SCM Running state is not proof of kernel enforcement; use the explicit protection state."},_monitor,_scopedRules,_protection,_containmentAuthorization);
    public DiagnosticsDto Diagnostics() {lock(_gate)return DiagnosticsLocked();}
    public LiveFrame Frame(GuardSettings settings,long sequence,bool full,ref long telemetrySeen,
        ref long incidentSeen,ref long recoverySeen,ref long stateSeen)
    {
        lock(_gate)
        {
            bool changed=stateSeen!=_revision;
            var frame=new LiveFrame(LocalApiContract.ProtocolVersion,_instanceId,sequence,_revision,
                full?"snapshot":changed?"update":"heartbeat",DateTime.UtcNow,StatusLocked(settings),
                full||telemetrySeen!=_telemetryRevision?DiagnosticsLocked():null,
                full||incidentSeen!=_incidentRevision?_incidents.Take(50).ToArray():null,
                full||recoverySeen!=_recoveryRevision?_recovery:null,_incidentRevision,_incidents.Count);
            telemetrySeen=_telemetryRevision;incidentSeen=_incidentRevision;recoverySeen=_recoveryRevision;stateSeen=_revision;
            return frame;
        }
    }
}

internal static class DriverServiceProbe
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorServiceDoesNotExist = 1060;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string serviceName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatusProcess status, int bufferSize, out int bytesNeeded);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static KernelComponentStatus Query(string serviceName)
    {
        if (!OperatingSystem.IsWindows()) return new("Unsupported", false, false, "Windows service manager unavailable.");
        var scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return new("Unknown", false, false, "Unable to query Service Control Manager.");
        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                return error == ErrorServiceDoesNotExist
                    ? new("NotInstalled", false, false, "Minifilter service is not installed on this machine.")
                    : new("Unknown", false, false, $"Minifilter status query failed (Win32 {error}).");
            }
            try
            {
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _))
                    return new("Unknown", true, false, $"Minifilter status query failed (Win32 {Marshal.GetLastWin32Error()}).");
                var state = status.CurrentState switch
                {
                    1 => "Stopped",
                    2 => "StartPending",
                    3 => "StopPending",
                    4 => "Running",
                    5 => "ContinuePending",
                    6 => "PausePending",
                    7 => "Paused",
                    _ => "Unknown"
                };
                var running = status.CurrentState == 4;
                return new(state, true, running, running
                    ? "Service reports running. Kernel enforcement is claimed only by the explicit protection state machine after activation."
                    : "Installed but not running.");
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
