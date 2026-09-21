using System.Text.Json.Serialization;

namespace RansomGuard.Core;

public static class LocalApiContract
{
    public const int ProtocolVersion = 2;
    public const string PipeName = "RansomGuard.ReadOnly.v2";
    public const string StatusCommand = "status";
    public const string IncidentsCommand = "incidents";
    public const string DiagnosticsCommand = "diagnostics";
    public const string SubscribeCommand = "subscribe";

    public static bool IsKnownCommand(string? command) => command is StatusCommand or IncidentsCommand or DiagnosticsCommand or SubscribeCommand;
    public static int ClampIncidentLimit(int value) => Math.Clamp(value <= 0 ? 25 : value, 1, 50);
}

public sealed record ApiRequest(int Protocol, string Command, int Limit = 25);
public sealed record ApiResponse<T>(int Protocol, bool Ok, string? Error, T? Data);

public sealed record KernelComponentStatus(
    string State,
    bool Installed,
    bool Running,
    string Note);

public sealed record GuardStatusDto(
    string Product,
    string Version,
    DateTime ServiceStartedUtc,
    double UptimeSeconds,
    string ProtectionMode,
    bool AutomaticContainmentForOrdinaryProcesses,
    bool KernelEnforcementActive,
    KernelComponentStatus Minifilter,
    int ProtectedRootCount,
    int CanaryCount,
    int IncidentCount,
    DateTime? LastHeartbeatUtc,
    string SafetyNote,
    string[]? MonitoredRoots = null,
    MonitoringHealthDto? Monitor = null);

public sealed record TelemetryDto(
    DateTime? ObservedUtc,
    int? EventsLost,
    long QueueDropped,
    long IncidentQueueDropped,
    long WindowEvictions,
    long TruncatedWindows,
    long PathsResolved,
    long PathsUnresolved,
    double P50Ms,
    double P95Ms,
    double P99Ms,
    double MaxMs);

public sealed record IncidentSummaryDto(
    string CaseId,
    DateTime CapturedUtc,
    int Pid,
    string ProcessName,
    int Score,
    string Priority,
    int DistinctFiles,
    int Writes,
    int Renames,
    int Deletes,
    string SignatureStatus,
    string LocalDisposition,
    string Action,
    string[] Reasons,
    ScopedTrustDecision? ScopedTrust = null);

public sealed record DiagnosticsDto(
    string Version,
    string Runtime,
    string Os,
    bool Is64BitProcess,
    string Pipe,
    string PipePolicy,
    TelemetryDto Telemetry,
    string[] Notes,
    MonitoringHealthDto? Monitor = null, ScopedRuleSetDto? ScopedRules = null);

// No key material, memory addresses or arbitrary write commands are sent to the UI.
public sealed record RecoverySummaryDto(string State, string? Algorithm, bool KeyRecovered,
    int DecryptedFiles, int VerifiedFiles, int SelectedFiles, string Note, DateTime ObservedUtc);
public sealed record LiveFrame(int Protocol, string InstanceId, long Sequence, long StateRevision,
    string Kind, DateTime SentUtc, GuardStatusDto Status, DiagnosticsDto? Diagnostics,
    IncidentSummaryDto[]? Incidents, RecoverySummaryDto? Recovery,
    long IncidentRevision, int RetainedIncidentCount);

// Limited read-only summaries: approval notes, full paths, and user SIDs stay in the administrator-only store.
public sealed record ScopedRuleSummaryDto(string Id, string Name, string ExecutableName, string Sha256,
    bool Enabled, DateTime ExpiresUtc, string[] Operations, int DirectoryCount, string Effect, bool OneRunOnly,
    string State, DateTime? LastCheckedUtc, string LastResult, long MatchedIncidents, long QuietedWarnings);
public sealed record ScopedRuleSetDto(string StoreState, long Revision, string StoreDigest, DateTime ObservedUtc,
    ScopedRuleSummaryDto[] Rules, string Note);
