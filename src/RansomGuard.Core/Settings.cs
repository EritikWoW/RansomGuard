namespace RansomGuard.Core;
public sealed class GuardSettings
{
    public int SchemaVersion { get; set; } = 4;
    // Production enforcement is explicit. Audit remains the default; no Suspend/Kill switch is introduced here.
    public string Mode { get; set; } = "Audit";
    public EnforceSettings Enforce { get; set; } = new();
    public string[] ProtectedRoots { get; set; } = Array.Empty<string>();
    public string[] CanaryFiles { get; set; } = Array.Empty<string>();
    public int WindowSeconds { get; set; } = 10;
    public int RiskThreshold { get; set; } = 85;
    public int QueueCapacity { get; set; } = 8192;
    public int MaxProcesses { get; set; } = 256;
    public int MaxEventsPerProcess { get; set; } = 512;
    public int IncidentCooldownSeconds { get; set; } = 60;
    public int MaxEvidenceEvents { get; set; } = 128;
    public int MaxIncidents { get; set; } = 200;
    public string[] ProtectedExtensions { get; set; } = new[] {
        ".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
        ".csv", ".xml", ".json", ".jpg", ".jpeg", ".png", ".zip", ".7z", ".rar", ".sql",
        ".db", ".sqlite", ".sqlite3", ".1cd", ".dt", ".cf", ".cfe", ".dwg", ".psd" };
    public void Validate()
    {
        if (SchemaVersion != 4)
            throw new InvalidOperationException("Only schema 4 is supported. Review the 0.8.0 protection-mode settings before starting the service.");
        if (!string.Equals(Mode, "Audit", StringComparison.Ordinal) &&
            !string.Equals(Mode, "Enforce", StringComparison.Ordinal))
            throw new InvalidOperationException("Mode must be exactly Audit or Enforce.");
        if (Enforce is null)
            throw new InvalidOperationException("Enforce settings are required even when Audit mode is selected.");
        Enforce.ValidateFoundation();
        if (WindowSeconds is < 2 or > 60 || RiskThreshold is < 50 or > 300 ||
            QueueCapacity is < 128 or > 32768 || MaxProcesses is < 8 or > 1024 ||
            MaxEventsPerProcess is < 32 or > 2048 || IncidentCooldownSeconds is < 10 or > 600 ||
            MaxEvidenceEvents is < 8 or > 256 || MaxIncidents is < 1 or > 1000)
            throw new InvalidOperationException("Unsafe/out-of-range limits in settings.");
        if (ProtectedRoots is null || CanaryFiles is null || ProtectedExtensions is null ||
            ProtectedRoots.Length > 64 || CanaryFiles.Length > 64 || ProtectedExtensions.Length > 128)
            throw new InvalidOperationException("Invalid configuration arrays.");
        foreach (var path in ProtectedRoots.Concat(CanaryFiles))
            if (WinPaths.Normalize(path) is null || path.Contains('%'))
                throw new InvalidOperationException("Use explicit local absolute paths, not variables or network paths: " + path);

        if (string.Equals(Mode, "Enforce", StringComparison.Ordinal))
        {
            if (ProtectedRoots.Length != 1)
                throw new InvalidOperationException("0.8.0 Enforce foundation requires exactly one explicit ProtectedRoot; multi-root kernel orchestration is not qualified yet.");
            var normalized = WinPaths.Normalize(ProtectedRoots[0])!;
            if (normalized.Length <= 3)
                throw new InvalidOperationException("Enforce ProtectedRoot cannot be an entire drive.");
        }
    }
}

public sealed class EnforceSettings
{
    public bool RequireSignedDriver { get; set; } = true;
    public bool AutomaticContainment { get; set; } = false;
    public int StartupTimeoutSeconds { get; set; } = 30;
    public int GateWorkers { get; set; } = 4;
    public long RollbackMaxStoreMiB { get; set; } = 8192;
    public long RollbackMinFreeMiB { get; set; } = 2048;
    public int ReconnectDelaySeconds { get; set; } = 2;

    public void ValidateFoundation()
    {
        if (!RequireSignedDriver)
            throw new InvalidOperationException("Enforce cannot disable the signed-driver requirement.");
        if (AutomaticContainment)
            throw new InvalidOperationException("AutomaticContainment remains disabled until production detector-to-containment policy is separately qualified.");
        if (StartupTimeoutSeconds is < 10 or > 120)
            throw new InvalidOperationException("Enforce StartupTimeoutSeconds must be between 10 and 120 seconds.");
        if (GateWorkers is < 1 or > 8)
            throw new InvalidOperationException("Enforce GateWorkers must be between 1 and 8.");
        if (RollbackMaxStoreMiB is < 64 or > 1048576 || RollbackMinFreeMiB is < 64 or > 1048576)
            throw new InvalidOperationException("Enforce rollback storage limits must be between 64 and 1048576 MiB.");
        if (ReconnectDelaySeconds is < 1 or > 30)
            throw new InvalidOperationException("Enforce ReconnectDelaySeconds must be between 1 and 30 seconds.");
    }
}
public static class WinPaths
{
    // Pure normalization for policy comparison. Filesystem canonicalization is done separately.
    public static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var p = value.Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length < 3 || !char.IsAsciiLetter(p[0]) || p[1] != ':' || p[2] != '\\') return null;
        if (p[3..].Contains(':') || p.Contains('\0') || p.Contains('*') || p.Contains('?')) return null;
        var parts = new List<string>();
        foreach (var part in p[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") { if (parts.Count == 0) return null; parts.RemoveAt(parts.Count - 1); continue; }
            if (part.EndsWith(' ') || part.EndsWith('.')) return null;
            parts.Add(part);
        }
        return char.ToUpperInvariant(p[0]) + @":\" + string.Join("\\", parts);
    }
    public static bool Equal(string? a, string? b)
    {
        var x=Normalize(a); var y=Normalize(b);
        return x is not null && y is not null && string.Equals(x,y,StringComparison.OrdinalIgnoreCase);
    }
    public static bool Under(string? path, string? root)
    {
        var p=Normalize(path); var r=Normalize(root);
        return p is not null && r is not null &&
            p.StartsWith(r.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    }
    public static string Extension(string p)
    {
        var dot=p.LastIndexOf('.'); var slash=p.LastIndexOf('\\');
        return dot > slash ? p[dot..] : "";
    }
}
