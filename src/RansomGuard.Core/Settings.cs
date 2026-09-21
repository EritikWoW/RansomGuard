namespace RansomGuard.Core;
public sealed class GuardSettings
{
    public int SchemaVersion { get; set; } = 3;
    // There is deliberately no production Suspend/Kill switch. --lab enrolls only our child.
    public string Mode { get; set; } = "Audit";
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
        if (SchemaVersion != 3 || !string.Equals(Mode, "Audit", StringComparison.Ordinal))
            throw new InvalidOperationException("Only schema 3 / Mode=Audit is supported. Do not copy v0.2 appsettings.json. Use test_lab.cmd for the isolated test.");
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
