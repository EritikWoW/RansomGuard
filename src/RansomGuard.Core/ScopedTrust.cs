using System.Text.RegularExpressions;

namespace RansomGuard.Core;

// Exception means a narrowly scoped review preference, never an exemption from monitoring.
public sealed record ScopedTrustRule
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string ImagePath { get; init; }
    public required string Sha256 { get; init; }
    public required string UserSid { get; init; }
    public required string[] Roots { get; init; }
    public required string[] Operations { get; init; }
    public required string SignaturePolicy { get; init; } // ValidEmbedded or ExactUnsignedHash
    public string? CertificateSha256 { get; init; }
    public ProcessKey? Instance { get; init; } // Optional one-run authorization; never inherited by children.
    public string Effect { get; init; } = "AnnotateOnly";
    public bool Enabled { get; init; } = true;
    public int MaxDistinctFiles { get; init; } = 16;
    public int MaxWrites { get; init; } = 256;
    public int MaxRenames { get; init; } = 16;
    public int MaxDeletes { get; init; } = 16;
    public int QuietSeconds { get; init; } = 120;
    public required DateTime CreatedUtc { get; init; }
    public required DateTime ExpiresUtc { get; init; }
    public required string ApprovedBySid { get; init; }
    public required string Reason { get; init; }
}

public sealed record ScopedTrustDocument(int SchemaVersion, long Revision, DateTime UpdatedUtc, ScopedTrustRule[] Rules);
public sealed record ScopedProcessEvidence(ProcessKey Process, string? UserSid, ImageEvidence Image,
    bool IdentityVerified, bool PathsChecked, DateTime VerifiedUtc, string? Error);
public sealed record ScopedTrustDecision(bool Applies, string? RuleId, string Effect, string Reason,
    bool NotificationQuieted = false, string? RulesDigest = null, DateTime? CheckedUtc = null)
{
    public static ScopedTrustDecision No(string reason, string? ruleId = null) => new(false, ruleId, "None", reason);
}

public static class ScopedTrustPolicy
{
    public const int SchemaVersion = 1;
    public const int MaxRules = 128;
    public const int MaxStoreBytes = 512 * 1024;
    public const int MaxRuleDays = 30;
    public static bool SidValid(string? sid) => sid is not null && sid.Length <= 184 &&
        Regex.IsMatch(sid, @"\AS-1-\d{1,15}(?:-\d{1,10}){1,15}\z", RegexOptions.CultureInvariant);
    public static bool ExactLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1024 || path.Contains('%') ||
            path.Any(char.IsControl) || path.IndexOfAny(new[] {'"','<','>','|'}) >= 0) return false;
        var normalized = WinPaths.Normalize(path);
        // No variables, device namespaces, traversal, aliases, trailing separators or implicit expansion.
        return normalized is not null && path.Length > 3 &&
            string.Equals(path, normalized, StringComparison.OrdinalIgnoreCase);
    }
    public static bool NarrowRoot(string? path) => ExactLocalPath(path) && path![3..].Split('\\').Length >= 2;
    public static void Validate(ScopedTrustRule r)
    {
        if (!Guid.TryParseExact(r.Id, "N", out _) || string.IsNullOrWhiteSpace(r.Name) || r.Name.Length > 80 ||
            r.Name.Any(char.IsControl) || !ExactLocalPath(r.ImagePath) || !r.ImagePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            !DecisionPolicy.HashEqual(r.Sha256, r.Sha256) || !SidValid(r.UserSid) || !SidValid(r.ApprovedBySid))
            throw new ArgumentException("Invalid rule identity: exact local EXE, SHA-256 and user SID are required.");
        if (r.Roots is null || r.Roots.Length is < 1 or > 8 || r.Roots.Any(x => !NarrowRoot(x)) ||
            r.Roots.Distinct(StringComparer.OrdinalIgnoreCase).Count() != r.Roots.Length)
            throw new ArgumentException("Use 1-8 explicit narrow local directories; drive roots, traversal and wildcards are forbidden.");
        if (r.Operations is null || r.Operations.Length is < 1 or > 3 ||
            r.Operations.Any(x => x is not ("Write" or "Rename" or "Delete")) || r.Operations.Distinct().Count() != r.Operations.Length)
            throw new ArgumentException("Operations must be a unique subset of Write, Rename, Delete.");
        if (r.SignaturePolicy is not ("ValidEmbedded" or "ExactUnsignedHash") ||
            (r.SignaturePolicy == "ValidEmbedded" && !DecisionPolicy.HashEqual(r.CertificateSha256, r.CertificateSha256)) ||
            (r.SignaturePolicy == "ExactUnsignedHash" && r.CertificateSha256 is not null))
            throw new ArgumentException("Require a valid embedded signer, or explicitly approve this exact unsigned hash.");
        if (r.Effect is not ("AnnotateOnly" or "QuietRepeat") || r.QuietSeconds is < 30 or > 600 ||
            r.MaxDistinctFiles is < 1 or > 64 || r.MaxWrites is < 1 or > 2048 ||
            r.MaxRenames is < 0 or > 32 || r.MaxDeletes is < 0 or > 32)
            throw new ArgumentException("Rule effect or operation limits are out of range.");
        if (r.CreatedUtc.Kind != DateTimeKind.Utc || r.ExpiresUtc.Kind != DateTimeKind.Utc ||
            r.ExpiresUtc <= r.CreatedUtc || r.ExpiresUtc - r.CreatedUtc > TimeSpan.FromDays(MaxRuleDays) ||
            string.IsNullOrWhiteSpace(r.Reason) || r.Reason.Length > 400 || r.Reason.Any(char.IsControl))
            throw new ArgumentException("Require a UTC lifetime of at most 30 days and a one-line approval reason.");
        if (r.Instance is ProcessKey p && (p.Pid <= 4 || p.CreationFileTimeUtc <= 0))
            throw new ArgumentException("Invalid one-run process identity.");
    }
    public static void ValidateDocument(ScopedTrustDocument document)
    {
        if (document.SchemaVersion != SchemaVersion || document.Revision < 1 || document.UpdatedUtc.Kind != DateTimeKind.Utc ||
            document.Rules is null || document.Rules.Length > MaxRules || document.Rules.Any(r => r is null))
            throw new ArgumentException("Invalid scoped trust document.");
        foreach (var r in document.Rules) Validate(r);
        if (document.Rules.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != document.Rules.Length)
            throw new ArgumentException("Duplicate rule identifier.");
    }
    public static ScopedTrustDecision Evaluate(ScopedTrustRule rule, RiskSignal risk, ScopedProcessEvidence proof,
        bool telemetryHealthy, bool confirmedCanary, bool suspiciousContentChange, bool isLab, DateTime now)
    {
        ScopedTrustDecision No(string why) => ScopedTrustDecision.No(why, rule.Id);
        try { Validate(rule); } catch (ArgumentException) { return No("InvalidRule"); }
        if (!rule.Enabled) return No("Disabled");
        if (now.Kind != DateTimeKind.Utc || now < rule.CreatedUtc || now >= rule.ExpiresUtc) return No("ExpiredOrClockInvalid");
        if (isLab) return No("LabNeverExempted");
        if (confirmedCanary || risk.CanaryCandidate || risk.Evidence.Any(e => e.CanaryCandidate)) return No("CanaryOverridesRule");
        if (suspiciousContentChange) return No("ContentEvidenceOverridesRule");
        if (proof.Image.LocalDisposition != "Unknown" && proof.Image.LocalDisposition != "ReviewedTrusted")
            return No("DenyOrReputationStateUnknown");
        if (!telemetryHealthy || risk.TruncatedWindow || risk.Writes < 0 || risk.Renames < 0 || risk.Deletes < 0 ||
            risk.Evidence.Length == 0 || (long)risk.Writes + risk.Renames + risk.Deletes != risk.Evidence.LongLength)
            return No("IncompleteEvidence");
        if (risk.Evidence.Any(e => e.Process != risk.Process || e.EventUtc.Kind != DateTimeKind.Utc ||
                e.ReceivedUtc.Kind != DateTimeKind.Utc || e.EventUtc > e.ReceivedUtc.AddSeconds(1)) ||
            risk.Evidence.Count(e => e.Kind == FileKind.Write) != risk.Writes ||
            risk.Evidence.Count(e => e.Kind == FileKind.Rename) != risk.Renames ||
            risk.Evidence.Count(e => e.Kind == FileKind.Delete) != risk.Deletes ||
            risk.Evidence.Select(e => WinPaths.Normalize(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != risk.DistinctFiles)
            return No("EvidenceCountersMismatch");
        if (now < risk.DetectedUtc || now - risk.DetectedUtc > TimeSpan.FromSeconds(10) ||
            risk.Evidence.Any(e => now - e.EventUtc > TimeSpan.FromSeconds(60) || now < e.EventUtc ||
                e.EventUtc < rule.CreatedUtc || e.EventUtc >= rule.ExpiresUtc)) return No("StaleEvidenceOrPreApproval");
        if (risk.Process.Pid <= 4 || risk.Process.CreationFileTimeUtc <= 0 || proof.Error is not null || !proof.IdentityVerified || !proof.PathsChecked || proof.Process != risk.Process ||
            proof.UserSid != rule.UserSid || proof.VerifiedUtc > now || now - proof.VerifiedUtc > TimeSpan.FromSeconds(5) ||
            (rule.Instance is ProcessKey instance && instance != proof.Process)) return No("ProcessOrUserNotVerified");
        if (!WinPaths.Equal(rule.ImagePath, risk.ImagePath) || !WinPaths.Equal(rule.ImagePath, proof.Image.Path) ||
            proof.Image.Status != "Hashed" || proof.Image.Error is not null ||
            proof.Image.ObservedUtc > now || now - proof.Image.ObservedUtc > TimeSpan.FromSeconds(5) ||
            !DecisionPolicy.HashEqual(rule.Sha256, proof.Image.Sha256)) return No("ImageChangedOrNotFresh");
        if (rule.SignaturePolicy == "ValidEmbedded")
        {
            if (proof.Image.Signature.Status != "ValidCached" || proof.Image.Signature.NativeStatus != "0x00000000" ||
                !DecisionPolicy.HashEqual(rule.CertificateSha256, proof.Image.Signature.CertificateThumbprint))
                return No("SignatureNotVerified");
        }
        else if (proof.Image.Signature.Status != "NoEmbeddedSignatureOrCatalogOnly") return No("UnsignedSignatureStateChanged");
        if (risk.DistinctFiles > rule.MaxDistinctFiles || risk.Writes > rule.MaxWrites ||
            risk.Renames > rule.MaxRenames || risk.Deletes > rule.MaxDeletes) return No("BehaviorBudgetExceeded");
        foreach (var e in risk.Evidence)
        {
            if (!rule.Operations.Contains(e.Kind.ToString(), StringComparer.Ordinal)) return No("OperationOutsideRule");
            if (!ExactLocalPath(e.Path) || !rule.Roots.Any(root => WinPaths.Under(e.Path, root))) return No("PathOutsideRule");
            // Current ETW source has no authoritative rename destination. Never assume it stayed in scope.
            if (e.Kind == FileKind.Rename && (e.DestinationPath is not string destination ||
                !ExactLocalPath(destination) || !rule.Roots.Any(root => WinPaths.Under(destination, root))))
                return No("RenameDestinationUnknownOrOutsideRule");
        }
        return new(true, rule.Id, rule.Effect, "ExactIdentityAndObservedContextMatched");
    }
}

// Single incident-consumer only. First occurrence is never quieted; scores/evidence are untouched.
public sealed class ScopedRepeatTracker
{
    private sealed record Seen(DateTime FirstUtc, DateTime LastNotificationUtc, int Score, string Pattern, int Writes, int Renames, int Deletes, int Files);
    private readonly Dictionary<(ProcessKey Process, string Rule), Seen> _seen = new();
    private long _revision = -1;
    public bool ShouldQuiet(ScopedTrustRule rule, RiskSignal risk, long revision, DateTime now)
    {
        if (revision != _revision) { _seen.Clear(); _revision = revision; }
        if (rule.Effect != "QuietRepeat" || !rule.Enabled || now < rule.CreatedUtc || now >= rule.ExpiresUtc ||
            risk.CanaryCandidate || risk.TruncatedWindow || risk.Evidence.Any(e => e.CanaryCandidate)) return false;
        var key = (risk.Process, rule.Id);
        string pattern = string.Join("|", risk.Reasons.OrderBy(s => s, StringComparer.Ordinal));
        bool quiet = _seen.TryGetValue(key, out var previous) && now >= previous.LastNotificationUtc &&
            now - previous.LastNotificationUtc < TimeSpan.FromSeconds(rule.QuietSeconds) &&
            now - previous.FirstUtc < TimeSpan.FromMinutes(30) && risk.Score <= previous.Score && pattern == previous.Pattern &&
            risk.Writes <= previous.Writes && risk.Renames <= previous.Renames && risk.Deletes <= previous.Deletes && risk.DistinctFiles <= previous.Files;
        if (!quiet)
        {
            if (_seen.Count >= 256 && !_seen.ContainsKey(key)) _seen.Remove(_seen.MinBy(p => p.Value.LastNotificationUtc).Key);
            _seen[key] = new(now, now, risk.Score, pattern, risk.Writes, risk.Renames, risk.Deletes, risk.DistinctFiles);
        }
        return quiet;
    }
    public void Revoke(ProcessKey process)
    { foreach (var key in _seen.Keys.Where(k => k.Process == process).ToArray()) _seen.Remove(key); }
}
