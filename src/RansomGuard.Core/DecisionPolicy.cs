using System.Security.Cryptography;
namespace RansomGuard.Core;
public static class DecisionPolicy
{
    // Hashes identify bytes; signatures identify a signing chain, not the safety of runtime code.
    // No executable name, location, publisher name, first-seen count or negative lookup grants immunity.
    public static ActionDecision Decide(RiskSignal risk, ImageEvidence image, LabIdentity? lab,
        bool sameLiveIdentity, bool criticalStateKnown, bool isCritical, bool telemetryHealthy, DateTime now)
    {
        if (lab is null) return new(false, "AuditOnly: automatic action against ordinary applications is disabled in this build.");
        if (risk.Process != lab.Process) return new(false, "Not the explicitly launched lab child.");
        if (now > lab.ExpiresUtc) return new(false, "Lab authorization expired.");
        if (!sameLiveIdentity || risk.Process.CreationFileTimeUtc <= 0) return new(false, "Process identity unavailable/changed.");
        if (!criticalStateKnown || isCritical || risk.Process.Pid <= 4) return new(false, "Critical/unknown process safety gate.");
        if (!telemetryHealthy || risk.TruncatedWindow || risk.DeliveryLagMs is < 0 or > 3000 ||
            risk.MaxEvidenceDeliveryLagMs > 3000 || (now-risk.LastEventUtc).TotalSeconds > 10 || risk.LastEventUtc > now.AddSeconds(1))
            return new(false, "Incomplete or stale evidence: no automatic action.");
        if (!WinPaths.Equal(image.Path, lab.ImagePath) || !WinPaths.Equal(risk.ImagePath, lab.ImagePath))
            return new(false, "Image path mismatch.");
        if (image.Status != "Hashed" || !HashEqual(image.Sha256,lab.Sha256)) return new(false, "Fresh SHA-256 does not match lab enrollment.");
        return new(true, "Explicit lab enrollment only; single PID; no process-tree action.");
    }
    public static bool HashEqual(string? a, string? b)
    {
        if (a?.Length != 64 || b?.Length != 64) return false;
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(a),Convert.FromHexString(b)); }
        catch (FormatException) { return false; }
    }
    public static string Priority(RiskSignal risk, ImageEvidence image, bool confirmedCanaryChange)
    {
        if (confirmedCanaryChange) return "UrgentReview: confirmed canary content change; writer attribution still requires review";
        if (image.LocalDisposition == "BlockedByAdministrator") return "UrgentReview: exact locally blocked hash";
        if (risk.CanaryCandidate) return "ElevatedReview: canary operation observed but not yet confirmed";
        if (image.LocalDisposition == "ReviewedTrusted") return "Review: administrator-reviewed image; behavior is NOT discarded";
        return "Review: suspicious file activity, not proof of encryption";
    }
}
