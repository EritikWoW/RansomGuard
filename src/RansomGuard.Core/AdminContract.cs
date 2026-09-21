namespace RansomGuard.Core;

// Only UI launch intents, NOT additional commands on the read-only service pipe.
public static class AdminContract
{
    public const string ServiceName = "RansomGuardV03";
    private static readonly string[] Actions = ["rules", "add", "edit", "disable", "remove", "install", "start", "stop", "restart", "uninstall", "state-repair"];
    public static bool IsAction(string? value) => value is not null && Actions.Contains(value, StringComparer.Ordinal);
    public static bool NeedsRuleId(string action) => action is "edit" or "disable" or "remove";
    public static void ValidateIntent(string action, string? ruleId)
    {
        if (!IsAction(action)) throw new ArgumentException("Unsupported administrative action.");
        if (NeedsRuleId(action) && !Guid.TryParseExact(ruleId, "N", out _))
            throw new ArgumentException("A canonical rule id is required.");
        if (!NeedsRuleId(action) && ruleId is not null)
            throw new ArgumentException("Unexpected rule id.");
    }
    public static string Confirmation(string action, string? sha256 = null) => action switch
    {
        "add" or "edit" when DecisionPolicy.HashEqual(sha256, sha256) => "TRUST " + sha256![..12].ToUpperInvariant(),
        "state-repair" => "QUARANTINE",
        "disable" => "DISABLE", "remove" => "REMOVE", "install" => "INSTALL",
        "start" => "START", "stop" => "STOP", "restart" => "RESTART", "uninstall" => "UNINSTALL",
        _ => throw new ArgumentException("Unsupported confirmation.")
    };
    public static void CheckConfirmation(string action, string entered, string? hash = null)
    {
        if (!string.Equals(Confirmation(action, hash), entered, StringComparison.Ordinal))
            throw new OperationCanceledException("Confirmation did not match. Nothing changed.");
    }
}

public sealed record RuleDraft(string Name, string ImagePath, string UserSid, string[] Roots, string[] Operations,
    int Hours, string Effect, string Reason, bool AllowUnsigned, int? Pid = null,
    int MaxDistinctFiles = 16, int MaxWrites = 256, int MaxRenames = 16, int MaxDeletes = 16, int QuietSeconds = 120);
