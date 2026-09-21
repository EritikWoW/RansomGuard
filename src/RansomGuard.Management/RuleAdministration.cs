using System.Security.Principal;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record ProcessChoice(int Pid, string Name, string ImagePath, string UserSid, long CreatedFileTime)
{ public string Display => $"{Name} | PID {Pid} | {UserSid}"; }
public sealed record RuleList(string State, string Digest, ScopedTrustRule[] Rules, string? Error);
public sealed class PreparedRule
{
    internal PreparedRule(ScopedTrustRule rule, string digest, ImageEvidence image, bool edit)
    { Rule = rule; Digest = digest; Image = image; IsEdit = edit; }
    public ScopedTrustRule Rule { get; }
    public ImageEvidence Image { get; }
    internal string Digest { get; }
    internal bool IsEdit { get; }
}

// Called ONLY by the elevated dialog. Every entry point enforces elevation itself.
public static class RuleAdministration
{
    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    public static void DemandAdministrator() => ScopedRuleStore.DemandAdministrator();
    public static ProcessChoice[] Processes()
    {
        DemandAdministrator();
        var rows = new List<ProcessChoice>();
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                if (rows.Count >= 1024) continue;
                try
                {
                    if (process.Id <= 4) continue;
                    using var h = Native.OpenProcess(Native.Query | Native.Synchronize, false, process.Id);
                    var identity = Native.Identity(h, process.Id);
                    if (identity is not ProcessKey k || Native.ImagePath(h) is not string path) continue;
                    rows.Add(new(k.Pid, Path.GetFileName(path) ?? path, path, ScopedRuleVerifier.UserSid(h), k.CreationFileTimeUtc));
                }
                catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or InvalidOperationException or UnauthorizedAccessException) { }
            }
        }
        return rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Pid).ToArray();
    }
    public static RuleList List()
    {
        DemandAdministrator();
        var s = new ScopedRuleStore(new SecureStore()).Load();
        return new(s.State, s.Digest, s.Rules, s.Error);
    }
    public static PreparedRule Prepare(RuleDraft d, string? editId)
    {
        string actor = ScopedRuleStore.DemandAdministrator();
        var store = new SecureStore();
        var snapshot = new ScopedRuleStore(store).Load();
        if (snapshot.State == "UnavailableOrInvalid") throw new IOException(snapshot.Error);
        if (editId is not null && !snapshot.Rules.Any(r => r.Id == editId)) throw new IOException("Rule disappeared. Refresh the list.");
        if (editId is null && snapshot.Rules.Length >= ScopedTrustPolicy.MaxRules) throw new IOException("Rule limit reached.");
        if (d.Hours is < 1 or > 720) throw new ArgumentException("Lifetime must be 1-720 hours.");
        if (!ScopedTrustPolicy.ExactLocalPath(d.ImagePath) || !d.ImagePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Select an exact local EXE path.");
        if (!ScopedTrustPolicy.SidValid(d.UserSid) || new SecurityIdentifier(d.UserSid).Value != d.UserSid)
            throw new ArgumentException("A valid canonical process user SID is required.");
        ScopedRuleVerifier.CheckScopes(d.Roots, store.Root);
        var image = new ImageInspector(store).Inspect(d.ImagePath, true);
        if (image.Status != "Hashed" || image.Sha256 is not string hash || image.Error is not null ||
            image.LocalDisposition is not ("Unknown" or "ReviewedTrusted")) throw new IOException("EXE/reputation not verified: " + image.Error);
        if (image.Size is null or > 128L * 1024 * 1024) throw new IOException("EXE exceeds the 128 MiB scoped-verification limit.");
        bool signed = image.Signature.Status == "ValidCached" && image.Signature.NativeStatus == "0x00000000" &&
            DecisionPolicy.HashEqual(image.Signature.CertificateThumbprint, image.Signature.CertificateThumbprint);
        if (!signed && !(d.AllowUnsigned && image.Signature.Status == "NoEmbeddedSignatureOrCatalogOnly"))
            throw new IOException("Valid embedded signature required. The explicit unsigned option only accepts a missing embedded signature, never an invalid signature.");
        ProcessKey? instance = null;
        if (d.Pid is int pid)
        {
            if (pid <= 4) throw new ArgumentException("Invalid process id.");
            using var handle = Native.OpenProcess(Native.Query | Native.Synchronize, false, pid);
            instance = Native.Identity(handle, pid) ?? throw new IOException("Process identity unavailable.");
            if (!WinPaths.Equal(d.ImagePath, Native.ImagePath(handle)) || ScopedRuleVerifier.UserSid(handle) != d.UserSid)
                throw new IOException("PID does not match the selected EXE and user.");
        }
        var now = DateTime.UtcNow;
        var rule = new ScopedTrustRule
        {
            Id = editId ?? Guid.NewGuid().ToString("N"), Name = d.Name, ImagePath = d.ImagePath, Sha256 = hash, UserSid = d.UserSid,
            Roots = d.Roots.ToArray(), Operations = d.Operations.ToArray(), Effect = d.Effect, Reason = d.Reason,
            CreatedUtc = now, ExpiresUtc = now.AddHours(d.Hours), ApprovedBySid = actor, Instance = instance, Enabled = true,
            SignaturePolicy = signed ? "ValidEmbedded" : "ExactUnsignedHash", CertificateSha256 = signed ? image.Signature.CertificateThumbprint : null,
            MaxDistinctFiles = d.MaxDistinctFiles, MaxWrites = d.MaxWrites, MaxRenames = d.MaxRenames, MaxDeletes = d.MaxDeletes, QuietSeconds = d.QuietSeconds
        };
        ScopedTrustPolicy.Validate(rule);
        return new(rule, snapshot.Digest, image, editId is not null);
    }
    public static void Save(PreparedRule prepared, string confirmation)
    {
        using var maintenance = StateMaintenanceGate.Acquire();
        DemandAdministrator();
        var rule = prepared.Rule;
        AdminContract.CheckConfirmation(prepared.IsEdit ? "edit" : "add", confirmation, rule.Sha256);
        ScopedTrustPolicy.Validate(rule);
        if (DateTime.UtcNow >= rule.ExpiresUtc) throw new IOException("Review expired. Verify again.");
        var store = new SecureStore();
        var fresh = new ImageInspector(store).Inspect(rule.ImagePath, true);
        if (fresh.Status != "Hashed" || !DecisionPolicy.HashEqual(fresh.Sha256, rule.Sha256) ||
            fresh.Signature != prepared.Image.Signature || fresh.LocalDisposition is not ("Unknown" or "ReviewedTrusted"))
            throw new IOException("EXE/signature/reputation changed during review. Nothing saved.");
        ScopedRuleVerifier.CheckScopes(rule.Roots, store.Root);
        if (rule.Instance is ProcessKey key)
        {
            using var h = Native.OpenProcess(Native.Query | Native.Synchronize, false, key.Pid);
            if (Native.Identity(h, key.Pid) != key || ScopedRuleVerifier.UserSid(h) != rule.UserSid || !WinPaths.Equal(Native.ImagePath(h), rule.ImagePath))
                throw new IOException("Pinned process changed or exited.");
        }
        new ScopedRuleStore(store).Commit(prepared.Digest, old => prepared.IsEdit
            ? old.Select(r => r.Id == rule.Id ? rule : r).ToArray() : old.Append(rule).ToArray(),
            prepared.IsEdit ? "ui-reapprove" : "ui-add", rule.Reason);
    }
    public static void Change(string action, string id, string digest, string reason, string confirmation)
    {
        using var maintenance = StateMaintenanceGate.Acquire();
        DemandAdministrator(); AdminContract.ValidateIntent(action, id); AdminContract.CheckConfirmation(action, confirmation);
        if (action is not ("disable" or "remove")) throw new ArgumentException("Unsupported rule mutation.");
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 400 || reason.Any(char.IsControl)) throw new ArgumentException("A one-line review reason is required.");
        new ScopedRuleStore(new SecureStore()).Commit(digest, old =>
        {
            if (!old.Any(r => r.Id == id)) throw new IOException("Rule no longer exists.");
            return action == "remove" ? old.Where(r => r.Id != id).ToArray() : old.Select(r => r.Id == id ? r with { Enabled = false } : r).ToArray();
        }, "ui-" + action, reason);
    }
}
