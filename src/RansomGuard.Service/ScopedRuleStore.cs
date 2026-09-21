using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal sealed record RuleStoreSnapshot(string State, string Digest, ScopedTrustDocument? Document, string? Error)
{
    public ScopedTrustRule[] Rules => Document?.Rules ?? Array.Empty<ScopedTrustRule>();
    public long Revision => Document?.Revision ?? 0;
}

internal sealed class ScopedRuleStore
{
    private readonly SecureStore _store;
    public string Folder { get; }
    public string FilePath => Path.Combine(Folder, "rules.json");
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, MaxDepth = 12,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false
    };
    public ScopedRuleStore(SecureStore store, string folderName = "ScopedTrust")
    {
        if (folderName != "ScopedTrust" && !System.Text.RegularExpressions.Regex.IsMatch(folderName, @"\AScopedTrust\.SelfTest\.[a-f0-9]{32}\z"))
            throw new ArgumentException("Invalid private store name.");
        _store = store; Folder = Path.Combine(store.Root, folderName);
    }
    public RuleStoreSnapshot Load()
    {
        try
        {
            FileSafety.NoReparse(Folder);
            if (!Directory.Exists(Folder)) return new("Empty", "absent", null, null);
            VerifyAcl(new DirectoryInfo(Folder).GetAccessControl());
            FileSafety.NoReparse(FilePath);
            if (!File.Exists(FilePath)) return new("Empty", "absent", null, null);
            using var file = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (file.Length is <= 0 or > ScopedTrustPolicy.MaxStoreBytes) throw new IOException("Rule-store size rejected.");
            VerifyAcl(file.GetAccessControl());
            if (!WinPaths.Equal(Native.FinalFilePath(file.SafeFileHandle), FilePath)) throw new IOException("Rule-store path mismatch.");
            var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
            using (var parsed = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 })) CheckKeys(parsed.RootElement);
            var document = JsonSerializer.Deserialize<ScopedTrustDocument>(bytes, Json) ?? throw new JsonException("Empty rule document.");
            ScopedTrustPolicy.ValidateDocument(document);
            return new("Loaded", Convert.ToHexString(SHA256.HashData(bytes)), document, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or System.Security.SecurityException)
        {
            // No last-known-good fallback after loss of integrity: all preferences stop applying.
            return new("UnavailableOrInvalid", "invalid", null, ex.GetType().Name + ": " + ex.Message);
        }
    }
    private static void CheckKeys(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            { if (!names.Add(property.Name)) throw new JsonException("Duplicate JSON field."); CheckKeys(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) CheckKeys(item);
    }
    private static void VerifyAcl(FileSystemSecurity security)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            (!owner.Equals(Admins) && !owner.Equals(SystemSid))) throw new UnauthorizedAccessException("Untrusted rule-store owner.");
        var allowed = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
        if (allowed.Any(r => r.AccessControlType == AccessControlType.Allow &&
            !r.IdentityReference.Equals(Admins) && !r.IdentityReference.Equals(SystemSid)))
            throw new UnauthorizedAccessException("Rule-store ACL permits an additional principal. No rules will be used.");
    }
    public static string DemandAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("An elevated administrator context is required for rule changes. Use the UAC-approved RansomGuard dialog.");
        return identity.User?.Value ?? throw new UnauthorizedAccessException("Administrator SID unavailable.");
    }
    private static void SetPrivateAcl(string path)
    {
        using var me = WindowsIdentity.GetCurrent();
        var acl = new FileSecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(me.IsSystem ? SystemSid : Admins);
        foreach (var sid in new[] { Admins, SystemSid }) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
    }
    public RuleStoreSnapshot Commit(string expectedDigest, Func<ScopedTrustRule[], ScopedTrustRule[]> change, string action, string reason)
    {
        string actor = DemandAdministrator();
        SecureStore.EnsureDirectory(Folder);
        var lockPath = Path.Combine(Folder, "write.lock"); FileSafety.NoReparse(lockPath);
        // Protect against concurrent administrator CLI updates; no named mutex squatting by a normal user.
        using var editLock = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SetPrivateAcl(lockPath);
        var current = Load();
        if (current.State == "UnavailableOrInvalid") throw new IOException("Rule-store integrity failed. Nothing changed: " + current.Error);
        if (current.Digest != expectedDigest) throw new IOException("Rule store changed during review. Run the command again and review it.");
        var next = new ScopedTrustDocument(1, checked(current.Revision + 1), DateTime.UtcNow, change(current.Rules));
        ScopedTrustPolicy.ValidateDocument(next);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(next, Json);
        if (bytes.Length > ScopedTrustPolicy.MaxStoreBytes) throw new IOException("Rule-store size limit reached.");
        string nextDigest = Convert.ToHexString(SHA256.HashData(bytes));
        _store.Audit(new { Utc = DateTime.UtcNow, Event = "ScopedRuleChangePrepared", ActorSid = actor, Action = action, Reason = reason,
            PreviousDigest = current.Digest, NextDigest = nextDigest, next.Revision });
        string temp = Path.Combine(Folder, "rules." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            { SetPrivateAcl(temp); file.Write(bytes); file.Flush(true); VerifyAcl(file.GetAccessControl()); }
            FileSafety.NoReparse(FilePath);
            File.Move(temp, FilePath, true); // Atomic replacement on the same local volume.
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
        var result = Load();
        if (result.Digest != nextDigest) throw new IOException("Rule-store verification after commit failed.");
        try
        {
            _store.Audit(new { Utc = DateTime.UtcNow, Event = "ScopedRuleChangeCommitted", ActorSid = actor, Action = action,
                Digest = nextDigest, next.Revision });
        }
        catch (IOException ex)
        {
            throw new IOException("Rule revision " + next.Revision + " WAS committed, but final audit append failed. " +
                "The prepared record exists. Inspect --rules list before retrying; this is not a rollback.", ex);
        }
        return result;
    }
}
