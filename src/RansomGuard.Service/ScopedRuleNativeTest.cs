using System.Security.AccessControl;
using System.Security.Principal;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal static class ScopedRuleNativeTest
{
    public static int Run(SecureStore store)
    {
        string actor = ScopedRuleStore.DemandAdministrator();
        var rules = new ScopedRuleStore(store, "ScopedTrust.SelfTest." + Guid.NewGuid().ToString("N"));
        int tests = 0;
        void Check(bool condition, string name)
        { if (!condition) throw new IOException("FAIL: " + name); tests++; Console.WriteLine("PASS: " + name); }
        try
        {
            Check(rules.Load().State == "Empty", "isolated test store starts empty");
            var now = DateTime.UtcNow;
            var rule = new ScopedTrustRule
            {
                Id = Guid.NewGuid().ToString("N"), Name = "Selftest fixture - never active", ImagePath = @"C:\Synthetic\NeverRuns\fixture.exe",
                Sha256 = new string('A', 64), UserSid = actor, ApprovedBySid = actor, Roots = [@"C:\Synthetic\NeverRuns"],
                Operations = ["Write"], SignaturePolicy = "ExactUnsignedHash", CreatedUtc = now, ExpiresUtc = now.AddMinutes(1), Reason = "Native ACL selftest"
            };
            var written = rules.Commit("absent", _ => [rule], "selftest-add", "Isolated selftest fixture");
            Check(written.State == "Loaded" && written.Rules.Length == 1, "private ACL write and fresh read");
            bool rejected = false;
            try { rules.Commit("stale", x => x, "selftest-conflict", "Must reject"); }
            catch (IOException) { rejected = true; }
            Check(rejected, "optimistic concurrency rejects stale revision");
            var file = new FileInfo(rules.FilePath); var original = file.GetAccessControl();
            try
            {
                var unsafeAcl = file.GetAccessControl();
                unsafeAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.ReadData, AccessControlType.Allow));
                file.SetAccessControl(unsafeAcl);
                Check(rules.Load().State == "UnavailableOrInvalid", "additional principal invalidates the isolated file");
            }
            finally { file.SetAccessControl(original); }
            var removed = rules.Commit(written.Digest, _ => [], "selftest-remove", "Isolated selftest cleanup");
            Check(removed.State == "Loaded" && removed.Rules.Length == 0 && removed.Revision == 2, "atomic removal increments revision");
            using var process = Native.OpenProcess(Native.Query | Native.Synchronize, false, Environment.ProcessId);
            Check(Native.Identity(process, Environment.ProcessId) is not null, "own PID and creation time queried");
            Check(ScopedRuleVerifier.UserSid(process) == actor, "token user queried with TOKEN_QUERY only");
            Console.WriteLine($"Native scoped-rule tests passed: {tests}. No real rule/ETW/driver/process-action was created. Audit journal contains selftest entries.");
            return 0;
        }
        finally
        {
            // Delete only our fresh private test directory and known files, never recurse into existing user data.
            FileSafety.NoReparse(rules.Folder);
            if (Directory.Exists(rules.Folder))
            {
                foreach (string name in new[] { "rules.json", "write.lock" })
                { var path = Path.Combine(rules.Folder, name); FileSafety.NoReparse(path); if (File.Exists(path)) File.Delete(path); }
                Directory.Delete(rules.Folder, false);
            }
        }
    }
}
