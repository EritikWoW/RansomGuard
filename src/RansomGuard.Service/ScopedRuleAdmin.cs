using System.Globalization;
using System.Security.Principal;
using System.Text.Json;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal static class ScopedRuleAdmin
{
    public static int Run(string[] args, SecureStore store)
    {
        string actor = ScopedRuleStore.DemandAdministrator();
        if(args.Length==1 && args[0]=="selftest")return ScopedRuleNativeTest.Run(store);
        if (args.Length == 0 || args[0] == "help")
        {
            Console.WriteLine("--rules list | selftest");
            Console.WriteLine("--rules add --exe PATH --user-sid SID --scope DIRECTORY [--scope DIRECTORY] --operations Write,Delete --hours 8 --name NAME --reason TEXT [--effect AnnotateOnly|QuietRepeat] [--pid PID] [--allow-unsigned-exact-hash]");
            Console.WriteLine("--rules disable|remove --id RULE_ID --reason TEXT");
            Console.WriteLine("No wildcard/publisher-wide/process-name exclusions. No Defender/driver settings changed. Changes require typed confirmation.");
            return 0;
        }
        var rules = new ScopedRuleStore(store);
        var snapshot = rules.Load();
        if (args[0] == "list" && args.Length == 1)
        {
            Console.WriteLine(JsonSerializer.Serialize(snapshot, ScopedRuleStore.Json));
            return snapshot.State == "UnavailableOrInvalid" ? 1 : 0;
        }
        if (snapshot.State == "UnavailableOrInvalid") throw new IOException("Invalid rule store. No change performed: " + snapshot.Error);
        if (args[0] is not ("add" or "disable" or "remove")) throw new ArgumentException("Unknown rules command. Use --rules help.");
        var values = Parse(args[1..], args[0] == "add"
            ? new[] { "exe", "user-sid", "scope", "operations", "hours", "name", "reason", "effect", "pid", "allow-unsigned-exact-hash" }
            : new[] { "id", "reason" });
        string One(string key, string? fallback = null) => values.TryGetValue(key, out var list)
            ? list.Single() : fallback ?? throw new ArgumentException("Missing --" + key);
        string reason = One("reason");
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 400 || reason.Any(char.IsControl)) throw new ArgumentException("A bounded one-line reason is required.");
        if (args[0] != "add")
        {
            string id = One("id");
            var existing = snapshot.Rules.SingleOrDefault(r => r.Id == id) ?? throw new ArgumentException("Rule id not found.");
            Console.WriteLine(JsonSerializer.Serialize(existing, ScopedRuleStore.Json));
            Confirm(args[0].ToUpperInvariant() + " " + id);
            rules.Commit(snapshot.Digest, entries => args[0] == "remove"
                ? entries.Where(r => r.Id != id).ToArray()
                : entries.Select(r => r.Id == id ? r with { Enabled = false } : r).ToArray(), args[0], reason);
            Console.WriteLine("Rule change saved. Monitoring and incident storage remain enabled.");
            return 0;
        }
        if (snapshot.Rules.Length >= ScopedTrustPolicy.MaxRules) throw new IOException("Rule limit reached; remove unused rules explicitly.");
        string path = One("exe");
        if (!ScopedTrustPolicy.ExactLocalPath(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Supply the exact local EXE path, with no environment variables or trailing separator.");
        string sid = One("user-sid");
        var sidObject = new SecurityIdentifier(sid); // OS parser complements the pure policy check.
        if (sidObject.Value != sid) throw new ArgumentException("Use a canonical SID.");
        string[] roots = values.TryGetValue("scope", out var scopes) ? scopes.ToArray() : throw new ArgumentException("Missing --scope.");
        ScopedRuleVerifier.CheckScopes(roots, store.Root);
        int hours = int.Parse(One("hours", "8"), CultureInfo.InvariantCulture);
        if (hours is < 1 or > 720) throw new ArgumentException("Lifetime must be 1-720 hours; indefinite trust is not allowed.");
        var inspector = new ImageInspector(store);
        var image = inspector.Inspect(path, fresh: true);
        if (image.Status != "Hashed" || image.Sha256 is not string hash || image.Error is not null)
            throw new IOException("Cannot verify executable: " + image.Error);
        if (image.LocalDisposition is not ("Unknown" or "ReviewedTrusted"))
            throw new IOException("A locally blocked or unknown-integrity reputation store cannot create an exception.");
        bool allowUnsigned = values.ContainsKey("allow-unsigned-exact-hash");
        string signaturePolicy;
        string? certificate;
        if (image.Signature.Status == "ValidCached" && image.Signature.NativeStatus == "0x00000000" &&
            DecisionPolicy.HashEqual(image.Signature.CertificateThumbprint, image.Signature.CertificateThumbprint))
        { signaturePolicy = "ValidEmbedded"; certificate = image.Signature.CertificateThumbprint; }
        else if (allowUnsigned && image.Signature.Status == "NoEmbeddedSignatureOrCatalogOnly")
        { signaturePolicy = "ExactUnsignedHash"; certificate = null; }
        else throw new IOException("Signature not verified. Only a missing embedded signature may use explicit --allow-unsigned-exact-hash; revocation/invalid/unknown signatures cannot be overridden.");
        ProcessKey? instance = null;
        if (values.ContainsKey("pid"))
        {
            int pid = int.Parse(One("pid"), CultureInfo.InvariantCulture);
            if (pid <= 4) throw new ArgumentException("Invalid process id.");
            using var process = Native.OpenProcess(Native.Query | Native.Synchronize, false, pid);
            instance = Native.Identity(process, pid) ?? throw new IOException("Live process identity unavailable.");
            if (!WinPaths.Equal(path, Native.ImagePath(process)) || ScopedRuleVerifier.UserSid(process) != sid)
                throw new IOException("Selected process does not match the EXE and user SID.");
        }
        DateTime now = DateTime.UtcNow;
        var rule = new ScopedTrustRule
        {
            Id = Guid.NewGuid().ToString("N"), Name = One("name"), ImagePath = path, Sha256 = hash, UserSid = sid,
            Roots = roots, Operations = One("operations", "Write").Split(',', StringSplitOptions.TrimEntries),
            SignaturePolicy = signaturePolicy, CertificateSha256 = certificate, Instance = instance,
            Effect = One("effect", "AnnotateOnly"), CreatedUtc = now, ExpiresUtc = now.AddHours(hours), ApprovedBySid = actor, Reason = reason
        };
        ScopedTrustPolicy.Validate(rule);
        Console.WriteLine(JsonSerializer.Serialize(rule, ScopedRuleStore.Json));
        Console.WriteLine("Publisher display only: " + (image.Signature.Publisher ?? "unavailable"));
        Console.WriteLine("This is NOT proof that runtime code is safe. All events/incidents and the original risk score stay visible. QuietRepeat only reduces repeated console warning level.");
        Console.WriteLine("Rename evidence without a known destination will NOT be quieted. Missing/changed paths and expired rules receive normal review.");
        Confirm("TRUST " + hash[..12]);
        // Long user think-time must not silently authorize a file replaced after the preview.
        var rechecked = inspector.Inspect(path, fresh: true);
        if (!DecisionPolicy.HashEqual(hash, rechecked.Sha256) || rechecked.Status != "Hashed" || rechecked.Signature != image.Signature ||
            rechecked.LocalDisposition is not ("Unknown" or "ReviewedTrusted")) throw new IOException("EXE/reputation changed while waiting for confirmation.");
        ScopedRuleVerifier.CheckScopes(roots, store.Root);
        if (rule.Instance is ProcessKey pinned)
        {
            using var process = Native.OpenProcess(Native.Query | Native.Synchronize, false, pinned.Pid);
            if (Native.Identity(process, pinned.Pid) != pinned || ScopedRuleVerifier.UserSid(process) != sid) throw new IOException("One-run process already changed/exited.");
        }
        if (DateTime.UtcNow >= rule.ExpiresUtc) throw new IOException("Rule expired during confirmation.");
        rules.Commit(snapshot.Digest, entries => entries.Append(rule).ToArray(), "add", reason);
        Console.WriteLine("Saved rule: " + rule.Id + ". It is rechecked on each matching incident, never inherited by children.");
        return 0;
    }
    private static Dictionary<string, List<string>> Parse(string[] args, string[] allowed)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        for (int i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Expected --option.");
            string key = args[i][2..];
            if (!allowed.Contains(key, StringComparer.Ordinal)) throw new ArgumentException("Unsupported option --" + key);
            string value = key == "allow-unsigned-exact-hash" ? "true" : ++i < args.Length
                ? args[i] : throw new ArgumentException("Missing value --" + key);
            if (result.TryGetValue(key, out var list))
            { if (key != "scope") throw new ArgumentException("Duplicate option --" + key); list.Add(value); }
            else result.Add(key, new List<string> { value });
        }
        return result;
    }
    private static void Confirm(string expected)
    {
        if (Console.IsInputRedirected) throw new InvalidOperationException("Interactive confirmation is required; redirected stdin is refused.");
        Console.Write("Type exactly '" + expected + "' to apply: ");
        if (!string.Equals(Console.ReadLine(), expected, StringComparison.Ordinal)) throw new OperationCanceledException("Not confirmed. Nothing changed.");
    }
}
