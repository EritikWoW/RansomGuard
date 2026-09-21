using RansomGuard.Core;
using System.Text.Json;

int tests = 0;
void Check(bool condition, string name) { if (!condition) throw new Exception("FAIL: " + name); tests++; Console.WriteLine("PASS: " + name); }
void Bad(ScopedTrustRule value, string name)
{ bool failed = false; try { ScopedTrustPolicy.Validate(value); } catch (ArgumentException) { failed = true; } Check(failed, name); }
DateTime now = new(2026, 9, 20, 12, 0, 0, DateTimeKind.Utc);
string exe = @"C:\Apps\Example\worker.exe", root = @"C:\Users\Example\Cache";
string hash = new('A', 64), cert = new('B', 64), sid = "S-1-5-21-100-200-300-1001";
ProcessKey process = new(1234, now.AddMinutes(-5).ToFileTimeUtc());
var rule = new ScopedTrustRule
{
    Id = "11223344556677889900aabbccddeeff", Name = "Synthetic test rule", ImagePath = exe, Sha256 = hash, UserSid = sid,
    Roots = [root], Operations = ["Write", "Delete"], SignaturePolicy = "ValidEmbedded", CertificateSha256 = cert,
    Effect = "QuietRepeat", CreatedUtc = now.AddHours(-1), ExpiresUtc = now.AddHours(1), ApprovedBySid = sid, Reason = "Unit test"
};
var entries = Enumerable.Range(0, 21).Select(i => new FileSignal(now.AddSeconds(-1), now, process, "worker.exe", exe,
    root + @"\a" + (i % 3) + ".txt", FileKind.Write)).ToArray();
var risk = new RiskSignal(process, "worker.exe", exe, now, now.AddSeconds(-1), 1000, 110, 21, 0, 0, 3, false, false,
    ["synthetic repetitive write pattern"], entries);
var image = new ImageEvidence(exe, hash, 2000, "Hashed", new("ValidCached", "0x00000000", "Example", cert), "Unknown", now, null);
var proof = new ScopedProcessEvidence(process, sid, image, true, true, now, null);
ScopedTrustDecision Decide(ScopedTrustRule? r = null, RiskSignal? s = null, ScopedProcessEvidence? p = null,
    bool healthy = true, bool canary = false, bool content = false, bool lab = false, DateTime? time = null)
    => ScopedTrustPolicy.Evaluate(r ?? rule, s ?? risk, p ?? proof, healthy, canary, content, lab, time ?? now);
Check(Decide().Applies, "strict SHA256 + user + whole observed scope match");
Check(Decide().Effect == "QuietRepeat", "effect is a review preference, not a block decision");
Check(!Decide(lab: true).Applies, "owned LAB process is never exempted");
Check(!Decide(canary: true).Applies, "confirmed canary overrides any trust");
Check(!Decide(s: risk with { CanaryCandidate = true }).Applies, "unconfirmed canary also vetoes preference");
Check(!Decide(s: risk with { Evidence = entries.Select((e, i) => i == 0 ? e with { CanaryCandidate = true } : e).ToArray() }).Applies, "earlier canary in evidence vetoes preference");
Check(!Decide(content: true).Applies, "suspected content transformation overrides rule");
Check(!Decide(healthy: false).Applies, "unhealthy telemetry refuses preference");
Check(!Decide(r: rule with { Enabled = false }).Applies, "disabled rule");
Check(!Decide(time: rule.ExpiresUtc).Applies, "expires exactly at boundary");
Check(!Decide(time: rule.CreatedUtc.AddSeconds(-1)).Applies, "clock rollback/preapproval rejected");
Check(!Decide(s: risk with { TruncatedWindow = true }).Applies, "truncated source window");
Check(!Decide(s: risk with { Evidence = entries[..20] }).Applies, "truncated evidence array cannot soften complete counters");
Check(!Decide(s: risk with { Evidence = [] }).Applies, "empty evidence cannot authorize a rule");
Check(!Decide(s: risk with { DistinctFiles = 4 }).Applies, "mismatched path counters");
Check(!Decide(s: risk with { Writes = -1 }).Applies, "negative counters");
Check(!Decide(s: risk with { Writes = 20, Deletes = 1 }).Applies, "operation counters must match evidence");
Check(!Decide(p: proof with { IdentityVerified = false }).Applies, "unknown live identity");
Check(!Decide(p: proof with { Error = "partial query failed" }).Applies, "contradictory proof error vetoes preference");
Check(!Decide(p: proof with { PathsChecked = false }).Applies, "unverified filesystem context");
Check(!Decide(p: proof with { UserSid = null }).Applies, "unknown user");
Check(!Decide(p: proof with { UserSid = sid + "1" }).Applies, "another user");
Check(!Decide(p: proof with { Process = process with { CreationFileTimeUtc = process.CreationFileTimeUtc + 1 } }).Applies, "reused PID");
Check(!Decide(p: proof with { Process = process with { Pid = process.Pid + 1 } }).Applies, "child PID does not inherit trust");
Check(Decide(r: rule with { Instance = process }).Applies, "one-run exact generation accepted");
Check(!Decide(r: rule with { Instance = process with { Pid = 3210 } }).Applies, "one-run different process");
Check(!Decide(p: proof with { VerifiedUtc = now.AddSeconds(-6) }).Applies, "stale verification");
Check(!Decide(p: proof with { VerifiedUtc = now.AddSeconds(1) }).Applies, "future verification");
Check(!Decide(p: proof with { Image = image with { Status = "HashedCached" } }).Applies, "old cache is not a grant");
Check(!Decide(p: proof with { Image = image with { Sha256 = new string('C', 64) } }).Applies, "changed EXE bytes");
Check(!Decide(p: proof with { Image = image with { Sha256 = null } }).Applies, "missing executable hash");
Check(!Decide(p: proof with { Image = image with { ObservedUtc = now.AddSeconds(-6) } }).Applies, "stale executable evidence");
Check(!Decide(p: proof with { Image = image with { Error = "failed" } }).Applies, "error evidence does not grant trust");
Check(!Decide(p: proof with { Image = image with { Path = @"C:\Downloads\worker.exe" } }).Applies, "same filename elsewhere");
Check(!Decide(s: risk with { ImagePath = @"C:\Apps\Example2\worker.exe" }).Applies, "lookalike EXE directory");
Check(!Decide(p: proof with { Image = image with { LocalDisposition = "BlockedByAdministrator" } }).Applies, "deny overrides scoped rule");
Check(!Decide(p: proof with { Image = image with { LocalDisposition = "StoreInvalid" } }).Applies, "invalid reputation store cannot grant exception");
Check(Decide(p: proof with { Image = image with { LocalDisposition = "ReviewedTrusted" } }).Applies, "reviewed trusted still needs all checks");
Check(!Decide(p: proof with { Image = image with { Signature = image.Signature with { Publisher = "Example", NativeStatus = "0x800B010C", Status = "Revoked" } } }).Applies, "publisher text is not signature proof");
Check(!Decide(p: proof with { Image = image with { Signature = image.Signature with { NativeStatus = "0x00000001" } } }).Applies, "nonzero WinVerifyTrust is not success");
Check(!Decide(p: proof with { Image = image with { Signature = image.Signature with { Status = "RevocationUnavailable" } } }).Applies, "offline uncertainty rejects signed rule");
Check(!Decide(p: proof with { Image = image with { Signature = image.Signature with { CertificateThumbprint = new string('D', 64) } } }).Applies, "signer change");
var unsignedRule = rule with { SignaturePolicy = "ExactUnsignedHash", CertificateSha256 = null };
var unsignedProof = proof with { Image = image with { Signature = new("NoEmbeddedSignatureOrCatalogOnly", "0x800B0100", null, null) } };
Check(Decide(unsignedRule, p: unsignedProof).Applies, "explicit exact unsigned exception");
Check(!Decide(unsignedRule, p: unsignedProof with { Image = unsignedProof.Image with { Signature = new("BadDigest", "0x80096010", null, null) } }).Applies, "unsigned opt-in cannot override invalid signature");
Check(!Decide(r: rule with { MaxWrites = 20 }).Applies, "behavior write budget");
Check(!Decide(r: rule with { MaxDistinctFiles = 2 }).Applies, "behavior file budget");
Check(!Decide(r: rule with { Operations = ["Delete"] }).Applies, "operation outside rule");
RiskSignal ChangePaths(string path) => risk with { Evidence = entries.Select(e => e with { Path = path }).ToArray(), DistinctFiles = 1 };
Check(!Decide(s: ChangePaths(root + "Other\\a.txt")).Applies, "scope boundary, not string prefix");
Check(!Decide(s: ChangePaths(@"C:\Users\Example\Documents\a.txt")).Applies, "outside configured directory");
Check(!Decide(s: ChangePaths(root + @"\..\Documents\a.txt")).Applies, "event path traversal refused");
Check(!Decide(s: ChangePaths(root + @"\a.txt:stream")).Applies, "alternate data stream refused");
Check(!Decide(s: ChangePaths(@"\Device\HarddiskVolume2\a.txt")).Applies, "unresolved device path not trusted");
Check(!Decide(s: ChangePaths(root)).Applies, "root itself not a child file");
Check(!Decide(time: now.AddSeconds(11)).Applies, "old decision cannot grant a new exception");
Check(!Decide(s: risk with { DetectedUtc = now.AddSeconds(1) }).Applies, "future decision");
Check(!Decide(s: risk with { Evidence = entries.Select(e => e with { EventUtc = rule.CreatedUtc.AddSeconds(-1) }).ToArray() }).Applies, "rule is not retroactive");
var renameEntries = entries.Select((e, i) => i == 0 ? e with { Kind = FileKind.Rename } : e).ToArray();
var renameRisk = risk with { Writes = 20, Renames = 1, Evidence = renameEntries };
var renameRule = rule with { Operations = ["Write", "Rename"] };
Check(!Decide(renameRule, renameRisk).Applies, "unknown rename destination: no suppression");
Check(Decide(renameRule, renameRisk with { Evidence = renameEntries.Select(e => e.Kind == FileKind.Rename ? e with { DestinationPath = root + @"\b.txt" } : e).ToArray() }).Applies, "both rename endpoints within scope (abstract verified evidence)");
Check(!Decide(renameRule, renameRisk with { Evidence = renameEntries.Select(e => e.Kind == FileKind.Rename ? e with { DestinationPath = @"C:\Outside\b.txt" } : e).ToArray() }).Applies, "rename target outside scope");
var deleted = risk with { Writes = 20, Deletes = 1, Evidence = entries.Select((e, i) => i == 0 ? e with { Kind = FileKind.Delete } : e).ToArray() };
Check(Decide(s: deleted).Applies, "delete preference still needs verified parent scope");
Check(!Decide(r: rule with { MaxDeletes = 0 }, s: deleted).Applies, "delete budget");
Bad(rule with { Sha256 = new string('A', 32) }, "MD5-length hash rejected");
Bad(rule with { Sha256 = new string('Z', 64) }, "nonhex hash rejected");
Bad(rule with { Roots = [@"C:\"] }, "whole drive forbidden");
Bad(rule with { Roots = [@"C:\Users"] }, "broad top-level directory forbidden");
Bad(rule with { Roots = [root + @"\..\Cache"] }, "rule traversal forbidden");
Bad(rule with { Roots = [@"\\server\share\Cache"] }, "UNC scope forbidden");
Bad(rule with { Roots = [root + "*"] }, "glob forbidden");
Bad(rule with { Roots = [@"%USERPROFILE%\Cache"] }, "variable expansion forbidden");
Bad(rule with { Roots = [root, root.ToLowerInvariant()] }, "duplicate scopes forbidden");
Bad(rule with { Roots = [] }, "empty scope forbidden");
Bad(rule with { ExpiresUtc = now.AddDays(31) }, "permanent/oversized lifetime forbidden");
Bad(rule with { CreatedUtc = DateTime.SpecifyKind(now, DateTimeKind.Unspecified) }, "ambiguous time zone rejected");
Bad(rule with { SignaturePolicy = "AnyPublisher" }, "publisher-wide immunity forbidden");
Bad(rule with { Effect = "SkipMonitoring" }, "cannot disable monitoring with a rule");
Bad(rule with { Operations = ["Open"] }, "open is not mutation");
Bad(rule with { Operations = ["Write", "Write"] }, "duplicate operations");
Bad(rule with { Reason = "" }, "reason required");
Bad(rule with { Name = "line1\nline2" }, "control characters cannot forge console output");
Bad(rule with { ImagePath = @"worker.exe" }, "basename only cannot identify executable");
Bad(rule with { ImagePath = exe + ":ads" }, "image ADS forbidden");
Bad(rule with { UserSid = "Everyone" }, "no group/name matching instead of token SID");
Bad(rule with { CertificateSha256 = new string('A', 40) }, "signer fingerprint must be SHA256");
Bad(rule with { QuietSeconds = 99999 }, "unbounded notification silence forbidden");
Bad(rule with { MaxDistinctFiles = 10000 }, "large multi-file burst not quieted");
var document = new ScopedTrustDocument(1, 1, now, [rule]);
ScopedTrustPolicy.ValidateDocument(document);
var roundtrip = JsonSerializer.Deserialize<ScopedTrustDocument>(JsonSerializer.Serialize(document))!;
Check(roundtrip.Rules[0].Sha256 == hash, "rule JSON round trip");
bool invalidDoc = false;
try { ScopedTrustPolicy.ValidateDocument(document with { Rules = [rule, rule] }); } catch (ArgumentException) { invalidDoc = true; }
Check(invalidDoc, "duplicate rule IDs reject entire document");
var tracker = new ScopedRepeatTracker();
Check(!tracker.ShouldQuiet(rule, risk, 1, now), "first occurrence always visible");
Check(tracker.ShouldQuiet(rule, risk, 1, now.AddSeconds(1)), "identical subsequent contextual warning may be quieter");
Check(!tracker.ShouldQuiet(rule, risk with { Score = 200 }, 1, now.AddSeconds(2)), "rising risk is not quieted");
Check(!tracker.ShouldQuiet(rule, risk with { Reasons = ["different signal"] }, 1, now.AddSeconds(3)), "new reason is not quieted");
Check(!tracker.ShouldQuiet(rule, risk, 2, now.AddSeconds(4)), "policy revision resets repeat state");
Check(tracker.ShouldQuiet(rule, risk, 2, now.AddSeconds(5)), "repeat state rebuilt under new revision");
tracker.Revoke(process);
Check(!tracker.ShouldQuiet(rule, risk, 2, now.AddSeconds(6)), "mismatch revokes repeat state");
Check(!tracker.ShouldQuiet(rule, risk, 2, now.AddSeconds(200)), "quiet period does not renew forever on every hit");
Check(!tracker.ShouldQuiet(rule, risk, 2, rule.ExpiresUtc), "expired rule cannot quiet repeats");
Check(!tracker.ShouldQuiet(rule with { Effect = "AnnotateOnly" }, risk, 2, now.AddSeconds(201)), "annotation alone never suppresses warnings");
var growing = new ScopedRepeatTracker();
growing.ShouldQuiet(rule, risk, 1, now);
Check(!growing.ShouldQuiet(rule, risk with { Writes = 22 }, 1, now.AddSeconds(1)), "growing writes remain visible even without a score change");
Check(!growing.ShouldQuiet(rule, risk with { DistinctFiles = 4 }, 1, now.AddSeconds(2)), "growing file breadth remains visible");
Check(!growing.ShouldQuiet(rule, risk with { Deletes = 1 }, 1, now.AddSeconds(3)), "growing deletes remain visible");
Check(!DecisionPolicy.Decide(risk, image, null, true, true, false, true, now).AllowLabSuspend, "scoped rule cannot authorize ordinary process suspension");
Check(risk.Score == 110 && risk.Evidence.Length == 21, "evidence/score unchanged by policy evaluation");
Console.WriteLine($"All {tests} scoped trust policy tests passed. No Windows process, ETW, ACL or UI integration was exercised.");
