using RansomGuard.Core;
int passed = 0;
void Check(bool ok, string name) { if (!ok) throw new Exception(name); passed++; Console.WriteLine("PASS: " + name); }
void Reject(Action action, string name)
{
    bool rejected = false;
    try { action(); } catch (Exception ex) when (ex is ArgumentException or OperationCanceledException) { rejected = true; }
    Check(rejected, name);
}
string id = Guid.NewGuid().ToString("N"), hash = new string('A', 64);
foreach (var action in new[] { "rules", "add", "edit", "disable", "remove", "install", "update", "start", "stop", "restart", "uninstall", "state-repair", "recovery-review" })
{
    Check(AdminContract.IsAction(action), "recognized UI action " + action);
    AdminContract.ValidateIntent(action, AdminContract.NeedsRuleId(action) ? id : null);
    Check(true, "valid action and id pairing " + action);
}
foreach (var bad in new string?[] { null, "", "kill", "suspend", "load", "shell", "INSTALL", "start RansomGuard", "start;calc", "..", "--install" })
    Check(!AdminContract.IsAction(bad), "reject unsupported verb " + (bad ?? "null"));
foreach (var action in new[] { "edit", "disable", "remove" })
{
    Reject(() => AdminContract.ValidateIntent(action, null), action + " requires id");
    Reject(() => AdminContract.ValidateIntent(action, "../rules.json"), action + " rejects path");
    Reject(() => AdminContract.ValidateIntent(action, "RansomGuardV03"), action + " rejects service-name-as-id");
}
foreach (var action in new[] { "rules", "add", "install", "update", "start", "stop", "restart", "uninstall", "state-repair", "recovery-review" })
    Reject(() => AdminContract.ValidateIntent(action, id), action + " rejects unrelated id");
foreach (var action in new[] { "install", "update", "start", "stop", "restart", "uninstall", "state-repair", "disable", "remove" })
{
    AdminContract.CheckConfirmation(action, AdminContract.Confirmation(action));
    Check(true, "exact confirmation " + action);
    Reject(() => AdminContract.CheckConfirmation(action, "yes"), "generic consent rejected " + action);
    Reject(() => AdminContract.CheckConfirmation(action, AdminContract.Confirmation(action) + " "), "trailing-space consent rejected " + action);
}
Check(AdminContract.Confirmation("add", hash) == "TRUST AAAAAAAAAAAA", "exact hash confirmation");
Reject(() => AdminContract.Confirmation("add", new string('A', 32)), "MD5 cannot approve rule");
Reject(() => AdminContract.Confirmation("add", null), "missing hash cannot approve rule");
Reject(() => AdminContract.CheckConfirmation("edit", "TRUST BBBBBBBBBBBB", hash), "mismatched hash confirmation rejected");
Check(AdminContract.ServiceName == "RansomGuardV03", "single fixed own service name");
Check(ServiceUpdatePolicy.IsForwardVersion("0.8.7.0", "0.9.0.0"), "forward update version accepted");
Check(!ServiceUpdatePolicy.IsForwardVersion("0.8.7.0", "0.8.7.0"), "same-version replay rejected");
Check(!ServiceUpdatePolicy.IsForwardVersion("0.9.0.0", "0.8.7.0"), "downgrade rejected");
Check(!ServiceUpdatePolicy.IsForwardVersion("invalid", "0.9.0.0"), "invalid installed version rejected");
Check(!ServiceUpdatePolicy.IsForwardVersion("0.8.7.0", "invalid"), "invalid target version rejected");
Check(!AdminContract.NeedsRuleId("recovery-review"), "recovery review never accepts a rule id");
Reject(() => AdminContract.Confirmation("recovery-review"), "recovery review has no mutation confirmation verb");

var ready = new SetupReview(true, false, "NotInstalled", true, true, SetupStorage.Private, true, "revision-1");
Check(SetupReviewPolicy.CanInstall(ready, false), "reviewed folder plan permits install click");
Check(SetupReviewPolicy.CanInstall(ready with { Storage = SetupStorage.Missing }, false), "new state created only by approved install");
Check(!SetupReviewPolicy.CanInstall(null, false), "no review cannot install");
Check(!SetupReviewPolicy.CanInstall(ready, true), "busy cannot submit twice");
Check(!SetupReviewPolicy.CanInstall(ready with { Installed = true }, false), "existing registration never overwritten");
Check(!SetupReviewPolicy.CanInstall(ready with { PackageVerified = false }, false), "unverified package cannot install");
Check(!SetupReviewPolicy.CanInstall(ready with { FoldersVerified = false }, false), "unreviewed folder paths cannot install");
Check(!SetupReviewPolicy.CanInstall(ready with { ServiceQuerySucceeded = false }, false), "unknown registration cannot install");
foreach (var storage in new[] { SetupStorage.Unknown, SetupStorage.Unreadable, SetupStorage.NeedsReview })
    Check(!SetupReviewPolicy.CanInstall(ready with { Storage = storage }, false), "uncertain or unsafe store never bypassed: " + storage);
var unsafeState = ready with { Storage = SetupStorage.NeedsReview };
Check(!SetupReviewPolicy.CanReset(unsafeState, false, false), "installation intent does not authorize state reset");
Check(SetupReviewPolicy.CanReset(unsafeState, true, false), "separate explicit reset acknowledgement");
Check(!SetupReviewPolicy.CanReset(null, true, false), "reset needs snapshot");
Check(!SetupReviewPolicy.CanReset(unsafeState, true, true), "reset double click blocked");
Check(!SetupReviewPolicy.CanReset(unsafeState with { CanArchive = false }, true, false), "wrong-owner state not auto archived");
Check(!SetupReviewPolicy.CanReset(unsafeState with { StorageRevision = null }, true, false), "reset requires identity revision");
Check(!SetupReviewPolicy.CanReset(unsafeState with { StorageRevision = "" }, true, false), "empty revision rejected");
Check(!SetupReviewPolicy.CanReset(ready, true, false), "valid store not reset");
Check(!SetupReviewPolicy.CanReset(unsafeState with { ServiceQuerySucceeded = false }, true, false), "unknown SCM prevents reset");
foreach (var state in new[] { "Running", "StartPending", "StopPending", "Unknown" })
    Check(!SetupReviewPolicy.CanReset(unsafeState with { Installed = true, ServiceState = state }, true, false), "reset refuses non-idle registration: " + state);
var stopped = ready with { Installed = true, ServiceState = "Stopped" };
var running = stopped with { ServiceState = "Running" };
Check(SetupReviewPolicy.CanControl(stopped, "start", false, false), "start uses its own explicit button");
Check(!SetupReviewPolicy.CanControl(stopped, "stop", true, false), "cannot stop missing running state");
foreach (string action in new[] { "stop", "restart", "uninstall" })
{
    var state = action == "uninstall" ? stopped : running;
    Check(!SetupReviewPolicy.CanControl(state, action, false, false), "consequence consent required: " + action);
    Check(SetupReviewPolicy.CanControl(state, action, true, false), "reviewed service action: " + action);
    Check(!SetupReviewPolicy.CanControl(state with { PackageVerified = false }, action, true, false), "paired binary required: " + action);
    Check(!SetupReviewPolicy.CanControl(state, action, true, true), "busy service action rejected: " + action);
}
Check(!SetupReviewPolicy.CanControl(running, "uninstall", true, false), "no silent stop during unregister");
Check(!SetupReviewPolicy.CanControl(stopped with { Storage = SetupStorage.NeedsReview }, "start", true, false), "store reset not implicit in start");
foreach (string bad in new[] { "kill", "load", "shell", "state-repair", "INSTALL", "" })
    Check(!SetupReviewPolicy.CanControl(stopped, bad, true, false), "no extra wizard operation: " + bad);
Console.WriteLine($"All {passed} administration contract tests passed. No Windows service, UAC or rule store was accessed.");
