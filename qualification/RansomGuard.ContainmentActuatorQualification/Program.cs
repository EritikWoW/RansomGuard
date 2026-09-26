using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using RansomGuard.Core;
using RansomGuard.Service;

if (!OperatingSystem.IsWindows())
    return 2;

if (args.Length == 4 && string.Equals(args[0], "--fixture", StringComparison.Ordinal))
    return RunFixture(args[1], args[2], args[3]);

if (args.Length == 6 && string.Equals(args[0], "--state-change-helper", StringComparison.Ordinal))
    return RunStateChangeHelper(args[1], args[2], args[3], args[4], args[5]);

if (args.Length != 3 || !string.Equals(args[0], "--run", StringComparison.Ordinal))
{
    Console.Error.WriteLine("Use: --run <results-dir> <expected-sha> | --fixture <ready> <release> <heartbeat> | --state-change-helper <pid> <creation-filetime> <ready> <release> <result>");
    return 3;
}

if (!string.Equals(Environment.GetEnvironmentVariable("RANSOMGUARD_LAB_VM"), "I_UNDERSTAND", StringComparison.Ordinal))
{
    Console.Error.WriteLine("REFUSED: disposable VM acknowledgement is required.");
    return 4;
}

using (var identity = WindowsIdentity.GetCurrent())
{
    if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) && !identity.IsSystem)
    {
        Console.Error.WriteLine("REFUSED: elevated Administrator/SYSTEM qualification is required.");
        return 5;
    }
}

var results = Path.GetFullPath(args[1]);
var expectedSha = args[2];
if (expectedSha.Length != 40 || !expectedSha.All(Uri.IsHexDigit))
{
    Console.Error.WriteLine("expected SHA must be 40 hexadecimal characters.");
    return 6;
}
Directory.CreateDirectory(results);

var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Qualification executable path unavailable.");
var target = StartFixture(exe, results, "target");
var unrelated = StartFixture(exe, results, "unrelated");

try
{
    WaitForFile(target.Ready, TimeSpan.FromSeconds(10));
    WaitForFile(unrelated.Ready, TimeSpan.FromSeconds(10));

    var targetKey = ProcessIdentity(target.Process);
    var targetPath = ImagePath(target.Process);
    var targetHash = HashFresh(targetPath) ?? throw new IOException("Unable to hash target image.");

    var platform = new WindowsContainmentActuationPlatform(HashFresh);

    bool successSuspended;
    bool exactIdentityBound;
    bool unrelatedUnaffected;
    bool resumeRecovered;
    bool replayRejected;
    string successArtifactState;
    string successResumeState;

    var successLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-success"));
    var successProtection = ProtectedSnapshot();
    var successBinding = Binding(targetKey, targetPath, targetHash, successProtection, "success");
    var successRequest = new ContainmentActuationRequest(
        Guid.NewGuid().ToString("N"),
        successBinding,
        DateTime.UtcNow);

    var actuator = new ContainmentActuator(platform);
    var suspended = actuator.Suspend(
        successRequest,
        successLedger,
        lease => Validate(successBinding, lease, successProtection, true, successLedger),
        new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(5)));

    successArtifactState = suspended.State;
    exactIdentityBound =
        successLedger.Records.First().Phase == ContainmentActuationLedgerPhase.Prepared &&
        successLedger.Records
            .Where(x => x.Phase == ContainmentActuationLedgerPhase.SuspendOwned)
            .All(x => x.ThreadId != 0 && x.ThreadCreationFileTimeUtc > 0);

    Thread.Sleep(150);
    var targetBeatA = ReadHeartbeat(target.Heartbeat);
    var unrelatedBeatA = ReadHeartbeat(unrelated.Heartbeat);
    Thread.Sleep(400);
    var targetBeatB = ReadHeartbeat(target.Heartbeat);
    var unrelatedBeatB = ReadHeartbeat(unrelated.Heartbeat);

    successSuspended =
        suspended.State == ContainmentActuationResultState.Suspended.ToString() &&
        suspended.OwnedSuspendCount > 0 &&
        targetBeatA == targetBeatB;
    unrelatedUnaffected = unrelatedBeatB > unrelatedBeatA;

    var resumed = actuator.ResumeOwned(successRequest, successLedger);
    successResumeState = resumed.State;
    resumeRecovered =
        resumed.State == ContainmentActuationResultState.Resumed.ToString() &&
        resumed.OwnedSuspendCount == 0 &&
        WaitForHeartbeatAdvance(target.Heartbeat, targetBeatB, TimeSpan.FromSeconds(3));

    replayRejected = false;
    try
    {
        actuator.Suspend(
            successRequest with { RequestId = Guid.NewGuid().ToString("N") },
            successLedger,
            lease => Validate(successBinding, lease, successProtection, true, successLedger),
            new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(3)));
    }
    catch (InvalidOperationException ex) when (ex.Message.StartsWith("ActuationRevalidationDenied:", StringComparison.Ordinal))
    {
        replayRejected = true;
    }

    var mismatchBinding = Binding(
        targetKey with { CreationFileTimeUtc = targetKey.CreationFileTimeUtc + 1 },
        targetPath,
        targetHash,
        ProtectedSnapshot(),
        "pid-reuse");
    var mismatchLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-pid-reuse"));
    var identityMismatchRejected = false;
    try
    {
        actuator.Suspend(
            new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), mismatchBinding, DateTime.UtcNow),
            mismatchLedger,
            lease => Validate(mismatchBinding, lease, ProtectedSnapshot(mismatchBinding.ProtectionObservedUtc), true, mismatchLedger));
    }
    catch (InvalidOperationException ex) when (ex.Message == "ProcessIdentityChanged")
    {
        identityMismatchRejected = true;
    }

    var hashProtection = ProtectedSnapshot();
    var hashBinding = Binding(targetKey, targetPath, new string('F', 64), hashProtection, "hash-drift");
    var hashLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-hash-drift"));
    var hashDriftRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), hashBinding, DateTime.UtcNow),
        hashLedger,
        lease => Validate(hashBinding, lease, hashProtection, true, hashLedger));

    var expiredProtection = ProtectedSnapshot();
    var expiredEvaluated = DateTime.UtcNow.AddSeconds(-5);
    var expiredBinding = Binding(
        targetKey,
        targetPath,
        targetHash,
        expiredProtection,
        "expired",
        expiredEvaluated,
        expiredEvaluated.AddSeconds(3));
    var expiredLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-expired"));
    var expiryRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), expiredBinding, DateTime.UtcNow),
        expiredLedger,
        lease => Validate(expiredBinding, lease, expiredProtection, true, expiredLedger));

    var degradedProtection = ProtectedSnapshot();
    var degradedBinding = Binding(targetKey, targetPath, targetHash, degradedProtection, "degraded");
    var degradedCurrent = TransitionSnapshot(
        ProtectionPhase.DegradedProtected,
        degradedBinding.ProtectionObservedUtc.AddTicks(1));
    var degradedLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-degraded"));
    var degradedRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), degradedBinding, DateTime.UtcNow),
        degradedLedger,
        lease => Validate(degradedBinding, lease, degradedCurrent, true, degradedLedger));

    var maintenanceProtection = ProtectedSnapshot();
    var maintenanceBinding = Binding(targetKey, targetPath, targetHash, maintenanceProtection, "maintenance");
    var maintenanceLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-maintenance"));
    var maintenanceRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), maintenanceBinding, DateTime.UtcNow),
        maintenanceLedger,
        lease => Validate(
            maintenanceBinding,
            lease,
            TransitionSnapshot(ProtectionPhase.Maintenance, maintenanceBinding.ProtectionObservedUtc.AddTicks(1)),
            true,
            maintenanceLedger));

    var failedProtection = ProtectedSnapshot();
    var failedBinding = Binding(targetKey, targetPath, targetHash, failedProtection, "failed");
    var failedLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-failed"));
    var failedRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), failedBinding, DateTime.UtcNow),
        failedLedger,
        lease => Validate(
            failedBinding,
            lease,
            TransitionSnapshot(ProtectionPhase.Failed, failedBinding.ProtectionObservedUtc.AddTicks(1)),
            true,
            failedLedger));

    var stoppedProtection = ProtectedSnapshot();
    var stoppedBinding = Binding(targetKey, targetPath, targetHash, stoppedProtection, "stopped");
    var stoppedLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-stopped"));
    var stoppedRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), stoppedBinding, DateTime.UtcNow),
        stoppedLedger,
        lease => Validate(
            stoppedBinding,
            lease,
            TransitionSnapshot(ProtectionPhase.Stopped, stoppedBinding.ProtectionObservedUtc.AddTicks(1)),
            true,
            stoppedLedger));

    var telemetryProtection = ProtectedSnapshot();
    var telemetryBinding = Binding(targetKey, targetPath, targetHash, telemetryProtection, "telemetry-loss");
    var telemetryLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-telemetry-loss"));
    var telemetryRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), telemetryBinding, DateTime.UtcNow),
        telemetryLedger,
        lease => Validate(telemetryBinding, lease, telemetryProtection, false, telemetryLedger));

    var unknownCriticalProtection = ProtectedSnapshot();
    var unknownCriticalBinding = Binding(targetKey, targetPath, targetHash, unknownCriticalProtection, "critical-unknown");
    var unknownCriticalLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-critical-unknown"));
    var unknownCriticalRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), unknownCriticalBinding, DateTime.UtcNow),
        unknownCriticalLedger,
        lease => Validate(
            unknownCriticalBinding,
            lease,
            unknownCriticalProtection,
            true,
            unknownCriticalLedger,
            criticalStateKnownOverride: false));

    var criticalProtection = ProtectedSnapshot();
    var criticalBinding = Binding(targetKey, targetPath, targetHash, criticalProtection, "critical");
    var criticalLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-critical"));
    var criticalRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), criticalBinding, DateTime.UtcNow),
        criticalLedger,
        lease => Validate(
            criticalBinding,
            lease,
            criticalProtection,
            true,
            criticalLedger,
            criticalStateKnownOverride: true,
            isCriticalOverride: true));

    var selfProtection = ProtectedSnapshot();
    var selfBinding = Binding(targetKey, targetPath, targetHash, selfProtection, "self");
    var selfLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-self"));
    var selfRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), selfBinding, DateTime.UtcNow),
        selfLedger,
        lease => Validate(
            selfBinding,
            lease,
            selfProtection,
            true,
            selfLedger,
            isSelf: true));

    var serviceProtection = ProtectedSnapshot();
    var serviceBinding = Binding(targetKey, targetPath, targetHash, serviceProtection, "protected-service");
    var serviceLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-protected-service"));
    var protectedServiceRejected = RevalidationRejected(
        actuator,
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), serviceBinding, DateTime.UtcNow),
        serviceLedger,
        lease => Validate(
            serviceBinding,
            lease,
            serviceProtection,
            true,
            serviceLedger,
            isProtectedServiceProcess: true));

    var partialProtection = ProtectedSnapshot();
    var partialBinding = Binding(targetKey, targetPath, targetHash, partialProtection, "partial");
    var partialLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-partial"));
    var partialPlatform = new WrappedPlatform(platform, failSuspendOrdinal: 2, cancelAfterSuspendOrdinal: 0, null);
    var partialActuator = new ContainmentActuator(partialPlatform);
    var partialResult = partialActuator.Suspend(
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), partialBinding, DateTime.UtcNow),
        partialLedger,
        lease => Validate(partialBinding, lease, partialProtection, true, partialLedger),
        new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(5)));
    var partialRecovered =
        partialResult.State == ContainmentActuationResultState.FailedRecovered.ToString() &&
        partialResult.OwnedSuspendCount == 0 &&
        WaitForHeartbeatAdvance(target.Heartbeat, ReadHeartbeat(target.Heartbeat), TimeSpan.FromSeconds(2));

    var restartProtection = ProtectedSnapshot();
    var restartBinding = Binding(targetKey, targetPath, targetHash, restartProtection, "restart-recovery");
    var restartRequest = new ContainmentActuationRequest(
        Guid.NewGuid().ToString("N"),
        restartBinding,
        DateTime.UtcNow);
    var restartLedgerRoot = Path.Combine(results, "ledger-restart-recovery");
    var restartLedger = new ContainmentActuationLedger(restartLedgerRoot);
    var restartSuspended = actuator.Suspend(
        restartRequest,
        restartLedger,
        lease => Validate(restartBinding, lease, restartProtection, true, restartLedger),
        new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(5)));
    Thread.Sleep(150);
    var restartBeatA = ReadHeartbeat(target.Heartbeat);
    Thread.Sleep(350);
    var restartBeatB = ReadHeartbeat(target.Heartbeat);
    var restartWasSuspended =
        restartSuspended.State == ContainmentActuationResultState.Suspended.ToString() &&
        restartSuspended.OwnedSuspendCount > 0 &&
        restartBeatA == restartBeatB;

    restartLedger.VerifyAll();
    var reopenedRestartLedger = new ContainmentActuationLedger(restartLedgerRoot, createIfMissing: false);
    reopenedRestartLedger.VerifyAll();
    var restartResumed = new ContainmentActuator(platform).ResumeOwned(restartRequest, reopenedRestartLedger);
    reopenedRestartLedger.VerifyAll();
    var restartRecoveryRecovered =
        restartWasSuspended &&
        restartResumed.State == ContainmentActuationResultState.Resumed.ToString() &&
        restartResumed.OwnedSuspendCount == 0 &&
        WaitForHeartbeatAdvance(target.Heartbeat, restartBeatB, TimeSpan.FromSeconds(3));

    var timeoutProtection = ProtectedSnapshot();
    var timeoutBinding = Binding(targetKey, targetPath, targetHash, timeoutProtection, "timeout");
    var timeoutLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-timeout"));
    var timeoutPlatform = new WrappedPlatform(
        platform,
        failSuspendOrdinal: 0,
        cancelAfterSuspendOrdinal: 0,
        cancel: null,
        delayAfterSuspendOrdinal: 1,
        delayAfterSuspend: TimeSpan.FromMilliseconds(250));
    var timeoutActuator = new ContainmentActuator(timeoutPlatform);
    var timeoutResult = timeoutActuator.Suspend(
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), timeoutBinding, DateTime.UtcNow),
        timeoutLedger,
        lease => Validate(timeoutBinding, lease, timeoutProtection, true, timeoutLedger),
        new ContainmentActuatorOptions(256, 6, TimeSpan.FromMilliseconds(100)));
    var timeoutRecovered =
        timeoutResult.State == ContainmentActuationResultState.FailedRecovered.ToString() &&
        timeoutResult.OwnedSuspendCount == 0 &&
        timeoutResult.ReasonCodes.Contains("ActuationTimedOut", StringComparer.Ordinal) &&
        WaitForHeartbeatAdvance(target.Heartbeat, ReadHeartbeat(target.Heartbeat), TimeSpan.FromSeconds(2));

    var cancelProtection = ProtectedSnapshot();
    var cancelBinding = Binding(targetKey, targetPath, targetHash, cancelProtection, "cancel");
    var cancelLedger = new ContainmentActuationLedger(Path.Combine(results, "ledger-cancel"));
    using var cts = new CancellationTokenSource();
    var cancelPlatform = new WrappedPlatform(platform, failSuspendOrdinal: 0, cancelAfterSuspendOrdinal: 1, cts);
    var cancelActuator = new ContainmentActuator(cancelPlatform);
    var cancelResult = cancelActuator.Suspend(
        new ContainmentActuationRequest(Guid.NewGuid().ToString("N"), cancelBinding, DateTime.UtcNow),
        cancelLedger,
        lease => Validate(cancelBinding, lease, cancelProtection, true, cancelLedger),
        new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(5)),
        cts.Token);
    var cancellationRecovered =
        cancelResult.State == ContainmentActuationResultState.FailedRecovered.ToString() &&
        cancelResult.OwnedSuspendCount == 0 &&
        WaitForHeartbeatAdvance(target.Heartbeat, ReadHeartbeat(target.Heartbeat), TimeSpan.FromSeconds(2));

    var stateChangeApiAvailable = ProcessStateChangeNative.IsAvailable();
    var stateChangeExplicitResumeRecovered = false;
    var stateChangeCrashReleaseRecovered = false;

    if (stateChangeApiAvailable)
    {
        var explicitHelper = StartStateChangeHelper(exe, targetKey, results, "state-change-explicit");
        try
        {
            if (WaitForFileOrExit(explicitHelper.Ready, explicitHelper.Process, TimeSpan.FromSeconds(10)))
            {
                Thread.Sleep(150);
                var explicitBeatA = ReadHeartbeat(target.Heartbeat);
                Thread.Sleep(350);
                var explicitBeatB = ReadHeartbeat(target.Heartbeat);
                var explicitFrozen = explicitBeatA == explicitBeatB;

                File.WriteAllText(explicitHelper.Release, "resume");
                var helperExited = explicitHelper.Process.WaitForExit(5000);
                var helperSucceeded = helperExited && explicitHelper.Process.ExitCode == 0;
                stateChangeExplicitResumeRecovered =
                    explicitFrozen &&
                    helperSucceeded &&
                    WaitForHeartbeatAdvance(target.Heartbeat, explicitBeatB, TimeSpan.FromSeconds(3));
            }
        }
        finally
        {
            StopHelper(explicitHelper);
        }

        var crashHelper = StartStateChangeHelper(exe, targetKey, results, "state-change-crash");
        try
        {
            if (WaitForFileOrExit(crashHelper.Ready, crashHelper.Process, TimeSpan.FromSeconds(10)))
            {
                Thread.Sleep(150);
                var crashBeatA = ReadHeartbeat(target.Heartbeat);
                Thread.Sleep(350);
                var crashBeatB = ReadHeartbeat(target.Heartbeat);
                var crashFrozen = crashBeatA == crashBeatB;

                if (!crashHelper.Process.HasExited)
                {
                    crashHelper.Process.Kill(entireProcessTree: false);
                    crashHelper.Process.WaitForExit(5000);
                }

                stateChangeCrashReleaseRecovered =
                    crashFrozen &&
                    WaitForHeartbeatAdvance(target.Heartbeat, crashBeatB, TimeSpan.FromSeconds(3));
            }
        }
        finally
        {
            StopHelper(crashHelper);
        }
    }

    var passed =
        successSuspended &&
        exactIdentityBound &&
        unrelatedUnaffected &&
        resumeRecovered &&
        replayRejected &&
        identityMismatchRejected &&
        hashDriftRejected &&
        expiryRejected &&
        degradedRejected &&
        maintenanceRejected &&
        failedRejected &&
        stoppedRejected &&
        telemetryRejected &&
        unknownCriticalRejected &&
        criticalRejected &&
        selfRejected &&
        protectedServiceRejected &&
        partialRecovered &&
        restartRecoveryRecovered &&
        timeoutRecovered &&
        cancellationRecovered &&
        stateChangeApiAvailable &&
        stateChangeExplicitResumeRecovered &&
        stateChangeCrashReleaseRecovered;

    var summary = new
    {
        schema = 1,
        expectedSha = expectedSha.ToLowerInvariant(),
        target = new { targetKey.Pid, targetKey.CreationFileTimeUtc, path = targetPath, sha256 = targetHash },
        successArtifactState,
        successResumeState,
        successSuspended,
        exactIdentityBound,
        unrelatedUnaffected,
        resumeRecovered,
        replayRejected,
        identityMismatchRejected,
        hashDriftRejected,
        expiryRejected,
        degradedRejected,
        maintenanceRejected,
        failedRejected,
        stoppedRejected,
        telemetryRejected,
        unknownCriticalRejected,
        criticalRejected,
        selfRejected,
        protectedServiceRejected,
        partialRecovered,
        restartRecoveryRecovered,
        timeoutRecovered,
        cancellationRecovered,
        stateChangeApiAvailable,
        stateChangeExplicitResumeRecovered,
        stateChangeCrashReleaseRecovered,
        osVersion = Environment.OSVersion.VersionString,
        passed
    };
    File.WriteAllText(
        Path.Combine(results, "containment-actuator-qualification.json"),
        JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));

    return passed ? 0 : 20;
}
finally
{
    StopFixture(target);
    StopFixture(unrelated);
}

static int RunStateChangeHelper(
    string pidText,
    string creationFileTimeText,
    string ready,
    string release,
    string result)
{
    ready = Path.GetFullPath(ready);
    release = Path.GetFullPath(release);
    result = Path.GetFullPath(result);
    foreach (var path in new[] { ready, release, result })
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(parent))
            Directory.CreateDirectory(parent);
        if (File.Exists(path))
            File.Delete(path);
    }

    if (!int.TryParse(pidText, out var pid) || pid <= 4 ||
        !long.TryParse(creationFileTimeText, out var creationFileTime) || creationFileTime <= 0)
    {
        File.WriteAllText(result, "invalid-target-identity");
        return 31;
    }

    if (!ProcessStateChangeNative.IsAvailable())
    {
        File.WriteAllText(result, "process-state-change-api-unavailable");
        return 32;
    }

    const uint ProcessSetInformation = 0x0200;
    using var process = Native.OpenProcess(
        Native.Query | Native.Synchronize | Native.SuspendResume | ProcessSetInformation,
        false,
        pid);
    if (process.IsInvalid)
    {
        File.WriteAllText(result, "open-process-failed:" + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
        return 33;
    }

    var live = Native.Identity(process, pid);
    var expected = new ProcessKey(pid, creationFileTime);
    if (live is null || live.Value != expected)
    {
        File.WriteAllText(result, "process-identity-changed");
        return 34;
    }

    var createStatus = ProcessStateChangeNative.NtCreateProcessStateChange(
        out var stateChange,
        ProcessStateChangeNative.ProcessStateAllAccess,
        IntPtr.Zero,
        process,
        0);
    if (createStatus < 0 || stateChange == IntPtr.Zero)
    {
        File.WriteAllText(result, $"create-state-change-failed:0x{unchecked((uint)createStatus):X8}");
        return 35;
    }

    try
    {
        var suspendStatus = ProcessStateChangeNative.NtChangeProcessState(
            stateChange,
            process,
            ProcessStateChangeNative.ProcessStateChangeSuspend,
            IntPtr.Zero,
            UIntPtr.Zero,
            0);
        if (suspendStatus < 0)
        {
            File.WriteAllText(result, $"suspend-state-change-failed:0x{unchecked((uint)suspendStatus):X8}");
            return 36;
        }

        File.WriteAllText(
            ready,
            $"pid={pid};creationFileTime={creationFileTime};utc={DateTime.UtcNow:O}");

        var deadline = DateTime.UtcNow.AddMinutes(5);
        while (!File.Exists(release))
        {
            if (DateTime.UtcNow >= deadline)
            {
                File.WriteAllText(result, "release-timeout");
                return 37;
            }
            Thread.Sleep(25);
        }

        var resumeStatus = ProcessStateChangeNative.NtChangeProcessState(
            stateChange,
            process,
            ProcessStateChangeNative.ProcessStateChangeResume,
            IntPtr.Zero,
            UIntPtr.Zero,
            0);
        if (resumeStatus < 0)
        {
            File.WriteAllText(result, $"resume-state-change-failed:0x{unchecked((uint)resumeStatus):X8}");
            return 38;
        }

        File.WriteAllText(result, "explicit-resume-success");
        return 0;
    }
    finally
    {
        if (stateChange != IntPtr.Zero)
            _ = Native.CloseHandle(stateChange);
    }
}

static StateChangeHelper StartStateChangeHelper(
    string exe,
    ProcessKey target,
    string results,
    string name)
{
    var ready = Path.Combine(results, name + ".ready");
    var release = Path.Combine(results, name + ".release");
    var result = Path.Combine(results, name + ".result");
    foreach (var path in new[] { ready, release, result })
        if (File.Exists(path)) File.Delete(path);

    var start = new ProcessStartInfo(exe) { UseShellExecute = false };
    start.ArgumentList.Add("--state-change-helper");
    start.ArgumentList.Add(target.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
    start.ArgumentList.Add(target.CreationFileTimeUtc.ToString(System.Globalization.CultureInfo.InvariantCulture));
    start.ArgumentList.Add(ready);
    start.ArgumentList.Add(release);
    start.ArgumentList.Add(result);
    var process = Process.Start(start) ?? throw new IOException("Unable to launch process-state-change helper.");
    return new(process, ready, release, result);
}

static bool WaitForFileOrExit(string path, Process process, TimeSpan timeout)
{
    var deadline = DateTime.UtcNow + timeout;
    while (DateTime.UtcNow < deadline)
    {
        if (File.Exists(path))
            return true;
        if (process.HasExited)
            return false;
        Thread.Sleep(25);
    }
    return false;
}

static void StopHelper(StateChangeHelper helper)
{
    try
    {
        if (!helper.Process.HasExited)
        {
            helper.Process.Kill(entireProcessTree: false);
            helper.Process.WaitForExit(3000);
        }
    }
    catch { }
    finally
    {
        helper.Process.Dispose();
    }
}

static int RunFixture(string ready, string release, string heartbeat)
{
    ready = Path.GetFullPath(ready);
    release = Path.GetFullPath(release);
    heartbeat = Path.GetFullPath(heartbeat);
    Directory.CreateDirectory(Path.GetDirectoryName(ready)!);
    foreach (var p in new[] { ready, release, heartbeat })
        if (File.Exists(p)) File.Delete(p);

    using var stop = new CancellationTokenSource();
    var workers = Enumerable.Range(0, 3).Select(_ =>
    {
        var thread = new Thread(() =>
        {
            while (!stop.IsCancellationRequested && !File.Exists(release))
                Thread.Sleep(25);
        })
        { IsBackground = true };
        thread.Start();
        return thread;
    }).ToArray();

    File.WriteAllText(ready, Environment.ProcessId.ToString());
    try
    {
        while (!File.Exists(release))
        {
            File.WriteAllText(heartbeat, DateTime.UtcNow.Ticks.ToString());
            Thread.Sleep(40);
        }
    }
    finally
    {
        stop.Cancel();
        foreach (var worker in workers)
            worker.Join(1000);
    }
    return 0;
}

static Fixture StartFixture(string exe, string results, string name)
{
    var ready = Path.Combine(results, name + ".ready");
    var release = Path.Combine(results, name + ".release");
    var heartbeat = Path.Combine(results, name + ".heartbeat");
    foreach (var p in new[] { ready, release, heartbeat })
        if (File.Exists(p)) File.Delete(p);

    var start = new ProcessStartInfo(exe) { UseShellExecute = false };
    start.ArgumentList.Add("--fixture");
    start.ArgumentList.Add(ready);
    start.ArgumentList.Add(release);
    start.ArgumentList.Add(heartbeat);
    var process = Process.Start(start) ?? throw new IOException("Unable to launch fixture.");
    return new(process, ready, release, heartbeat);
}

static void StopFixture(Fixture fixture)
{
    try
    {
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.Release)!);
        File.WriteAllText(fixture.Release, "release");
        if (!fixture.Process.WaitForExit(3000))
            fixture.Process.Kill(entireProcessTree: false);
    }
    catch { }
    finally { fixture.Process.Dispose(); }
}

static void WaitForFile(string path, TimeSpan timeout)
{
    var deadline = DateTime.UtcNow + timeout;
    while (!File.Exists(path))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for fixture: " + path);
        Thread.Sleep(25);
    }
}

static long ReadHeartbeat(string path)
{
    if (!File.Exists(path))
        return 0;
    return long.TryParse(File.ReadAllText(path), out var value) ? value : 0;
}

static bool WaitForHeartbeatAdvance(string path, long baseline, TimeSpan timeout)
{
    var deadline = DateTime.UtcNow + timeout;
    while (DateTime.UtcNow < deadline)
    {
        if (ReadHeartbeat(path) > baseline)
            return true;
        Thread.Sleep(40);
    }
    return false;
}

static ProcessKey ProcessIdentity(Process process)
{
    using var handle = Native.OpenProcess(Native.Query | Native.Synchronize, false, process.Id);
    return Native.Identity(handle, process.Id)
        ?? throw new IOException("Unable to bind fixture process identity.");
}

static string ImagePath(Process process)
{
    using var handle = Native.OpenProcess(Native.Query | Native.Synchronize, false, process.Id);
    return Native.ImagePath(handle)
        ?? throw new IOException("Unable to resolve fixture image path.");
}

static string? HashFresh(string? rawPath)
{
    var path = WinPaths.Normalize(rawPath);
    if (path is null || !File.Exists(path))
        return null;
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
    return Convert.ToHexString(SHA256.HashData(stream));
}

static ProtectionStatusDto ProtectedSnapshot(DateTime? observedUtc = null) =>
    new(
        RequestedProtectionMode.Enforce.ToString(),
        ProtectionPhase.Protected.ToString(),
        true,
        true,
        true,
        false,
        "containment actuator qualification",
        observedUtc ?? DateTime.UtcNow);

static ProtectionStatusDto TransitionSnapshot(ProtectionPhase phase, DateTime observedUtc) =>
    phase switch
    {
        ProtectionPhase.DegradedProtected => new(
            RequestedProtectionMode.Enforce.ToString(),
            phase.ToString(),
            true,
            false,
            true,
            false,
            "qualification degraded",
            observedUtc),
        ProtectionPhase.Maintenance => new(
            RequestedProtectionMode.Enforce.ToString(),
            phase.ToString(),
            true,
            false,
            false,
            false,
            "qualification maintenance",
            observedUtc),
        ProtectionPhase.Failed => new(
            RequestedProtectionMode.Enforce.ToString(),
            phase.ToString(),
            true,
            false,
            false,
            false,
            "qualification failed",
            observedUtc),
        ProtectionPhase.Stopped => new(
            RequestedProtectionMode.Enforce.ToString(),
            phase.ToString(),
            false,
            false,
            false,
            false,
            "qualification stopped",
            observedUtc),
        _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, "Unsupported qualification transition.")
    };

static ContainmentActuationBinding Binding(
    ProcessKey process,
    string imagePath,
    string imageSha256,
    ProtectionStatusDto protection,
    string caseSuffix,
    DateTime? evaluatedUtc = null,
    DateTime? expiresUtc = null)
{
    var evaluated = evaluatedUtc ?? DateTime.UtcNow;
    var expires = expiresUtc ?? evaluated.AddSeconds(8);
    return new(
        Guid.NewGuid().ToString("N"),
        "qual-" + caseSuffix,
        evaluated,
        expires,
        process,
        imagePath,
        imageSha256,
        protection.ObservedUtc,
        new(ContainmentAuthorizationState.Eligible.ToString(), true, Array.Empty<string>()));
}

static ContainmentActuationValidationDecision Validate(
    ContainmentActuationBinding binding,
    IContainmentProcessActuationLease lease,
    ProtectionStatusDto protection,
    bool telemetryHealthy,
    ContainmentActuationLedger ledger,
    bool? criticalStateKnownOverride = null,
    bool? isCriticalOverride = null,
    bool isSelf = false,
    bool isProtectedServiceProcess = false) =>
    ContainmentActuationPolicy.Evaluate(
        new(
            binding,
            DateTime.UtcNow,
            lease.Process,
            lease.ImagePath,
            lease.ImageSha256,
            protection,
            telemetryHealthy,
            criticalStateKnownOverride ?? lease.CriticalStateKnown,
            isCriticalOverride ?? lease.IsCritical,
            isSelf,
            isProtectedServiceProcess,
            ledger.IsAuthorizationConsumed(binding.AuthorizationId)));

static bool RevalidationRejected(
    ContainmentActuator actuator,
    ContainmentActuationRequest request,
    ContainmentActuationLedger ledger,
    Func<IContainmentProcessActuationLease, ContainmentActuationValidationDecision> validate)
{
    try
    {
        _ = actuator.Suspend(
            request,
            ledger,
            validate,
            new ContainmentActuatorOptions(256, 6, TimeSpan.FromSeconds(3)));
        return false;
    }
    catch (InvalidOperationException ex)
    {
        return ex.Message.StartsWith("ActuationRevalidationDenied:", StringComparison.Ordinal) ||
               ex.Message is "ActuationValidationBindingMismatch" or "ProcessIdentityChanged";
    }
}

sealed record StateChangeHelper(Process Process, string Ready, string Release, string Result);

static class ProcessStateChangeNative
{
    internal const uint ProcessStateAllAccess = 0x001F0001;
    internal const int ProcessStateChangeSuspend = 1;
    internal const int ProcessStateChangeResume = 2;

    internal static bool IsAvailable()
    {
        if (!NativeLibrary.TryLoad("ntdll.dll", out var library))
            return false;
        try
        {
            return NativeLibrary.TryGetExport(library, "NtCreateProcessStateChange", out _) &&
                   NativeLibrary.TryGetExport(library, "NtChangeProcessState", out _);
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    [System.Runtime.InteropServices.DllImport("ntdll.dll")]
    internal static extern int NtCreateProcessStateChange(
        out IntPtr processStateChangeHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        ProcessHandle processHandle,
        uint reserved);

    [System.Runtime.InteropServices.DllImport("ntdll.dll")]
    internal static extern int NtChangeProcessState(
        IntPtr processStateChangeHandle,
        ProcessHandle processHandle,
        int stateChangeType,
        IntPtr extendedInformation,
        UIntPtr extendedInformationLength,
        uint reserved);
}

sealed record Fixture(Process Process, string Ready, string Release, string Heartbeat);

sealed class WrappedPlatform : IContainmentProcessActuationPlatform
{
    private readonly IContainmentProcessActuationPlatform _inner;
    private readonly int _failSuspendOrdinal;
    private readonly int _cancelAfterSuspendOrdinal;
    private readonly CancellationTokenSource? _cancel;
    private readonly int _delayAfterSuspendOrdinal;
    private readonly TimeSpan _delayAfterSuspend;

    public WrappedPlatform(
        IContainmentProcessActuationPlatform inner,
        int failSuspendOrdinal,
        int cancelAfterSuspendOrdinal,
        CancellationTokenSource? cancel,
        int delayAfterSuspendOrdinal = 0,
        TimeSpan? delayAfterSuspend = null)
    {
        _inner = inner;
        _failSuspendOrdinal = failSuspendOrdinal;
        _cancelAfterSuspendOrdinal = cancelAfterSuspendOrdinal;
        _cancel = cancel;
        _delayAfterSuspendOrdinal = delayAfterSuspendOrdinal;
        _delayAfterSuspend = delayAfterSuspend ?? TimeSpan.Zero;
    }

    public IContainmentProcessActuationLease Open(ProcessKey expectedProcess) =>
        new WrappedLease(
            _inner.Open(expectedProcess),
            _failSuspendOrdinal,
            _cancelAfterSuspendOrdinal,
            _cancel,
            _delayAfterSuspendOrdinal,
            _delayAfterSuspend);
}

sealed class WrappedLease : IContainmentProcessActuationLease
{
    private readonly IContainmentProcessActuationLease _inner;
    private readonly int _failSuspendOrdinal;
    private readonly int _cancelAfterSuspendOrdinal;
    private readonly CancellationTokenSource? _cancel;
    private readonly int _delayAfterSuspendOrdinal;
    private readonly TimeSpan _delayAfterSuspend;
    private int _suspendOrdinal;

    public WrappedLease(
        IContainmentProcessActuationLease inner,
        int failSuspendOrdinal,
        int cancelAfterSuspendOrdinal,
        CancellationTokenSource? cancel,
        int delayAfterSuspendOrdinal,
        TimeSpan delayAfterSuspend)
    {
        _inner = inner;
        _failSuspendOrdinal = failSuspendOrdinal;
        _cancelAfterSuspendOrdinal = cancelAfterSuspendOrdinal;
        _cancel = cancel;
        _delayAfterSuspendOrdinal = delayAfterSuspendOrdinal;
        _delayAfterSuspend = delayAfterSuspend;
    }

    public ProcessKey Process => _inner.Process;
    public string? ImagePath => _inner.ImagePath;
    public string? ImageSha256 => _inner.ImageSha256;
    public bool CriticalStateKnown => _inner.CriticalStateKnown;
    public bool IsCritical => _inner.IsCritical;

    public IReadOnlyList<ContainmentActuationThreadKey> EnumerateThreads(int maxThreads, CancellationToken cancellationToken) =>
        _inner.EnumerateThreads(maxThreads, cancellationToken);

    public bool TrySuspendThread(ContainmentActuationThreadKey thread, out string diagnostic)
    {
        var ordinal = Interlocked.Increment(ref _suspendOrdinal);
        if (_failSuspendOrdinal > 0 && ordinal == _failSuspendOrdinal)
        {
            diagnostic = "SyntheticQualificationSuspendFailure";
            return false;
        }

        var ok = _inner.TrySuspendThread(thread, out diagnostic);
        if (ok && _delayAfterSuspendOrdinal > 0 && ordinal == _delayAfterSuspendOrdinal && _delayAfterSuspend > TimeSpan.Zero)
            Thread.Sleep(_delayAfterSuspend);
        if (ok && _cancelAfterSuspendOrdinal > 0 && ordinal == _cancelAfterSuspendOrdinal)
            _cancel?.Cancel();
        return ok;
    }

    public bool TryResumeThread(ContainmentActuationThreadKey thread, out string diagnostic) =>
        _inner.TryResumeThread(thread, out diagnostic);

    public void Dispose() => _inner.Dispose();
}
