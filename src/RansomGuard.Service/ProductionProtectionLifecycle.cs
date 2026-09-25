using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using RansomGuard.Core;
using RansomGuard.Rollback;

namespace RansomGuard.Service;

internal sealed class ProductionProtectionLifecycle : BackgroundService
{
    private readonly ILogger<ProductionProtectionLifecycle> _log;
    private readonly GuardSettings _settings;
    private readonly SecureStore _store;
    private readonly ProtectionPackageAdmission _admission;
    private readonly ProtectionStateMachine _protection;
    private readonly RuntimeState _runtime;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly string _applicationBase;
    private static readonly TimeSpan GateShutdownSignalTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan GateExitTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DriverMaintenanceCleanupTimeout = TimeSpan.FromSeconds(10);

    public ProductionProtectionLifecycle(
        ILogger<ProductionProtectionLifecycle> log,
        GuardSettings settings,
        SecureStore store,
        ProtectionPackageAdmission admission,
        ProtectionStateMachine protection,
        RuntimeState runtime,
        IHostApplicationLifetime lifetime,
        string applicationBase)
    {
        _log = log;
        _settings = settings;
        _store = store;
        _admission = admission;
        _protection = protection;
        _runtime = runtime;
        _lifetime = lifetime;
        _applicationBase = Path.GetFullPath(applicationBase);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();

        if (!_admission.ReadyForLifecycle)
        {
            _protection.MarkUnavailable("Protection package is not admitted for production lifecycle activation.");
            PublishProtection();
            return;
        }

        var root = Path.GetFullPath(_settings.ProtectedRoots.Single()).TrimEnd('\\');
        var packageRoot = Path.Combine(_applicationBase, "Protection");
        var driverDirectory = Path.Combine(packageRoot, "Driver");
        var gateClientPath = Path.Combine(packageRoot, "GateClient", "RansomGuard.GateClient.exe");
        FileSafety.NoReparse(packageRoot);
        FileSafety.NoReparse(driverDirectory);
        FileSafety.NoReparse(gateClientPath);

        try
        {
            _protection.BeginKernelStartup();
            PublishProtection();

            await ProductionDriverLifecycle.EnsureReadyAsync(
                driverDirectory,
                _admission,
                root,
                TimeSpan.FromSeconds(_settings.Enforce.StartupTimeoutSeconds),
                stoppingToken).ConfigureAwait(false);
            _runtime.RefreshDriverStatus();

            var sessionId = ResolveProductionSessionId(root);
            var firstActivation = true;
            while (!stoppingToken.IsCancellationRequested)
            {
                using var gate = StartGateClient(gateClientPath, root, sessionId);
                var signals = new GateLifecycleSignals();
                var stdoutPump = PumpOutputAsync(gate, sessionId, signals);
                var stderrPump = PumpErrorAsync(gate, signals);

                bool ready;
                try
                {
                    ready = await signals.Ready.Task.WaitAsync(
                        TimeSpan.FromSeconds(_settings.Enforce.StartupTimeoutSeconds),
                        stoppingToken).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    ready = false;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    ready = false;
                }

                if (!ready)
                {
                    if (stoppingToken.IsCancellationRequested)
                    {
                        // A child that never proved READY is not eligible for maintenance authorization,
                        // even during service stop. Abrupt termination preserves any uncertain/retained
                        // kernel gate fail-safe and intentionally leaves the driver loaded for restart.
                        await TerminateUnreadyChildAsync(gate).ConfigureAwait(false);
                        await DrainPumpsAsync(stdoutPump, stderrPump).ConfigureAwait(false);
                        return;
                    }

                    var stdoutTail = signals.OutputTail();
                    var stderrTail = signals.ErrorTail();
                    var startupFailure = gate.HasExited
                        ? $"ProductionGate exited before activation (exit={gate.ExitCode})."
                        : "ProductionGate activation readiness timed out.";
                    var lastStdout = stdoutTail.LastOrDefault() ?? "<none>";
                    var lastStderr = stderrTail.LastOrDefault() ?? "<none>";
                    var startupDiagnostic = startupFailure +
                        " LastStdout=[" + lastStdout + "]" +
                        " LastStderr=[" + lastStderr + "]" +
                        " StdoutTail=[" + string.Join(" | ", stdoutTail) + "]" +
                        " StderrTail=[" + string.Join(" | ", stderrTail) + "]";
                    _store.Audit(new
                    {
                        Type = "ProductionLifecycleStartupFailed",
                        Utc = DateTime.UtcNow,
                        Session = sessionId,
                        Reason = startupFailure,
                        Stdout = stdoutTail,
                        Stderr = stderrTail
                    });

                    await TerminateUnreadyChildAsync(gate).ConfigureAwait(false);
                    await DrainPumpsAsync(stdoutPump, stderrPump).ConfigureAwait(false);

                    if (firstActivation)
                        throw new InvalidOperationException(startupDiagnostic);

                    _log.LogError("{Reason} Kernel fail-safe remains DegradedProtected; reconnect will retry.", startupFailure);
                    await Task.Delay(
                        TimeSpan.FromSeconds(_settings.Enforce.ReconnectDelaySeconds),
                        stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (firstActivation)
                {
                    _protection.MarkKernelConnected();
                    PublishProtection();
                    _protection.MarkProtected();
                    firstActivation = false;
                }
                else
                {
                    _protection.MarkReconnectedProtected("ProductionGate reconnected to the retained root/profile and activation preflight completed.");
                }
                PublishProtection();
                _runtime.RefreshDriverStatus();
                _store.Audit(new
                {
                    Type = "ProductionProtectionActivated",
                    Utc = DateTime.UtcNow,
                    Session = sessionId,
                    Root = root,
                    GateClientPid = gate.Id,
                    Protection = _protection.Snapshot(),
                    PackageSigner = _admission.SignerCertificateSha256,
                    Altitude = _admission.Altitude
                });

                try
                {
                    await gate.WaitForExitAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    await StopForServiceShutdownAsync(gate, signals, root).ConfigureAwait(false);
                    await DrainPumpsAsync(stdoutPump, stderrPump).ConfigureAwait(false);
                    return;
                }

                await DrainPumpsAsync(stdoutPump, stderrPump).ConfigureAwait(false);

                if (signals.CleanStop.Task.IsCompletedSuccessfully && signals.CleanStop.Task.Result)
                {
                    _protection.MarkFailed("ProductionGate deactivated cleanly without an authorized service shutdown; protection is no longer active.");
                    PublishProtection();
                    _store.Audit(new
                    {
                        Type = "ProductionGateUnexpectedCleanExit",
                        Utc = DateTime.UtcNow,
                        Session = sessionId,
                        ExitCode = gate.ExitCode
                    });
                    return;
                }

                _protection.MarkDegraded($"ProductionGate exited unexpectedly (exit={gate.ExitCode}); kernel fail-safe remains active while reconnect is attempted.");
                PublishProtection();
                _store.Audit(new
                {
                    Type = "ProductionGateLost",
                    Utc = DateTime.UtcNow,
                    Session = sessionId,
                    ExitCode = gate.ExitCode,
                    Stderr = signals.ErrorTail(),
                    Protection = _protection.Snapshot()
                });

                await Task.Delay(
                    TimeSpan.FromSeconds(_settings.Enforce.ReconnectDelaySeconds),
                    stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            var snapshot = _protection.Snapshot();
            try
            {
                if (snapshot.State == "Protected")
                {
                    _protection.MarkDegraded("Production lifecycle supervisor failed; the supervised channel is being torn down fail-safe.");
                    PublishProtection();
                }
                else if (snapshot.State != "DegradedProtected")
                {
                    _protection.MarkFailed("Production lifecycle failed: " + ex.GetType().Name + ": " + ex.Message);
                    PublishProtection();
                }
            }
            catch (Exception stateError)
            {
                _log.LogError(stateError, "Unable to publish terminal production lifecycle state.");
            }

            try
            {
                _store.Audit(new
                {
                    Type = "ProductionLifecycleFailure",
                    Utc = DateTime.UtcNow,
                    Error = ex.GetType().Name,
                    ex.Message,
                    Protection = _protection.Snapshot()
                });
            }
            catch (Exception auditError) when (auditError is IOException or UnauthorizedAccessException)
            {
                _log.LogError(auditError, "Unable to persist production lifecycle failure evidence.");
            }

            _log.LogCritical(ex, "Production protection lifecycle failed; Enforce host will stop rather than continue without supervision.");
            Environment.ExitCode = 8;
            _lifetime.StopApplication();
        }
    }

    private string ResolveProductionSessionId(string root)
    {
        var repository = new RollbackRepository(_store.Rollback);
        repository.VerifyAll();

        var normalizedRoot = Path.GetFullPath(root).TrimEnd('\\').ToUpperInvariant();
        var rootHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(normalizedRoot)))[..16];
        var expectedPrefix = "production-" + rootHash + "-";
        var active = new List<string>();
        var blocked = new List<string>();

        foreach (var id in repository.SessionIds())
        {
            if (!id.StartsWith("production-", StringComparison.Ordinal))
                continue;

            var session = repository.OpenSession(id);
            var lifecycle = new RollbackSessionLifecycleStore(session.Root);
            lifecycle.VerifyAll();
            var lifecycleState = lifecycle.Snapshot.State;
            if (lifecycleState == RollbackSessionLifecycleState.Active)
                active.Add(id);
            else if (lifecycleState is RollbackSessionLifecycleState.Faulted
                     or RollbackSessionLifecycleState.LegacyUnmanaged)
                blocked.Add(id + ":" + lifecycleState);
        }

        if (blocked.Count != 0)
            throw new InvalidOperationException(
                "Faulted or unmanaged production rollback evidence requires explicit recovery before Enforce can start: " +
                string.Join(", ", blocked.Order(StringComparer.Ordinal)));

        var foreign = active
            .Where(id => !id.StartsWith(expectedPrefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (foreign.Length != 0)
            throw new InvalidOperationException(
                "An Active production rollback session is bound to another protected root: " +
                string.Join(", ", foreign));

        var matching = active
            .Where(id => id.StartsWith(expectedPrefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (matching.Length > 1)
            throw new InvalidOperationException(
                "Multiple Active production rollback sessions exist for the configured protected root.");

        if (matching.Length == 1)
        {
            _log.LogWarning(
                "Resuming Active production rollback session {Session} for retained root {Root}.",
                matching[0], root);
            return matching[0];
        }

        var sessionId =
            expectedPrefix +
            DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "-" +
            Guid.NewGuid().ToString("N")[..16];
        _log.LogInformation(
            "Selected new production rollback session {Session} for root {Root}.",
            sessionId, root);
        return sessionId;
    }

    private Process StartGateClient(string gateClientPath, string root, string sessionId)
    {
        var start = new ProcessStartInfo
        {
            FileName = gateClientPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(gateClientPath)!
        };
        foreach (var arg in new[]
        {
            "--production",
            "--root", root,
            "--session", sessionId,
            "--gate-workers", _settings.Enforce.GateWorkers.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--max-store-mib", _settings.Enforce.RollbackMaxStoreMiB.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--min-free-mib", _settings.Enforce.RollbackMinFreeMiB.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--service-control-stdin"
        })
            start.ArgumentList.Add(arg);

        var process = Process.Start(start) ?? throw new InvalidOperationException("Failed to start the admitted ProductionGate client.");
        _log.LogInformation("ProductionGate started with pid={Pid}; session={Session}.", process.Id, sessionId);
        return process;
    }

    private async Task PumpOutputAsync(Process process, string sessionId, GateLifecycleSignals signals)
    {
        var ready = $"RG-LIFECYCLE READY schema=1 pid={process.Id} session={sessionId} profile=ProductionGate";
        var clean = $"RG-LIFECYCLE STOPPED schema=1 pid={process.Id} session={sessionId} clean=1";
        var faulted = $"RG-LIFECYCLE STOPPED schema=1 pid={process.Id} session={sessionId} clean=0";
        try
        {
            while (await process.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                signals.AddOutput(line);
                if (string.Equals(line, ready, StringComparison.Ordinal))
                    signals.Ready.TrySetResult(true);
                else if (string.Equals(line, clean, StringComparison.Ordinal))
                    signals.CleanStop.TrySetResult(true);
                else if (string.Equals(line, faulted, StringComparison.Ordinal))
                    signals.CleanStop.TrySetResult(false);
                else
                    _log.LogDebug("ProductionGate: {Line}", line);
            }
        }
        catch (IOException ex)
        {
            _log.LogDebug(ex, "ProductionGate stdout closed.");
        }
        finally
        {
            signals.Ready.TrySetResult(false);
            signals.CleanStop.TrySetResult(false);
        }
    }

    private async Task PumpErrorAsync(Process process, GateLifecycleSignals signals)
    {
        try
        {
            while (await process.StandardError.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                signals.AddError(line);
                _log.LogWarning("ProductionGate stderr: {Line}", line);
            }
        }
        catch (IOException ex)
        {
            _log.LogDebug(ex, "ProductionGate stderr closed.");
        }
    }

    private async Task StopForServiceShutdownAsync(Process gate, GateLifecycleSignals signals, string root)
    {
        if (gate.HasExited)
        {
            if (_protection.Snapshot().State == "Protected")
            {
                _protection.MarkDegraded("ProductionGate exited during service shutdown before graceful deactivation was confirmed.");
                PublishProtection();
            }
            return;
        }

        try
        {
            await gate.StandardInput.WriteLineAsync("shutdown").ConfigureAwait(false);
            await gate.StandardInput.FlushAsync().ConfigureAwait(false);

            var clean = await signals.CleanStop.Task.WaitAsync(GateShutdownSignalTimeout).ConfigureAwait(false);
            await gate.WaitForExitAsync().WaitAsync(GateExitTimeout).ConfigureAwait(false);
            if (!clean || gate.ExitCode != 0)
                throw new InvalidOperationException($"ProductionGate did not confirm clean deactivation (exit={gate.ExitCode}).");
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or TimeoutException)
        {
            if (!gate.HasExited)
            {
                try { gate.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            }

            var failedSnapshot = _protection.Snapshot();
            if (failedSnapshot.State is "Protected" or "DegradedProtected")
            {
                // After the service has sent the authorized shutdown command, a lost acknowledgement
                // cannot prove whether kernel deactivation committed. Never publish a false active
                // protection claim in this ambiguity. The driver is deliberately left loaded.
                _protection.MarkFailed("Authorized production maintenance outcome is unconfirmed; no active kernel-enforcement claim is made and the driver remains loaded.");
                PublishProtection();
            }

            TryAuditMaintenanceFailure("ProductionProtectionMaintenanceStopFailed", ex, root);
            _log.LogError(ex, "Production protection maintenance outcome is unconfirmed; driver unload is refused.");
            return;
        }

        var snapshot = _protection.Snapshot();
        if (snapshot.State is "Protected" or "DegradedProtected")
        {
            _protection.BeginMaintenance("ProductionGate committed terminal evidence and kernel confirmed whole-gate deactivation.");
            PublishProtection();
        }

        try
        {
            await ProductionDriverLifecycle.StopAfterMaintenanceAsync(root, DriverMaintenanceCleanupTimeout).ConfigureAwait(false);
            _runtime.RefreshDriverStatus();
            _store.Audit(new
            {
                Type = "ProductionProtectionMaintenanceStop",
                Utc = DateTime.UtcNow,
                Root = root,
                Protection = _protection.Snapshot()
            });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or TimeoutException)
        {
            // Kernel Maintenance was already confirmed. A driver detach/unload problem is cleanup
            // failure, not an unknown enforcement state. Keep the truthful Maintenance snapshot.
            _runtime.RefreshDriverStatus();
            TryAuditMaintenanceFailure("ProductionDriverMaintenanceCleanupFailed", ex, root);
            _log.LogError(ex, "Kernel Maintenance is confirmed, but driver detach/unload cleanup failed; no active enforcement claim is made.");
        }
    }

    private void TryAuditMaintenanceFailure(string type, Exception error, string root)
    {
        try
        {
            _store.Audit(new
            {
                Type = type,
                Utc = DateTime.UtcNow,
                Root = root,
                Error = error.GetType().Name,
                error.Message,
                Protection = _protection.Snapshot()
            });
        }
        catch (Exception auditError) when (auditError is IOException or UnauthorizedAccessException)
        {
            _log.LogError(auditError, "Unable to persist production maintenance failure evidence.");
        }
    }

    private static async Task TerminateUnreadyChildAsync(Process gate)
    {
        if (gate.HasExited)
            return;

        // READY is the only proof that this child completed activation preflight.
        // Never send the maintenance-authorizing "shutdown" command to an uncertain child:
        // on a reconnect timeout that could race a late activation and release the retained
        // fail-safe gate. Abrupt termination is conservative; any connected gate disconnects
        // into DegradedProtected and a later reconnect must prove readiness again.
        try
        {
            gate.Kill(entireProcessTree: true);
            await gate.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            // Process exited between the HasExited check and Kill/WaitForExitAsync.
        }
        catch (TimeoutException)
        {
            throw new InvalidOperationException("Unready ProductionGate did not terminate within the bounded fail-safe timeout.");
        }
    }

    private void PublishProtection()
    {
        var snapshot = _protection.Snapshot();
        _runtime.UpdateProtection(snapshot);
        _log.LogInformation(
            "Protection state={State}; kernel={Kernel}; channel={Channel}; reason={Reason}",
            snapshot.State,
            snapshot.KernelEnforcementActive,
            snapshot.KernelChannelConnected,
            snapshot.Reason);
    }

    private static async Task DrainPumpsAsync(Task stdoutPump, Task stderrPump)
    {
        try
        {
            await Task.WhenAll(stdoutPump, stderrPump).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }
    }

    private sealed class GateLifecycleSignals
    {
        private readonly object _gate = new();
        private readonly Queue<string> _outputs = new();
        private readonly Queue<string> _errors = new();
        public TaskCompletionSource<bool> Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> CleanStop { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void AddOutput(string value)
        {
            lock (_gate)
            {
                if (_outputs.Count == 24)
                    _outputs.Dequeue();
                _outputs.Enqueue(value.Length <= 512 ? value : value[..512]);
            }
        }

        public void AddError(string value)
        {
            lock (_gate)
            {
                if (_errors.Count == 16)
                    _errors.Dequeue();
                _errors.Enqueue(value.Length <= 512 ? value : value[..512]);
            }
        }

        public string[] OutputTail()
        {
            lock (_gate)
                return _outputs.ToArray();
        }

        public string[] ErrorTail()
        {
            lock (_gate)
                return _errors.ToArray();
        }
    }
}

internal static class ProductionDriverLifecycle
{
    private const string ServiceName = "RansomGuardMinifilter";
    private const string ServiceKeyPath = @"SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter";

    private static class NativeMethods
    {
        [DllImport("newdev.dll", EntryPoint = "DiInstallDriverW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DiInstallDriver(
            IntPtr hwndParent,
            string infPath,
            uint flags,
            [MarshalAs(UnmanagedType.Bool)] out bool needReboot);
    }

    public static async Task EnsureReadyAsync(
        string driverDirectory,
        ProtectionPackageAdmission admission,
        string protectedRoot,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!admission.ReadyForLifecycle)
            throw new InvalidOperationException("Production driver lifecycle requires an admitted protection package.");
        var admittedAltitude = admission.Altitude
            ?? throw new InvalidOperationException("Admitted production protection package is missing its altitude.");

        var driverRoot = Path.GetFullPath(driverDirectory);
        var inf = Path.Combine(driverRoot, "RansomGuardMinifilter.inf");
        var sys = Path.Combine(driverRoot, "RansomGuardMinifilter.sys");
        foreach (var path in new[] { driverRoot, inf, sys })
            FileSafety.NoReparse(path);

        if (!ServiceExists())
        {
            // File-system minifilters are primitive drivers. Use the Windows primitive-driver
            // installation API directly instead of the legacy InstallHInfSection compatibility
            // wrapper, which can report process success without publishing the service registration.
            cancellationToken.ThrowIfCancellationRequested();
            InstallPrimitiveDriverPackage(inf);

            var registrationTimeout = timeout < TimeSpan.FromSeconds(5)
                ? timeout
                : TimeSpan.FromSeconds(5);
            await WaitForServiceRegistrationAsync(registrationTimeout, cancellationToken).ConfigureAwait(false);
        }

        ValidateRegisteredContract(sys, admission);
        var fltmc = Path.Combine(Environment.SystemDirectory, "fltmc.exe");
        var filters = await RunToolAsync(fltmc, new[] { "filters" }, timeout, cancellationToken, allowNonZero: false)
            .ConfigureAwait(false);
        if (!ContainsFilter(filters.Stdout))
        {
            await RunToolAsync(fltmc, new[] { "load", ServiceName }, timeout, cancellationToken).ConfigureAwait(false);
            filters = await RunToolAsync(fltmc, new[] { "filters" }, timeout, cancellationToken).ConfigureAwait(false);
            if (!ContainsFilter(filters.Stdout))
                throw new InvalidOperationException("Filter Manager did not report RansomGuardMinifilter after load.");
        }

        var volume = Path.GetPathRoot(protectedRoot)?.TrimEnd('\\')
            ?? throw new InvalidOperationException("Protected root has no local volume.");
        if (volume.Length != 2 || volume[1] != ':')
            throw new InvalidOperationException("Production lifecycle supports one explicit local drive volume.");

        var instances = await RunToolAsync(
            fltmc,
            new[] { "instances", "-f", ServiceName },
            timeout,
            cancellationToken,
            allowNonZero: true).ConfigureAwait(false);
        var attachedVolumes = AttachedVolumes(instances.Stdout, admittedAltitude);
        if (attachedVolumes.Length == 0)
        {
            await RunToolAsync(
                fltmc,
                new[] { "attach", ServiceName, volume },
                timeout,
                cancellationToken).ConfigureAwait(false);
            instances = await RunToolAsync(
                fltmc,
                new[] { "instances", "-f", ServiceName },
                timeout,
                cancellationToken).ConfigureAwait(false);
            attachedVolumes = AttachedVolumes(instances.Stdout, admittedAltitude);
        }

        if (attachedVolumes.Length != 1 ||
            !string.Equals(attachedVolumes[0], volume, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Production minifilter must have exactly one instance on the configured protected-root volume. Observed: " +
                (attachedVolumes.Length == 0 ? "<none>" : string.Join(", ", attachedVolumes)) +
                ". fltmc=" + instances.Combined);
    }

    public static async Task StopAfterMaintenanceAsync(string protectedRoot, TimeSpan timeout)
    {
        var fltmc = Path.Combine(Environment.SystemDirectory, "fltmc.exe");
        var volume = Path.GetPathRoot(protectedRoot)?.TrimEnd('\\')
            ?? throw new InvalidOperationException("Protected root has no local volume.");
        var cleanupClock = Stopwatch.StartNew();

        TimeSpan Remaining()
        {
            var remaining = timeout - cleanupClock.Elapsed;
            if (remaining <= TimeSpan.Zero)
                throw new TimeoutException("Production driver maintenance cleanup exceeded its total shutdown budget.");
            return remaining;
        }

        var instances = await RunToolAsync(
            fltmc,
            new[] { "instances", "-f", ServiceName },
            Remaining(),
            CancellationToken.None,
            allowNonZero: true).ConfigureAwait(false);

        CommandResult? detach = null;
        if (instances.Stdout.Contains(volume, StringComparison.OrdinalIgnoreCase))
        {
            for (var attempt = 0; attempt < 20; attempt++)
            {
                detach = await RunToolAsync(
                    fltmc,
                    new[] { "detach", ServiceName, volume },
                    Remaining(),
                    CancellationToken.None,
                    allowNonZero: true).ConfigureAwait(false);
                if (detach.ExitCode == 0)
                    break;
                await Task.Delay(100).ConfigureAwait(false);
            }
        }

        var filters = await RunToolAsync(
            fltmc,
            new[] { "filters" },
            Remaining(),
            CancellationToken.None).ConfigureAwait(false);

        CommandResult? unload = null;
        if (ContainsFilter(filters.Stdout))
        {
            unload = await RunToolAsync(
                fltmc,
                new[] { "unload", ServiceName },
                Remaining(),
                CancellationToken.None,
                allowNonZero: true).ConfigureAwait(false);
        }

        var finalFilters = await RunToolAsync(
            fltmc,
            new[] { "filters" },
            Remaining(),
            CancellationToken.None).ConfigureAwait(false);

        if (ContainsFilter(finalFilters.Stdout))
        {
            var detachEvidence = detach is null
                ? "<not-attempted>"
                : $"exit={detach.ExitCode}; output={detach.Combined}";
            var unloadEvidence = unload is null
                ? "<not-attempted>"
                : $"exit={unload.ExitCode}; output={unload.Combined}";
            throw new InvalidOperationException(
                "Production driver maintenance cleanup left RansomGuardMinifilter loaded after bounded detach/unload attempts. " +
                $"detach=[{detachEvidence}] unload=[{unloadEvidence}] finalFilters=[{finalFilters.Combined}]");
        }
    }

    private static void InstallPrimitiveDriverPackage(string infPath)
    {
        var fullInfPath = Path.GetFullPath(infPath);
        FileSafety.NoReparse(fullInfPath);

        if (!NativeMethods.DiInstallDriver(
                IntPtr.Zero,
                fullInfPath,
                flags: 0,
                out var needReboot))
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"DiInstallDriverW failed for the admitted production minifilter package. Win32Error={error}.");
        }

        if (needReboot)
            throw new InvalidOperationException(
                "DiInstallDriverW reported that production minifilter installation requires a reboot; refusing Enforce startup.");
    }

    private static bool ServiceExists()
    {
        using var key = Registry.LocalMachine.OpenSubKey(ServiceKeyPath, writable: false);
        return key is not null;
    }

    private static async Task WaitForServiceRegistrationAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero)
            throw new TimeoutException("Production minifilter registration timeout is not positive.");

        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ServiceExists())
                return;

            var remaining = timeout - clock.Elapsed;
            var delay = remaining < TimeSpan.FromMilliseconds(100)
                ? remaining
                : TimeSpan.FromMilliseconds(100);
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }

        if (!ServiceExists())
            throw new InvalidOperationException(
                "RansomGuardMinifilter service registration did not become visible after successful DiInstallDriverW.");
    }

    private static void ValidateRegisteredContract(string packageSysPath, ProtectionPackageAdmission admission)
    {
        using var service = Registry.LocalMachine.OpenSubKey(ServiceKeyPath, writable: false)
            ?? throw new InvalidOperationException("RansomGuardMinifilter service registration is missing after package staging.");

        if (Convert.ToInt32(service.GetValue("Start", -1), System.Globalization.CultureInfo.InvariantCulture) != 3)
            throw new InvalidOperationException("Registered production minifilter must remain demand-start.");
        if (Convert.ToInt32(service.GetValue("Type", -1), System.Globalization.CultureInfo.InvariantCulture) != 2)
            throw new InvalidOperationException("Registered production minifilter must be a filesystem driver.");

        using var instances = service.OpenSubKey(@"Parameters\Instances", writable: false)
            ?? throw new InvalidOperationException("Registered production minifilter instance configuration is missing.");
        var defaultInstance = instances.GetValue("DefaultInstance") as string;
        if (string.IsNullOrWhiteSpace(defaultInstance))
            throw new InvalidOperationException("Registered production minifilter DefaultInstance is missing.");

        using var instance = instances.OpenSubKey(defaultInstance, writable: false)
            ?? throw new InvalidOperationException("Registered production minifilter default instance key is missing.");
        var altitude = instance.GetValue("Altitude") as string;
        var flags = Convert.ToInt32(instance.GetValue("Flags", -1), System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(altitude, admission.Altitude, StringComparison.Ordinal) || flags != 1)
            throw new InvalidOperationException("Registered production minifilter altitude/attachment flags do not match the admitted package.");

        var imagePath = service.GetValue("ImagePath") as string;
        if (string.IsNullOrWhiteSpace(imagePath))
            throw new InvalidOperationException("Registered production minifilter ImagePath is missing.");
        var installedImage = ResolveServiceImagePath(imagePath);
        FileSafety.NoReparse(installedImage);
        if (!File.Exists(installedImage))
            throw new FileNotFoundException("Registered production minifilter image does not exist.", installedImage);

        var packageHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(packageSysPath)));
        var installedHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(installedImage)));
        if (!DecisionPolicy.HashEqual(packageHash, installedHash))
            throw new InvalidOperationException("Registered production minifilter image bytes do not match the admitted package.");
    }

    private static string ResolveServiceImagePath(string value)
    {
        var path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                path[@"\SystemRoot\".Length..]);
        else if (!Path.IsPathRooted(path))
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path);
        return Path.GetFullPath(path);
    }

    private static string[] AttachedVolumes(string output, string altitude)
    {
        var volumes = new List<string>();
        foreach (var raw in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.TrimEnd();
            var searchFrom = 0;
            while (searchFrom < line.Length)
            {
                var altitudeIndex = line.IndexOf(altitude, searchFrom, StringComparison.Ordinal);
                if (altitudeIndex < 0)
                    break;

                var afterAltitude = altitudeIndex + altitude.Length;
                var leftBoundary = altitudeIndex == 0 || char.IsWhiteSpace(line[altitudeIndex - 1]);
                var rightBoundary = afterAltitude == line.Length || char.IsWhiteSpace(line[afterAltitude]);
                if (leftBoundary && rightBoundary)
                {
                    // Filtered fltmc instance output omits the filter name from each data row and
                    // reports Volume Name first. Match the admitted invariant altitude token so
                    // parsing does not depend on localized column headers.
                    var volume = line[..altitudeIndex].Trim();
                    volumes.Add(volume.Length == 0 ? "<unnamed>" : volume);
                    break;
                }

                searchFrom = altitudeIndex + altitude.Length;
            }
        }

        return volumes.ToArray();
    }

    private static bool ContainsFilter(string output)
    {
        foreach (var raw in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.TrimStart();
            if (line.StartsWith(ServiceName, StringComparison.OrdinalIgnoreCase) &&
                (line.Length == ServiceName.Length || char.IsWhiteSpace(line[ServiceName.Length])))
                return true;
        }

        return false;
    }

    private static async Task<CommandResult> RunToolAsync(
        string executable,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool allowNonZero = false)
    {
        if (!File.Exists(executable))
            throw new FileNotFoundException("Required Windows lifecycle tool is missing.", executable);

        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Failed to start Windows lifecycle tool: " + Path.GetFileName(executable));
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            KillLifecycleTool(process);
            throw;
        }
        catch (OperationCanceledException)
        {
            KillLifecycleTool(process);
            throw new TimeoutException("Windows lifecycle tool timed out: " + Path.GetFileName(executable));
        }

        var result = new CommandResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));
        if (!allowNonZero && result.ExitCode != 0)
            throw new InvalidOperationException(
                $"{Path.GetFileName(executable)} failed with exit={result.ExitCode}: {result.Combined}");
        return result;
    }

    private static void KillLifecycleTool(Process process)
    {
        if (process.HasExited)
            return;

        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
    }

    private sealed record CommandResult(int ExitCode, string Stdout, string Stderr)
    {
        public string Combined
        {
            get
            {
                var value = (Stdout + Environment.NewLine + Stderr).Trim();
                return value.Length <= 4096 ? value : value[..4096];
            }
        }
    }
}
