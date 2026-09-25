[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$settingsPath=Join-Path $RepositoryRoot 'src\RansomGuard.Core\Settings.cs'
$runtimePath=Join-Path $RepositoryRoot 'src\RansomGuard.Core\ProtectionRuntime.cs'
$serviceRuntimePath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\RuntimeState.cs'
$programPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\Program.cs'
$bootstrapPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\WindowsServiceBootstrap.cs'
$lifecyclePath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\ProductionProtectionLifecycle.cs'
$appSettingsPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\appsettings.json'
$driverPath=Join-Path $RepositoryRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
foreach($path in @($settingsPath,$runtimePath,$serviceRuntimePath,$programPath,$bootstrapPath,$lifecyclePath,$appSettingsPath,$driverPath,$buildPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Production Enforce lifecycle file missing: $path"}
}

$settings=Get-Content -LiteralPath $settingsPath -Raw
$runtime=Get-Content -LiteralPath $runtimePath -Raw
$serviceRuntime=Get-Content -LiteralPath $serviceRuntimePath -Raw
$program=Get-Content -LiteralPath $programPath -Raw
$bootstrap=Get-Content -LiteralPath $bootstrapPath -Raw
$lifecycle=Get-Content -LiteralPath $lifecyclePath -Raw
$appSettings=Get-Content -LiteralPath $appSettingsPath -Raw
$driverSource=Get-Content -LiteralPath $driverPath -Raw
$build=Get-Content -LiteralPath $buildPath -Raw

foreach($required in @(
    'public int SchemaVersion { get; set; } = 4',
    'Mode must be exactly Audit or Enforce.',
    'RequireSignedDriver',
    'AutomaticContainment',
    'GateWorkers',
    'RollbackMaxStoreMiB',
    'RollbackMinFreeMiB',
    'ReconnectDelaySeconds',
    '0.8.0 Enforce foundation requires exactly one explicit ProtectedRoot',
    'Enforce ProtectedRoot cannot be an entire drive.'
)){
    if($settings -notmatch [regex]::Escape($required)){throw "Enforce settings invariant missing: $required"}
}

foreach($required in @(
    'ProtectionPhase.EnforceStarting',
    'ProtectionPhase.EnforceUnavailable',
    'ProtectionPhase.KernelConnected',
    'ProtectionPhase.Protected',
    'ProtectionPhase.DegradedProtected',
    'ProtectionPhase.Maintenance',
    'Kernel enforcement cannot start before rollback repository validation.',
    'MarkReconnectedProtected',
    'A ProductionGate reconnect may return to Protected only from DegradedProtected after rollback readiness.',
    'KernelEnforcementActive does not match the protection phase.',
    'Enforce mode cannot silently downgrade to AuditOnly.',
    'DegradedProtected represents loss of the user-mode kernel channel.',
    'var kernelEnforcement = _phase is ProtectionPhase.Protected or ProtectionPhase.DegradedProtected'
)){
    if($runtime -notmatch [regex]::Escape($required)){throw "Protection state invariant missing: $required"}
}

$serviceMode=$program.IndexOf('if(WindowsServiceHelpers.IsWindowsService())')
$outerWindowsService=$program.IndexOf('serviceBuilder.Services.AddWindowsService',$serviceMode)
$outerBootstrap=$program.IndexOf('serviceBuilder.Services.AddHostedService<WindowsServiceBootstrap>()',$outerWindowsService)
$outerRun=$program.IndexOf('serviceHost.Run()',$outerBootstrap)
$legacyHeavyStart=$program.IndexOf('var store=new SecureStore()',$outerRun)
if($serviceMode -lt 0 -or $outerWindowsService -lt 0 -or $outerBootstrap -lt 0 -or $outerRun -lt 0 -or
   $serviceMode -gt $outerWindowsService -or $outerWindowsService -gt $outerBootstrap -or $outerBootstrap -gt $outerRun){
    throw 'Windows Service mode must establish the SCM WindowsServiceLifetime before heavy runtime bootstrap.'
}
if($legacyHeavyStart -ge 0 -and $legacyHeavyStart -lt $outerRun){
    throw 'SecureStore/package/rollback startup work must not run before the SCM service host enters Run.'
}

foreach($required in @(
    'internal sealed class WindowsServiceBootstrap : BackgroundService',
    'Windows Service bootstrap failed after SCM startup; stopping the outer service host.',
    'using (StateMaintenanceGate.Acquire())',
    'Type = "ServiceBootstrapStateStoreReady"',
    'Type = "ServiceBootstrapSettingsValidated"',
    'Type = "ServiceBootstrapRollbackVerified"',
    'Type = "ServiceBootstrapProtectionAdmissionStarting"',
    'Type = "ServiceBootstrapProtectionAdmissionFinished"',
    'var rollbackRepository = new RollbackRepository(store.Rollback)',
    'protection.MarkRollbackReady()',
    'ProtectionPackageVerifier.Inspect(',
    'Type = "RollbackStoreReady"',
    'var runtime = new RuntimeState(protection.Snapshot())',
    'new ProductionProtectionLifecycle(',
    'using var innerHost = builder.Build()',
    'await innerHost.RunAsync(stoppingToken)'
)){
    if($bootstrap -notmatch [regex]::Escape($required)){
        throw "SCM-first Windows Service bootstrap invariant missing: $required"
    }
}

$narrowStateBlock=@'
        using (StateMaintenanceGate.Acquire())
        {
            store = new SecureStore();
        }
        store.Audit(new
'@
if($bootstrap.IndexOf($narrowStateBlock,[StringComparison]::Ordinal) -lt 0){
    throw 'SCM bootstrap must release StateMaintenanceGate immediately after trusted SecureStore initialization.'
}

$bootstrapRollback=$bootstrap.IndexOf('protection.MarkRollbackReady()')
$bootstrapInspect=$bootstrap.IndexOf('ProtectionPackageVerifier.Inspect(',$bootstrapRollback)
$bootstrapRuntime=$bootstrap.IndexOf('var runtime = new RuntimeState(protection.Snapshot())',$bootstrapInspect)
$bootstrapLifecycle=$bootstrap.IndexOf('new ProductionProtectionLifecycle(',$bootstrapRuntime)
if($bootstrapRollback -lt 0 -or $bootstrapInspect -lt 0 -or $bootstrapRuntime -lt 0 -or $bootstrapLifecycle -lt 0 -or
   $bootstrapRollback -gt $bootstrapInspect -or $bootstrapInspect -gt $bootstrapRuntime -or $bootstrapRuntime -gt $bootstrapLifecycle){
    throw 'SCM-first bootstrap must preserve rollback -> admission -> runtime -> lifecycle ordering.'
}

$rollbackReady=$program.IndexOf('protection.MarkRollbackReady()')
$inspect=$program.IndexOf('ProtectionPackageVerifier.Inspect(AppContext.BaseDirectory,ProductInfo.Version)',$rollbackReady)
$admissionCheck=$program.IndexOf('!protectionPackage.ReadyForLifecycle',$inspect)
$runtimeCreate=$program.IndexOf('new RuntimeState(protection.Snapshot())',$admissionCheck)
$lifecycleRegistration=$program.IndexOf('new ProductionProtectionLifecycle(',$runtimeCreate)
if($rollbackReady -lt 0 -or $inspect -lt 0 -or $admissionCheck -lt 0 -or $runtimeCreate -lt 0 -or $lifecycleRegistration -lt 0 -or
   $rollbackReady -gt $inspect -or $inspect -gt $admissionCheck -or $admissionCheck -gt $runtimeCreate -or $runtimeCreate -gt $lifecycleRegistration){
    throw 'Service startup must validate rollback readiness, inspect package admission, create explicit runtime state, then register the production lifecycle only for an admitted package.'
}

foreach($required in @(
    'ProtectionPackageAdmission _admission',
    '_admission.ReadyForLifecycle',
    '_protection.BeginKernelStartup()',
    'ProductionDriverLifecycle.EnsureReadyAsync',
    '_protection.MarkKernelConnected()',
    '_protection.MarkProtected()',
    '_protection.MarkDegraded(',
    '_protection.MarkReconnectedProtected(',
    '--production',
    '--service-control-stdin',
    'RG-LIFECYCLE READY',
    'RG-LIFECYCLE STOPPED',
    'ProductionDriverLifecycle.StopAfterMaintenanceAsync',
    '_protection.BeginMaintenance(',
    'using System.Runtime.InteropServices;',
    'newdev.dll',
    'DiInstallDriverW',
    'InstallPrimitiveDriverPackage(inf)',
    'Marshal.GetLastWin32Error()',
    'flags: 0',
    'production minifilter installation requires a reboot; refusing Enforce startup.',
    'WaitForServiceRegistrationAsync',
    'TimeSpan.FromSeconds(5)',
    'RansomGuardMinifilter service registration did not become visible after successful DiInstallDriverW.',
    'fltmc.exe',
    'new[] { "load", ServiceName }',
    'new[] { "attach", ServiceName, volume }',
    'admission.ReadyForLifecycle',
    'var admittedAltitude = admission.Altitude',
    'Admitted production protection package is missing its altitude.',
    'AttachedVolumes(instances.Stdout, admittedAltitude)',
    'attachedVolumes.Length != 1',
    'Production minifilter must have exactly one instance on the configured protected-root volume.',
    'new[] { "detach", ServiceName, volume }',
    'CommandResult? detach = null',
    'new[] { "unload", ServiceName }',
    'CommandResult? unload = null',
    'var finalFilters = await RunToolAsync(',
    'Production driver maintenance cleanup left RansomGuardMinifilter loaded after bounded detach/unload attempts.',
    'Registry.LocalMachine.OpenSubKey',
    'FileSafety.NoReparse',
    'DecisionPolicy.HashEqual(packageHash, installedHash)',
    'Registered production minifilter altitude/attachment flags do not match the admitted package.',
    'TerminateUnreadyChildAsync(gate)',
    'signals.AddOutput(line)',
    'public string[] OutputTail()',
    'var startupDiagnostic = startupFailure +',
    'StdoutTail=[',
    'Never send the maintenance-authorizing "shutdown" command to an uncertain child',
    'gate.Kill(entireProcessTree: true)',
    'IHostApplicationLifetime _lifetime',
    '_lifetime.StopApplication()',
    'Environment.ExitCode = 8',
    'catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)',
    'Enforce host will stop rather than continue without supervision.',
    'Authorized production maintenance outcome is unconfirmed; no active kernel-enforcement claim is made and the driver remains loaded.',
    'ProductionDriverMaintenanceCleanupFailed',
    'Kernel Maintenance is confirmed, but driver detach/unload cleanup failed',
    'KillLifecycleTool(process)',
    'catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)',
    'line.Length == ServiceName.Length || char.IsWhiteSpace(line[ServiceName.Length])',
    'ResolveProductionSessionId(root)',
    'RollbackSessionLifecycleState.Active',
    'An Active production rollback session is bound to another protected root:',
    'Multiple Active production rollback sessions exist for the configured protected root.',
    'RollbackSessionLifecycleState.Faulted',
    'RollbackSessionLifecycleState.LegacyUnmanaged',
    'Faulted or unmanaged production rollback evidence requires explicit recovery before Enforce can start:',
    'Resuming Active production rollback session',
    'GateShutdownSignalTimeout = TimeSpan.FromSeconds(10)',
    'GateExitTimeout = TimeSpan.FromSeconds(3)',
    'DriverMaintenanceCleanupTimeout = TimeSpan.FromSeconds(10)',
    'var cleanupClock = Stopwatch.StartNew()',
    'Production driver maintenance cleanup exceeded its total shutdown budget.'
)){
    if($lifecycle -notmatch [regex]::Escape($required)){throw "Production lifecycle invariant missing: $required"}
}

foreach($forbidden in @(
    'new[] { "/add-driver", inf }',
    'setupapi.dll,InstallHinfSection',
    'rundll32.exe'
)){
    if($lifecycle -match [regex]::Escape($forbidden)){
        throw "Production lifecycle must use the architecture-decorated primitive-driver install path, not legacy/pre-staged registration: $forbidden"
    }
}

$terminateStart=$lifecycle.IndexOf('private static async Task TerminateUnreadyChildAsync(Process gate)')
$terminateEnd=$lifecycle.IndexOf('private void PublishProtection()',$terminateStart)
if($terminateStart -lt 0 -or $terminateEnd -lt 0 -or $terminateStart -gt $terminateEnd){
    throw 'Production supervisor must retain an explicit bounded unready-child termination path.'
}
$terminateBody=$lifecycle.Substring($terminateStart,$terminateEnd-$terminateStart)
if($terminateBody -match [regex]::Escape('StandardInput.WriteLineAsync("shutdown")')){
    throw 'Unready ProductionGate termination must never authorize maintenance/deactivation.'
}
if($terminateBody -notmatch [regex]::Escape('gate.Kill(entireProcessTree: true)')){
    throw 'Unready ProductionGate termination must be abrupt so an uncertain reconnect stays fail-safe.'
}

$notReady=$lifecycle.IndexOf('if (!ready)')
$stopCheck=$lifecycle.IndexOf('if (stoppingToken.IsCancellationRequested)',$notReady)
$terminateOnStop=$lifecycle.IndexOf('await TerminateUnreadyChildAsync(gate).ConfigureAwait(false);',$stopCheck)
$startupThrow=$lifecycle.IndexOf('throw new InvalidOperationException(startupDiagnostic);',$terminateOnStop)
if($notReady -lt 0 -or $stopCheck -lt 0 -or $terminateOnStop -lt 0 -or $startupThrow -lt 0 -or
   $notReady -gt $stopCheck -or $stopCheck -gt $terminateOnStop -or $terminateOnStop -gt $startupThrow){
    throw 'Unready initial/reconnect children must never receive maintenance authorization; initial uncertainty must terminate Enforce supervision.'
}

$cleanupStart=$lifecycle.IndexOf('public static async Task StopAfterMaintenanceAsync')
$cleanupDetach=$lifecycle.IndexOf('new[] { "detach", ServiceName, volume }',$cleanupStart)
$cleanupUnload=$lifecycle.IndexOf('new[] { "unload", ServiceName }',$cleanupDetach)
$cleanupFinal=$lifecycle.IndexOf('var finalFilters = await RunToolAsync(',$cleanupUnload)
$cleanupLoaded=$lifecycle.IndexOf('if (ContainsFilter(finalFilters.Stdout))',$cleanupFinal)
if($cleanupStart -lt 0 -or $cleanupDetach -lt 0 -or $cleanupUnload -lt 0 -or $cleanupFinal -lt 0 -or $cleanupLoaded -lt 0 -or
   $cleanupStart -gt $cleanupDetach -or $cleanupDetach -gt $cleanupUnload -or $cleanupUnload -gt $cleanupFinal -or $cleanupFinal -gt $cleanupLoaded){
    throw 'Production maintenance cleanup must treat detach as best-effort, attempt unload, and fail only from verified final Filter Manager state.'
}

$legacyDetachFailure=$lifecycle.IndexOf('Filter Manager refused production detach after clean maintenance:',$cleanupStart)
if($legacyDetachFailure -ge 0){
    throw 'Production maintenance cleanup must not fail solely because explicit detach was refused.'
}

$shutdownWrite=$lifecycle.IndexOf('StandardInput.WriteLineAsync("shutdown")')
$maintenanceFailed=$lifecycle.IndexOf('ProductionProtectionMaintenanceStopFailed',$shutdownWrite)
$maintenanceBegin=$lifecycle.IndexOf('_protection.BeginMaintenance(',$maintenanceFailed)
$driverStop=$lifecycle.IndexOf('ProductionDriverLifecycle.StopAfterMaintenanceAsync',$maintenanceBegin)
$cleanupFailed=$lifecycle.IndexOf('ProductionDriverMaintenanceCleanupFailed',$driverStop)
if($shutdownWrite -lt 0 -or $maintenanceFailed -lt 0 -or $maintenanceBegin -lt 0 -or $driverStop -lt 0 -or $cleanupFailed -lt 0 -or
   $shutdownWrite -gt $maintenanceFailed -or $maintenanceFailed -gt $maintenanceBegin -or
   $maintenanceBegin -gt $driverStop -or $driverStop -gt $cleanupFailed){
    throw 'Maintenance acknowledgement ambiguity and post-Maintenance driver cleanup failure must remain distinct lifecycle states.'
}

$begin=$lifecycle.IndexOf('_protection.BeginKernelStartup()')
$driver=$lifecycle.IndexOf('ProductionDriverLifecycle.EnsureReadyAsync',$begin)
$startClient=$lifecycle.IndexOf('StartGateClient(',$driver)
$kernelConnected=$lifecycle.IndexOf('_protection.MarkKernelConnected()',$startClient)
$protected=$lifecycle.IndexOf('_protection.MarkProtected()',$kernelConnected)
if($begin -lt 0 -or $driver -lt 0 -or $startClient -lt 0 -or $kernelConnected -lt 0 -or $protected -lt 0 -or
   $begin -gt $driver -or $driver -gt $startClient -or $startClient -gt $kernelConnected -or $kernelConnected -gt $protected){
    throw 'Production activation ordering must be rollback/startup state -> exact driver lifecycle -> ProductionGate -> kernel-connected -> Protected.'
}

$sessionSelection=$lifecycle.IndexOf('var sessionId = ResolveProductionSessionId(root);')
$supervisorLoop=$lifecycle.IndexOf('while (!stoppingToken.IsCancellationRequested)',$sessionSelection)
$gateWithStableSession=$lifecycle.IndexOf('StartGateClient(gateClientPath, root, sessionId)',$supervisorLoop)
if($sessionSelection -lt 0 -or $supervisorLoop -lt 0 -or $gateWithStableSession -lt 0 -or
   $sessionSelection -gt $supervisorLoop -or $supervisorLoop -gt $gateWithStableSession){
    throw 'Production reconnect must select one root-bound rollback session before the supervisor loop and reuse it for every GateClient attempt.'
}

$readyBranch=$lifecycle.IndexOf('if (firstActivation)')
$reconnectTransition=$lifecycle.IndexOf('_protection.MarkReconnectedProtected(',$readyBranch)
$exitWait=$lifecycle.IndexOf('await gate.WaitForExitAsync(stoppingToken)',$reconnectTransition)
$degradedTransition=$lifecycle.IndexOf('_protection.MarkDegraded(',$exitWait)
$reconnectDelay=$lifecycle.IndexOf('_settings.Enforce.ReconnectDelaySeconds',$degradedTransition)
$loopEnd=$lifecycle.IndexOf('catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)',$reconnectDelay)
if($readyBranch -lt 0 -or $reconnectTransition -lt 0 -or $exitWait -lt 0 -or $degradedTransition -lt 0 -or
   $reconnectDelay -lt 0 -or $loopEnd -lt 0 -or
   $readyBranch -gt $reconnectTransition -or $reconnectTransition -gt $exitWait -or
   $exitWait -gt $degradedTransition -or $degradedTransition -gt $reconnectDelay -or $reconnectDelay -gt $loopEnd){
    throw 'Production supervisor must accept reconnect readiness only in the reconnect branch, then publish DegradedProtected after unexpected child exit and delay before the next loop attempt.'
}

foreach($required in @(
    'static BOOLEAN RgIsNamespaceMutatingFsctl',
    'FSCTL_SET_REPARSE_POINT',
    'FSCTL_DELETE_REPARSE_POINT',
    'FSCTL_SET_REPARSE_POINT_EX',
    'namespaceMutation = RgIsNamespaceMutatingFsctl(fsctl);',
    'if (!namespaceMutation && !RgIsDataMutatingFsctl(fsctl))',
    'if (namespaceMutation) {',
    'return RgCompleteDenied(Data);'
)){
    if($driverSource -notmatch [regex]::Escape($required)){
        throw "Kernel namespace-FSCTL invariant missing: $required"
    }
}

$fsctlStart=$driverSource.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreFileSystemControl(')
$fsctlOutside=$driverSource.IndexOf('if (scope == RgScopeOutside)',$fsctlStart)
$fsctlNamespace=$driverSource.IndexOf('if (namespaceMutation) {',$fsctlOutside)
$fsctlDeny=$driverSource.IndexOf('return RgCompleteDenied(Data);',$fsctlNamespace)
$fsctlPreservation=$driverSource.IndexOf('!RgStreamHasDurablePreservation(FltObjects)',$fsctlDeny)
if($fsctlStart -lt 0 -or $fsctlOutside -lt 0 -or $fsctlNamespace -lt 0 -or $fsctlDeny -lt 0 -or $fsctlPreservation -lt 0 -or
   $fsctlStart -gt $fsctlOutside -or $fsctlOutside -gt $fsctlNamespace -or
   $fsctlNamespace -gt $fsctlDeny -or $fsctlDeny -gt $fsctlPreservation){
    throw 'Protected namespace-mutating FSCTLs must be classified after outside-scope escape and denied before ordinary data-FSCTL preservation admission.'
}

foreach($required in @(
    'ProductInfo.Version',
    '_protection.KernelEnforcementActive',
    '_protection.AutomaticContainmentActive',
    '_protection.State',
    'ProtectionStateMachine.ValidateSnapshot(protection)',
    'ProtectionStateMachine.ValidateSnapshot(value)',
    'A connected UI or SCM Running state is not proof of kernel enforcement'
)){
    if($serviceRuntime -notmatch [regex]::Escape($required)){throw "Runtime status invariant missing: $required"}
}

$app=($appSettings | ConvertFrom-Json)
if([int]$app.SchemaVersion -ne 4 -or [string]$app.Mode -ne 'Audit'){
    throw 'Default appsettings must remain schema 4 / Audit.'
}
if($app.Enforce.RequireSignedDriver -ne $true -or $app.Enforce.AutomaticContainment -ne $false){
    throw 'Default Enforce policy must require signed driver and keep automatic containment disabled.'
}
if([int]$app.Enforce.GateWorkers -lt 1 -or [int]$app.Enforce.GateWorkers -gt 8){
    throw 'Default Enforce GateWorkers must stay within the qualified 1..8 bound.'
}

foreach($required in @(
    "'.sys','.cat','.inf'",
    "*GateClient*",
    'driverInstalledByBuild=$false',
    'kernelWriteGateActive=$false'
)){
    if($build -notmatch [regex]::Escape($required)){
        throw "Normal Audit bundle boundary missing: $required"
    }
}

Write-Host 'Production Enforce lifecycle gate PASSED: admitted package only, rollback-before-kernel ordering, deterministic driver registration/load/attach, explicit ProductionGate readiness, degraded reconnect, and clean maintenance deactivation.' -ForegroundColor Green
