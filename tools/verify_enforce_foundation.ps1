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
$appSettingsPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\appsettings.json'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
foreach($path in @($settingsPath,$runtimePath,$serviceRuntimePath,$programPath,$appSettingsPath,$buildPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Enforce foundation file missing: $path"}
}

$settings=Get-Content -LiteralPath $settingsPath -Raw
$runtime=Get-Content -LiteralPath $runtimePath -Raw
$serviceRuntime=Get-Content -LiteralPath $serviceRuntimePath -Raw
$program=Get-Content -LiteralPath $programPath -Raw
$appSettings=Get-Content -LiteralPath $appSettingsPath -Raw
$build=Get-Content -LiteralPath $buildPath -Raw

foreach($required in @(
    'public int SchemaVersion { get; set; } = 4',
    'Mode must be exactly Audit or Enforce.',
    'RequireSignedDriver',
    'AutomaticContainment',
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
    'var kernelEnforcement = _phase is ProtectionPhase.Protected or ProtectionPhase.DegradedProtected'
)){
    if($runtime -notmatch [regex]::Escape($required)){throw "Protection state invariant missing: $required"}
}

$rollbackReady=$program.IndexOf('protection.MarkRollbackReady()')
$unavailable=$program.IndexOf('protection.MarkUnavailable(',$rollbackReady)
$runtimeCreate=$program.IndexOf('new RuntimeState(protection.Snapshot())',$unavailable)
if($rollbackReady -lt 0 -or $unavailable -lt 0 -or $runtimeCreate -lt 0 -or
   $rollbackReady -gt $unavailable -or $unavailable -gt $runtimeCreate){
    throw 'Service startup must validate rollback readiness, publish EnforceUnavailable for this foundation milestone, then construct RuntimeState from that explicit snapshot.'
}

foreach($required in @(
    'ProductInfo.Version',
    '_protection.KernelEnforcementActive',
    '_protection.AutomaticContainmentActive',
    '_protection.State',
    'A connected UI or SCM Running state is not proof of kernel enforcement'
)){
    if($serviceRuntime -notmatch [regex]::Escape($required)){throw "Runtime status invariant missing: $required"}
}
if($serviceRuntime -match '"0\.7\.1\.0"'){
    throw 'RuntimeState still contains the stale 0.7.1.0 literal.'
}

$app=($appSettings | ConvertFrom-Json)
if([int]$app.SchemaVersion -ne 4 -or [string]$app.Mode -ne 'Audit'){
    throw 'Default appsettings must remain schema 4 / Audit until production lifecycle qualification is complete.'
}
if($app.Enforce.RequireSignedDriver -ne $true -or $app.Enforce.AutomaticContainment -ne $false){
    throw 'Default Enforce policy must require signed driver and keep automatic containment disabled.'
}

# This milestone defines the production contract only. Do not silently add driver/service mutation
# to the normal service before the dedicated lifecycle qualification exists.
foreach($forbidden in @(
    'fltmc.exe',
    'FilterLoad(',
    'StartServiceW(',
    'CreateServiceW(',
    'sc.exe start RansomGuardMinifilter'
)){
    if(($program+$serviceRuntime) -match [regex]::Escape($forbidden)){
        throw "0.8.0 foundation must not mutate driver lifecycle yet: $forbidden"
    }
}

foreach($required in @(
    "'.sys','.cat','.inf'",
    "*GateClient*",
    'driverInstalledByBuild=$false',
    'kernelWriteGateActive=$false'
)){
    if($build -notmatch [regex]::Escape($required)){
        throw "Normal bundle boundary missing: $required"
    }
}

Write-Host 'Production Enforce foundation gate PASSED: explicit schema/state contract, rollback-before-kernel ordering, no false Protected claim, and no normal-bundle driver lifecycle mutation.' -ForegroundColor Green
