[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$preparePath=Join-Path $RepositoryRoot 'minifilter-tools\prepare_production_lifecycle_qualification_package.ps1'
$runPath=Join-Path $RepositoryRoot 'minifilter-tools\run_production_lifecycle_lab.ps1'
$workflowPath=Join-Path $RepositoryRoot '.github\workflows\minifilter-runtime-vm.yml'
$lifecyclePath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\ProductionProtectionLifecycle.cs'
foreach($path in @($preparePath,$runPath,$workflowPath,$lifecyclePath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Production lifecycle VM qualification source missing: $path"}
}

$prepare=Get-Content -LiteralPath $preparePath -Raw
$run=Get-Content -LiteralPath $runPath -Raw

if($prepare -match [regex]::Escape("-match '(?i)\x64\'") -or
   $prepare -match [regex]::Escape("-match '(?i)\x86\'")){
    throw 'Qualification package tool discovery must not use malformed trailing-backslash x64/x86 regexes.'
}
$workflow=Get-Content -LiteralPath $workflowPath -Raw
$lifecycle=Get-Content -LiteralPath $lifecyclePath -Raw

foreach($required in @(
    'Assert-DisposableVm',
    'RANSOMGUARD_LAB_VM',
    'I_UNDERSTAND',
    "QualificationAltitude='385201.806'",
    "QualificationAltitude -eq '370099.4242'",
    'qualificationOnly=$true',
    'certificateThumbprint=$thumb',
    'serviceSha256=',
    'gateClientSha256=',
    'driverSysSha256=',
    'driverInfSha256=',
    'driverCatSha256=',
    "Profile='ProductionProtection'",
    'Protocol=18',
    "Provider='RansomGuard'",
    'UNASSIGNED LAB PLACEHOLDER|RansomGuard Lab|370099\.4242',
    'Get-AuthenticodeSignature',
    'Inf2Cat',
    'Test-PathSegment',
    "Where-Object {Test-PathSegment $_.FullName 'x64'}",
    "Where-Object {Test-PathSegment $_.FullName 'x86'}",
    '[StringComparison]::OrdinalIgnoreCase',
    'git -C $repoRoot rev-parse HEAD',
    'This package must never be distributed or reused outside the disposable VM'
)){
    if($prepare -notmatch [regex]::Escape($required) -and $prepare -notmatch $required){
        throw "Production lifecycle qualification package invariant missing: $required"
    }
}

foreach($required in @(
    'Assert-DisposableVm',
    'RANSOMGUARD_LAB_VM',
    'ExpectedCommit',
    'qualificationOnly',
    'Remove-RansomGuardDriverRegistration',
    'Remove-QualificationServiceIfOwned',
    "Mode='Enforce'",
    'AutomaticContainment=$false',
    'ReconnectDelaySeconds=5',
    'Invoke-Sc @(''create'',$serviceName',
    "'obj= LocalSystem'",
    "Wait-AuditType 'ProductionProtectionActivated'",
    "Wait-AuditType 'ProductionGateLost'",
    "'DegradedProtected'",
    'Get-Process -Id $firstGatePid -ErrorAction SilentlyContinue',
    'reconnectPidReused',
    'ExpectedSession',
    'Reconnect must preserve the same production rollback session.',
    'Service restart must preserve the same production rollback session.',
    'Test-AccessDeniedException',
    "Wait-AuditType 'ProductionProtectionMaintenanceStop'",
    "'Maintenance'",
    'reconnectReplacementObserved',
    'Get-CimInstance Win32_Service -Filter "Name=''$serviceName''"',
    'Stop-Process -Id $servicePid -Force',
    'serviceCrashObserved',
    'serviceCrashGateExited',
    'serviceCrashDeniedMutation',
    'serviceCrashPreservedHash',
    'serviceRestartProtected',
    'serviceRestartMutationAllowed',
    'driverUnloadedAfterMaintenance',
    'cleanupPassed',
    'production-lifecycle-result.json',
    'production-lifecycle-audit.json',
    'auditEvidenceCount',
    'finalTargetSha256',
    'Remove-Item -LiteralPath $root -Recurse -Force',
    'pnputil.exe /delete-driver',
    "fltmc filters"
)){
    if($run -notmatch [regex]::Escape($required)){
        throw "Production lifecycle VM runtime invariant missing: $required"
    }
}

foreach($required in @(
    'Run production service lifecycle qualification',
    'prepare_production_lifecycle_qualification_package.ps1',
    'run_production_lifecycle_lab.ps1',
    '-ExpectedCommit $env:RG_WORKFLOW_SHA',
    "qualification-package.json",
    "production-lifecycle-result.json",
    "production-lifecycle-audit.json",
    'auditEvidenceCount',
    "'admittedAndProtected'",
    "'gateClientLossObserved'",
    "'degradedDeniedMutation'",
    "'reconnectProtected'",
    "'reconnectReplacementObserved'",
    "'serviceCrashObserved'",
    "'serviceCrashGateExited'",
    "'serviceCrashDeniedMutation'",
    "'serviceCrashPreservedHash'",
    "'serviceRestartProtected'",
    "'serviceRestartMutationAllowed'",
    "'maintenanceStopObserved'",
    "'driverUnloadedAfterMaintenance'",
    "'cleanupPassed'",
    "'passed'",
    'ransomguard-production-lifecycle-evidence',
    'RG_PRODUCTION_LIFECYCLE_RESULTS',
    'Remove signed qualification packages',
    'Join-Path $env:RUNNER_TEMP ''RansomGuard-ProductionLifecycle-Qualification'''
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Runtime workflow is missing the production lifecycle qualification invariant: $required"
    }
}

$prepareCall=$workflow.IndexOf('prepare_production_lifecycle_qualification_package.ps1')
$packageCommit=$workflow.IndexOf('$packageSummary.commit -ne $env:RG_WORKFLOW_SHA',$prepareCall)
$runCall=$workflow.IndexOf('run_production_lifecycle_lab.ps1',$packageCommit)
$resultCommit=$workflow.IndexOf('$summary.commit -ne $env:RG_WORKFLOW_SHA',$runCall)
$artifact=$workflow.IndexOf('ransomguard-production-lifecycle-evidence',$resultCommit)
if($prepareCall -lt 0 -or $packageCommit -lt 0 -or $runCall -lt 0 -or $resultCommit -lt 0 -or $artifact -lt 0 -or
   $prepareCall -gt $packageCommit -or $packageCommit -gt $runCall -or $runCall -gt $resultCommit -or $resultCommit -gt $artifact){
    throw 'Production lifecycle VM workflow must bind package and runtime evidence to RG_WORKFLOW_SHA before artifact publication.'
}

foreach($forbidden in @(
    '(?i)Restart-Computer',
    '(?i)Stop-Computer',
    '(?i)shutdown\.exe',
    '(?i)bcdedit',
    '(?i)Set-MpPreference',
    '(?i)Add-MpPreference',
    '(?i)Remove-MpPreference',
    '(?i)DisableRealtimeMonitoring',
    '(?i)Confirm-SecureBootUEFI',
    '(?i)diskpart',
    '(?i)Clear-Disk',
    '(?i)Remove-Partition',
    '(?i)Format-Volume',
    '(?i)Initialize-Disk',
    '(?i)select\s+disk',
    '(?i)clean\s+all',
    '(?i)taskkill',
    '(?i)Stop-Process\s+-Name'
)){
    if($prepare -match $forbidden -or $run -match $forbidden){
        throw "Production lifecycle qualification harness contains a forbidden host/security mutation: $forbidden"
    }
}

foreach($required in @(
    '_admission.ReadyForLifecycle',
    'ProductionDriverLifecycle.EnsureReadyAsync',
    'StartGateClient',
    '_protection.MarkDegraded(',
    '_protection.MarkReconnectedProtected(',
    'ProductionDriverLifecycle.StopAfterMaintenanceAsync',
    '_protection.BeginMaintenance('
)){
    if($lifecycle -notmatch [regex]::Escape($required)){
        throw "Service lifecycle implementation no longer matches the VM qualification contract: $required"
    }
}

Write-Host 'Production lifecycle VM harness gate PASSED: disposable-VM only, exact-SHA package/runtime provenance, synthetic qualification-only production shape, activation/loss/degraded/reconnect/maintenance proof, bounded cleanup and no boot/Defender/disk-security mutation.' -ForegroundColor Green
