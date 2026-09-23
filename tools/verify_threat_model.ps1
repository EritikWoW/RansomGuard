[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$threatPath=Join-Path $RepositoryRoot 'docs\THREAT_MODEL.md'
$securityPath=Join-Path $RepositoryRoot 'docs\SECURITY.md'
$driverPath=Join-Path $RepositoryRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
$policyPath=Join-Path $RepositoryRoot 'src\RansomGuard.Core\DecisionPolicy.cs'
$workerPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\GuardWorker.cs'

foreach($path in @($threatPath,$securityPath,$driverPath,$policyPath,$workerPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Threat-model source missing: $path"
    }
}

$threat=Get-Content -LiteralPath $threatPath -Raw
$security=Get-Content -LiteralPath $securityPath -Raw
$driver=Get-Content -LiteralPath $driverPath -Raw
$policy=Get-Content -LiteralPath $policyPath -Raw
$worker=Get-Content -LiteralPath $workerPath -Raw

foreach($required in @(
    'ordinary product remains AuditOnly',
    'unresolved/name-query-failed scope classification currently fails open',
    'kernel-mode requestors are outside the ordinary observation path',
    'preserve-before-allow',
    'Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion',
    'production detector-to-containment orchestration remains unimplemented',
    'Do not describe the current normal bundle as production ransomware blocking'
)){
    if(-not $threat.Contains($required)){
        throw "Threat model is missing required current-boundary statement: $required"
    }
}

if(-not $security.Contains('[THREAT_MODEL.md](THREAT_MODEL.md)')){
    throw 'SECURITY.md must link to the canonical threat model.'
}

foreach($required in @(
    'Data->RequestorMode == KernelMode',
    'Unresolved/out-of-root CREATEs fail open',
    'Unresolved/out-of-root paths fail open',
    'return FLT_PREOP_SUCCESS_NO_CALLBACK'
)){
    if(-not $driver.Contains($required)){
        throw "Driver boundary changed without threat-model review: $required"
    }
}

if(-not $policy.Contains('AuditOnly: automatic action against ordinary applications is disabled in this build.')){
    throw 'DecisionPolicy ordinary-process AuditOnly boundary changed without threat-model review.'
}
if(-not $worker.Contains('Mode=AUDIT for ALL ordinary applications')){
    throw 'GuardWorker ordinary-process AuditOnly statement changed without threat-model review.'
}
if(-not $worker.Contains('Diagnostics-only state. There is NO file monitoring.')){
    throw 'GuardWorker explicit ETW degradation boundary changed without threat-model review.'
}

Write-Host 'Threat-model gate PASSED: documentation matches current AuditOnly, kernel-requestor, unresolved-path fail-open and explicit monitoring-degradation boundaries.'
