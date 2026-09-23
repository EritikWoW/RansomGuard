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
$gateClientPath=Join-Path $RepositoryRoot 'src\RansomGuard.GateClient\Program.cs'
$globalPath=Join-Path $RepositoryRoot 'global.json'
$supplyGatePath=Join-Path $RepositoryRoot 'tools\verify_supply_chain.ps1'
$codeOwnersPath=Join-Path $RepositoryRoot '.github\CODEOWNERS'

foreach($path in @($threatPath,$securityPath,$driverPath,$policyPath,$workerPath,$gateClientPath,$globalPath,$supplyGatePath,$codeOwnersPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Threat-model source missing: $path"
    }
}

$threat=Get-Content -LiteralPath $threatPath -Raw
$security=Get-Content -LiteralPath $securityPath -Raw
$driver=Get-Content -LiteralPath $driverPath -Raw
$policy=Get-Content -LiteralPath $policyPath -Raw
$worker=Get-Content -LiteralPath $workerPath -Raw
$gateClient=Get-Content -LiteralPath $gateClientPath -Raw
$global=Get-Content -LiteralPath $globalPath -Raw | ConvertFrom-Json
$supplyGate=Get-Content -LiteralPath $supplyGatePath -Raw
$codeOwners=Get-Content -LiteralPath $codeOwnersPath -Raw

foreach($required in @(
    'ordinary product remains AuditOnly',
    'unresolved/name-query-failed scope classification currently fails open',
    'kernel-mode requestors are outside the ordinary observation path',
    'preserve-before-allow',
    'Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion',
    'production detector-to-containment orchestration remains unimplemented',
    'one synchronous communication handle',
    'reply-required preservation is deliberately serialized',
    'current runner reported ReFS creation unsupported',
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

if($driver -notmatch 'FltCreateCommunicationPort\([^;]+RgConnect\s*,\s*RgDisconnect\s*,\s*RgMessage\s*,\s*1\s*\)'){
    throw 'Threat-model single-client port boundary changed without review.'
}
foreach($required in @(
    'using var workerSlots = new SemaphoreSlim(options.GateWorkers, options.GateWorkers);',
    'if (GateMessagePolicy.RequiresReply((RgEventType)ev.EventType))',
    'await worker.ConfigureAwait(false);',
    'FilterReplyMessage',
    'synchronous handle'
)){
    if(-not $gateClient.Contains($required)){
        throw "Threat-model synchronous GateClient boundary changed without review: $required"
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

if([string]$global.sdk.version -ne '10.0.401' -or [string]$global.sdk.rollForward -ne 'disable'){
    throw 'Threat-model supply-chain statement requires exact SDK 10.0.401 with roll-forward disabled.'
}
foreach($required in @(
    'committed win-x64 lock graphs',
    'full-SHA action pins',
    'restore drift is disabled'
)){
    if(-not $supplyGate.Contains($required)){
        throw "Threat-model supply-chain control changed without review: $required"
    }
}
if(-not $codeOwners.Contains('does not require approval or provide independent review')){
    throw 'CODEOWNERS must explicitly state that routing alone does not enforce review.'
}


Write-Host 'Threat-model gate PASSED: docs match AuditOnly/fail-open/kernel exclusions, serialized synchronous gate semantics, current supply-chain controls, and explicit governance limits.'
