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
$protocolPath=Join-Path $RepositoryRoot 'native\shared\rg_minifilter_protocol.h'
$verifierGatePath=Join-Path $RepositoryRoot 'tools\verify_driver_verifier_vm_harness.ps1'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
if(-not(Test-Path -LiteralPath $workflowRoot -PathType Container)){
    throw "Threat-model workflow root missing: $workflowRoot"
}
$workflowPaths=@(
    Get-ChildItem -LiteralPath $workflowRoot -File |
        Where-Object { $_.Extension -in @('.yml','.yaml') } |
        Sort-Object FullName |
        Select-Object -ExpandProperty FullName
)
if($workflowPaths.Count -eq 0){
    throw 'Threat-model gate found no GitHub Actions workflows to audit.'
}
$globalPath=Join-Path $RepositoryRoot 'global.json'
$supplyGatePath=Join-Path $RepositoryRoot 'tools\verify_supply_chain.ps1'
$codeOwnersPath=Join-Path $RepositoryRoot '.github\CODEOWNERS'

foreach($path in @($threatPath,$securityPath,$driverPath,$policyPath,$workerPath,$gateClientPath,$protocolPath,$verifierGatePath,$buildPath,$globalPath,$supplyGatePath,$codeOwnersPath)+$workflowPaths){
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
$protocol=Get-Content -LiteralPath $protocolPath -Raw
$verifierGate=Get-Content -LiteralPath $verifierGatePath -Raw
$global=Get-Content -LiteralPath $globalPath -Raw | ConvertFrom-Json
$supplyGate=Get-Content -LiteralPath $supplyGatePath -Raw
$codeOwners=Get-Content -LiteralPath $codeOwnersPath -Raw

foreach($required in @(
    'ordinary product remains AuditOnly',
    'Intentional fail-open gap',
    'Kernel-mode requestor / compromised kernel component / BYOVD path',
    'preserve-before-allow',
    'Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion',
    'Production detector-to-containment orchestration remains unimplemented.',
    'one synchronous communication handle',
    'reply-required preservation is deliberately serialized',
    'current wire contract is protocol v15',
    'For the exact 0.7.30 Driver Verifier qualification head',
    'overflow width of 16 against a kernel admission cap of 8 (8 allowed / 8 denied)',
    'Persisted reboot timestamps are SHA-bound and parsed from raw offset-bearing JSON',
    '0.7.31 adds a separate sustained mixed-workload qualification harness',
    'Source presence is not qualification evidence',
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
    'current user/kernel wire contract is protocol v15',
    'The 0.7.30 qualification campaign materially increases confidence in this LAB boundary but does not change it into a production claim.',
    '16 requests against cap 8 -> 8 allowed / 8 denied',
    '0.7.31 adds a manual sustained mixed-workload qualification contract',
    'Source presence or a hosted compile is not treated as endurance evidence',
    'CODEOWNERS',
    'does not itself require approval'
)){
    if(-not $security.Contains($required)){
        throw "SECURITY.md is missing required current-boundary statement: $required"
    }
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
if(-not $protocol.Contains('#define RG_PROTOCOL_VERSION 15u')){
    throw 'Threat-model protocol-v15 boundary changed without review.'
}
if(-not $gateClient.Contains('ProtocolVersion = 15')){
    throw 'GateClient protocol-v15 connection boundary changed without threat-model review.'
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
foreach($required in @(
    '/driver/ @EritikWoW',
    '/src/RansomGuard.GateClient/ @EritikWoW',
    '/.github/workflows/ @EritikWoW',
    '/docs/THREAT_MODEL.md @EritikWoW',
    '/tools/verify_threat_model.ps1 @EritikWoW'
)){
    if(-not $codeOwners.Contains($required)){
        throw "CODEOWNERS security-routing invariant missing: $required"
    }
}

if(-not $verifierGate.Contains('persisted reboot timestamps are parsed from raw offset-bearing JSON without timezone coercion')){
    throw 'Threat model requires the timezone-safe Driver Verifier reboot-proof source gate.'
}

$build=Get-Content -LiteralPath $buildPath -Raw
if(-not $build.Contains("tools\verify_threat_model.ps1")){
    throw 'build_windows.ps1 must run the threat-model gate before building release artifacts.'
}
foreach($workflowPath in $workflowPaths){
    $workflow=Get-Content -LiteralPath $workflowPath -Raw
    if(-not $workflow.Contains('.\tools\verify_threat_model.ps1')){
        throw "Threat-model gate is not wired into workflow: $workflowPath"
    }
}

Write-Host "Threat-model gate PASSED: docs match AuditOnly/fail-open/kernel exclusions, protocol v15, serialized synchronous gate semantics, current Driver Verifier/fault qualification limits, supply-chain controls, CODEOWNERS routing, build_windows.ps1 and all $($workflowPaths.Count) repository workflows invoke this gate."
