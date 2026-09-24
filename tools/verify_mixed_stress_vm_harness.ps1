[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$scriptPath=Join-Path $RepositoryRoot 'minifilter-tools\run_concurrency_stress_lab.ps1'
$workflowPath=Join-Path $RepositoryRoot '.github\workflows\minifilter-mixed-stress-vm.yml'
foreach($path in @($scriptPath,$workflowPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Mixed endurance source missing: $path"
    }
}

$tokens=$null
$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$errors)
if(@($errors).Count -ne 0){
    throw "Mixed endurance harness parse failed: $(@($errors | ForEach-Object {$_.Message}) -join ' | ')"
}

$script=Get-Content -LiteralPath $scriptPath -Raw
$workflow=Get-Content -LiteralPath $workflowPath -Raw

foreach($required in @(
    '[ValidateRange(0,240)][int]$MixedRounds=0',
    '[ValidateRange(0,60000)][int]$MixedRoundPauseMilliseconds=0',
    'mixedRoundsRequested=$MixedRounds',
    'mixedRoundPauseMilliseconds=$MixedRoundPauseMilliseconds',
    'mixedRoundsCompleted=0',
    'mixedOperationsCompleted=0',
    'mixedStartedUtc=$null',
    'mixedFinishedUtc=$null',
    'mixedElapsedSeconds=0.0',
    'mixedWorkloadPassed=($MixedRounds -eq 0)',
    '$mixedStopwatch=[Diagnostics.Stopwatch]::StartNew()',
    'mixed-r{0:D4}.go',
    'all mixed workload helpers for round {0} to reach the shared start barrier',
    'mixed-r{0:D4}-create',
    'mixed-r{0:D4}-rename',
    'mixed-r{0:D4}-truncate',
    'mixed-r{0:D4}-delete',
    'mixed-r{0:D4}-mapped',
    "'create-new'",
    "'rename-file'",
    "'truncate-eof'",
    "'delete-file'",
    "'map-write'",
    'Wait-DeleteFinalizations $deleteFinalizationJournal @($mixedDeleteTargets[$i])',
    'Assert-GateWorkersHealthy $gateErr',
    'GateClient exited unexpectedly during mixed workload round',
    '$summary.mixedRoundsCompleted=$round',
    '$summary.mixedOperationsCompleted=($round*5)',
    '$summary.mixedFinishedUtc=[DateTime]::UtcNow.ToString(''o'')',
    '$summary.mixedElapsedSeconds=[Math]::Round($mixedStopwatch.Elapsed.TotalSeconds,3)',
    '$minimumPauseSeconds',
    '$summary.mixedWorkloadPassed=$true',
    '@($mixedCreateTargets)',
    '@($mixedRenameSources)',
    '@($mixedTruncateTargets)',
    '@($mixedDeleteTargets)',
    '@($mixedMappedTargets)',
    '$summary.mappedWritePassed -and $summary.mixedWorkloadPassed',
    '& $unloadScript -Volume $drive | Out-Host'
)){
    if(-not $script.Contains($required)){
        throw "Mixed endurance harness invariant missing: $required"
    }
}

$gateStart=$script.IndexOf('$gate=Start-LoggedProcess')
$mixedStart=$script.IndexOf('$mixedStopwatch=[Diagnostics.Stopwatch]::StartNew()')
$evidence=$script.IndexOf('$createIntents=Read-JsonLines')
$cleanup=$script.IndexOf('finally{',$evidence)
if($gateStart -lt 0 -or $mixedStart -lt 0 -or $evidence -lt 0 -or $cleanup -lt 0 -or
   $gateStart -gt $mixedStart -or $mixedStart -gt $evidence -or $evidence -gt $cleanup){
    throw 'Mixed endurance ordering must keep one GateClient alive across mixed waves, then verify evidence, then clean up.'
}

foreach($required in @(
    'name: Minifilter mixed endurance VM lab',
    'workflow_dispatch:',
    'default: C:\RansomGuard-VM-MixedStress',
    "default: '16'",
    "default: '60'",
    "default: '10000'",
    'timeout-minutes: 60',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RG_MIXED_ROUNDS: ${{ inputs.mixed_rounds }}',
    'RG_MIXED_ROUND_PAUSE_MS: ${{ inputs.round_pause_ms }}',
    'RG_WORKFLOW_SHA: ${{ github.sha }}',
    '.\tools\verify_powershell_automation.ps1',
    '.\tools\verify_supply_chain.ps1',
    '.\tools\verify_threat_model.ps1',
    '.\tools\verify_concurrency_stress_vm_harness.ps1',
    '.\tools\verify_mixed_stress_vm_harness.ps1',
    'runtime-package.json',
    'provenance.commit -ne $env:RG_WORKFLOW_SHA',
    'sysSha256',
    'infSha256',
    'catSha256',
    '-MixedRounds $rounds',
    '-MixedRoundPauseMilliseconds $pauseMs',
    "'mixedWorkloadPassed'",
    'mixedRoundsCompleted -ne $rounds',
    'mixedOperationsCompleted -ne ($rounds*5)',
    'mixedElapsedSeconds',
    'mixedStartedUtc',
    'mixedFinishedUtc',
    'overflowDenied -lt 1',
    'gateWorkers -ne 8',
    'kernelGateCap -ne 8',
    'ransomguard-mixed-stress-evidence'
)){
    if(-not $workflow.Contains($required)){
        throw "Mixed endurance workflow invariant missing: $required"
    }
}

if($workflow -match '(?m)^\s*(push|pull_request|schedule):'){
    throw 'Mixed endurance VM workflow must remain manual-only.'
}
if($workflow -match '(?im)\b(verifier(?:\.exe)?|shutdown(?:\.exe)?|Restart-Computer|Stop-Computer|Format-Volume|diskpart(?:\.exe)?|bcdedit(?:\.exe)?)\b'){
    throw 'Mixed endurance VM workflow must not reboot, enable Driver Verifier, alter boot policy, or manage disks.'
}
if($script -match '(?im)\b(verifier(?:\.exe)?|shutdown(?:\.exe)?|Restart-Computer|Stop-Computer|Format-Volume|diskpart(?:\.exe)?|bcdedit(?:\.exe)?)\b'){
    throw 'Mixed endurance harness must not reboot, enable Driver Verifier, alter boot policy, or manage disks.'
}
if($workflow -notmatch [regex]::Escape('if(-not [int]::TryParse($env:RG_MIXED_ROUNDS,[ref]$rounds) -or $rounds -lt 1 -or $rounds -gt 240)')){
    throw 'Mixed endurance workflow must bound mixed_rounds to 1..240.'
}
if($workflow -notmatch [regex]::Escape('if(-not [int]::TryParse($env:RG_MIXED_ROUND_PAUSE_MS,[ref]$pauseMs) -or $pauseMs -lt 0 -or $pauseMs -gt 60000)')){
    throw 'Mixed endurance workflow must bound round_pause_ms to 0..60000.'
}

Write-Host 'Mixed endurance source gate PASSED: one exact-commit signed driver and one GateClient/rollback session survive bounded baseline qualification plus configurable sustained mixed CREATE/RENAME/TRUNCATE/DELETE/mapped-write waves; 60 x 5 operations with 10-second inter-round pauses is the default manual profile; elapsed time, durable transaction correlation, delete finalization, mapped pre-images, worker health and cleanup remain mandatory.'
