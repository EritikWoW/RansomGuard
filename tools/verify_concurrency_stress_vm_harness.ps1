[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$scriptPath=Join-Path $RepositoryRoot 'minifilter-tools\run_concurrency_stress_lab.ps1'
if(-not(Test-Path -LiteralPath $scriptPath -PathType Leaf)){
    throw 'Concurrency stress harness is missing.'
}

$tokens=$null
$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$errors)
if(@($errors).Count -ne 0){
    $messages=@($errors | ForEach-Object {$_.Message})
    throw "Concurrency stress harness PowerShell parse failed: $($messages -join ' | ')"
}

$script=Get-Content -LiteralPath $scriptPath -Raw

foreach($required in @(
    '[ValidateRange(9,32)][int]$Parallelism=16',
    '[ValidateRange(0,240)][int]$MixedRounds=0',
    '[ValidateRange(0,60000)][int]$MixedRoundPauseMilliseconds=0',
    'mixedRoundsRequested',
    'mixedRoundsCompleted',
    'mixedOperationsCompleted',
    'mixedStartedUtc',
    'mixedFinishedUtc',
    'mixedElapsedSeconds',
    'mixedWorkloadPassed',
    'mixed-r{0:D4}.go',
    'all mixed workload helpers for round {0} to reach the shared start barrier',
    '$minimumPauseSeconds',
    'RANSOMGUARD_LAB_VM',
    'I_UNDERSTAND',
    "RootBase='C:\RansomGuard-VM-Stress'",
    "'--gate-workers','8'",
    'kernelGateCap=8',
    'qualificationParallelism=8',
    'admissionOverflowPassed',
    'overflowDenied',
    'Wait-StressGroupAllowAccessDenied',
    'Assert-OverflowDeniedEvidence',
    'overflow-r{0:D2}.go',
    'all CREATE overflow helpers to reach the shared start barrier',
    'create-qualification.go',
    'all CREATE qualification helpers to reach the shared start barrier',
    'rename-qualification.go',
    'all RENAME qualification helpers to reach the shared start barrier',
    'mapped-qualification.go',
    'all MAPPED-WRITE qualification helpers to reach the shared start barrier',
    'Win32Error:\s*5',
    'create-new',
    'rename-file',
    'truncate-eof',
    'delete-file',
    'map-write',
    'Wait-AllPaths $ready',
    'Assert-CreateEvidence',
    'Assert-RenameEvidence',
    'Assert-TruncateEvidence',
    'Assert-DeleteEvidence',
    'Assert-MappedEvidence',
    'Assert-RequestUnique',
    'Assert-NoPendingTransactions',
    'Assert-GateWorkersHealthy',
    'Wait-DeleteFinalizations',
    'gateWorkersHealthyPassed',
    'noPendingTransactionsPassed',
    'snapshotRelativePath',
    'Get-FileHash -LiteralPath $snapshot -Algorithm SHA256',
    'originalSha256',
    'writable-section-journal.jsonl',
    'paging-write-journal.jsonl',
    'create-intent-journal.jsonl',
    'create-completion-journal.jsonl',
    'rename-journal.jsonl',
    'rename-completion-journal.jsonl',
    'truncate-intent-journal.jsonl',
    'truncate-completion-journal.jsonl',
    'delete-intent-journal.jsonl',
    'delete-completion-journal.jsonl',
    'delete-finalization-journal.jsonl',
    'Bounded gate workers\s*:\s*8',
    'kernel gate ACTIVE',
    'GateClient exited unexpectedly during concurrency stress',
    'CONCURRENCY STRESS LAB PASSED',
    'cleanupPassed=$false',
    '& $unloadScript -Volume $drive | Out-Host'
)){
    if(-not $script.Contains($required)){
        throw "Concurrency stress source invariant missing: $required"
    }
}

$startGate=$script.IndexOf('$gate=Start-LoggedProcess')
$createPhase=$script.IndexOf('Start-Helper ("create-')
$renamePhase=$script.IndexOf('Start-Helper ("rename-')
$truncatePhase=$script.IndexOf('Start-Helper ("truncate-')
$deletePhase=$script.IndexOf('Start-Helper ("delete-')
$mappedPhase=$script.IndexOf('Start-Helper ("mapped-')
$mixedPhase=$script.IndexOf('Start-Helper ("mixed-r{0:D4}-create"')
$evidence=$script.IndexOf('$createIntents=Read-JsonLines')
$cleanup=$script.IndexOf('finally{',$evidence)
$unload=$script.IndexOf('& $unloadScript -Volume $drive | Out-Host',$cleanup)
if($startGate -lt 0 -or $createPhase -lt 0 -or $renamePhase -lt 0 -or
   $truncatePhase -lt 0 -or $deletePhase -lt 0 -or $mappedPhase -lt 0 -or
   $mixedPhase -lt 0 -or $evidence -lt 0 -or $cleanup -lt 0 -or $unload -lt 0 -or
   $startGate -gt $createPhase -or $createPhase -gt $renamePhase -or
   $renamePhase -gt $truncatePhase -or $truncatePhase -gt $deletePhase -or
   $deletePhase -gt $mappedPhase -or $mappedPhase -gt $mixedPhase -or
   $mixedPhase -gt $evidence -or $evidence -gt $cleanup -or $cleanup -gt $unload){
    throw 'Concurrency stress ordering must remain gate -> CREATE -> RENAME -> TRUNCATE -> DELETE -> mapped-write -> optional mixed waves -> evidence -> finally/unload.'
}

if($script -match '(?im)\b(Format-Volume|diskpart(?:\.exe)?|Initialize-Disk|Clear-Disk|Remove-Partition|Resize-Partition|bcdedit(?:\.exe)?|verifier(?:\.exe)?|shutdown(?:\.exe)?|Restart-Computer|Stop-Computer)\b'){
    throw 'Concurrency stress milestone must not format disks, alter boot policy, enable Driver Verifier, or reboot/shutdown the VM.'
}
if($script -match '(?im)\b(taskkill|wmic\s+process|Get-Process\s+[^#\r\n]*\|\s*Stop-Process)\b'){
    throw 'Concurrency stress harness must stop only process objects it started, never broad process-name selections.'
}
if($script -match '(?im)Remove-Item[^\r\n]*\$RootBase'){
    throw 'Concurrency stress harness must not recursively delete the caller-supplied RootBase.'
}
if($script -notmatch [regex]::Escape('if($full -notmatch ''(?i)RansomGuard'')') -or
   $script -notmatch [regex]::Escape('if([string]::IsNullOrWhiteSpace($drive) -or $full -eq $drive)')){
    throw 'Concurrency stress root safety checks are missing.'
}


$helperPath=Join-Path $RepositoryRoot 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs'
if(-not(Test-Path -LiteralPath $helperPath -PathType Leaf)){
    throw 'RuntimeHarness source is missing for deterministic concurrency barriers.'
}
$helper=Get-Content -LiteralPath $helperPath -Raw
foreach($required in @(
    'OptionalPath(options, "--ready")',
    'OptionalPath(options, "--go")',
    'WaitForOptionalBarrier',
    'WaitForOptionalBarrier(readyMarker, goMarker, "create-new")',
    'WaitForOptionalBarrier(readyMarker, goMarker, "rename-file")',
    'WaitForOptionalBarrier(readyMarker, goMarker, "map-write")'
)){
    if(-not $helper.Contains($required)){
        throw "RuntimeHarness concurrency barrier invariant missing: $required"
    }
}

$workflowPath=Join-Path $RepositoryRoot '.github\workflows\minifilter-stress-vm.yml'
if(-not(Test-Path -LiteralPath $workflowPath -PathType Leaf)){
    throw 'Concurrency stress VM workflow is missing.'
}
$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'name: Minifilter concurrency stress VM lab',
    'workflow_dispatch:',
    'default: C:\RansomGuard-VM-Stress',
    "default: '16'",
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    '.\tools\verify_concurrency_stress_vm_harness.ps1',
    '.\minifilter-tools\run_concurrency_stress_lab.ps1',
    'transactionCorrelationPassed',
    'admissionOverflowPassed',
    'qualificationParallelism',
    'overflowDenied',
    'noPendingTransactionsPassed',
    'preimageHashPassed',
    'gateStayedAlive',
    'gateWorkersHealthyPassed',
    'cleanupPassed',
    'ransomguard-concurrency-stress-evidence'
)){
    if(-not $workflow.Contains($required)){
        throw "Concurrency stress workflow invariant missing: $required"
    }
}
if($workflow -match '(?m)^\s*(push|pull_request|schedule):'){
    throw 'Concurrency stress VM workflow must remain manual-only.'
}
if($workflow -match '(?im)\b(verifier(?:\.exe)?|shutdown(?:\.exe)?|Restart-Computer|Stop-Computer|Format-Volume|diskpart(?:\.exe)?)\b'){
    throw 'Concurrency stress VM workflow must not reboot, enable Driver Verifier, or format/manage disks.'
}

Write-Host 'Concurrency stress source gate PASSED: baseline qualification remains bounded at cap=8, optional sustained mixed waves share one GateClient/rollback session, every mixed round synchronizes CREATE/RENAME/TRUNCATE/DELETE/mapped-write behind one barrier, elapsed time is recorded, DELETE finalization/worker health remain mandatory, all transactions are correlated to durable evidence, pre-images are hash-checked, cleanup is bounded, and reboot/disk/verifier operations are absent.'
