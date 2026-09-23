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
    'RANSOMGUARD_LAB_VM',
    'I_UNDERSTAND',
    "RootBase='C:\RansomGuard-VM-Stress'",
    "'--gate-workers','8'",
    'kernelGateCap=8',
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
$evidence=$script.IndexOf('$createIntents=Read-JsonLines')
$cleanup=$script.IndexOf('finally{',$evidence)
$unload=$script.IndexOf('& $unloadScript -Volume $drive | Out-Host',$cleanup)
if($startGate -lt 0 -or $createPhase -lt 0 -or $renamePhase -lt 0 -or
   $truncatePhase -lt 0 -or $deletePhase -lt 0 -or $mappedPhase -lt 0 -or
   $evidence -lt 0 -or $cleanup -lt 0 -or $unload -lt 0 -or
   $startGate -gt $createPhase -or $createPhase -gt $renamePhase -or
   $renamePhase -gt $truncatePhase -or $truncatePhase -gt $deletePhase -or
   $deletePhase -gt $mappedPhase -or $mappedPhase -gt $evidence -or
   $evidence -gt $cleanup -or $cleanup -gt $unload){
    throw 'Concurrency stress ordering must remain gate -> CREATE -> RENAME -> TRUNCATE -> DELETE -> mapped-write -> evidence -> finally/unload.'
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
if($script -notmatch [regex]::Escape("if($full -notmatch '(?i)RansomGuard')") -or
   $script -notmatch [regex]::Escape('if([string]::IsNullOrWhiteSpace($drive) -or $full -eq $drive)')){
    throw 'Concurrency stress root safety checks are missing.'
}

Write-Host 'Concurrency stress source gate PASSED: default parallelism=16 exceeds kernel cap=8, all destructive/mapped phases are correlated to durable evidence, pre-images are hash-checked, cleanup is bounded, and reboot/disk/verifier operations are absent.'
