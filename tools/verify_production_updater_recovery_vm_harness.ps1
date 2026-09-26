[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-updater-interrupted-recovery-vm.yml'
$harnessPath=Join-Path $root 'qualification\run_production_updater_interrupted_recovery_vm.ps1'
$helperPath=Join-Path $root 'qualification\RansomGuard.UpdaterQualification\Program.cs'
$recoveryPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateRecoveryAdministration.cs'
$updaterPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateAdministration.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'

foreach($path in @($workflowPath,$harnessPath,$helperPath,$recoveryPath,$updaterPath,$dispatcherPath,$windowsCiPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Updater interrupted-recovery qualification source missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$helper=Get-Content -LiteralPath $helperPath -Raw
$recovery=Get-Content -LiteralPath $recoveryPath -Raw
$updater=Get-Content -LiteralPath $updaterPath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$windowsCi=Get-Content -LiteralPath $windowsCiPath -Raw

foreach($required in @(
    'RansomGuard production updater interrupted recovery VM qualification',
    'expected_sha',
    'phase:',
    '- arm',
    '- resume',
    '- verify',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'ref: ${{ inputs.expected_sha }}',
    'git rev-parse HEAD',
    'verify_production_updater_recovery_vm_harness.ps1',
    'run_production_updater_interrupted_recovery_vm.ps1',
    'shutdown.exe',
    'success() &&',
    'ransomguard-production-updater-recovery-${{ inputs.phase }}-${{ inputs.expected_sha }}'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater recovery workflow invariant missing: $required"}
}
if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Updater interrupted-recovery workflow must not continue after a failed qualification phase.'
}
if($workflow -match [regex]::Escape('BaseIntermediateOutputPath=obj-updater-recovery-') -or
   $workflow -match [regex]::Escape('BaseOutputPath=bin-updater-recovery-')){
    throw 'Updater recovery qualification must keep custom build roots under SDK-standard obj/bin exclusions.'
}
foreach($required in @(
    'BaseIntermediateOutputPath=obj\updater-recovery-old-service\',
    'BaseIntermediateOutputPath=obj\updater-recovery-old-helper\',
    'BaseIntermediateOutputPath=obj\updater-recovery-current-service\',
    'BaseIntermediateOutputPath=obj\updater-recovery-current-helper\'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater recovery build-isolation invariant missing: $required"}
}

foreach($required in @(
    'function Remove-QualificationBuildFamily',
    "Remove-QualificationBuildFamily 'updater-recovery-old-service'",
    "Remove-QualificationBuildFamily 'updater-recovery-old-helper'",
    "Remove-QualificationBuildFamily 'updater-recovery-current-service'",
    "Remove-QualificationBuildFamily 'updater-recovery-current-helper'"
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater recovery phase-cleanup invariant missing: $required"}
}

$oldServiceCleanup=$workflow.IndexOf("Remove-QualificationBuildFamily 'updater-recovery-old-service'",[StringComparison]::Ordinal)
$oldHelperRestore=$workflow.IndexOf('dotnet restore $helper --locked-mode -r win-x64 -p:Version=0.8.6.0 -p:BaseIntermediateOutputPath=obj\updater-recovery-old-helper\',[StringComparison]::Ordinal)
$currentServiceCleanup=$workflow.IndexOf("Remove-QualificationBuildFamily 'updater-recovery-current-service'",[StringComparison]::Ordinal)
$currentHelperRestore=$workflow.IndexOf('dotnet restore $helper --locked-mode -r win-x64 -p:BaseIntermediateOutputPath=obj\updater-recovery-current-helper\',[StringComparison]::Ordinal)
if($oldServiceCleanup -lt 0 -or $oldHelperRestore -lt 0 -or $oldServiceCleanup -ge $oldHelperRestore){
    throw 'Old updater-recovery service build family must be removed before building the old helper.'
}
if($currentServiceCleanup -lt 0 -or $currentHelperRestore -lt 0 -or $currentServiceCleanup -ge $currentHelperRestore){
    throw 'Current updater-recovery service build family must be removed before building the current helper.'
}

foreach($required in @(
    "ValidateSet('arm','resume','verify')",
    'Write-InterruptedRecord',
    "'Prepared'",
    'AbortBeforeCommit',
    'RollbackToPrevious',
    'SCM target committed while durable journal remains Prepared',
    'review-recovery',
    'recover-update',
    'RolledBack',
    'firstRebootObserved',
    'secondRebootObserved',
    'idempotentTerminalStatePassed',
    'truncatedJournalRejected',
    'campaign-state-final.json',
    'PRODUCTION-UPDATER-RECOVERY ARM PASS',
    'PRODUCTION-UPDATER-RECOVERY RESUME PASS',
    'PRODUCTION-UPDATER-RECOVERY VERIFY PASS'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "Updater recovery harness invariant missing: $required"}
}
foreach($forbidden in @(
    '\bStop-Process\b',
    '\btaskkill(?:\.exe)?\b',
    '\bTerminateProcess\b',
    '\bProcess\.Kill\s*\(',
    '\bRestart-Computer\b',
    '\bshutdown(?:\.exe)?\b'
)){
    if($harness -match $forbidden){throw "Updater recovery harness contains forbidden in-process crash/reboot shortcut: $forbidden"}
}

foreach($required in @(
    'review-recovery',
    'ServiceAdministration.ReviewInterruptedUpdate',
    'recover-update',
    'ServiceAdministration.RecoverInterruptedUpdate',
    'ROLLBACK UPDATE',
    'expect-recovery-review-failure'
)){
    if($helper -notmatch [regex]::Escape($required)){throw "Updater recovery qualification helper invariant missing: $required"}
}

foreach($source in @($recovery,$updater)){
    if($source -notmatch [regex]::Escape('catch (JsonException ex)') -or
       $source -notmatch [regex]::Escape('Update transaction record invalid:')){
        throw 'Updater/recovery journal parsing must normalize truncated JSON to a fail-closed IOException.'
    }
}

foreach($required in @(
    'ReadSingleIncompleteUpdate',
    'Multiple incomplete update transactions exist',
    'SCM ImagePath changed while update recovery was acquiring a stable stopped state',
    'SCM ImagePath is neither the recorded previous image nor the recorded target image',
    'VerifyRecordedPreviousImage',
    '"AbortedBeforeCommit"',
    '"RollbackScmCommitted"',
    '"RolledBack"',
    '"RollbackFailed"'
)){
    if($recovery -notmatch [regex]::Escape($required)){throw "Interrupted updater recovery invariant missing: $required"}
}

foreach($required in @(
    '/run-production-updater-recovery-arm-vm ',
    '/run-production-updater-recovery-resume-vm ',
    '/run-production-updater-recovery-verify-vm ',
    'production-updater-interrupted-recovery-vm.yml'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){throw "Updater recovery dispatcher invariant missing: $required"}
}
if($windowsCi -notmatch [regex]::Escape('verify_production_updater_recovery_vm_harness.ps1')){
    throw 'Windows CI must run the updater interrupted-recovery source gate.'
}

Write-Host 'Production updater interrupted-recovery VM harness gate PASSED: exact-SHA three-phase reboot campaign, post-SCM/pre-journal crash window, explicit recovery, idempotent second reboot, truncated-journal fail-closed check and cleanup.'
