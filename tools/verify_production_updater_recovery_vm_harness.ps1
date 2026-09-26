[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-updater-interrupted-recovery-vm.yml'
$quarantineWorkflowPath=Join-Path $root '.github\workflows\production-updater-recovery-quarantine-vm.yml'
$harnessPath=Join-Path $root 'qualification\run_production_updater_interrupted_recovery_vm.ps1'
$quarantineHarnessPath=Join-Path $root 'qualification\quarantine_production_updater_recovery_vm.ps1'
$helperPath=Join-Path $root 'qualification\RansomGuard.UpdaterQualification\Program.cs'
$recoveryPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateRecoveryAdministration.cs'
$updaterPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateAdministration.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'

foreach($path in @($workflowPath,$quarantineWorkflowPath,$harnessPath,$quarantineHarnessPath,$helperPath,$recoveryPath,$updaterPath,$dispatcherPath,$windowsCiPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Updater interrupted-recovery qualification source missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$quarantineWorkflow=Get-Content -LiteralPath $quarantineWorkflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$quarantineHarness=Get-Content -LiteralPath $quarantineHarnessPath -Raw
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
    '[ValidateNotNullOrEmpty()][string]$StateFile',
    '$StateFile=[IO.Path]::GetFullPath($StateFile)',
    '$hashFile=$StateFile+''.sha256''',
    '$statePath=[IO.Path]::GetFullPath([IO.Path]::Combine($active,''updater-recovery-campaign.json''))',
    'Read-State -StateFile $statePath -ExpectedSha $ExpectedCommit',
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
if($harness -match [regex]::Escape('foreach($p in @($Path,$Path+''.sha256''))')){
    throw 'Updater recovery campaign state verification must use an explicit normalized state file and hash file path.'
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
    'RansomGuard production updater recovery quarantine VM',
    'campaign_sha',
    'repair_source_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'ref: \${{ inputs.repair_source_sha }}',
    'git rev-parse HEAD',
    'verify_production_updater_recovery_vm_harness.ps1',
    'quarantine_production_updater_recovery_vm.ps1',
    'ransomguard-production-updater-recovery-quarantine-\${{ inputs.campaign_sha }}-\${{ inputs.repair_source_sha }}'
)){
    if($quarantineWorkflow -notmatch [regex]::Escape($required)){throw "Updater recovery quarantine workflow invariant missing: $required"}
}
if($quarantineWorkflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Updater recovery quarantine workflow must not continue after a failed cleanup/recovery step.'
}

foreach($required in @(
    '[ValidatePattern(''^[A-Fa-f0-9]{40}$'')][string]$ExpectedCampaignCommit',
    '[ValidatePattern(''^[A-Fa-f0-9]{40}$'')][string]$RepairSourceCommit',
    'campaign-state-pre-quarantine.json',
    'Campaign state SHA-256 mismatch.',
    'Only an armed failed campaign may be quarantined',
    'SCM image does not match the stale campaign target image.',
    '''review-recovery''',
    '''RollbackToPrevious''',
    '''recover-update''',
    '''RolledBack''',
    '''uninstall''',
    'Active-quarantined',
    'UPDATER-RECOVERY-QUARANTINE PASS'
)){
    if($quarantineHarness -notmatch [regex]::Escape($required)){throw "Updater recovery quarantine harness invariant missing: $required"}
}
foreach($forbidden in @(
    '\bStop-Process\b',
    '\btaskkill(?:\.exe)?\b',
    '\bTerminateProcess\b',
    '\bProcess\.Kill\s*\(',
    '\bsc(?:\.exe)?\s+(?:delete|config)\b'
)){
    if($quarantineHarness -match $forbidden){throw "Updater recovery quarantine harness contains forbidden direct cleanup shortcut: $forbidden"}
}
if($quarantineHarness -notmatch [regex]::Escape('Move-Item -LiteralPath $active -Destination $quarantinedActive')){
    throw 'Updater recovery quarantine must preserve the exact stale Active state instead of deleting it in place.'
}

foreach($required in @(
    '/run-production-updater-recovery-arm-vm ',
    '/run-production-updater-recovery-resume-vm ',
    '/run-production-updater-recovery-verify-vm ',
    '/quarantine-production-updater-recovery-vm ',
    'production-updater-interrupted-recovery-vm.yml',
    'production-updater-recovery-quarantine-vm.yml'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){throw "Updater recovery dispatcher invariant missing: $required"}
}
if($windowsCi -notmatch [regex]::Escape('verify_production_updater_recovery_vm_harness.ps1')){
    throw 'Windows CI must run the updater interrupted-recovery source gate.'
}

Write-Host 'Production updater interrupted-recovery VM harness gate PASSED: exact-SHA three-phase reboot campaign plus owner-only stale-campaign quarantine that preserves state, performs reviewed rollback, unregisters the stale service and cannot use direct SCM/kill shortcuts.'
