[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){$RepositoryRoot=Join-Path $PSScriptRoot '..'}
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-updater-rollback-vm.yml'
$harnessPath=Join-Path $root 'qualification\run_production_updater_rollback_vm.ps1'
$helperPath=Join-Path $root 'qualification\RansomGuard.UpdaterQualification\Program.cs'
$failurePath=Join-Path $root 'qualification\RansomGuard.UpdaterFailureFixture\Program.cs'
$updaterPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateAdministration.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'

foreach($path in @($workflowPath,$harnessPath,$helperPath,$failurePath,$updaterPath,$dispatcherPath,$windowsCiPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Updater rollback qualification source missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$helper=Get-Content -LiteralPath $helperPath -Raw
$failure=Get-Content -LiteralPath $failurePath -Raw
$updater=Get-Content -LiteralPath $updaterPath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$windowsCi=Get-Content -LiteralPath $windowsCiPath -Raw

foreach($required in @(
    'RansomGuard production updater rollback VM qualification',
    'expected_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'ref: ${{ inputs.expected_sha }}',
    'git rev-parse HEAD',
    '-p:Version=0.8.6.0',
    'RansomGuard.UpdaterQualification',
    'RansomGuard.UpdaterFailureFixture',
    'run_production_updater_rollback_vm.ps1',
    'ransomguard-production-updater-rollback-${{ inputs.expected_sha }}'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater rollback workflow invariant missing: $required"}
}
if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Updater rollback workflow must not continue after qualification failure.'
}

if($workflow -match [regex]::Escape('BaseIntermediateOutputPath=obj-updater-') -or
   $workflow -match [regex]::Escape('BaseOutputPath=bin-updater-')){
    throw 'Updater qualification must not place custom obj/bin roots beside SDK default roots; generated AssemblyInfo can be globbed as source.'
}
foreach($required in @(
    'BaseIntermediateOutputPath=obj\updater-old\',
    'BaseIntermediateOutputPath=obj\updater-current\',
    'BaseIntermediateOutputPath=obj\updater-failure\'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater build-isolation invariant missing: $required"}
}

foreach($required in @(
    'function Remove-QualificationBuildFamily',
    "Remove-QualificationBuildFamily 'updater-old'",
    "Remove-QualificationBuildFamily 'updater-current'",
    "Get-ChildItem -LiteralPath '.\src','.\qualification' -Directory -Recurse -Force"
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Updater phase-cleanup invariant missing: $required"}
}

foreach($required in @(
    'expect-review-failure',
    'bytes do not match',
    'review-update',
    'update',
    'replay/downgrade rejected',
    'expect-update-failure',
    'rolled back to the previous verified image',
    'Completed',
    'RolledBack',
    'ServiceUpdateCompleted',
    'ServiceUpdateRolledBack',
    'Get-UpdateRecord',
    'forwardTransactionId',
    'baselineBeforeRollback',
    'rollbackTransactionId',
    'Expected exactly one new terminal RolledBack transaction',
    'forward-completed-transaction.json',
    'forward-completed-audit.json',
    'previousImageRestored',
    'cleanupPassed',
    'PRODUCTION-UPDATER-ROLLBACK-EVIDENCE PASS'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "Updater rollback harness invariant missing: $required"}
}

foreach($required in @(
    'audit.jsonl',
    'audit.1.jsonl',
    'audit.2.jsonl',
    'audit.3.jsonl',
    'Assert-NoReparsePath $path'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "Updater rollback audit-rotation evidence invariant missing: $required"}
}

$forwardAuditCapture=$harness.IndexOf("'forward-completed-audit.json'",[StringComparison]::Ordinal)
$firstUninstall=$harness.IndexOf("@('uninstall')",[StringComparison]::Ordinal)
if($forwardAuditCapture -lt 0 -or $firstUninstall -lt 0 -or $forwardAuditCapture -ge $firstUninstall){
    throw 'Updater qualification must capture exact ServiceUpdateCompleted audit evidence before the first uninstall removes the product data root.'
}

foreach($forbidden in @(
    '\bStop-Process\b',
    '\btaskkill(?:\.exe)?\b',
    '\bTerminateProcess\b',
    '\bRestart-Computer\b',
    '\bshutdown(?:\.exe)?\b'
)){
    if($harness -match $forbidden){throw "Updater rollback harness contains forbidden recovery shortcut: $forbidden"}
}

foreach($required in @(
    'ServiceAdministration.Install',
    'ServiceAdministration.ReviewUpdateInput',
    'ServiceAdministration.Update',
    'ServiceAdministration.Execute',
    '"INSTALL"',
    '"UPDATE"',
    '"UNINSTALL"'
)){
    if($helper -notmatch [regex]::Escape($required)){throw "Updater qualification helper invariant missing: $required"}
}

if($failure -notmatch 'intentional SCM startup failure'){
    throw 'Updater failure fixture must remain an explicit intentional startup-failure target.'
}

foreach($required in @(
    'EnsureNoIncompleteUpdate',
    'ServiceUpdatePolicy.IsForwardVersion',
    'ChangeServiceImage(service, targetImage)',
    'scmCommitted = true',
    '"ScmCommitted"',
    '"RollbackStarting"',
    '"RollbackScmCommitted"',
    '"RolledBack"',
    'VerifyInstalledImage(previousImage)'
)){
    if($updater -notmatch [regex]::Escape($required)){throw "Transactional updater invariant missing: $required"}
}

foreach($required in @(
    '/run-production-updater-rollback-vm ',
    'production-updater-rollback-vm.yml',
    'Dispatched production updater rollback VM qualification for exact SHA'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){throw "Updater rollback dispatcher invariant missing: $required"}
}
if($harness -match [regex]::Escape('Get-UpdateRecords $startedUtc')){
    throw 'Updater qualification evidence must bind to exact transaction IDs, not a timestamp-only journal window.'
}
foreach($forbiddenAuditWindow in @(
    'function Get-AuditEntries([DateTimeOffset]$SinceUtc)',
    '-ge $SinceUtc',
    'Get-AuditEntries $startedUtc'
)){
    if($harness -match [regex]::Escape($forbiddenAuditWindow)){
        throw "Updater audit evidence must bind to exact transaction IDs without a VM-clock window: $forbiddenAuditWindow"
    }
}
if($harness -notmatch [regex]::Escape('function Get-AuditEntries {')){
    throw 'Updater audit evidence reader must remain transaction-driven and clock-independent.'
}
if($windowsCi -notmatch [regex]::Escape('verify_production_updater_vm_harness.ps1')){
    throw 'Windows CI must run the updater rollback source gate.'
}

Write-Host 'Production updater rollback VM harness gate PASSED: exact-SHA disposable VM, real ServiceAdministration path, tampered hash/replay rejection, forward update, post-commit failure and deterministic rollback evidence.'
