$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

$lifecycle=Join-Path $root 'src\RansomGuard.Rollback\RollbackSessionLifecycleStore.cs'
$retentionStore=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionStore.cs'
$retentionPlan=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionPlan.cs'
$retentionExecutor=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionExecutor.cs'
$maintenanceLease=Join-Path $root 'src\RansomGuard.Rollback\RollbackMaintenanceLease.cs'
$repository=Join-Path $root 'src\RansomGuard.Rollback\RollbackRepository.cs'
$gateClient=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'
$cli=Join-Path $root 'src\RansomGuard.RollbackMaintenanceCli\Program.cs'
$project=Join-Path $root 'src\RansomGuard.RollbackMaintenanceCli\RansomGuard.RollbackMaintenanceCli.csproj'
$build=Join-Path $root 'build_windows.ps1'
$launcher=Join-Path $root 'rollback_maintenance.cmd'
$tests=Join-Path $root 'tests\RansomGuard.Rollback.Tests\Program.cs'

foreach($path in @($lifecycle,$retentionStore,$retentionPlan,$retentionExecutor,$maintenanceLease,$repository,$gateClient,$cli,$project,$build,$launcher,$tests)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Rollback retention source missing: $path"}
}

$leaseText=Get-Content -LiteralPath $maintenanceLease -Raw
foreach($required in @(
    'FileShare.None',
    'maintenance.lock',
    'Another rollback maintenance operation currently owns the repository lease',
    'Rollback repository root does not exist',
    'RejectReparse(root)',
    'FileOptions.WriteThrough',
    'Flush(true)'
)){
    if($leaseText -notmatch [regex]::Escape($required)){throw "Maintenance lease invariant missing: $required"}
}

$lifecycleText=Get-Content -LiteralPath $lifecycle -Raw
foreach($required in @(
    'session-lifecycle.jsonl',
    'RollbackSessionLifecycleEventType.Created',
    'RollbackSessionLifecycleEventType.Completed',
    'RollbackSessionLifecycleEventType.Faulted',
    'RollbackSessionLifecycleEventType.HoldSet',
    'RollbackSessionLifecycleEventType.HoldReleased',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Rollback session lifecycle hash chain mismatch',
    'Rollback session lifecycle timestamps must be monotonic',
    'Rollback session lifecycle timestamps are not monotonic',
    'IsRetentionEligible'
)){
    if($lifecycleText -notmatch [regex]::Escape($required)){throw "Lifecycle invariant missing: $required"}
}

$repositoryText=Get-Content -LiteralPath $repository -Raw
foreach($required in @(
    'new RollbackSessionLifecycleStore(path).InitializeCreated(createdUtc)',
    'new RollbackSessionLifecycleStore(store.Root).VerifyAll()',
    'new RollbackRetentionStore(_root, createIfMissing: false).VerifyAll()'
)){
    if($repositoryText -notmatch [regex]::Escape($required)){throw "Repository retention invariant missing: $required"}
}

$gateText=Get-Content -LiteralPath $gateClient -Raw
foreach($required in @(
    'gateWorkerFailures',
    'createOperationStore.PendingIntents.Count',
    'renameStore.PendingIntents.Count',
    'MarkCompletedAsync',
    'MarkFaultedAsync',
    'session-lifecycle-terminal'
)){
    if($gateText -notmatch [regex]::Escape($required)){throw "Gate lifecycle invariant missing: $required"}
}
if($gateText -match [regex]::Escape('RollbackRetentionExecutor.ExecuteAsync')){
    throw 'GateClient must never execute retention automatically.'
}
if($gateText -match '(?i)retention-(execute|purge|cleanup)'){
    throw 'GateClient must not expose an automatic retention execution path.'
}

$retentionStoreText=Get-Content -LiteralPath $retentionStore -Raw
foreach($required in @(
    'retention-journal.jsonl',
    'PurgeStarted',
    'Quarantined',
    'PurgeCompleted',
    'Incomplete retention purge can only continue with the original plan/evidence identity',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Rollback retention journal hash chain mismatch'
)){
    if($retentionStoreText -notmatch [regex]::Escape($required)){throw "Retention journal invariant missing: $required"}
}

$planText=Get-Content -LiteralPath $retentionPlan -Raw
foreach($required in @(
    'TimeSpan.FromDays(30)',
    '32L * 1024 * 1024 * 1024',
    'TimeSpan.FromHours(24)',
    'RollbackSessionLifecycleState.LegacyUnmanaged',
    'snapshot.IsHeld',
    'HasPendingTransactions',
    'UnresolvedExcessBytes',
    'AgeExpired',
    'CapacityPressure',
    'ComputeSessionDigest',
    'ComputeInventoryDigest',
    'ResumePurgeFromSessions',
    'ResumePurgeFromRetired',
    'FinalizeMissingQuarantine'
)){
    if($planText -notmatch [regex]::Escape($required)){throw "Retention planner invariant missing: $required"}
}
if($planText -match '\b(Directory\.Delete|File\.Delete|Directory\.Move|File\.Move)\s*\('){
    throw 'Retention planner must remain read-only.'
}
if($planText -match [regex]::Escape('File.ReadAllBytes')){
    throw 'Retention planner must stream session hashing; rollback evidence may be multi-gigabyte.'
}
foreach($required in @(
    'FileOptions.SequentialScan',
    'SHA256.HashData(stream)'
)){
    if($planText -notmatch [regex]::Escape($required)){throw "Retention streaming hash invariant missing: $required"}
}

$executorText=Get-Content -LiteralPath $retentionExecutor -Raw
foreach($required in @(
    'RollbackMaintenanceLease.Acquire(repositoryFull)',
    'RollbackRetentionPlanner.Build(',
    'ValidateRequestedPlan(requestedPlan, current, repositoryFull)',
    'VerifyCompletedAndUnheld(source)',
    'RollbackRetentionEventType.PurgeStarted',
    'Directory.Move(source, destination)',
    'RollbackRetentionEventType.Quarantined',
    'SafeDeleteTree(destination)',
    'RollbackRetentionEventType.PurgeCompleted',
    'ResumeFromSessionsAsync',
    'ResumeFromRetiredAsync',
    'FinalizeMissingQuarantineAsync',
    'Retention cleanup refuses reparse-point paths'
)){
    if($executorText -notmatch [regex]::Escape($required)){throw "Retention executor invariant missing: $required"}
}
$movePos=$executorText.IndexOf('Directory.Move(source, destination)')
$deletePos=$executorText.IndexOf('SafeDeleteTree(destination)')
$startedPos=$executorText.IndexOf('RollbackRetentionEventType.PurgeStarted')
$quarantinePos=$executorText.IndexOf('RollbackRetentionEventType.Quarantined')
if($startedPos -lt 0 -or $movePos -lt 0 -or $quarantinePos -lt 0 -or $deletePos -lt 0 -or
   $startedPos -gt $movePos -or $movePos -gt $quarantinePos -or $quarantinePos -gt $deletePos){
    throw 'New retention purge must journal Started, move to Retired, journal Quarantined, then delete.'
}
if($executorText -match 'Directory\.Delete\(source'){
    throw 'Retention executor must never delete directly from Sessions.'
}

$cliText=Get-Content -LiteralPath $cli -Raw
foreach($required in @(
    'case "status":',
    'case "retention-plan":',
    'case "retention-execute":',
    'case "hold":',
    'case "release-hold":',
    'RollbackRetentionPlanner.Build',
    'RollbackRetentionExecutor.ExecuteAsync',
    'RollbackMaintenanceLease.Acquire(repositoryRoot)',
    'using var reportStream = OpenNewOutput(reportPath);',
    'FileMode.CreateNew',
    'Active, Faulted, Held, legacy and pending-transaction sessions are never selected'
)){
    if($cliText -notmatch [regex]::Escape($required)){throw "Maintenance CLI invariant missing: $required"}
}
$leaseOccurrences=[regex]::Matches($cliText,[regex]::Escape('RollbackMaintenanceLease.Acquire(repositoryRoot)')).Count
if($leaseOccurrences -lt 2){
    throw 'Both hold and release-hold must acquire the repository maintenance lease.'
}
if($cliText -match '(?i)case\s+"(delete|purge-now|force-delete|ignore-hold|ignore-pending)"'){
    throw 'Rollback maintenance CLI must not expose force/destructive bypass verbs.'
}

$reportReserve=$cliText.IndexOf('using var reportStream = OpenNewOutput(reportPath);')
$retentionExecute=$cliText.IndexOf('RollbackRetentionExecutor.ExecuteAsync(')
if($reportReserve -lt 0 -or $retentionExecute -lt 0 -or $reportReserve -gt $retentionExecute){
    throw 'Retention report output must be reserved before destructive execution begins.'
}

$buildText=Get-Content -LiteralPath $build -Raw
foreach($required in @(
    '$rollbackMaintenance = ''src\RansomGuard.RollbackMaintenanceCli\RansomGuard.RollbackMaintenanceCli.csproj''',
    '$rollbackMaintenanceDir=Join-Path $labRelease ''RollbackMaintenance''',
    'publish'',$rollbackMaintenance',
    '''rollback_maintenance.cmd''',
    '$_.Name -like ''*RollbackMaintenance*'''
)){
    if($buildText -notmatch [regex]::Escape($required)){throw "Retention LAB packaging invariant missing: $required"}
}

$launcherText=Get-Content -LiteralPath $launcher -Raw
if($launcherText -notmatch [regex]::Escape('RollbackMaintenance\RansomGuard.RollbackMaintenance.exe')){
    throw 'Rollback maintenance launcher must target LAB-only executable.'
}

$testText=Get-Content -LiteralPath $tests -Raw
foreach($required in @(
    'rollback maintenance lease serializes retention and hold changes',
    'retention planner selects only eligible completed unheld sessions',
    'retention executor rejects stale plan after lifecycle hold change',
    'retention executor quarantines and purges eligible completed session',
    'retention journal records started/quarantined/completed purge chain',
    'retention planner selects oldest eligible sessions under capacity pressure',
    'retention planner detects moved incomplete purge after crash',
    'retention executor resumes quarantined purge and commits completion receipt'
)){
    if($testText -notmatch [regex]::Escape($required)){throw "Retention test invariant missing: $required"}
}

Write-Host 'Rollback retention source gate PASSED: explicit lifecycle, hold protection, deterministic planning, stale-plan refusal, Sessions-to-Retired quarantine, crash resume, reparse-safe purge, LAB-only manual CLI.' -ForegroundColor Green
