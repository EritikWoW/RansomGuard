$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

$lifecycle=Join-Path $root 'src\RansomGuard.Rollback\RollbackSessionLifecycleStore.cs'
$release=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionReleaseStore.cs'
$planner=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionPlan.cs'
$purgeStore=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionPurgeStore.cs'
$executor=Join-Path $root 'src\RansomGuard.Rollback\RollbackRetentionPurgeExecutor.cs'
$gateClient=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'
$cli=Join-Path $root 'src\RansomGuard.RollbackRetentionCli\Program.cs'
$project=Join-Path $root 'src\RansomGuard.RollbackRetentionCli\RansomGuard.RollbackRetentionCli.csproj'
$build=Join-Path $root 'build_windows.ps1'
$launcher=Join-Path $root 'rollback_retention.cmd'
$tests=Join-Path $root 'tests\RansomGuard.Rollback.Tests\Program.cs'

foreach($path in @($lifecycle,$release,$planner,$purgeStore,$executor,$gateClient,$cli,$project,$build,$launcher,$tests)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Rollback retention source missing: $path"}
}

$lifecycleText=Get-Content -LiteralPath $lifecycle -Raw
foreach($required in @(
    'RollbackSessionLifecycleState.Opened',
    'RollbackSessionLifecycleState.ClosedCleanly',
    'session-lifecycle.jsonl',
    'FileOptions.WriteThrough',
    'Rollback session lifecycle hash chain mismatch',
    'Rollback session lifecycle close time predates open time'
)){
    if($lifecycleText -notmatch [regex]::Escape($required)){throw "Retention lifecycle invariant missing: $required"}
}

$gateText=Get-Content -LiteralPath $gateClient -Raw
foreach($required in @(
    'new RollbackSessionLifecycleStore(store.Root)',
    '"session-lifecycle-open"',
    'RecordOpenedAsync',
    '"session-lifecycle-close"',
    'RecordClosedCleanlyAsync',
    'await Task.WhenAll(activeWorkers)',
    'if (cts.IsCancellationRequested)'
)){
    if($gateText -notmatch [regex]::Escape($required)){throw "Gate lifecycle invariant missing: $required"}
}
$openPos=$gateText.IndexOf('RecordOpenedAsync')
$preflightPos=$gateText.IndexOf('ActivationPreflight.RunAsync')
$workersPos=$gateText.IndexOf('await Task.WhenAll(activeWorkers)')
$closePos=$gateText.IndexOf('RecordClosedCleanlyAsync')
if($openPos -lt 0 -or $preflightPos -lt 0 -or $openPos -gt $preflightPos){
    throw 'Session Opened lifecycle record must be durable before activation preflight.'
}
if($workersPos -lt 0 -or $closePos -lt 0 -or $closePos -lt $workersPos){
    throw 'ClosedCleanly lifecycle record must be written only after all gate workers finish.'
}
$shutdownGuardPos=$gateText.IndexOf('if (cts.IsCancellationRequested)',$workersPos)
if($shutdownGuardPos -lt 0 -or $shutdownGuardPos -gt $closePos){
    throw 'ClosedCleanly lifecycle record must be guarded by explicit cancellation/normal shutdown.'
}

$releaseText=Get-Content -LiteralPath $release -Raw
foreach($required in @(
    'retention-release-journal.jsonl',
    'RecoveryPlanId',
    'TryGetLatestRelease',
    'FileOptions.WriteThrough',
    'Rollback retention release hash chain mismatch'
)){
    if($releaseText -notmatch [regex]::Escape($required)){throw "Retention release invariant missing: $required"}
}
if($releaseText -match 'Directory\.Delete\s*\('){
    throw 'Retention release store must never delete rollback evidence.'
}

$plannerText=Get-Content -LiteralPath $planner -Raw
foreach($required in @(
    'repository.VerifyAll()',
    'releases.VerifyAll()',
    'lifecycle.IsClosedCleanly',
    'PendingIntents.Count',
    'recoveryPlan.BlockedCount',
    'release.RecoveryPlanId.Equals(recoveryPlan.PlanId',
    'RollbackRetentionDecision.LegacyUnmarked',
    'RollbackRetentionDecision.NotClosedCleanly',
    'RollbackRetentionDecision.PendingTransactions',
    'RollbackRetentionDecision.RecoveryBlocked',
    'RollbackRetentionDecision.NotReleased',
    'RollbackRetentionDecision.ReleaseStale',
    'RollbackRetentionDecision.TooYoung',
    'RollbackRetentionDecision.Eligible',
    'RollbackRecoveryPlanner.Build(repository.Root, sessionId)',
    'Recovery plan changed; retention release requires the current RecoveryPlanId'
)){
    if($plannerText -notmatch [regex]::Escape($required)){throw "Retention planner invariant missing: $required"}
}
if($plannerText -match '\b(Directory\.Delete|File\.Delete|Directory\.Move|File\.Move)\s*\('){
    throw 'Retention planning/release must remain non-destructive.'
}

$purgeText=Get-Content -LiteralPath $purgeStore -Raw
foreach($required in @(
    'RollbackRetentionPurgeState.Intent',
    'RollbackRetentionPurgeState.Quarantined',
    'RollbackRetentionPurgeState.Completed',
    'retention-purge-journal.jsonl',
    'Retention purge operation metadata changed between durable states',
    'FileOptions.WriteThrough'
)){
    if($purgeText -notmatch [regex]::Escape($required)){throw "Retention purge journal invariant missing: $required"}
}

$executorText=Get-Content -LiteralPath $executor -Raw
foreach($required in @(
    'RollbackRetentionPlanner.Build(',
    'requestedPlan.PlanId.Equals(current.PlanId',
    'item.Decision != RollbackRetentionDecision.Eligible',
    'RecordIntentAsync',
    'Directory.Move(expectedSessionRoot, quarantineFull)',
    'RecordQuarantinedAsync',
    'Directory.Delete(quarantineFull, recursive: true)',
    'RecordCompletedAsync',
    'VerifyTreeNoReparse',
    'Retention quarantine escaped the rollback repository'
)){
    if($executorText -notmatch [regex]::Escape($required)){throw "Retention purge executor invariant missing: $required"}
}
if($executorText -match [regex]::Escape('requestedPlan.Sessions')){
    throw 'Retention purge executor must never trust caller-supplied session entries.'
}
$intentPos=$executorText.IndexOf('RecordIntentAsync')
$movePos=$executorText.IndexOf('Directory.Move(expectedSessionRoot, quarantineFull)')
$quarantinePos=$executorText.IndexOf('RecordQuarantinedAsync')
$deletePos=$executorText.IndexOf('Directory.Delete(quarantineFull, recursive: true)')
$completePos=$executorText.IndexOf('RecordCompletedAsync')
if($intentPos -lt 0 -or $movePos -lt 0 -or $quarantinePos -lt 0 -or $deletePos -lt 0 -or $completePos -lt 0 -or
   -not($intentPos -lt $movePos -and $movePos -lt $quarantinePos -and $quarantinePos -lt $deletePos -and $deletePos -lt $completePos)){
    throw 'Retention purge ordering must remain Intent -> atomic quarantine move -> Quarantined -> delete -> Completed.'
}

$cliText=Get-Content -LiteralPath $cli -Raw
foreach($required in @(
    'MinimumPurgeAgeHours = 24',
    'DefaultMinimumAgeHours = 168',
    'case "plan":',
    'case "release":',
    'case "purge":',
    'RELEASE:',
    'PURGE:',
    'RollbackRetentionPlanner.ReleaseAsync',
    'RollbackRetentionPurgeExecutor.PurgeSessionAsync',
    'There is no wildcard/all-sessions purge'
)){
    if($cliText -notmatch [regex]::Escape($required)){throw "Retention CLI invariant missing: $required"}
}
if($cliText -match '(?i)--(force|all|wildcard|yes|auto-purge|disable-age)'){
    throw 'Retention CLI must not expose force/all/wildcard/age-bypass purge switches.'
}
if($cliText -match '\b(Directory\.Delete|File\.Delete|Directory\.Move|File\.Move)\s*\('){
    throw 'Retention CLI must delegate destructive work to the revalidated purge executor.'
}

$buildText=Get-Content -LiteralPath $build -Raw
foreach($required in @(
    '$rollbackRetention = ''src\RansomGuard.RollbackRetentionCli\RansomGuard.RollbackRetentionCli.csproj''',
    'verify_rollback_retention.ps1',
    '$rollbackRetentionDir=Join-Path $labRelease ''RollbackRetention''',
    'publish'',$rollbackRetention',
    '''rollback_retention.cmd''',
    '''ROLLBACK_RETENTION.md''',
    '$_.Name -like ''*RollbackRetention*'''
)){
    if($buildText -notmatch [regex]::Escape($required)){throw "Retention LAB packaging invariant missing: $required"}
}
$publishPos=$buildText.IndexOf('publish'',$rollbackRetention')
$labDirPos=$buildText.IndexOf('$rollbackRetentionDir=Join-Path $labRelease ''RollbackRetention''')
if($publishPos -lt 0 -or $labDirPos -lt 0 -or $publishPos -lt $labDirPos){
    throw 'Rollback retention CLI must be published only inside Engineering LAB packaging.'
}

$launcherText=Get-Content -LiteralPath $launcher -Raw
if($launcherText -notmatch [regex]::Escape('RollbackRetention\RansomGuard.RollbackRetention.exe')){
    throw 'Rollback retention launcher must target the LAB-only executable.'
}

$testText=Get-Content -LiteralPath $tests -Raw
foreach($required in @(
    'legacy session without lifecycle is never purge-eligible',
    'opened-only session is never purge-eligible',
    'pending CREATE keeps retention blocked even after clean close',
    'new rollback evidence invalidates an older retention release',
    'retention purge durably records Intent -> Quarantined -> Completed',
    'stale retention plan is rejected before candidate session is moved',
    'retention purge audit journal corruption is rejected'
)){
    if($testText -notmatch [regex]::Escape($required)){throw "Retention test invariant missing: $required"}
}

Write-Host 'Rollback retention source gate PASSED: clean lifecycle, exact RecoveryPlan release, age barrier, stale-plan refusal, quarantine-first single-session purge, durable purge states, no force/all bypass, LAB-only CLI.' -ForegroundColor Green
