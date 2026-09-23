$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$planner=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryPlan.cs'
$executor=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryExecutor.cs'
$restart=Join-Path $root 'src\RansomGuard.Rollback\RestartReconciliationStore.cs'
$truncate=Join-Path $root 'src\RansomGuard.Rollback\TruncateOperationStore.cs'
$cli=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\Program.cs'
$project=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\RansomGuard.RollbackRecoveryCli.csproj'
$build=Join-Path $root 'build_windows.ps1'
$launcher=Join-Path $root 'rollback_recovery.cmd'
$tests=Join-Path $root 'tests\RansomGuard.Rollback.Tests\Program.cs'

foreach($path in @($planner,$executor,$restart,$truncate,$cli,$project,$build,$launcher,$tests)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Verified rollback recovery source missing: $path"}
}

$plannerText=Get-Content -LiteralPath $planner -Raw
foreach($required in @(
    'RollbackRepository(repositoryRoot)',
    'repository.VerifyAll()',
    'store.VerifyAll()',
    'RestoreFullPreimageCopy',
    'RestoreRangeCowCopy',
    'ReviewOriginallyAbsentPath',
    'ReviewCreateTransaction',
    'ReviewRenameTopology',
    'ReviewTruncateTransaction',
    'RecoveryActionState.Ready',
    'RecoveryActionState.Review',
    'RecoveryActionState.Blocked',
    'AutomaticTopologyMutationAllowed: false',
    'ComputeJournalEvidenceDigest',
    'ComputePlanId',
    'CREATE intent has no authoritative kernel completion',
    'RENAME intent has no authoritative kernel completion',
    'TRUNCATE intent has no authoritative kernel completion',
    'truncates.AssessRestart(intent)',
    'restartEvidence?.Assess(',
    'reviewable ? RecoveryActionState.Review : RecoveryActionState.Blocked',
    'restart evidence never becomes a kernel completion',
    'Automatic deletion is forbidden',
    'live topology is never renamed automatically'
)){
    if($plannerText -notmatch [regex]::Escape($required)){throw "Recovery planner invariant missing: $required"}
}
if($plannerText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'Recovery planner must remain read-only and must not contain delete/move primitives.'
}

$restartText=Get-Content -LiteralPath $restart -Raw
foreach($required in @(
    'RestartEvidenceAssessmentState.NoEvidence',
    'RestartEvidenceAssessmentState.ConsistentSupportsCompleted',
    'RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted',
    'RestartEvidenceAssessmentState.Unresolved',
    'x.OperationKind == operationKind',
    'x.RequestSequence == requestSequence',
    'x.IntentRecordSha256.Equals(intentRecordSha256',
    'matches.All(x =>',
    'SameObservedTopology(x, firstObservation)',
    'left.SourceVolumeSerialHex.Equals(right.SourceVolumeSerialHex',
    'left.SourceFileIdHex.Equals(right.SourceFileIdHex',
    'left.DestinationVolumeSerialHex.Equals(right.DestinationVolumeSerialHex',
    'left.DestinationFileIdHex.Equals(right.DestinationFileIdHex',
    'matches[^1].RecordSha256'
)){
    if($restartText -notmatch [regex]::Escape($required)){throw "Restart recovery invariant missing: $required"}
}
if($restartText -match 'RecordCompletionAsync|RecordCompletion\s*\('){
    throw 'Restart evidence must never expose an authoritative completion writer.'
}

$truncateText=Get-Content -LiteralPath $truncate -Raw
foreach($required in @(
    'truncate-intent-journal.jsonl',
    'truncate-completion-journal.jsonl',
    'truncate-restart-journal.jsonl',
    'RecordIntentAsync(',
    'RecordCompletionAsync(',
    'RecordRestartObservationAsync(',
    'ClassifyRestart(',
    'TruncateMetric.EndOfFile',
    'RestartEvidenceState.SupportsCompleted',
    'RestartEvidenceState.SupportsNotCompleted',
    'RestartEvidenceState.Indeterminate',
    'RestartEvidenceState.Ambiguous',
    'AssessRestart('
)){
    if($truncateText -notmatch [regex]::Escape($required)){
        throw "TRUNCATE recovery invariant missing: $required"
    }
}
if($truncateText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'TRUNCATE transaction store must remain evidence-only and must not mutate live topology.'
}

$executorText=Get-Content -LiteralPath $executor -Raw
foreach($required in @(
    'RollbackRecoveryPlanner.Build(repositoryFull, requestedPlan.SessionId)',
    'ValidateRequestedPlan(requestedPlan, current, repositoryFull)',
    'current.Actions.Where(x => x.State == RecoveryActionState.Ready)',
    'RestoreToNewCopyAsync',
    'Recovery output root already exists',
    'Recovery output root must remain outside the rollback repository',
    'Recovery plan is stale or does not match the currently validated rollback evidence',
    'AutomaticTopologyMutationPerformed: false',
    'RejectExistingReparseAncestors(outputFull)',
    'Ready recovery action kind'
)){
    if($executorText -notmatch [regex]::Escape($required)){throw "Recovery executor invariant missing: $required"}
}
if($executorText -match [regex]::Escape('requestedPlan.Actions')){
    throw 'Recovery executor must never execute caller-supplied plan actions; it must execute the freshly rebuilt current plan.'
}
if($executorText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'Recovery executor must never delete/move live evidence or topology.'
}

$readySwitch=$executorText.IndexOf('switch (action.Kind)')
if($readySwitch -lt 0){throw 'Recovery executor action switch missing.'}
$readyBlock=$executorText.Substring($readySwitch)
foreach($allowed in @(
    'case RecoveryActionKind.RestoreFullPreimageCopy:',
    'case RecoveryActionKind.RestoreRangeCowCopy:'
)){
    if($readyBlock -notmatch [regex]::Escape($allowed)){throw "Recovery executor ready action missing: $allowed"}
}
foreach($forbidden in @(
    'case RecoveryActionKind.ReviewOriginallyAbsentPath:',
    'case RecoveryActionKind.ReviewCreateTransaction:',
    'case RecoveryActionKind.ReviewRenameTopology:',
    'case RecoveryActionKind.ReviewTruncateTransaction:'
)){
    if($readyBlock -match [regex]::Escape($forbidden)){throw "Recovery executor must not execute topology review action: $forbidden"}
}

$cliText=Get-Content -LiteralPath $cli -Raw
foreach($required in @(
    'case "plan":',
    'case "execute":',
    'RollbackRecoveryPlanner.Build',
    'RollbackRecoveryExecutor.ExecuteReadyAsync',
    'FileMode.CreateNew',
    'RejectExistingReparseAncestors(parent)',
    'Live source/evidence files are never overwritten, renamed or deleted'
)){
    if($cliText -notmatch [regex]::Escape($required)){throw "Recovery CLI invariant missing: $required"}
}
if($cliText -match '(?i)case\s+"(delete|remove|rename|overwrite|restore-in-place)"'){
    throw 'Recovery CLI must not expose a destructive topology verb.'
}
if($cliText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'Recovery CLI must not contain destructive filesystem primitives.'
}

$buildText=Get-Content -LiteralPath $build -Raw
foreach($required in @(
    '$rollbackRecovery = ''src\RansomGuard.RollbackRecoveryCli\RansomGuard.RollbackRecoveryCli.csproj''',
    '$rollbackRecoveryDir=Join-Path $labRelease ''RollbackRecovery''',
    'publish'',$rollbackRecovery',
    '''rollback_recovery.cmd''',
    '''ROLLBACK_RECOVERY.md''',
    '$_.Name -like ''*RollbackRecovery*'''
)){
    if($buildText -notmatch [regex]::Escape($required)){throw "Recovery LAB packaging invariant missing: $required"}
}
if($buildText -notmatch 'if\(\$IncludeLab\)\{\$projects\+=@\([^\)]*\$rollbackRecovery[^\)]*\)\}'){
    throw 'Rollback recovery CLI must remain in the Engineering LAB project restore set.'
}
$publishPos=$buildText.IndexOf("publish',`$rollbackRecovery")
$labPublishPos=$buildText.IndexOf("`$rollbackRecoveryDir=Join-Path `$labRelease 'RollbackRecovery'")
if($publishPos -lt 0 -or $labPublishPos -lt 0 -or $publishPos -lt $labPublishPos){
    throw 'Rollback recovery CLI must be published only inside the Engineering LAB packaging block.'
}

$launcherText=Get-Content -LiteralPath $launcher -Raw
if($launcherText -notmatch [regex]::Escape('RollbackRecovery\RansomGuard.RollbackRecovery.exe')){
    throw 'Rollback recovery launcher must target the LAB-only executable.'
}

$testText=Get-Content -LiteralPath $tests -Raw
foreach($required in @(
    'restart assessment accepts only exact consistent decisive evidence',
    'restart assessment rejects same-decision evidence with identity drift',
    'restart assessment keeps conflicting observations unresolved',
    'restart assessment does not borrow evidence from another request or intent',
    'consistent restart CREATE evidence becomes review-only crash recovery',
    'consistent restart RENAME evidence becomes review-only crash recovery',
    'ambiguous restart RENAME evidence remains blocked',
    'restart TRUNCATE EOF evidence recognizes requested length on the same FILE_ID',
    'restart TRUNCATE EOF evidence recognizes unchanged original length',
    'TRUNCATE restart evidence is idempotent and assessment binds the exact intent',
    'consistent restart TRUNCATE evidence becomes review-only and never a live length mutation',
    'stale recovery plan is rejected before any output is created'
)){
    if($testText -notmatch [regex]::Escape($required)){throw "Crash reconciliation recovery test invariant missing: $required"}
}

Write-Host 'Verified rollback recovery source gate PASSED: CREATE/RENAME/TRUNCATE restart review, copy-out-only Ready actions, stale-plan refusal, no manufactured completion or automatic live mutation.' -ForegroundColor Green
