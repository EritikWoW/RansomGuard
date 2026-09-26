$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$planner=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryPlan.cs'
$executor=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryExecutor.cs'
$restart=Join-Path $root 'src\RansomGuard.Rollback\RestartReconciliationStore.cs'
$truncate=Join-Path $root 'src\RansomGuard.Rollback\TruncateOperationStore.cs'
$delete=Join-Path $root 'src\RansomGuard.Rollback\DeleteOperationStore.cs'
$cli=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\Program.cs'
$project=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\RansomGuard.RollbackRecoveryCli.csproj'
$build=Join-Path $root 'build_windows.ps1'
$launcher=Join-Path $root 'rollback_recovery.cmd'
$tests=Join-Path $root 'tests\RansomGuard.Rollback.Tests\Program.cs'

foreach($path in @($planner,$executor,$restart,$truncate,$delete,$cli,$project,$build,$launcher,$tests)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Verified rollback recovery source missing: $path"}
}

$plannerText=Get-Content -LiteralPath $planner -Raw
foreach($required in @(
    'RollbackRepository(repositoryRoot, createIfMissing)',
    'repository.VerifyAll()',
    'createIfMissing: createIfMissing',
    'store.VerifyAll()',
    'RestoreFullPreimageCopy',
    'RestoreRangeCowCopy',
    'ReviewOriginallyAbsentPath',
    'ReviewCreateTransaction',
    'ReviewRenameTopology',
    'ReviewTruncateTransaction',
    'ReviewDeleteTransaction',
    'RecoveryActionState.Ready',
    'RecoveryActionState.Review',
    'RecoveryActionState.Blocked',
    'AutomaticTopologyMutationAllowed: false',
    'ComputeJournalEvidenceDigest',
    'ComputePlanId',
    'CREATE intent has no authoritative kernel completion',
    'RENAME intent has no authoritative kernel completion',
    'TRUNCATE intent has no authoritative kernel completion',
    'DELETE intent has no authoritative disposition completion',
    'DELETE disposition was accepted',
    'deletes.AssessFinalization(intent)',
    'DeleteFinalizationAssessmentState.CleanupObservedOnly',
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
    'AssessRestart(',
    'TRUNCATE restart observation intent binding mismatch',
    'TRUNCATE restart observation path does not match its committed intent',
    'TRUNCATE restart assessment intent binding mismatch'
)){
    if($truncateText -notmatch [regex]::Escape($required)){
        throw "TRUNCATE recovery invariant missing: $required"
    }
}
if($truncateText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'TRUNCATE transaction store must remain evidence-only and must not mutate live topology.'
}

$deleteText=Get-Content -LiteralPath $delete -Raw
foreach($required in @(
    'delete-intent-journal.jsonl',
    'delete-completion-journal.jsonl',
    'delete-finalization-journal.jsonl',
    'RecordIntentAsync(',
    'RecordCompletionAsync(',
    'RecordFinalizationAsync(',
    'AssessFinalization(',
    'ClassifyPathObservation(',
    'DeleteFinalizationState.CleanupObserved',
    'LivePostCleanupProbe = 4',
    'DeleteFinalizationAssessmentState.CleanupObservedOnly',
    'DeleteFinalizationAssessmentState.ConsistentDeletedObserved',
    'DeleteFinalizationAssessmentState.ConsistentStillPresent',
    'DeleteFinalizationAssessmentState.Unresolved',
    'DELETE finalization assessment intent binding mismatch'
)){
    if($deleteText -notmatch [regex]::Escape($required)){
        throw "DELETE recovery invariant missing: $required"
    }
}
if($deleteText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'DELETE transaction store must remain evidence-only and must not mutate live topology.'
}

$executorText=Get-Content -LiteralPath $executor -Raw
foreach($required in @(
    'RollbackRecoveryPlanner.Build(',
    'createIfMissing: false, verifyRepositoryAll: false',
    'new RollbackRepository(repositoryFull, createIfMissing: false)',
    'repository.VerifySession(current.SessionId)',
    'new RangeRollbackStore(rangeRoot, createIfMissing: false)',
    'ValidateRequestedPlan(requestedPlan, current, repositoryFull)',
    'current.Actions.Where(x => x.State == RecoveryActionState.Ready)',
    'ComputeExpectedRecoveryAsync',
    'RestoreToNewCopyAsync',
    'ExpectedLength',
    'ExpectedSha256',
    'Recovered copy length mismatch',
    'Recovered copy SHA-256 does not match the pre-output evidence expectation',
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
    'case RecoveryActionKind.ReviewTruncateTransaction:',
    'case RecoveryActionKind.ReviewDeleteTransaction:'
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
    'TRUNCATE restart evidence rejects a cloned intent whose path does not match the committed record',
    'consistent restart TRUNCATE evidence becomes review-only and never a live length mutation',
    'DELETE finalization rejects a cloned intent whose path does not match the committed record',
    'DELETE exact-handle cleanup is durable but does not claim pathname deletion',
    'DELETE finalization accepts monotonic same-FILE_ID-present to pathname-missing transition',
    'conflicting DELETE topology/cancellation evidence remains unresolved and retention-protected',
    'authoritative DELETE plus observed pathname absence is topology review, never automatic recreation',
    'lost DELETE disposition completion with restart absence evidence remains review-only',
    'cleanup-only DELETE evidence remains blocked until pathname topology is proven',
    'stale recovery plan is rejected before any output is created',
    'existing recovery output root refuses overwrite',
    'reparse recovery destination is refused',
    'copy-out executor leaves damaged live sources untouched',
    'recovery output length and SHA-256 match evidence expectations',
    'partial recovery failure is reported without undoing completed copies'
)){
    if($testText -notmatch [regex]::Escape($required)){throw "Crash reconciliation recovery test invariant missing: $required"}
}

Write-Host 'Verified rollback recovery source gate PASSED: CREATE/RENAME/TRUNCATE/DELETE restart/finalization review, copy-out-only Ready actions, stale-plan refusal, no manufactured completion or automatic live mutation.' -ForegroundColor Green
