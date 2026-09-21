$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$planner=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryPlan.cs'
$executor=Join-Path $root 'src\RansomGuard.Rollback\RollbackRecoveryExecutor.cs'
$cli=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\Program.cs'
$project=Join-Path $root 'src\RansomGuard.RollbackRecoveryCli\RansomGuard.RollbackRecoveryCli.csproj'
$build=Join-Path $root 'build_windows.ps1'
$launcher=Join-Path $root 'rollback_recovery.cmd'

foreach($path in @($planner,$executor,$cli,$project,$build,$launcher)){
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
    'RecoveryActionState.Ready',
    'RecoveryActionState.Review',
    'RecoveryActionState.Blocked',
    'AutomaticTopologyMutationAllowed: false',
    'ComputeJournalEvidenceDigest',
    'ComputePlanId',
    'CREATE intent has no authoritative kernel completion',
    'RENAME intent has no authoritative kernel completion',
    'Automatic deletion is forbidden',
    'live topology is never renamed automatically'
)){
    if($plannerText -notmatch [regex]::Escape($required)){throw "Recovery planner invariant missing: $required"}
}
if($plannerText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'Recovery planner must remain read-only and must not contain delete/move primitives.'
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
    'case RecoveryActionKind.ReviewRenameTopology:'
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

Write-Host 'Verified rollback recovery source gate PASSED: revalidated deterministic plan, copy-out-only Ready actions, stale-plan refusal, reparse refusal, LAB-only CLI, no automatic delete/rename/overwrite.' -ForegroundColor Green
