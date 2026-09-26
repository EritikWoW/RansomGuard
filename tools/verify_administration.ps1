[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$launch=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\Administration\AdminLauncher.cs') -Raw
$window=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\Administration\AdminWindow.cs') -Raw
$rules=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\RuleAdministration.cs') -Raw
$service=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\ServiceAdministration.cs') -Raw
$updater=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\ServiceUpdateAdministration.cs') -Raw
$core=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Core\AdminContract.cs') -Raw
$recovery=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\ProductionRecoveryAdministration.cs') -Raw
$recoveryExecution=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\ProductionRecoveryExecutionAdministration.cs') -Raw
$recoveryPane=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\Administration\RecoveryReviewPane.cs') -Raw
foreach($required in @('Environment.ProcessPath','Verb = "runas"','AdminContract.ValidateIntent','child.WaitForExitAsync','1223')) {
 if(-not$launch.Contains($required)){throw "Missing elevation boundary: $required"}
}
foreach($required in @('DemandAdministrator','AdminContract.CheckConfirmation','Inspect(rule.ImagePath, true)','prepared.Digest','ScopedRuleVerifier.CheckScopes','Commit(')) {
 if(-not$rules.Contains($required)){throw "Missing administrative trust validation: $required"}
}
foreach($required in @('DemandAdministrator','AdminContract.CheckConfirmation','AdminContract.ServiceName','VerifyRegistration','FileMode.CreateNew','FileShare.Read','MatchesInstalledPeer','expectedServiceHash','WaitFor(service, 1)','TimeSpan.FromSeconds(30)','IsSha256Hex(record.ImageSha256)','value.All(char.IsAsciiHexDigit)')) {
 if(-not$service.Contains($required)){throw "Missing own-service control invariant: $required"}
}

foreach($required in @(
 'ReviewUpdateInput',
 'AdminContract.CheckConfirmation("update", confirmation)',
 'StateMaintenanceGate.Acquire',
 'EnsureNoIncompleteUpdate',
 'ServiceUpdatePolicy.IsForwardVersion',
 'FileMode.CreateNew',
 'Flush(true)',
 '"Prepared"',
 '"ScmCommitted"',
 '"TargetStarted"',
 '"TargetVerifiedStopped"',
 '"Completed"',
 '"RollbackStarting"',
 '"RollbackScmCommitted"',
 '"RolledBack"',
 '"RollbackFailed"',
 'ChangeServiceConfigW',
 'VerifyInstalledImage(previousImage)',
 'Update replay/downgrade rejected',
 'Do not retry blindly'
)) {
 if(-not$updater.Contains($required)){throw "Missing transactional updater invariant: $required"}
}
foreach($pattern in @(
 'Process\.Kill\s*\(',
 'TerminateProcess\s*\(',
 'FileMode\.Create\b',
 'FileMode\.OpenOrCreate',
 'FileMode\.Truncate',
 'Restart-Computer',
 'shutdown\.exe'
)) {
 if($updater -match $pattern){throw "Forbidden updater primitive: $pattern"}
}
if($core -notmatch '"update"' -or $core -notmatch '"update" => "UPDATE"'){
 throw 'Updater must be an explicit closed-list administrator intent with exact UPDATE confirmation.'
}
Write-Host 'Transactional service updater source gate PASSED: immutable staging, explicit SCM commit point, startup verification, durable rollback phases, downgrade/replay rejection.'

if($service.Contains('DecisionPolicy.HashEqual(record.ImageSha256, record.ImageSha256)')){
 throw 'Install record validation must not use a self-comparison as a SHA-256 format check.'
}
$wizard=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\Administration\SetupWizardPane.cs') -Raw
$text=($launch,$window,$wizard,$rules,$service) -join "`n"
foreach($pattern in @('Process\.Kill\s*\(','TerminateProcess\s*\(','NtSuspendProcess','NtResumeProcess','WriteProcessMemory','CreateRemoteThread','Set-MpPreference','bcdedit','fltmc(?:\.exe)?\s+(load|attach|unload)','ProcessStartInfo\s*\(\s*"(?:cmd|powershell)')) {
 if($text -match $pattern){throw "Forbidden admin action: $pattern"}
}
if($core -notmatch 'ServiceName = "RansomGuardV03"'){throw 'Management must be restricted to the own fixed service.'}
if($window -notmatch 'if \(!preview\) RuleAdministration.DemandAdministrator\(\)' -or $window -notmatch 'if \(_preview\)') {throw 'Admin rendering preview must not query or mutate Windows.'}
Write-Host 'UI administration source gate PASSED: same-EXE UAC, fixed verbs/own service, reviewed fresh SHA256, no mutating pipe protocol.'
Write-Host 'This is a source check. Actual UAC, SCM install/start/stop and ACL integration still require Windows tests.'

$project=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\RansomGuard.Ui.csproj') -Raw
$identity=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Ui\Administration\PackageIdentity.cs') -Raw
if(-not $project.Contains('RansomGuardServiceHash') -or -not $identity.Contains('RansomGuard.ServiceSha256')){throw 'Missing embedded UI/service hash pairing.'}
Write-Host 'Published UI is cryptographically paired to its service bytes; registration/path alone does not authorize installation.'

foreach($required in @(
 'RuleAdministration.DemandAdministrator',
 'StateMaintenanceGate.Acquire',
 'StateStoreAdministration.Inspect',
 'ServiceAdministration.Query',
 'RollbackRepository',
 'RollbackRecoveryPlanner.Build',
 'createIfMissing: false',
 'verifyRepositoryAll: false',
 'repository.VerifySession',
 'RollbackSessionLifecycleState.Completed',
 'RollbackSessionLifecycleState.Faulted',
 'MaxSessions = 128',
 'MaxActions = 200',
 'READ-ONLY PLAN'
)) {
 if(-not $recovery.Contains($required)){throw "Missing production recovery administration invariant: $required"}
}
foreach($pattern in @(
 'RollbackRecoveryExecutor',
 'ExecuteReadyAsync',
 'File\.Move\s*\(',
 'File\.Delete\s*\(',
 'File\.Create\s*\(',
 'File\.OpenWrite\s*\(',
 'Directory\.CreateDirectory\s*\(',
 'Directory\.Move\s*\(',
 'Directory\.Delete\s*\(',
 'File\.Copy\s*\(',
 'WriteAllBytes\s*\(',
 'WriteAllText\s*\('
)) {
 if($recovery -match $pattern){throw "Production recovery foundation must remain read-only: forbidden pattern '$pattern'"}
}
if($recovery -notmatch 'StartsWith\(ProductionPrefix' -or $recovery -notmatch 'production-'){
 throw 'Production recovery administration must enumerate only production-* sessions.'
}
if($recovery -notmatch 'Rollback Sessions directory does not exist; read-only recovery planning will not create it\.'){
 throw 'Production recovery administration must refuse a missing Sessions directory instead of creating state.'
}
Write-Host 'Production recovery administration source gate PASSED: UAC/admin-only, fixed private store, stopped-service boundary, terminal-session deterministic planning, bounded summaries, no execution verbs.'

foreach($required in @(
 'RuleAdministration.DemandAdministrator',
 'StateMaintenanceGate.Acquire',
 'Task.Run(',
 '.GetAwaiter().GetResult()',
 'ProductionRecoveryAdministration.EnsureIdle',
 'ProductionRecoveryAdministration.ValidateStateAndGetRollbackRoot',
 'RollbackSessionLifecycleState.Completed',
 'RollbackSessionLifecycleState.Faulted',
 'LifecycleRecordSha256',
 'RollbackRecoveryPlanner.Build',
 'createIfMissing: false',
 'verifyRepositoryAll: false',
 'RollbackRecoveryExecutor.ExecuteReadyAsync',
 'RecoveryActionKind.RestoreFullPreimageCopy',
 'RecoveryActionKind.RestoreRangeCowCopy',
 'MaxExecutionActions = 200',
 'Path.IsPathFullyQualified',
 'Network recovery destinations are not supported',
 'DriveType.Network',
 'DriveType.NoRootDirectory',
 'Recovery output root already exists',
 'Recovery output root must remain outside RansomGuard private state',
 'FileMode.CreateNew',
 'production-recovery-execution.json',
 'SourceOrTopologyMutationPerformed: false'
)) {
 if(-not $recoveryExecution.Contains($required)){throw "Missing production recovery execution invariant: $required"}
}
if($recoveryExecution -match '\bawait\b'){
 throw 'Production recovery execution must not retain the thread-affine StateMaintenanceGate across await.'
}
foreach($pattern in @(
 'File\.Delete\s*\(',
 'File\.Move\s*\(',
 'Directory\.Delete\s*\(',
 'Directory\.Move\s*\(',
 'FileMode\.Create\b',
 'FileMode\.OpenOrCreate',
 'FileMode\.Truncate',
 'ServiceAdministration\.Execute',
 'Process\.Kill\s*\(',
 'fltmc',
 'sc\.exe'
)) {
 if($recoveryExecution -match $pattern){throw "Production recovery execution boundary contains forbidden mutation/control primitive '$pattern'"}
}
Write-Host 'Production recovery execution source gate PASSED: explicit UAC/admin boundary, exact plan/evidence/lifecycle binding, local create-new copy-out only, bounded manifest, no source/topology/service mutation.'

foreach($required in @(
 'recovery-review',
 'ProductionRecoveryAdministration.ListSessions',
 'ProductionRecoveryAdministration.BuildPlan',
 'ProductionRecoveryExecutionRequest',
 'ProductionRecoveryExecutionAdministration.ExecuteCopyOutAsync',
 'selected.LastRecordSha256',
 '_executeApproval.IsChecked',
 'Path.IsPathFullyQualified',
 'SetPreviewScenario',
 'nativeStateQueries = false',
 'nativeExecutionCalls = false',
 'sourceMutationControls = false',
 'copyOutControls = _currentPlan is { ReadyCount: > 0, ActionsTruncated: false }'
)) {
 $source=if($required -eq 'recovery-review'){$core}else{$recoveryPane}
 if(-not $source.Contains($required)){throw "Missing elevated recovery review invariant: $required"}
}
foreach($required in @(
 'if (action == "recovery-review")',
 'new RecoveryReviewPane(preview)',
 'RecoveryPane = pane',
 'return;'
)) {
 if(-not $window.Contains($required)){throw "Recovery review must route to a dedicated pane before rule/setup mutation UI: $required"}
}
foreach($pattern in @(
 'RollbackRecoveryExecutor',
 'ExecuteReadyAsync',
 'ServiceAdministration\.Execute',
 'File\.Move\s*\(',
 'File\.Delete\s*\(',
 'File\.Copy\s*\(',
 'WriteAllBytes\s*\(',
 'WriteAllText\s*\(',
 'Directory\.CreateDirectory\s*\(',
 'Directory\.Delete\s*\('
)) {
 if($recoveryPane -match $pattern){throw "Elevated recovery UI contains a forbidden direct mutation/control primitive '$pattern'"}
}
if(([regex]::Matches($recoveryPane,'ProductionRecoveryExecutionAdministration\.ExecuteCopyOutAsync')).Count -ne 1){
 throw 'Elevated recovery UI must have exactly one reviewed call into the production copy-out boundary.'
}
if($window -match 'ProductionRecoveryExecutionAdministration|ExecuteCopyOutAsync'){
 throw 'Current elevated review window must not expose production copy-out execution before a separately reviewed UI slice.'
}
if($recoveryPane -notmatch 'if \(_preview\)' -or $recoveryPane -notmatch 'Synthetic scene only' -or $recoveryPane -notmatch 'RecoveryReview\.PreviewExecution'){
 throw 'Recovery review preview must remain synthetic-only and branch before production administration/execution calls.'
}
if($recoveryPane -notmatch 'Every execution attempt invalidates the operator-reviewed UI state' -or
   $recoveryPane -notmatch '_currentPlan = null;' -or
   $recoveryPane -notmatch 'ResetExecutionReview\(\)'){
 throw 'Recovery copy-out UI must invalidate the reviewed plan/approval after every execution attempt.'
}
Write-Host 'Elevated recovery UI source gate PASSED: explicit admin intent, synthetic preview, exact reviewed plan/evidence binding, one approved copy-out call, no direct filesystem/service mutation.'


if($window -match 'new AdminWindow\("state-repair"' -or $window -match 'TextBox _confirm') {throw 'Do not nest administrative recovery windows or require command tokens in the GUI.'}
foreach($required in @('SetupReviewPolicy.CanInstall','SetupReviewPolicy.CanReset','SetupReviewPolicy.CanControl','if (_preview) return','StateStoreAdministration.Recover','ServiceAdministration.ReviewInstallInput','IsExpanded = false','_acknowledged = false')) {
 if(-not $wizard.Contains($required)) {throw "Missing guided setup invariant: $required"}
}
Write-Host 'Guided setup source gate: single window, explicit action clicks, separate reset consent, preview cannot mutate, details collapsed.'
