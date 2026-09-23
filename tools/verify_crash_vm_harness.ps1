$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$gate=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.GateClient\Program.cs') -Raw
$helper=Get-Content -LiteralPath (Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs') -Raw
$harness=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\run_crash_reconciliation_lab.ps1') -Raw
$workflow=Get-Content -LiteralPath (Join-Path $root '.github\workflows\minifilter-crash-vm.yml') -Raw
$unload=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\unload_minifilter_lab.ps1') -Raw

foreach($required in @(
  '--drop-first-create-completion',
  '--drop-first-rename-completion',
  '--drop-first-truncate-completion',
  '--drop-first-delete-completion',
  'LAB COMPLETION LOSS: intentionally dropping authoritative CREATE result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative RENAME result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative TRUNCATE result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative DELETE disposition result',
  'Interlocked.CompareExchange(ref droppedCreateCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedRenameCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedTruncateCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedDeleteCompletion, 1, 0) == 0',
  'Only one completion-loss injection may be armed per GateClient session.',
  'cts.Cancel();',
  'Native.Cancel(port);',
  '--reconcile-only',
  'RECONCILE ONLY: observed=',
  'if (options.ReconcileOnly)',
  'RestartReconciliation.ObservePendingAsync('
)){
  if($gate -notmatch [regex]::Escape($required)){throw "GateClient completion-loss/restart invariant missing: $required"}
}

if($gate -match [regex]::Escape('Environment.FailFast("RansomGuard LAB fault injection: after durable CREATE intent, before kernel reply.")')){
  throw 'Completion-loss test must not hard-crash GateClient while the kernel is waiting for FilterReplyMessage.'
}

$createResult=$gate.IndexOf('if ((RgEventType)ev.EventType == RgEventType.CreateResult)')
$drop=$gate.IndexOf('if (options.DropFirstCreateCompletion',$createResult)
$cancel=$gate.IndexOf('cts.Cancel();',$drop)
$persist=$gate.IndexOf('CreateReconciliation.HandleAsync(',$createResult)
if($createResult -lt 0 -or $drop -lt 0 -or $cancel -lt 0 -or $persist -lt 0 -or
   $createResult -gt $drop -or $drop -gt $cancel -or $cancel -gt $persist){
  throw 'CREATE completion-loss injection must run after receiving CreateResult but before authoritative completion persistence.'
}

$renameResult=$gate.IndexOf('if ((RgEventType)ev.EventType == RgEventType.RenameResult)')
$renameDrop=$gate.IndexOf('if (options.DropFirstRenameCompletion',$renameResult)
$renameCancel=$gate.IndexOf('cts.Cancel();',$renameDrop)
$renamePersist=$gate.IndexOf('RenameReconciliation.HandleAsync(',$renameResult)
if($renameResult -lt 0 -or $renameDrop -lt 0 -or $renameCancel -lt 0 -or $renamePersist -lt 0 -or
   $renameResult -gt $renameDrop -or $renameDrop -gt $renameCancel -or $renameCancel -gt $renamePersist){
  throw 'RENAME completion-loss injection must run after receiving RenameResult but before authoritative completion persistence.'
}

$truncateResult=$gate.IndexOf('if ((RgEventType)ev.EventType == RgEventType.TruncateResult)')
$truncateDrop=$gate.IndexOf('if (options.DropFirstTruncateCompletion',$truncateResult)
$truncateCancel=$gate.IndexOf('cts.Cancel();',$truncateDrop)
$truncatePersist=$gate.IndexOf('TruncateReconciliation.HandleAsync(',$truncateResult)
if($truncateResult -lt 0 -or $truncateDrop -lt 0 -or $truncateCancel -lt 0 -or $truncatePersist -lt 0 -or
   $truncateResult -gt $truncateDrop -or $truncateDrop -gt $truncateCancel -or $truncateCancel -gt $truncatePersist){
  throw 'TRUNCATE completion-loss injection must run after receiving TruncateResult but before authoritative completion persistence.'
}

$deleteResult=$gate.IndexOf('if ((RgEventType)ev.EventType == RgEventType.DeleteDispositionResult)')
$deleteDrop=$gate.IndexOf('if (options.DropFirstDeleteCompletion',$deleteResult)
$deleteCancel=$gate.IndexOf('cts.Cancel();',$deleteDrop)
$deletePersist=$gate.IndexOf('DeleteReconciliation.HandleDispositionAsync(',$deleteResult)
if($deleteResult -lt 0 -or $deleteDrop -lt 0 -or $deleteCancel -lt 0 -or $deletePersist -lt 0 -or
   $deleteResult -gt $deleteDrop -or $deleteDrop -gt $deleteCancel -or $deleteCancel -gt $deletePersist){
  throw 'DELETE completion-loss injection must run after receiving DeleteDispositionResult but before authoritative completion persistence.'
}

$restart=$gate.IndexOf('RestartReconciliation.ObservePendingAsync(')
$reconcileOnly=$gate.IndexOf('if (options.ReconcileOnly)',$restart)
$newSession=$gate.IndexOf('repository.CreateSession(',$reconcileOnly)
if($restart -lt 0 -or $reconcileOnly -lt 0 -or $newSession -lt 0 -or
   $restart -gt $reconcileOnly -or $reconcileOnly -gt $newSession){
  throw 'Reconcile-only must observe pending intents and return before a new rollback session is created.'
}

foreach($required in @(
  'case "create-new":',
  'CreateNewFile(',
  'Require(options, "--file")',
  'OptionalPath(options, "--ready")',
  'OptionalPath(options, "--go")',
  'const uint CreateNew = 1',
  'CreateFileW(CREATE_NEW)',
  'The completion-loss scenario is about CREATE transaction reconciliation only.'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness completion-loss trigger invariant missing: $required"}
}
$createNewStart=$helper.IndexOf('static void CreateNewFile(string filePath, string? readyMarker, string? goMarker)')
$createNewEnd=$helper.IndexOf('static void RenameFile(',$createNewStart)
if($createNewStart -lt 0 -or $createNewEnd -lt 0){throw 'CreateNewFile source block missing.'}
$createNewBlock=$helper.Substring($createNewStart,$createNewEnd-$createNewStart)
if($createNewBlock -match [regex]::Escape('Native.WriteFile')){
  throw 'Completion-loss CREATE trigger must not issue a follow-up WRITE after CREATE_NEW.'
}

foreach($required in @(
  'case "rename-file":',
  'RenameFile(',
  'File.Move(sourcePath, destinationPath, overwrite: false)',
  'rename-file destination must start absent'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness RENAME completion-loss trigger invariant missing: $required"}
}

foreach($required in @(
  'case "truncate-eof":',
  'TruncateEndOfFile(',
  'SetFileInformationByHandle(',
  'FileEndOfFileInfo',
  'readyMarker',
  'goMarker',
  'Timed out waiting for durable CREATE completion before TRUNCATE.',
  'exactly one successful EOF mutation followed by a deliberately lost TruncateResult'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness TRUNCATE completion-loss trigger invariant missing: $required"}
}
$truncateHelperStart=$helper.IndexOf('static void TruncateEndOfFile(string filePath, long length, string readyMarker, string goMarker)')
$truncateHelperEnd=$helper.IndexOf('static void DeleteFileByDisposition(string filePath, string readyMarker, string goMarker)',$truncateHelperStart)
if($truncateHelperStart -lt 0 -or $truncateHelperEnd -lt 0){
  throw 'TruncateEndOfFile source block missing.'
}
$truncateHelperBlock=$helper.Substring($truncateHelperStart,$truncateHelperEnd-$truncateHelperStart)
if($truncateHelperBlock -match [regex]::Escape('Native.WriteFile')){
  throw 'Completion-loss TRUNCATE trigger must not issue a follow-up WRITE after EOF mutation.'
}

foreach($required in @(
  'case "delete-file":',
  'DeleteFileByDisposition(',
  'const uint DeleteAccess = 0x00010000',
  'const int FileDispositionInfo = 4',
  'FileDispositionInfo { DeleteFile = true }',
  'Timed out waiting for durable CREATE completion before DELETE disposition.',
  'SetFileInformationByHandle(FileDispositionInfo) failed',
  'Disposing this exact handle drives IRP_MJ_CLEANUP'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness DELETE completion-loss trigger invariant missing: $required"}
}
$deleteHelperStart=$helper.IndexOf('static void DeleteFileByDisposition(string filePath, string readyMarker, string goMarker)')
$deleteHelperEnd=$helper.IndexOf('static void MapAndWrite(',$deleteHelperStart)
if($deleteHelperStart -lt 0 -or $deleteHelperEnd -lt 0){
  throw 'DeleteFileByDisposition source block missing.'
}
$deleteHelperBlock=$helper.Substring($deleteHelperStart,$deleteHelperEnd-$deleteHelperStart)
if($deleteHelperBlock -match [regex]::Escape('Native.WriteFile')){
  throw 'Completion-loss DELETE trigger must not issue a follow-up WRITE after disposition.'
}
if($deleteHelperBlock -match [regex]::Escape('File.Delete(filePath)')){
  throw 'Completion-loss DELETE trigger must use the exact handle disposition, not a second high-level delete.'
}

foreach($required in @(
  'Assert-DisposableVm',
  'LAB-MINIFILTER',
  "'--drop-first-create-completion'",
  "'create-new'",
  'CREATE_NEW must complete before completion evidence is intentionally dropped',
  'CREATE target must exist because the filesystem operation completed before result loss',
  'create-intent-journal.jsonl',
  'create-completion-journal.jsonl',
  "'--reconcile-only'",
  'completed-evidence=1',
  'restart-reconciliation-journal.jsonl',
  '[int]$restartRecord.evidence -ne 1',
  '[int]$_.kind -eq 4',
  '[int]$transaction[0].state -eq 1',
  '[int]$transaction[0].state -ne 2',
  '[int]$plan.readyCount -ne 0',
  'completionLossObserved',
  'targetCreated',
  'restartSupportsCompleted',
  "'--drop-first-rename-completion'",
  "'rename-file'",
  'RENAME must complete before completion evidence is intentionally dropped',
  'RENAME source still exists even though the filesystem operation completed',
  'rename-state\rename-journal.jsonl',
  'rename-state\rename-completion-journal.jsonl',
  '[int]$renameRestartRecord.operationKind -ne 2',
  '[int]$renameRestartRecord.evidence -ne 1',
  '[int]$renameRestartRecord.sourceState -ne 1',
  '[int]$renameRestartRecord.destinationState -ne 2',
  '[int]$_.kind -eq 5',
  '[int]$renameTopology[0].state -eq 1',
  '[int]$renameTopology[0].state -ne 2',
  'automaticTopologyMutationAllowed',
  'renameCompletionLossObserved',
  'renameIntentDurable',
  'renameCompletionAbsent',
  'renameTopologyChanged',
  'renameRestartObserved',
  'renameRestartSupportsCompleted',
  'renameRecoveryTopologyNotReady',
  "'--drop-first-truncate-completion'",
  "'truncate-eof'",
  'TRUNCATE EOF must complete before completion evidence is intentionally dropped',
  'Wait-File $truncateReady $truncateTrigger 30',
  'Wait-LogPattern $truncateGateOut ''CreateResult\s+request='' $truncateGate 30',
  'Set-Content -LiteralPath $truncateGo -Value ''go''',
  'truncate-state\truncate-intent-journal.jsonl',
  'truncate-state\truncate-completion-journal.jsonl',
  'truncate-state\truncate-restart-journal.jsonl',
  '[int]$truncateRestartRecord.evidence -ne 1',
  '[int]$truncateRestartRecord.pathState -ne 2',
  '[int64]$truncateRestartRecord.observedLength -ne $truncateRequestedLength',
  '[int]$_.kind -eq 6',
  '[int]$truncateTransaction[0].state -eq 1',
  '[int]$truncateTransaction[0].state -ne 2',
  'TRUNCATE must retain exactly one verified Ready full-preimage copy-out action',
  'truncateCompletionLossObserved',
  'truncateIntentDurable',
  'truncateCompletionAbsent',
  'truncateLengthChanged',
  'truncateRestartObserved',
  'truncateRestartSupportsCompleted',
  'truncateRecoveryTransactionNotReady',
  "'--drop-first-delete-completion'",
  "'delete-file'",
  'Wait-File $deleteReady $deleteTrigger 30',
  'Wait-LogPattern $deleteGateOut ''CreateResult\s+request='' $deleteGate 30',
  'Set-Content -LiteralPath $deleteGo -Value ''go''',
  'DELETE disposition must complete before completion evidence is intentionally dropped',
  'DELETE pathname still exists after the disposition handle closed',
  'delete-state\delete-intent-journal.jsonl',
  'delete-state\delete-completion-journal.jsonl',
  'delete-state\delete-finalization-journal.jsonl',
  'Pre-restart DELETE finalization may only be exact-handle CleanupObserved evidence',
  'Restart DELETE evidence must never manufacture an authoritative disposition completion',
  '[int]$_.source -eq 2',
  '[int]$deleteRestartRecord.state -ne 1',
  '[int]$deleteRestartRecord.pathState -ne 1',
  '[int]$_.kind -eq 7',
  '[int]$deleteTransaction[0].state -eq 1',
  '[int]$deleteTransaction[0].state -ne 2',
  'DELETE must retain exactly one verified Ready full-preimage copy-out action',
  'deleteCompletionLossObserved',
  'deleteIntentDurable',
  'deleteCompletionAbsent',
  'deleteTargetRemoved',
  'deleteRestartObserved',
  'deleteRestartSupportsCompleted',
  'deleteRecoveryTransactionNotReady',
  'unload_minifilter_lab.ps1',
  'crash-runtime-result.json'
)){
  if($harness -notmatch [regex]::Escape($required)){throw "Completion-loss runtime harness invariant missing: $required"}
}

foreach($required in @(
  'workflow_dispatch:',
  'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
  'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
  'Checkout exact commit',
  'verify_runtime_runner_readiness.ps1',
  'build_lab.cmd',
  'prepare_runtime_driver_package.ps1',
  'run_crash_reconciliation_lab.ps1',
  'completionLossObserved',
  'createIntentDurable',
  'createCompletionAbsent',
  'targetCreated',
  'restartObserved',
  'restartSupportsCompleted',
  'recoveryTransactionNotReady',
  'renameCompletionLossObserved',
  'renameIntentDurable',
  'renameCompletionAbsent',
  'renameTopologyChanged',
  'renameRestartObserved',
  'renameRestartSupportsCompleted',
  'renameRecoveryTopologyNotReady',
  'truncateCompletionLossObserved',
  'truncateIntentDurable',
  'truncateCompletionAbsent',
  'truncateLengthChanged',
  'truncateRestartObserved',
  'truncateRestartSupportsCompleted',
  'truncateRecoveryTransactionNotReady',
  'deleteCompletionLossObserved',
  'deleteIntentDurable',
  'deleteCompletionAbsent',
  'deleteTargetRemoved',
  'deleteRestartObserved',
  'deleteRestartSupportsCompleted',
  'deleteRecoveryTransactionNotReady',
  'cleanupPassed',
  'Upload completion-loss evidence',
  'Ensure LAB minifilter is unloaded after run'
)){
  if($workflow -notmatch [regex]::Escape($required)){throw "Completion-loss VM workflow invariant missing: $required"}
}

if($workflow -match '(?m)^\s*push\s*:'){
  throw 'Completion-loss VM workflow must remain manual-only; do not consume the reusable self-hosted VM on every branch push.'
}

foreach($required in @(
  'Invoke-FltmcBounded',
  'WaitForExit($NativeTimeoutSeconds*1000)',
  'TIMEOUT: $Description did not return within $NativeTimeoutSeconds seconds',
  'revert the disposable VM checkpoint'
)){
  if($unload -notmatch [regex]::Escape($required)){throw "Bounded unload invariant missing: $required"}
}

if($workflow -notmatch [regex]::Escape('STALE KERNEL STATE: RansomGuardMinifilter is still loaded from an earlier crash/fault run.')){
  throw 'VM startup must fail fast on an already-loaded stale LAB minifilter.'
}

Write-Host 'Completion-loss VM harness source check PASSED: CREATE, RENAME, TRUNCATE and DELETE completed, authoritative results intentionally omitted, restart/finalization evidence remains conservative, live mutation transactions stay non-Ready.'
