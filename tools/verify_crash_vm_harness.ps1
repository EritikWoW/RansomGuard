$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$gate=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.GateClient\Program.cs') -Raw
$helper=Get-Content -LiteralPath (Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs') -Raw
$harness=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\run_crash_reconciliation_lab.ps1') -Raw
$workflow=Get-Content -LiteralPath (Join-Path $root '.github\workflows\minifilter-crash-vm.yml') -Raw
$unload=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\unload_minifilter_lab.ps1') -Raw

foreach($required in @(
  '--drop-first-create-completion',
  'LAB COMPLETION LOSS: intentionally dropping authoritative CREATE result',
  'Interlocked.CompareExchange(ref droppedCreateCompletion, 1, 0) == 0',
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

$restart=$gate.IndexOf('RestartReconciliation.ObservePendingAsync(')
$reconcileOnly=$gate.IndexOf('if (options.ReconcileOnly)',$restart)
$newSession=$gate.IndexOf('repository.CreateSession(',$reconcileOnly)
if($restart -lt 0 -or $reconcileOnly -lt 0 -or $newSession -lt 0 -or
   $restart -gt $reconcileOnly -or $reconcileOnly -gt $newSession){
  throw 'Reconcile-only must observe pending intents and return before a new rollback session is created.'
}

foreach($required in @(
  'case "create-new":',
  'CreateNewFile(Require(options, "--file"))',
  'const uint CreateNew = 1',
  'CreateFileW(CREATE_NEW)',
  'The completion-loss scenario is about CREATE transaction reconciliation only.'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness completion-loss trigger invariant missing: $required"}
}
$createNewStart=$helper.IndexOf('static void CreateNewFile(string filePath)')
$createNewEnd=$helper.IndexOf('static void MapAndWrite(string filePath)',$createNewStart)
if($createNewStart -lt 0 -or $createNewEnd -lt 0){throw 'CreateNewFile source block missing.'}
$createNewBlock=$helper.Substring($createNewStart,$createNewEnd-$createNewStart)
if($createNewBlock -match [regex]::Escape('Native.WriteFile')){
  throw 'Completion-loss CREATE trigger must not issue a follow-up WRITE after CREATE_NEW.'
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
  'cleanupPassed',
  'Upload crash evidence',
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

Write-Host 'Completion-loss VM harness source check PASSED: CREATE completed, authoritative result intentionally omitted, restart evidence supports completion, recovery transaction remains non-Ready.'
