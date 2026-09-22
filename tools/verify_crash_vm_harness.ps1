$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$gate=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.GateClient\Program.cs') -Raw
$helper=Get-Content -LiteralPath (Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs') -Raw
$harness=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\run_crash_reconciliation_lab.ps1') -Raw
$workflow=Get-Content -LiteralPath (Join-Path $root '.github\workflows\minifilter-crash-vm.yml') -Raw
$unload=Get-Content -LiteralPath (Join-Path $root 'minifilter-tools\unload_minifilter_lab.ps1') -Raw

foreach($required in @(
  '--fault-after-create-intent',
  'Environment.FailFast("RansomGuard LAB fault injection: after durable CREATE intent, before kernel reply.")',
  '--reconcile-only',
  'RECONCILE ONLY: observed=',
  'if (options.ReconcileOnly)',
  'RestartReconciliation.ObservePendingAsync('
)){
  if($gate -notmatch [regex]::Escape($required)){throw "GateClient crash/restart invariant missing: $required"}
}

$eval=$gate.IndexOf('var reply = await GateDecision.EvaluateAsync(')
$fault=$gate.IndexOf('if (options.FaultAfterCreateIntent',$eval)
$failFast=$gate.IndexOf('Environment.FailFast("RansomGuard LAB fault injection: after durable CREATE intent, before kernel reply.")',$fault)
$reply=$gate.IndexOf('Native.Reply(port, header.MessageId, reply)',$failFast)
if($eval -lt 0 -or $fault -lt 0 -or $failFast -lt 0 -or $reply -lt 0 -or
   $eval -gt $fault -or $fault -gt $failFast -or $failFast -gt $reply){
  throw 'CREATE intent crash point must remain after preservation decision/intent commit and before FilterReplyMessage.'
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
  'Native.WriteFile'
)){
  if($helper -notmatch [regex]::Escape($required)){throw "RuntimeHarness crash trigger invariant missing: $required"}
}

foreach($required in @(
  'Assert-DisposableVm',
  'LAB-MINIFILTER',
  "'--fault-after-create-intent'",
  "'create-new'",
  'GateClient did not prove the intended crash point',
  'CREATE target exists even though crash occurred before kernel reply',
  'create-intent-journal.jsonl',
  'create-completion-journal.jsonl',
  "'--reconcile-only'",
  'not-completed-evidence=1',
  'restart-reconciliation-journal.jsonl',
  '[int]$restartRecord.evidence -ne 2',
  '[int]$_.kind -eq 4',
  '[int]$transaction[0].state -eq 1',
  '[int]$transaction[0].state -ne 2',
  '[int]$plan.readyCount -ne 0',
  'unload_minifilter_lab.ps1',
  'crash-runtime-result.json'
)){
  if($harness -notmatch [regex]::Escape($required)){throw "Crash runtime harness invariant missing: $required"}
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
  'gateCrashObserved',
  'createIntentDurable',
  'createCompletionAbsent',
  'targetRemainedAbsent',
  'restartObserved',
  'restartSupportsNotCompleted',
  'recoveryTransactionNotReady',
  'cleanupPassed',
  'Upload crash evidence',
  'Ensure LAB minifilter is unloaded after run'
)){
  if($workflow -notmatch [regex]::Escape($required)){throw "Crash VM workflow invariant missing: $required"}
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
  throw 'Crash VM startup must fail fast on an already-loaded stale LAB minifilter instead of attempting an unbounded cleanup.'
}
if($workflow -match [regex]::Escape("Write-Warning 'Removing RansomGuardMinifilter left loaded by a prior failed LAB run.'")){
  throw 'Crash VM startup must not attempt to unload an unknown stale driver generation.'
}

Write-Host 'Crash/fault VM harness source check PASSED: durable CREATE intent crash, exact absent-path restart evidence, recovery transaction remains non-Ready.'
