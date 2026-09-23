$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$budget=Join-Path $root 'src\RansomGuard.Rollback\RollbackStorageBudget.cs'
$store=Join-Path $root 'src\RansomGuard.Rollback\RollbackStore.cs'
$gate=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'
$tests=Join-Path $root 'tests\RansomGuard.Rollback.Tests\Program.cs'

foreach($path in @($budget,$store,$gate,$tests)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Rollback storage budget source missing: $path"}
}

$budgetText=Get-Content -LiteralPath $budget -Raw
foreach($required in @(
    'RollbackStorageBudget',
    'MaxSessionBytes',
    'MinFreeBytes',
    'ReservedBytes',
    'ReserveAsync',
    'MeasureDirectoryBytes',
    'DriveInfo',
    'AvailableFreeSpace',
    'RollbackStorageBudgetExceededException',
    'EstimateFullPreimageBytes',
    'EstimateRangeCaptureBytes',
    'EstimateOriginallyAbsentBytes',
    'Rollback storage budget refuses reparse-point paths',
    '_reservedBytes = checked(_reservedBytes + estimatedBytes)',
    '_reservedBytes -= reservedBytes'
)){
    if($budgetText -notmatch [regex]::Escape($required)){throw "Storage budget invariant missing: $required"}
}
if($budgetText -match '(?i)unlimited|ignore.?quota|disable.?budget|bypass.?budget'){
    throw 'Storage budget source must not expose an unlimited/bypass mode.'
}

$storeText=Get-Content -LiteralPath $store -Raw
if($storeText -notmatch [regex]::Escape('public bool TryGetCapture(string path')){
    throw 'RollbackStore must expose committed-capture lookup so repeated operations do not reserve full file size again.'
}

$gateText=Get-Content -LiteralPath $gate -Raw
foreach($required in @(
    'DefaultMaxStoreMiB = 8192',
    'DefaultMinFreeMiB = 2048',
    '--max-store-mib',
    '--min-free-mib',
    'minFreeMiB < 64',
    '--min-free-mib must be between 64 and',
    'new RollbackStorageBudget(',
    'Rollback budget      : max-session=',
    'RollbackStorageBudget.MetadataReservationBytes',
    'EstimateRangeCaptureBytes',
    'EstimateFullPreimageBytes',
    'EstimateOriginallyAbsentBytes',
    'RollbackStorageBudgetExceededException',
    'return Deny(ev.Sequence, 13)',
    'activation-topology-root',
    'activation-topology-directory',
    'activation-file-evidence',
    'writable-section-evidence',
    'paging-write-evidence',
    'create-completion-evidence',
    'rename-completion-evidence',
    'truncate-completion-evidence',
    'restart-create-evidence',
    'restart-rename-evidence',
    'restart-truncate-evidence',
    'truncate-full-preimage',
    'gate-event:'
)){
    if($gateText -notmatch [regex]::Escape($required)){throw "Gate storage-budget invariant missing: $required"}
}
if($gateText -match '(?i)--(disable|ignore|bypass).*(budget|quota|free)'){
    throw 'GateClient must not expose a runtime switch that bypasses rollback storage admission.'
}

$evaluateStart=$gateText.IndexOf('public static async Task<RgGateReply> EvaluateAsync')
$evaluateEnd=$gateText.IndexOf('private static async Task<RgGateReply> EvaluateRenameAsync',$evaluateStart)
if($evaluateStart -lt 0 -or $evaluateEnd -lt 0){throw 'GateDecision EvaluateAsync source block missing.'}
$evaluate=$gateText.Substring($evaluateStart,$evaluateEnd-$evaluateStart)
if($evaluate -notmatch [regex]::Escape('truncateStore.RecordIntentAsync(')){
    throw 'TRUNCATE intent must remain inside the blocking gate storage-admission scope.'
}
$reserve=$evaluate.IndexOf('storageBudget.ReserveAsync(')
$writeCapture=$evaluate.IndexOf('writeStore.CaptureWritePreimageAsync(')
$fullCapture=$evaluate.IndexOf('store.CapturePreimageAsync(')
if($reserve -lt 0 -or $writeCapture -lt 0 -or $fullCapture -lt 0 -or
   $reserve -gt $writeCapture -or $reserve -gt $fullCapture){
    throw 'Blocking gate events must reserve storage before WRITE/full-preimage capture.'
}

$testText=Get-Content -LiteralPath $tests -Raw
foreach($required in @(
    'first-concurrent-reservation',
    'second-concurrent-reservation',
    'storage budget includes in-flight reservations in session quota',
    'storage budget re-measures committed session bytes before admission',
    'full pre-image estimator does not reserve an already committed capture',
    'range estimator does not reserve an already committed block/baseline',
    'absence estimator does not reserve an existing baseline again'
)){
    if($testText -notmatch [regex]::Escape($required)){throw "Storage budget test invariant missing: $required"}
}

Write-Host 'Rollback storage budget source gate PASSED: bounded session quota, free-space reserve, concurrent reservations, reparse refusal, fail-closed gate admission and no bypass switch.' -ForegroundColor Green
