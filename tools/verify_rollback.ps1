$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$store=Join-Path $root 'src\RansomGuard.Rollback\RollbackStore.cs'
$program=Join-Path $root 'src\RansomGuard.Service\Program.cs'
$rangeStore=Join-Path $root 'src\RansomGuard.Rollback\RangeRollbackStore.cs'
$createStore=Join-Path $root 'src\RansomGuard.Rollback\CreateRollbackStore.cs'
$createPolicy=Join-Path $root 'src\RansomGuard.Rollback\CreateGatePolicy.cs'
if(-not(Test-Path -LiteralPath $rangeStore)){throw 'RangeRollbackStore.cs missing.'}
if(-not(Test-Path -LiteralPath $createStore)){throw 'CreateRollbackStore.cs missing.'}
if(-not(Test-Path -LiteralPath $createPolicy)){throw 'CreateGatePolicy.cs missing.'}
$rangeText=Get-Content -LiteralPath $rangeStore -Raw
foreach($required in @(
    'CaptureWritePreimageAsync',
    'DefaultBlockSize',
    'RangeJournalKind.Baseline',
    'RangeJournalKind.Block',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'RestoreToNewCopyAsync',
    'output.SetLength(baseline.OriginalLength)',
    'Range rollback block SHA-256 mismatch',
    'Unjournaled range rollback object found',
    'Incomplete range rollback temp artifact found',
    'Range rollback block does not match the original file geometry'
)){
    if($rangeText -notmatch [regex]::Escape($required)){throw "Range rollback source gate missing invariant: $required"}
}
if($rangeText -match 'File\.Move\(temp,\s*full' -or $rangeText -match 'File\.WriteAllBytes\([^,]*damagedPath'){
    throw 'Range rollback source gate FAILED: recovery must not overwrite the damaged source.'
}

$createText=Get-Content -LiteralPath $createStore -Raw
foreach($required in @(
    'CaptureAbsentAsync',
    'WasOriginallyAbsent',
    'create-journal.jsonl',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Create rollback journal hash chain mismatch',
    'Cannot record an originally-absent baseline because the target exists'
)){
    if($createText -notmatch [regex]::Escape($required)){throw "Create rollback source gate missing invariant: $required"}
}
if($createText -match 'File\.Delete\(' -or $createText -match 'Directory\.Delete\('){
    throw 'Create rollback source gate FAILED: absence baseline store must not delete created data.'
}
$policyText=Get-Content -LiteralPath $createPolicy -Raw
foreach($required in @(
    'CreatePreservationAction.CaptureExistingPreimage',
    'CreatePreservationAction.RecordOriginallyAbsent',
    'CreateDisposition.Supersede',
    'CreateDisposition.Overwrite',
    'CreateDisposition.OverwriteIf',
    'CreateDisposition.OpenIf'
)){
    if($policyText -notmatch [regex]::Escape($required)){throw "Create gate policy missing invariant: $required"}
}

if(-not(Test-Path -LiteralPath $store)){throw 'RollbackStore.cs missing.'}
$text=Get-Content -LiteralPath $store -Raw
foreach($required in @(
    'FileOptions.WriteThrough',
    'Flush(true)',
    'FileMode.CreateNew',
    'OriginalSha256',
    'PreviousRecordSha256',
    'RecordSha256',
    'RestoreToNewCopyAsync',
    'Rollback pre-image hash mismatch',
    'Recovery output already exists',
    'Committed rollback object SHA-256 mismatch',
    'Unjournaled rollback object found',
    'Incomplete rollback temp artifact found'
)){
    if($text -notmatch [regex]::Escape($required)){throw "Rollback source gate missing invariant: $required"}
}
if($text -match 'File\.Move\(temp,\s*capture\.OriginalPath' -or $text -match 'File\.WriteAllBytes\([^,]*OriginalPath'){
    throw 'Rollback source gate FAILED: recovery must not overwrite the original path.'
}
$service=Get-Content -LiteralPath $program -Raw
if($service -notmatch 'rollbackRepository\.VerifyAll\(\)'){throw 'Service must validate the rollback repository before monitoring starts.'}
if($service -match 'CapturePreimageAsync\('){throw 'Normal service must not claim automatic pre-image capture before the minifilter write gate is validated.'}
$gate=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.GateClient\Program.cs') -Raw
if($gate -notmatch 'repository\.VerifyAll\(\)'){throw 'LAB gate must validate all existing rollback sessions before starting a new session.'}
$repository=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Rollback\RollbackRepository.cs') -Raw
if($repository -notmatch 'new RangeRollbackStore\(rangeRoot\)\.VerifyAll\(\)'){throw 'Repository verification must include nested write-cow stores.'}
if($repository -notmatch 'new CreateRollbackStore\(createRoot\)\.VerifyAll\(\)'){throw 'Repository verification must include nested create-state stores.'}
Write-Host 'Rollback source gate PASSED: full-file, range-COW and originally-absent create journals, hashes, crash-artifact rejection, write-through commits, first-state semantics, copy-only restore.'
Write-Host 'Normal service capture remains disabled; v0.7.3 keeps blocking preservation inside the explicit LAB gate only.'
