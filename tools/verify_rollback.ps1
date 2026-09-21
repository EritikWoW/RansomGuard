$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$store=Join-Path $root 'src\RansomGuard.Rollback\RollbackStore.cs'
$program=Join-Path $root 'src\RansomGuard.Service\Program.cs'
$rangeStore=Join-Path $root 'src\RansomGuard.Rollback\RangeRollbackStore.cs'
if(-not(Test-Path -LiteralPath $rangeStore)){throw 'RangeRollbackStore.cs missing.'}
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
    'Unjournaled range rollback object found'
)){
    if($rangeText -notmatch [regex]::Escape($required)){throw "Range rollback source gate missing invariant: $required"}
}
if($rangeText -match 'File\.Move\(temp,\s*full' -or $rangeText -match 'File\.WriteAllBytes\([^,]*damagedPath'){
    throw 'Range rollback source gate FAILED: recovery must not overwrite the damaged source.'
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
    'existing recovery output'
)){
    if($text -notmatch [regex]::Escape($required)){throw "Rollback source gate missing invariant: $required"}
}
if($text -match 'File\.Move\(temp,\s*capture\.OriginalPath' -or $text -match 'File\.WriteAllBytes\([^,]*OriginalPath'){
    throw 'Rollback source gate FAILED: recovery must not overwrite the original path.'
}
$service=Get-Content -LiteralPath $program -Raw
if($service -notmatch 'rollbackRepository\.VerifyAll\(\)'){throw 'Service must validate the rollback repository before monitoring starts.'}
if($service -match 'CapturePreimageAsync\('){throw 'Normal service must not claim automatic pre-image capture before the minifilter write gate is validated.'}
Write-Host 'Rollback source gate PASSED: full-file and range-aware COW journals, write-through commits, first-preimage semantics, copy-only restore.'
Write-Host 'Normal service capture remains disabled; v0.7.2 keeps blocking COW inside the explicit LAB gate only.'
