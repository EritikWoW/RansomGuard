$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$program=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'
$manifest=Join-Path $root 'src\RansomGuard.GateClient\app.manifest'
if(-not(Test-Path -LiteralPath $program) -or -not(Test-Path -LiteralPath $manifest)){throw 'Gate client source/manifest missing.'}
$text=Get-Content -LiteralPath $program -Raw
$manifestText=Get-Content -LiteralPath $manifest -Raw
foreach($required in @(
  'RANSOMGUARD-LAB-GATE-V1',
  'CapturePreimageAsync',
  'CaptureWritePreimageAsync',
  'SnapshotCommitted',
  'FilterReplyMessage',
  'LAB gate root cannot be an entire drive',
  'LAB gate root must not be inside Windows, Program Files, or ProgramData',
  'File.Exists(path)',
  'RgEventType.Truncate',
  'ev.ByteOffset < 0',
  'Gate capture failed'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Gate client invariant missing: $required"}
}
if($manifestText -notmatch 'requestedExecutionLevel\s+level="requireAdministrator"'){throw 'Gate client must require explicit administrator elevation.'}
if($text -match '\b(File\.Delete|Directory\.Delete|RestoreToNewCopyAsync|Process\.Kill|NtSuspendProcess|TerminateProcess)\b'){
  throw 'Gate client source contains a destructive/recovery/process-control primitive.'
}
$captureIndex=$text.IndexOf('CapturePreimageAsync')
$allowIndex=$text.IndexOf('Decision = RgGateDecision.SnapshotCommitted')
if($captureIndex -lt 0 -or $allowIndex -lt 0 -or $allowIndex -lt $captureIndex){throw 'SnapshotCommitted must be produced only after durable pre-image capture code.'}
Write-Host 'LAB gate client source check PASSED: explicit disposable root, range COW for writes, full pre-image for metadata-destructive operations, no destructive/process-control APIs.'
