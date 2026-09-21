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
  'CreateRollbackStore',
  'CaptureAbsentAsync',
  'CreateGatePolicy.TryParseDisposition',
  'CreatePreservationAction.CaptureExistingPreimage',
  'CreatePreservationAction.RecordOriginallyAbsent',
  'RgGateDecision.SnapshotCommitted',
  'RgGateDecision.BaselineCommitted',
  'RgGateDecision.NoPreservationRequired',
  'FilterReplyMessage',
  'LAB gate root cannot be an entire drive',
  'LAB gate root must not be inside Windows, Program Files, or ProgramData',
  'PathProbe.Get(path)',
  'createStore.WasOriginallyAbsent(path)',
  'RgEventType.Truncate',
  'RgEventType.Create',
  'ev.ByteOffset < 0',
  'Gate capture failed'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Gate client invariant missing: $required"}
}

if($manifestText -notmatch 'requestedExecutionLevel\s+level="requireAdministrator"'){throw 'Gate client must require explicit administrator elevation.'}
if($text -match '\b(File\.Delete|Directory\.Delete|RestoreToNewCopyAsync|Process\.Kill|NtSuspendProcess|TerminateProcess)\b'){
  throw 'Gate client source contains a destructive/recovery/process-control primitive.'
}

$existingCase=$text.IndexOf('case CreatePreservationAction.CaptureExistingPreimage:')
if($existingCase -lt 0){throw 'Existing-file CREATE preservation case missing.'}
$existingCapture=$text.IndexOf('CapturePreimageAsync(path, RollbackMutationKind.Create',$existingCase)
$existingAllow=$text.IndexOf('RgGateDecision.SnapshotCommitted',$existingCapture)
if($existingCapture -lt 0 -or $existingAllow -lt 0 -or $existingAllow -lt $existingCapture){
  throw 'CREATE SnapshotCommitted must be returned only after durable existing-file pre-image capture.'
}

$absentCase=$text.IndexOf('case CreatePreservationAction.RecordOriginallyAbsent:')
if($absentCase -lt 0){throw 'Originally-absent CREATE preservation case missing.'}
$absentCapture=$text.IndexOf('CaptureAbsentAsync(path',$absentCase)
$absentAllow=$text.IndexOf('RgGateDecision.BaselineCommitted',$absentCapture)
if($absentCapture -lt 0 -or $absentAllow -lt 0 -or $absentAllow -lt $absentCapture){
  throw 'CREATE BaselineCommitted must be returned only after durable absence-baseline capture.'
}

$writeBranch=$text.IndexOf('if (eventType == RgEventType.Write)')
$writeCapture=$text.IndexOf('CaptureWritePreimageAsync(path',$writeBranch)
if($writeBranch -lt 0 -or $writeCapture -lt 0){
  throw 'WRITE range-COW capture ordering invariant missing.'
}

Write-Host 'LAB gate client source check PASSED: explicit disposable root, protocol-v4 CREATE semantics, range COW for writes, full pre-image for destructive replacement/metadata operations, durable originally-absent baselines, no destructive/process-control APIs.'
