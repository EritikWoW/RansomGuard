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
  'FileIdentityStore',
  'RenameRollbackStore',
  'CaptureOrVerifyAsync',
  'CaptureIntentAsync',
  'CaptureAbsentAsync',
  'CreateGatePolicy.TryParseDisposition',
  '(ev.Flags >> 24) & 0xFF',
  'ev.Flags & 0x00FFFFFF',
  'ProtocolVersion = 5',
  'CreatePreservationAction.CaptureExistingPreimage',
  'CreatePreservationAction.RecordOriginallyAbsent',
  'CreatePreservationAction.DenyUnsupported',
  'CreateGatePolicy.Decide(disposition, state, createOptions)',
  'RgGateDecision.SnapshotCommitted',
  'RgGateDecision.BaselineCommitted',
  'RgGateDecision.NoPreservationRequired',
  'FilterReplyMessage',
  'LAB gate root cannot be an entire drive',
  'LAB gate root must not be inside Windows, Program Files, or ProgramData',
  'PathProbe.Get(path)',
  'ev.PathStatus != (uint)RgPathStatus.Resolved',
  'createStore.WasOriginallyAbsent(path)',
  'RgEventType.Truncate',
  'RgEventType.Create',
  'ev.DestinationPathStatus != (uint)RgPathStatus.Resolved',
  'resolver.Resolve(ev.DestinationPath)',
  'RollbackMutationKind.RenameDestination',
  'RenameDestinationState.OriginallyAbsent',
  'RenameDestinationState.ExistingFile',
  'RenameDestinationState.SameAsSource',
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

$identityCapture=$text.IndexOf('identityStore.CaptureOrVerifyAsync(path')
$writeBranch=$text.IndexOf('if (eventType == RgEventType.Write)')
$writeCapture=$text.IndexOf('CaptureWritePreimageAsync(path',$writeBranch)
if($identityCapture -lt 0 -or $writeBranch -lt 0 -or $writeCapture -lt 0 -or $identityCapture -gt $writeCapture){
  throw 'Existing-file identity must be durably captured/verified before WRITE preservation.'
}
$createIdentity=$text.IndexOf('identityStore.CaptureOrVerifyAsync(path',$existingCase)
if($createIdentity -lt 0 -or $createIdentity -gt $existingCapture){
  throw 'Destructive CREATE must capture/verify file identity before full pre-image capture.'
}

$renameBranch=$text.IndexOf('if (eventType == RgEventType.Rename)')
$renameSourceCapture=$text.IndexOf('CapturePreimageAsync(sourcePath, RollbackMutationKind.Rename',$renameBranch)
$renameIntent=$text.IndexOf('renameStore.CaptureIntentAsync(',$renameSourceCapture)
$renameAllow=$text.IndexOf('RgGateDecision.SnapshotCommitted',$renameIntent)
if($renameBranch -lt 0 -or $renameSourceCapture -lt 0 -or $renameIntent -lt 0 -or $renameAllow -lt 0 -or
   $renameSourceCapture -gt $renameIntent -or $renameIntent -gt $renameAllow){
  throw 'RENAME must preserve source/destination state and durably commit rename intent before allow.'
}

Write-Host 'LAB gate client source check PASSED: explicit disposable root, protocol-v5 CREATE/RENAME semantics, durable FILE_ID_INFO identity binding, range COW for writes, source/destination pre-image preservation, durable rename intents and originally-absent baselines, no destructive/process-control APIs.'
