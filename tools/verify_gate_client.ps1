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
  'CreateOperationStore',
  'CreateReconciliation.HandleAsync',
  'CreateCompletionState.Succeeded',
  'CreateCompletionState.SucceededNameUnresolved',
  'CreateCompletionState.SucceededIdentityUnresolved',
  'CreateCompletionState.SucceededNameAndIdentityUnresolved',
  'CreateCompletionState.Failed',
  'RgEventType.CreateResult',
  'RgIdentityStatus.Resolved',
  'FileIdentityStore',
  'RenameRollbackStore',
  'CaptureOrVerifyAsync',
  'CaptureIntentAsync',
  'RecordCompletionAsync',
  'RenameCompletionState.Succeeded',
  'RenameCompletionState.SucceededNameUnresolved',
  'RenameCompletionState.SucceededIdentityUnresolved',
  'RenameCompletionState.SucceededNameAndIdentityUnresolved',
  'RenameCompletionState.Failed',
  'FinalIdentity',
  'RgEventType.RenameResult',
  'ev.RelatedSequence',
  'ev.CompletionStatus',
  'CaptureAbsentAsync',
  'CreateGatePolicy.TryParseDisposition',
  '(ev.Flags >> 24) & 0xFF',
  'ev.Flags & 0x00FFFFFF',
  'ProtocolVersion = 8',
  'CreatePreservationAction.CaptureExistingPreimage',
  'CreatePreservationAction.RecordOriginallyAbsent',
  'CreatePreservationAction.DenyUnsupported',
  'CreateGatePolicy.Decide(disposition, observedState, createOptions)',
  'RgGateDecision.SnapshotCommitted',
  'RgGateDecision.BaselineCommitted',
  'RgGateDecision.NoPreservationRequired',
  'FilterReplyMessage',
  'LAB gate root cannot be an entire drive',
  'LAB gate root must not be inside Windows, Program Files, or ProgramData',
  'PathProbe.Get(path)',
  'ev.PathStatus != (uint)RgPathStatus.Resolved',
  'createStore.TryGetBaseline(path',
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
$existingCapture=$text.IndexOf('RollbackMutationKind.Create',$existingCase)
$createIntentAfterExisting=$text.IndexOf('createOperationStore.RecordIntentAsync(',$existingCapture)
$existingAllow=$text.IndexOf('CreatePreservationAction.CaptureExistingPreimage => Allow',$createIntentAfterExisting)
if($existingCapture -lt 0 -or $createIntentAfterExisting -lt 0 -or $existingAllow -lt 0 -or
   $existingCapture -gt $createIntentAfterExisting -or $createIntentAfterExisting -gt $existingAllow){
  throw 'CREATE SnapshotCommitted must follow durable pre-image capture and durable CREATE intent commit.'
}

$absentCase=$text.IndexOf('case CreatePreservationAction.RecordOriginallyAbsent:')
if($absentCase -lt 0){throw 'Originally-absent CREATE preservation case missing.'}
$absentCapture=$text.IndexOf('CaptureAbsentAsync(path',$absentCase)
$createIntentAfterAbsent=$text.IndexOf('createOperationStore.RecordIntentAsync(',$absentCapture)
$absentAllow=$text.IndexOf('CreatePreservationAction.RecordOriginallyAbsent => Allow',$createIntentAfterAbsent)
if($absentCapture -lt 0 -or $createIntentAfterAbsent -lt 0 -or $absentAllow -lt 0 -or
   $absentCapture -gt $createIntentAfterAbsent -or $createIntentAfterAbsent -gt $absentAllow){
  throw 'CREATE BaselineCommitted must follow durable absence-baseline capture and durable CREATE intent commit.'
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

$resultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.RenameResult)')
$resultPersist=$text.IndexOf('RenameReconciliation.HandleAsync(',$resultBranch)
$resultContinue=$text.IndexOf('continue;',$resultPersist)
$resultReply=$text.IndexOf('Native.Reply(',$resultBranch)
if($resultBranch -lt 0 -or $resultPersist -lt 0 -or $resultContinue -lt 0 -or
   ($resultReply -ge 0 -and $resultReply -lt $resultContinue)){
  throw 'RenameResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$createResultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.CreateResult)')
$createResultPersist=$text.IndexOf('CreateReconciliation.HandleAsync(',$createResultBranch)
$createResultContinue=$text.IndexOf('continue;',$createResultPersist)
$createResultReply=$text.IndexOf('Native.Reply(',$createResultBranch)
if($createResultBranch -lt 0 -or $createResultPersist -lt 0 -or $createResultContinue -lt 0 -or
   ($createResultReply -ge 0 -and $createResultReply -lt $createResultContinue)){
  throw 'CreateResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$createEvaluate=$text.IndexOf('private static async Task<RgGateReply> EvaluateCreateAsync')
$createIntent=$text.IndexOf('createOperationStore.RecordIntentAsync(',$createEvaluate)
$createReturn=$text.IndexOf('return action switch',$createIntent)
if($createEvaluate -lt 0 -or $createIntent -lt 0 -or $createReturn -lt 0 -or $createIntent -gt $createReturn){
  throw 'CREATE intent must be durably committed before any allow decision is returned.'
}

$renameBranch=$text.IndexOf('if (eventType == RgEventType.Rename)')
$renameSourceCapture=$text.IndexOf('CapturePreimageAsync(sourcePath, RollbackMutationKind.Rename',$renameBranch)
$renameIntent=$text.IndexOf('renameStore.CaptureIntentAsync(',$renameSourceCapture)
$renameAllow=$text.IndexOf('RgGateDecision.SnapshotCommitted',$renameIntent)
if($renameBranch -lt 0 -or $renameSourceCapture -lt 0 -or $renameIntent -lt 0 -or $renameAllow -lt 0 -or
   $renameSourceCapture -gt $renameIntent -or $renameIntent -gt $renameAllow){
  throw 'RENAME must preserve source/destination state and durably commit rename intent before allow.'
}

Write-Host 'LAB gate client source check PASSED: explicit disposable root, protocol-v8 CREATE/RENAME semantics with post-rename kernel identity, durable FILE_ID_INFO identity binding, range COW for writes, durable CREATE/RENAME intents and completions, originally-absent baselines, no destructive/process-control APIs.'
