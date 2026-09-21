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
  'ProtocolVersion = 9',
  'CreatePreservationAction.CaptureExistingPreimage',
  'CreatePreservationAction.RecordOriginallyAbsent',
  'CreatePreservationAction.DenyUnsupported',
  'CreateGatePolicy.Decide(disposition, observedState, createOptions, ev.Length)',
  'CreateGatePolicy.GenericWrite',
  'CreateGatePolicy.FileWriteData',
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
  'Gate capture failed',
  'SemaphoreSlim(options.GateWorkers, options.GateWorkers)',
  'Task.Run(() => ProcessMessageAsync(header, ev))',
  'DefaultGateWorkers = 4',
  'MaxGateWorkers = 8',
  '--gate-workers',
  'RestartReconciliation.ObservePendingAsync',
  'RestartReconciliationStore',
  'RestartReconciliationClassifier.ClassifyCreate',
  'RestartReconciliationClassifier.ClassifyRename',
  'PathProbe.ObserveForRestart',
  'PagingWriteEvidenceStore',
  'RgEventType.PagingWrite',
  'pagingStore.RecordAsync',
  'evidence-only'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Gate client invariant missing: $required"}
}

if($manifestText -notmatch 'requestedExecutionLevel\s+level="requireAdministrator"'){throw 'Gate client must require explicit administrator elevation.'}
if($text -match '\b(File\.Delete|Directory\.Delete|RestoreToNewCopyAsync|Process\.Kill|NtSuspendProcess|TerminateProcess)\b'){
  throw 'Gate client source contains a destructive/recovery/process-control primitive.'
}

$policyCall=$text.IndexOf('CreateGatePolicy.Decide(disposition, observedState, createOptions, ev.Length)')
if($policyCall -lt 0){throw 'CREATE desired access must participate in preservation policy.'}
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
$resultReturn=$text.IndexOf('return;',$resultPersist)
$resultReply=$text.IndexOf('Native.Reply(',$resultBranch)
if($resultBranch -lt 0 -or $resultPersist -lt 0 -or $resultReturn -lt 0 -or
   ($resultReply -ge 0 -and $resultReply -lt $resultReturn)){
  throw 'RenameResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$pagingBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.PagingWrite)')
$pagingPersist=$text.IndexOf('pagingStore.RecordAsync(',$pagingBranch)
$pagingReturn=$text.IndexOf('return;',$pagingPersist)
$pagingReply=$text.IndexOf('Native.Reply(',$pagingBranch)
if($pagingBranch -lt 0 -or $pagingPersist -lt 0 -or $pagingReturn -lt 0 -or
   ($pagingReply -ge 0 -and $pagingReply -lt $pagingReturn)){
  throw 'PagingWrite must be persisted as evidence only and must not receive FilterReplyMessage.'
}

$createResultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.CreateResult)')
$createResultPersist=$text.IndexOf('CreateReconciliation.HandleAsync(',$createResultBranch)
$createResultReturn=$text.IndexOf('return;',$createResultPersist)
$createResultReply=$text.IndexOf('Native.Reply(',$createResultBranch)
if($createResultBranch -lt 0 -or $createResultPersist -lt 0 -or $createResultReturn -lt 0 -or
   ($createResultReply -ge 0 -and $createResultReply -lt $createResultReturn)){
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

$workerDispatch=$text.IndexOf('Task.Run(() => ProcessMessageAsync(header, ev))')
$workerEvaluate=$text.IndexOf('GateDecision.EvaluateAsync(',$text.IndexOf('async Task ProcessMessageAsync'))
if($workerDispatch -lt 0 -or $workerEvaluate -lt 0){
  throw 'Gate messages must be dispatched through the bounded worker path.'
}
if($text -notmatch 'GateWorkers\s*<\s*1' -or $text -notmatch 'GateWorkers\s*>\s*MaxGateWorkers'){
  throw 'Gate worker argument must remain explicitly bounded.'
}
$verifyBeforeRestart=$text.IndexOf('repository.VerifyAll()')
$restartObserve=$text.IndexOf('RestartReconciliation.ObservePendingAsync(',$verifyBeforeRestart)
$createSession=$text.IndexOf('repository.CreateSession(',$restartObserve)
if($verifyBeforeRestart -lt 0 -or $restartObserve -lt 0 -or $createSession -lt 0 -or
   $verifyBeforeRestart -gt $restartObserve -or $restartObserve -gt $createSession){
  throw 'Pending restart evidence must be observed only after repository validation and before a new session starts.'
}
$restartClassStart=$text.IndexOf('static class RestartReconciliation')
$restartClassEnd=$text.IndexOf('readonly record struct RestartReconciliationSummary',$restartClassStart)
if($restartClassStart -lt 0 -or $restartClassEnd -lt 0){throw 'Restart reconciliation implementation missing.'}
$restartBlock=$text.Substring($restartClassStart,$restartClassEnd-$restartClassStart)
if($restartBlock -match 'RecordCompletionAsync'){
  throw 'Restart reconciliation evidence must never manufacture authoritative CREATE/RENAME completion.'
}
if($restartBlock -notmatch [regex]::Escape('PathPolicy.Under(intent.OriginalPath, currentRoot)') -or
   $restartBlock -notmatch [regex]::Escape('PathPolicy.Under(intent.DestinationPath, currentRoot)')){
  throw 'Restart reconciliation must remain scoped to the explicitly selected LAB root.'
}

Write-Host 'LAB gate client source check PASSED: protocol-v9 CREATE/RENAME gating, eager pre-image for write-capable existing-file opens, bounded workers, durable FILE_ID_INFO binding, restart and paging evidence, range COW, no destructive/process-control APIs.'
