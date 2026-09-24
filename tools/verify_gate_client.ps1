$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$program=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'
$manifest=Join-Path $root 'src\RansomGuard.GateClient\app.manifest'
$fileIdentity=Join-Path $root 'src\RansomGuard.Rollback\FileIdentityStore.cs'
if(-not(Test-Path -LiteralPath $program) -or
   -not(Test-Path -LiteralPath $manifest) -or
   -not(Test-Path -LiteralPath $fileIdentity)){
  throw 'Gate client source/manifest/file-identity source missing.'
}
$text=Get-Content -LiteralPath $program -Raw
$manifestText=Get-Content -LiteralPath $manifest -Raw
$fileIdentityText=Get-Content -LiteralPath $fileIdentity -Raw

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
  'TruncateOperationStore',
  'TruncateReconciliation.HandleAsync',
  'TruncateCompletionState.Succeeded',
  'TruncateCompletionState.Failed',
  'RgEventType.TruncateResult',
  'FileIdentityStore.QueryPathStandardInfo',
  'truncateStore.RecordIntentAsync',
  'pendingTruncateCount',
  'DeleteOperationStore',
  'DeleteReconciliation.HandleDispositionAsync',
  'DeleteReconciliation.HandleFinalizationAsync',
  'DeleteReconciliation.ObserveTopologyAsync',
  'DeleteDispositionCompletionState.AcceptedDeletePending',
  'DeleteFinalizationState.CleanupObserved',
  'DeleteFinalizationSource.LivePostCleanupProbe',
  'RgEventType.DeleteDispositionResult',
  'RgEventType.DeleteFinalized',
  'deleteStore.RecordIntentAsync',
  'unsettledDeleteCount',
  'ev.RelatedSequence',
  'ev.CompletionStatus',
  'CaptureAbsentAsync',
  'CreateGatePolicy.TryParseDisposition',
  '(ev.Flags >> 24) & 0xFF',
  'ev.Flags & 0x00FFFFFF',
  'public const uint Version = 18;',
  'ProtocolVersion = ProtocolContract.Version',
  'ProductionGate = 3',
  '--production',
  'GateProfile.Production',
  'ProductionGate forbids LAB prepare/fault/reconciliation/shutdown/containment options.',
  'ProductionGate rollback store is fixed to',
  'Environment.SpecialFolder.CommonApplicationData',
  'ProductionRootPolicy.Validate(options.Root)',
  'ProductionGate root/ancestor cannot be a reparse point',
  'ProductionGate root must not be inside Windows, Program Files, or ProgramData',
  'DevicePathResolver.ToNtScope(options.Root)',
  'GateVolumeLengthBytes = checked((uint)(ntVolume.Length * 2))',
  'public uint GateRootLengthBytes, GateVolumeLengthBytes;',
  'CreatePreservationAction.CaptureExistingPreimage',
  'CreatePreservationAction.RecordOriginallyAbsent',
  'CreatePreservationAction.DenyUnsupported',
  'CreateGatePolicy.Decide(disposition, observedState, createOptions, ev.Length)',
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
  'evidence-only',
  'WritableSectionEvidenceStore',
  'RgEventType.WritableSection',
  'WritableSectionAttestation.Evaluate',
  'sectionStore.RecordAsync',
  'BaselineVerified',
  'ActivationPreflight.RunAsync',
  'ActivationPreflightStore',
  'ActivationTopologyStore',
  'Native.OpenPreflight',
  'Native.OpenPreflightDirectory',
  'Directory.EnumerateDirectories',
  'FileFlagBackupSemantics',
  'DirectoriesHeld',
  'Native.Control',
  'RgControlCommand.ActivateGate',
  'RgControlCommand.ActivateAndContainProcess',
  'RgControlCommand.DeactivateGate',
  'RgControlCommand.ArmScopeAmbiguity',
  '--scope-ambiguity-pid',
  'LAB scope ambiguity : ARMED for exact kernel process pid=',
  'ScopeAmbiguityPid',
  'RgProtectionState.Protected',
  'RgProtectionState.Maintenance',
  'ProtectionState',
  'cleanShutdown',
  '--contain-pid',
  '--drop-first-create-completion',
  '--drop-first-rename-completion',
  '--drop-first-truncate-completion',
  '--drop-first-delete-completion',
  '--reconcile-only',
  'RECONCILE ONLY: observed=',
  'LAB COMPLETION LOSS: intentionally dropping authoritative CREATE result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative RENAME result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative TRUNCATE result',
  'LAB COMPLETION LOSS: intentionally dropping authoritative DELETE disposition result',
  'Interlocked.CompareExchange(ref droppedCreateCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedRenameCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedTruncateCompletion, 1, 0) == 0',
  'Interlocked.CompareExchange(ref droppedDeleteCompletion, 1, 0) == 0',
  'Only one completion-loss injection may be armed per GateClient session.',
  'TargetProcessId = containPid ?? 0',
  'ContainmentActive',
  'ContainedProcessId',
  'ContainmentEvidenceStore',
  'RgEventType.ContainmentActivated',
  'RgGateReplyFlags.ContainRequestor',
  'LabContainmentTrigger',
  '--contain-after-pid',
  'RecordRequestAsync',
  'RecordKernelActiveAsync',
  'pendingContainmentAckCount',
  'FilterSendMessage',
  'RgEventType.ActivationPreflight',
  'Activation refused:'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Gate client invariant missing: $required"}
}

foreach($required in @(
  'private const int FileStandardInfo = 1;',
  'public byte DeletePending;',
  'public byte Directory;',
  'QueryHandleStandardInfo(',
  'GetFileInformationByHandleExStandard('
)){
  if($fileIdentityText -notmatch [regex]::Escape($required)){
    throw "FILE_STANDARD_INFO interop invariant missing: $required"
  }
}
if($fileIdentityText -match '\[MarshalAs\(UnmanagedType\.Bool\)\]\s*public\s+bool\s+(DeletePending|Directory)'){
  throw 'FILE_STANDARD_INFO uses one-byte BOOLEAN fields, not Win32 BOOL marshaling.'
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

if($text -notmatch [regex]::Escape('CreateGatePolicy.Decide(disposition, observedState, createOptions, ev.Length)')){
  throw 'CREATE preservation policy must receive the kernel DesiredAccess field.'
}

$resultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.RenameResult)')
$resultPersist=$text.IndexOf('RenameReconciliation.HandleAsync(',$resultBranch)
$resultReturn=$text.IndexOf('return;',$resultPersist)
$resultReply=$text.IndexOf('Native.Reply(',$resultBranch)
if($resultBranch -lt 0 -or $resultPersist -lt 0 -or $resultReturn -lt 0 -or
   ($resultReply -ge 0 -and $resultReply -lt $resultReturn)){
  throw 'RenameResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$truncateResultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.TruncateResult)')
$truncateResultPersist=$text.IndexOf('TruncateReconciliation.HandleAsync(',$truncateResultBranch)
$truncateResultReturn=$text.IndexOf('return;',$truncateResultPersist)
$truncateResultReply=$text.IndexOf('Native.Reply(',$truncateResultBranch)
if($truncateResultBranch -lt 0 -or $truncateResultPersist -lt 0 -or $truncateResultReturn -lt 0 -or
   ($truncateResultReply -ge 0 -and $truncateResultReply -lt $truncateResultReturn)){
  throw 'TruncateResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$deleteResultBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.DeleteDispositionResult)')
$deleteResultPersist=$text.IndexOf('DeleteReconciliation.HandleDispositionAsync(',$deleteResultBranch)
$deleteResultReturn=$text.IndexOf('return;',$deleteResultPersist)
$deleteResultReply=$text.IndexOf('Native.Reply(',$deleteResultBranch)
if($deleteResultBranch -lt 0 -or $deleteResultPersist -lt 0 -or $deleteResultReturn -lt 0 -or
   ($deleteResultReply -ge 0 -and $deleteResultReply -lt $deleteResultReturn)){
  throw 'DeleteDispositionResult must be persisted as completion metadata and must not receive FilterReplyMessage.'
}

$deleteFinalBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.DeleteFinalized)')
$deleteCleanupPersist=$text.IndexOf('DeleteReconciliation.HandleFinalizationAsync(',$deleteFinalBranch)
$deleteDelay=$text.IndexOf('Task.Delay(100, cts.Token)',$deleteCleanupPersist)
$deleteLivePersist=$text.IndexOf('DeleteReconciliation.ObserveTopologyAsync(',$deleteDelay)
$deleteFinalReturn=$text.IndexOf('return;',$deleteLivePersist)
$deleteFinalReply=$text.IndexOf('Native.Reply(',$deleteFinalBranch)
if($deleteFinalBranch -lt 0 -or $deleteCleanupPersist -lt 0 -or $deleteDelay -lt 0 -or
   $deleteLivePersist -lt 0 -or $deleteFinalReturn -lt 0 -or
   $deleteFinalBranch -gt $deleteCleanupPersist -or $deleteCleanupPersist -gt $deleteDelay -or
   $deleteDelay -gt $deleteLivePersist -or
   ($deleteFinalReply -ge 0 -and $deleteFinalReply -lt $deleteFinalReturn)){
  throw 'DeleteFinalized must persist cleanup first, probe topology separately, and never receive FilterReplyMessage.'
}

$pagingBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.PagingWrite)')
$pagingPersist=$text.IndexOf('pagingStore.RecordAsync(',$pagingBranch)
$pagingReturn=$text.IndexOf('return;',$pagingPersist)
$pagingReply=$text.IndexOf('Native.Reply(',$pagingBranch)
if($pagingBranch -lt 0 -or $pagingPersist -lt 0 -or $pagingReturn -lt 0 -or
   ($pagingReply -ge 0 -and $pagingReply -lt $pagingReturn)){
  throw 'PagingWrite must be persisted as evidence only and must not receive FilterReplyMessage.'
}

$sectionBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.WritableSection)')
$sectionPersist=$text.IndexOf('sectionStore.RecordAsync(',$sectionBranch)
$sectionReturn=$text.IndexOf('return;',$sectionPersist)
$sectionReply=$text.IndexOf('Native.Reply(',$sectionBranch)
if($sectionBranch -lt 0 -or $sectionPersist -lt 0 -or $sectionReturn -lt 0 -or
   ($sectionReply -ge 0 -and $sectionReply -lt $sectionReturn)){
  throw 'WritableSection must be persisted as no-reply attestation evidence.'
}
$sectionEvaluate=$text.IndexOf('WritableSectionAttestation.Evaluate(',$sectionBranch)
$sectionIntent=$text.IndexOf('createOperationStore.Intents.SingleOrDefault',$sectionBranch)
if($sectionIntent -lt 0 -or $sectionEvaluate -lt 0 -or $sectionIntent -gt $sectionEvaluate){
  throw 'WritableSection must resolve the correlated CREATE intent before attestation.'
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

$lossOption=$text.IndexOf('case "--drop-first-create-completion"')
$lossBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.CreateResult)')
$lossCheck=$text.IndexOf('if (options.DropFirstCreateCompletion',$lossBranch)
$lossCancel=$text.IndexOf('cts.Cancel();',$lossCheck)
$lossPersist=$text.IndexOf('CreateReconciliation.HandleAsync(',$lossBranch)
if($lossOption -lt 0 -or $lossBranch -lt 0 -or $lossCheck -lt 0 -or $lossCancel -lt 0 -or $lossPersist -lt 0 -or
   $lossBranch -gt $lossCheck -or $lossCheck -gt $lossCancel -or $lossCancel -gt $lossPersist){
  throw 'LAB CREATE completion-loss injection must drop the received CreateResult before authoritative completion persistence.'
}
if($text -match [regex]::Escape('Environment.FailFast("RansomGuard LAB fault injection: after durable CREATE intent, before kernel reply.")')){
  throw 'GateClient must not hard-crash while the kernel is waiting for a blocking gate reply.'
}

$renameLossOption=$text.IndexOf('case "--drop-first-rename-completion"')
$renameLossBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.RenameResult)')
$renameLossCheck=$text.IndexOf('if (options.DropFirstRenameCompletion',$renameLossBranch)
$renameLossCancel=$text.IndexOf('cts.Cancel();',$renameLossCheck)
$renameLossPersist=$text.IndexOf('RenameReconciliation.HandleAsync(',$renameLossBranch)
if($renameLossOption -lt 0 -or $renameLossBranch -lt 0 -or $renameLossCheck -lt 0 -or
   $renameLossCancel -lt 0 -or $renameLossPersist -lt 0 -or
   $renameLossBranch -gt $renameLossCheck -or $renameLossCheck -gt $renameLossCancel -or
   $renameLossCancel -gt $renameLossPersist){
  throw 'LAB RENAME completion-loss injection must drop the received RenameResult before authoritative completion persistence.'
}

$truncateLossOption=$text.IndexOf('case "--drop-first-truncate-completion"')
$truncateLossBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.TruncateResult)')
$truncateLossCheck=$text.IndexOf('if (options.DropFirstTruncateCompletion',$truncateLossBranch)
$truncateLossCancel=$text.IndexOf('cts.Cancel();',$truncateLossCheck)
$truncateLossPersist=$text.IndexOf('TruncateReconciliation.HandleAsync(',$truncateLossBranch)
if($truncateLossOption -lt 0 -or $truncateLossBranch -lt 0 -or $truncateLossCheck -lt 0 -or
   $truncateLossCancel -lt 0 -or $truncateLossPersist -lt 0 -or
   $truncateLossBranch -gt $truncateLossCheck -or $truncateLossCheck -gt $truncateLossCancel -or
   $truncateLossCancel -gt $truncateLossPersist){
  throw 'LAB TRUNCATE completion-loss injection must drop the received TruncateResult before authoritative completion persistence.'
}

$deleteLossOption=$text.IndexOf('case "--drop-first-delete-completion"')
$deleteLossBranch=$text.IndexOf('if ((RgEventType)ev.EventType == RgEventType.DeleteDispositionResult)')
$deleteLossCheck=$text.IndexOf('if (options.DropFirstDeleteCompletion',$deleteLossBranch)
$deleteLossCancel=$text.IndexOf('cts.Cancel();',$deleteLossCheck)
$deleteLossPersist=$text.IndexOf('DeleteReconciliation.HandleDispositionAsync(',$deleteLossBranch)
if($deleteLossOption -lt 0 -or $deleteLossBranch -lt 0 -or $deleteLossCheck -lt 0 -or
   $deleteLossCancel -lt 0 -or $deleteLossPersist -lt 0 -or
   $deleteLossBranch -gt $deleteLossCheck -or $deleteLossCheck -gt $deleteLossCancel -or
   $deleteLossCancel -gt $deleteLossPersist){
  throw 'LAB DELETE completion-loss injection must drop the received DeleteDispositionResult before authoritative completion persistence.'
}

$renameBranch=$text.IndexOf('if (eventType == RgEventType.Rename)')
$renameSourceCapture=$text.IndexOf('CapturePreimageAsync(sourcePath, RollbackMutationKind.Rename',$renameBranch)
$renameIntent=$text.IndexOf('renameStore.CaptureIntentAsync(',$renameSourceCapture)
$renameAllow=$text.IndexOf('RgGateDecision.SnapshotCommitted',$renameIntent)
if($renameBranch -lt 0 -or $renameSourceCapture -lt 0 -or $renameIntent -lt 0 -or $renameAllow -lt 0 -or
   $renameSourceCapture -gt $renameIntent -or $renameIntent -gt $renameAllow){
  throw 'RENAME must preserve source/destination state and durably commit rename intent before allow.'
}

$truncateEvaluate=$text.IndexOf('private static async Task<RgGateReply> EvaluateTruncateAsync')
$truncateStandard=$text.IndexOf('FileIdentityStore.QueryPathStandardInfo(path, identityBaseline.Identity)',$truncateEvaluate)
$truncateCapture=$text.IndexOf('CapturePreimageAsync(',$truncateStandard)
$truncateIntent=$text.IndexOf('truncateStore.RecordIntentAsync(',$truncateStandard)
$truncateAllow=$text.IndexOf('return Allow(',$truncateIntent)
if($truncateEvaluate -lt 0 -or $truncateStandard -lt 0 -or $truncateCapture -lt 0 -or
   $truncateIntent -lt 0 -or $truncateAllow -lt 0 -or
   $truncateEvaluate -gt $truncateStandard -or $truncateStandard -gt $truncateCapture -or
   $truncateCapture -gt $truncateIntent -or $truncateIntent -gt $truncateAllow){
  throw 'Pre-existing TRUNCATE must bind standard info, commit a full pre-image, commit its durable intent, then allow.'
}

$deleteEvaluate=$text.IndexOf('private static async Task<RgGateReply> EvaluateDeleteAsync')
$deleteCapture=$text.IndexOf('CapturePreimageAsync(',$deleteEvaluate)
$deleteIntent=$text.IndexOf('deleteStore.RecordIntentAsync(',$deleteEvaluate)
$deleteAllow=$text.IndexOf('return Allow(',$deleteIntent)
if($deleteEvaluate -lt 0 -or $deleteCapture -lt 0 -or $deleteIntent -lt 0 -or $deleteAllow -lt 0 -or
   $deleteEvaluate -gt $deleteCapture -or $deleteCapture -gt $deleteIntent -or $deleteIntent -gt $deleteAllow){
  throw 'Pre-existing DELETE must commit its full pre-image and durable DELETE intent before allow.'
}
$deleteRestart=$text.IndexOf('var deleteRoot = Path.Combine(session.Root, "delete-state")')
$deleteUnsettled=$text.IndexOf('deletes.UnsettledIntents',$deleteRestart)
$deleteRestartPersist=$text.IndexOf('deletes.RecordFinalizationAsync(',$deleteUnsettled)
if($deleteRestart -lt 0 -or $deleteUnsettled -lt 0 -or $deleteRestartPersist -lt 0 -or
   $deleteRestart -gt $deleteUnsettled -or $deleteUnsettled -gt $deleteRestartPersist){
  throw 'Restart reconciliation must persist conservative topology evidence for unsettled DELETE transactions.'
}

$connect=$text.IndexOf('using var port = Native.Connect(')
$preflight=$text.IndexOf('ActivationPreflight.RunAsync(',$connect)
$workerLoop=$text.IndexOf('while (!cts.IsCancellationRequested)',$preflight)
if($connect -lt 0 -or $preflight -lt 0 -or $workerLoop -lt 0 -or
   $connect -gt $preflight -or $preflight -gt $workerLoop){
  throw 'LAB gate must connect and complete activation preflight before the normal receive loop.'
}
$preflightStart=$text.IndexOf('static class ActivationPreflight')
$preflightEnd=$text.IndexOf('readonly record struct ActivationPreflightSummary',$preflightStart)
if($preflightStart -lt 0 -or $preflightEnd -lt 0){throw 'ActivationPreflight implementation missing.'}
$preflightBlock=$text.Substring($preflightStart,$preflightEnd-$preflightStart)
foreach($required in @('Directory.EnumerateFiles','Directory.EnumerateDirectories','FileAttributes.ReparsePoint','Native.OpenPreflightProbe','Native.OpenPreflightHold','Native.OpenPreflightDirectory','ActivationPreflightStore','ActivationTopologyStore','FileIdentityStore.QueryHandleIdentity','RgEventType.ActivationPreflight','RgEventType.PagingWrite','RgEventType.WritableSection','heldHandles','RgControlCommand.ArmPreflight','RgControlCommand.ActivateGate','RgControlCommand.ActivateAndContainProcess','TargetProcessId = containPid ?? 0','Native.Control')){
  if($preflightBlock -notmatch [regex]::Escape($required)){throw "Activation preflight missing invariant: $required"}
}
$armInPreflight=$preflightBlock.IndexOf('RgControlCommand.ArmPreflight')
$probeInPreflight=$preflightBlock.IndexOf('Native.OpenPreflightProbe(path)')
$receiveInPreflight=$preflightBlock.IndexOf('ReceivePreflightEventAsync(port, path',$probeInPreflight)
$writableReject=$preflightBlock.IndexOf('if (writableView)',$receiveInPreflight)
$holdInPreflight=$preflightBlock.IndexOf('Native.OpenPreflightHold(path)',$writableReject)
$holdIdentity=$preflightBlock.IndexOf('FileIdentityStore.QueryHandleIdentity(hold)',$holdInPreflight)
$identityCompare=$preflightBlock.IndexOf('if (!identity.Equals(holdIdentity))',$holdIdentity)
$activateInPreflight=$preflightBlock.IndexOf('RgControlCommand.ActivateGate')
$disposeInPreflight=$preflightBlock.IndexOf('foreach (var handle in heldHandles) handle.Dispose()')
if($armInPreflight -lt 0 -or $probeInPreflight -lt 0 -or $receiveInPreflight -lt 0 -or
   $armInPreflight -gt $probeInPreflight -or $probeInPreflight -gt $receiveInPreflight){
  throw 'Every intentional kernel preflight probe must be armed before its file open.'
}
if($writableReject -lt 0 -or $holdInPreflight -lt 0 -or $writableReject -gt $holdInPreflight){
  throw 'Writable-section attestation must be evaluated before acquiring the share-sensitive file hold.'
}
if($holdIdentity -lt 0 -or $identityCompare -lt 0 -or $holdInPreflight -gt $holdIdentity -or $holdIdentity -gt $identityCompare){
  throw 'Activation must bind the share-sensitive hold to the exact kernel-attested FILE_ID_INFO.'
}
if($activateInPreflight -lt 0 -or $disposeInPreflight -lt 0 -or $holdInPreflight -gt $activateInPreflight -or $activateInPreflight -gt $disposeInPreflight){
  throw 'Activation must occur while share-sensitive file/directory handles are still held.'
}

$productionSwitch=$text.IndexOf('case "--production"')
$productionReject=$text.IndexOf('ProductionGate forbids LAB prepare/fault/reconciliation/shutdown/containment options.',$productionSwitch)
$productionStore=$text.IndexOf('Environment.SpecialFolder.CommonApplicationData',$productionReject)
$productionMode=$text.IndexOf('RgClientMode.ProductionGate')
$productionPreflight=$text.IndexOf('options.Profile == GateProfile.Lab ? options.ContainPid : null')
$productionScope=$text.IndexOf('options.Profile == GateProfile.Lab && options.ScopeAmbiguityPid')
$productionTrigger=$text.IndexOf('options.Profile == GateProfile.Lab && options.ContainAfterPid')
$productionContainEvent=$text.IndexOf('ProductionGate received forbidden containment activation evidence.')
if($productionSwitch -lt 0 -or $productionReject -lt 0 -or $productionStore -lt 0 -or
   $productionMode -lt 0 -or $productionPreflight -lt 0 -or $productionScope -lt 0 -or
   $productionTrigger -lt 0 -or $productionContainEvent -lt 0){
  throw 'ProductionGate profile must be explicit, fixed-store and unable to reach LAB containment/fault controls.'
}

$containActivation=$preflightBlock.IndexOf('RgControlCommand.ActivateAndContainProcess')
$containPidBind=$preflightBlock.IndexOf('TargetProcessId = containPid ?? 0',$containActivation)
$containReplyCheck=$preflightBlock.IndexOf('activationReply.ContainedProcessId != containPid.Value',$containPidBind)
if($containActivation -lt 0 -or $containPidBind -lt 0 -or $containReplyCheck -lt 0 -or
   $containActivation -gt $containPidBind -or $containPidBind -gt $containReplyCheck){
  throw 'Explicit LAB containment must be armed atomically with activation and verified against the exact requested PID.'
}
if($preflightBlock -match '(?i)ReleaseContainment|ClearContainment'){
  throw 'GateClient must not expose a runtime containment release/bypass command.'
}

if($preflightBlock -notmatch [regex]::Escape('activationReply.ProtectionState != (uint)RgProtectionState.Protected')){
  throw 'Activation reply must prove kernel protection state is Protected.'
}

$cleanShutdown=$text.IndexOf('var cleanShutdown =')
$lifecycleCompleted=$text.IndexOf('lifecycleStore.MarkCompletedAsync',$cleanShutdown)
$deactivateRequest=$text.IndexOf('RgControlCommand.DeactivateGate',$lifecycleCompleted)
$maintenanceCheck=$text.IndexOf('RgProtectionState.Maintenance',$deactivateRequest)
$faultedBranch=$text.IndexOf('Kernel gate graceful deactivation NOT authorized',$maintenanceCheck)
if($cleanShutdown -lt 0 -or $lifecycleCompleted -lt 0 -or $deactivateRequest -lt 0 -or
   $maintenanceCheck -lt 0 -or $faultedBranch -lt 0 -or
   $cleanShutdown -gt $lifecycleCompleted -or $lifecycleCompleted -gt $deactivateRequest -or
   $deactivateRequest -gt $maintenanceCheck -or $maintenanceCheck -gt $faultedBranch){
  throw 'Clean GateClient shutdown must durably complete the session before requesting whole-gate deactivation, while faulted shutdown must not authorize release.'
}
foreach($required in @(
  'deactivationReply.GateActivated != 1',
  'deactivationReply.GateActivated != 0',
  'deactivationReply.ContainmentActive != 0',
  'deactivationReply.ContainedProcessId != 0',
  'deactivationReply.ProtectionState != (uint)RgProtectionState.Maintenance'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Graceful deactivation reply invariant missing: $required"}
}

$fileProbeStart=$text.IndexOf('public static SafeFileHandle OpenPreflightProbe(string path)')
$fileHoldStart=$text.IndexOf('public static SafeFileHandle OpenPreflightHold(string path)',$fileProbeStart)
$directoryOpenStart=$text.IndexOf('public static SafeFileHandle OpenPreflightDirectory(string path)',$fileHoldStart)
if($fileProbeStart -lt 0 -or $fileHoldStart -lt 0 -or $directoryOpenStart -lt 0){
  throw 'Split activation file probe/hold source blocks are missing.'
}
$fileProbeBlock=$text.Substring($fileProbeStart,$fileHoldStart-$fileProbeStart)
foreach($required in @('FileReadAttributes','ShareRead','ShareWrite','ShareDelete','ShareRead | ShareWrite | ShareDelete','CreateFileW')){
  if($fileProbeBlock -notmatch [regex]::Escape($required)){throw "File activation probe missing invariant: $required"}
}
if($fileProbeBlock -match [regex]::Escape('FileReadData')){
  throw 'Kernel activation probe must remain attribute-only so existing write-capable mappings are observable instead of rejected by sharing.'
}

$fileHoldBlock=$text.Substring($fileHoldStart,$directoryOpenStart-$fileHoldStart)
foreach($required in @('FileReadData','FileReadAttributes','FileReadData | FileReadAttributes','ShareRead','CreateFileW')){
  if($fileHoldBlock -notmatch [regex]::Escape($required)){throw "File activation hold missing invariant: $required"}
}
if($fileHoldBlock -match 'ShareWrite|ShareDelete'){
  throw 'Activation file hold must not share WRITE or DELETE access.'
}

$directoryOpenEnd=$text.IndexOf('public static void Cancel',$directoryOpenStart)
if($directoryOpenStart -lt 0 -or $directoryOpenEnd -lt 0){throw 'OpenPreflightDirectory source block missing.'}
$directoryOpenBlock=$text.Substring($directoryOpenStart,$directoryOpenEnd-$directoryOpenStart)
foreach($required in @('FileListDirectory','FileReadAttributes','FileListDirectory | FileReadAttributes','ShareRead','FileFlagBackupSemantics','CreateFileW')){
  if($directoryOpenBlock -notmatch [regex]::Escape($required)){throw "Directory topology open missing invariant: $required"}
}
if($directoryOpenBlock -match 'CreateFileW\(path, FileReadAttributes, ShareRead'){
  throw 'Activation topology directory open must be share-sensitive; FILE_READ_ATTRIBUTES alone does not enforce the hold.'
}
if($directoryOpenBlock -match 'ShareWrite|ShareDelete'){
  throw 'Activation topology directory handles must not share WRITE or DELETE access.'
}
$rootOpen=$preflightBlock.IndexOf('Native.OpenPreflightDirectory(rootPath)')
$directoryEnumeration=$preflightBlock.IndexOf('Directory.EnumerateDirectories(rootPath')
$activateAfterTopology=$preflightBlock.IndexOf('RgControlCommand.ActivateGate')
if($rootOpen -lt 0 -or $directoryEnumeration -lt 0 -or $activateAfterTopology -lt 0 -or
   $rootOpen -gt $directoryEnumeration -or $directoryEnumeration -gt $activateAfterTopology){
  throw 'Protected root must be held before directory enumeration and remain held until kernel activation.'
}
if($preflightBlock -match 'Native\.Reply\('){throw 'Activation preflight events must remain no-reply evidence.'}

$containOption=$text.IndexOf('case "--contain-pid"')
$containRejectSystem=$text.IndexOf('parsedPid <= 4',$containOption)
$containRejectSelf=$text.IndexOf('parsedPid == Environment.ProcessId',$containOption)
$containPrepareReject=$text.IndexOf('Containment/fault/reconciliation/shutdown options cannot be combined with --prepare-root')
if($containOption -lt 0 -or $containRejectSystem -lt 0 -or $containRejectSelf -lt 0 -or $containPrepareReject -lt 0){
  throw 'LAB containment CLI must reject system/self PID and prepare-only combinations.'
}

$transitionOption=$text.IndexOf('case "--contain-after-pid"')
$transitionRejectSystem=$text.IndexOf('parsedTransitionPid <= 4',$transitionOption)
$transitionRejectSelf=$text.IndexOf('parsedTransitionPid == Environment.ProcessId',$transitionOption)
$transitionMutualExclusion=$text.IndexOf('--contain-pid, --scope-ambiguity-pid and --contain-after-pid are mutually exclusive.')
$transitionThresholdBinding=$text.IndexOf('Containment thresholds require --contain-after-pid.')
$scopeOption=$text.IndexOf('case "--scope-ambiguity-pid"')
$scopeRejectSystem=$text.IndexOf('parsedScopePid <= 4',$scopeOption)
$scopeRejectSelf=$text.IndexOf('parsedScopePid == Environment.ProcessId',$scopeOption)
if($transitionOption -lt 0 -or $transitionRejectSystem -lt 0 -or $transitionRejectSelf -lt 0 -or
   $scopeOption -lt 0 -or $scopeRejectSystem -lt 0 -or $scopeRejectSelf -lt 0 -or
   $transitionMutualExclusion -lt 0 -or $transitionThresholdBinding -lt 0){
  throw 'Containment/scope-probe CLI must be explicit, single-target and threshold-bounded.'
}

$triggerStart=$text.IndexOf('sealed class LabContainmentTrigger')
$triggerEnd=$text.IndexOf('sealed record Options(',$triggerStart)
if($triggerStart -lt 0 -or $triggerEnd -lt 0){throw 'LabContainmentTrigger implementation missing.'}
$triggerBlock=$text.Substring($triggerStart,$triggerEnd-$triggerStart)
foreach($required in @(
  'Process.GetProcessById(processId)',
  '_ = _process.Handle',
  '_process.HasExited',
  'SnapshotCommitted or RgGateDecision.BaselineCommitted',
  '_events < _requiredEvents',
  '_paths.Count < _requiredPaths'
)){
  if($triggerBlock -notmatch [regex]::Escape($required)){throw "Event-bound containment trigger invariant missing: $required"}
}

$processStart=$text.IndexOf('async Task ProcessMessageAsync')
$processEnd=$text.IndexOf('repository.VerifyAll()',$processStart)
if($processStart -lt 0 -or $processEnd -lt 0){throw 'ProcessMessageAsync source block missing.'}
$processBlock=$text.Substring($processStart,$processEnd-$processStart)
$requestPersist=$processBlock.IndexOf('containmentStore.RecordRequestAsync(')
$replyFlag=$processBlock.IndexOf('reply.Flags |= (uint)RgGateReplyFlags.ContainRequestor',$requestPersist)
$replySend=$processBlock.IndexOf('Native.Reply(port, header.MessageId, reply)',$replyFlag)
if($requestPersist -lt 0 -or $replyFlag -lt 0 -or $replySend -lt 0 -or
   $requestPersist -gt $replyFlag -or $replyFlag -gt $replySend){
  throw 'Containment request evidence must be durable before the event-bound reply flag is sent.'
}
$activationBranch=$processBlock.IndexOf('RgEventType.ContainmentActivated')
$activationPath=$processBlock.IndexOf('resolver.Resolve(ev.Path)',$activationBranch)
$activationRootScope=$processBlock.IndexOf('PathPolicy.Under(activationPath, options.Root)',$activationPath)
$activationPathBinding=$processBlock.IndexOf('Path.GetFullPath(activationPath).Equals(request.Path',$activationRootScope)
$activationPersist=$processBlock.IndexOf('containmentStore.RecordKernelActiveAsync(',$activationPathBinding)
$activationReturn=$processBlock.IndexOf('return;',$activationPersist)
$activationReply=$processBlock.IndexOf('Native.Reply(',$activationBranch)
if($activationBranch -lt 0 -or $activationPath -lt 0 -or $activationRootScope -lt 0 -or
   $activationPathBinding -lt 0 -or $activationPersist -lt 0 -or $activationReturn -lt 0 -or
   $activationBranch -gt $activationPath -or $activationPath -gt $activationRootScope -or
   $activationRootScope -gt $activationPathBinding -or $activationPathBinding -gt $activationPersist -or
   ($activationReply -ge 0 -and $activationReply -lt $activationReturn)){
  throw 'ContainmentActivated must persist as no-reply kernel evidence.'
}

$workerDispatch=$text.IndexOf('Task.Run(() => ProcessMessageAsync(header, ev))')
$workerEvaluate=$text.IndexOf('GateDecision.EvaluateAsync(',$text.IndexOf('async Task ProcessMessageAsync'))
if($workerDispatch -lt 0 -or $workerEvaluate -lt 0){
  throw 'Gate messages must be dispatched through the bounded worker path.'
}
if($text -notmatch 'GateWorkers\s*<\s*1' -or $text -notmatch 'GateWorkers\s*>\s*MaxGateWorkers'){
  throw 'Gate worker argument must remain explicitly bounded.'
}
foreach($required in @(
  '--shutdown-file',
  'MonitorShutdownFileAsync',
  'File.Exists(options.ShutdownFile)',
  'Native.Cancel(port)',
  '--shutdown-file must be outside the protected root.',
  'const int deactivationAttempts = 30',
  'Kernel remained busy for clean gate deactivation'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Graceful GateClient shutdown invariant missing: $required"}
}

foreach($required in @(
  'static class GateMessagePolicy',
  'public static bool RequiresReply(RgEventType type)',
  'if (GateMessagePolicy.RequiresReply((RgEventType)ev.EventType))',
  'await worker.ConfigureAwait(false);',
  'FLT_PORT_FLAG_SYNC_HANDLE'
)){
  if($text -notmatch [regex]::Escape($required)){throw "Synchronous filter-port reply ordering invariant missing: $required"}
}
$receiveLoopStart=$text.LastIndexOf('while (!cts.IsCancellationRequested)',$workerDispatch)
$receiveLoopEnd=$text.IndexOf('catch (OperationCanceledException)',$workerDispatch)
if($receiveLoopStart -lt 0 -or $receiveLoopEnd -lt 0){
  throw 'Runtime synchronous receive-loop source boundary missing.'
}
$receiveLoopBlock=$text.Substring($receiveLoopStart,$receiveLoopEnd-$receiveLoopStart)
if(([regex]::Matches($receiveLoopBlock,[regex]::Escape('Native.FilterGetMessage(port, buffer'))).Count -ne 1){
  throw 'Runtime synchronous receive loop must issue exactly one FilterGetMessage per iteration.'
}
$loopDispatch=$receiveLoopBlock.IndexOf('Task.Run(() => ProcessMessageAsync(header, ev))')
$replyRequired=$receiveLoopBlock.IndexOf('if (GateMessagePolicy.RequiresReply((RgEventType)ev.EventType))',$loopDispatch)
$replyAwait=$receiveLoopBlock.IndexOf('await worker.ConfigureAwait(false);',$replyRequired)
if($loopDispatch -lt 0 -or $replyRequired -lt 0 -or $replyAwait -lt 0 -or
   $loopDispatch -gt $replyRequired -or $replyRequired -gt $replyAwait){
  throw 'Reply-required worker must complete before the synchronous receive loop advances to its next iteration.'
}
$verifyBeforeRestart=$text.IndexOf('repository.VerifyAll()')
$restartObserve=$text.IndexOf('RestartReconciliation.ObservePendingAsync(',$verifyBeforeRestart)
$reconcileOnly=$text.IndexOf('if (options.ReconcileOnly)',$restartObserve)
$reconcileReturn=$text.IndexOf('return;',$reconcileOnly)
$createSession=$text.IndexOf('repository.CreateSession(',$restartObserve)
if($verifyBeforeRestart -lt 0 -or $restartObserve -lt 0 -or $reconcileOnly -lt 0 -or
   $reconcileReturn -lt 0 -or $createSession -lt 0 -or
   $verifyBeforeRestart -gt $restartObserve -or $restartObserve -gt $reconcileOnly -or
   $reconcileOnly -gt $reconcileReturn -or $reconcileReturn -gt $createSession){
  throw 'Pending restart evidence must be observed after repository validation, with reconcile-only exiting before any new session is created.'
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

Write-Host 'GateClient source check PASSED: protocol-v18 LAB/ProductionGate separation, fixed production store/root policy, LAB-only fault/containment controls, protected-volume fail-safe state, durable reconciliation and no destructive/process-control APIs.'
