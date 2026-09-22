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
  'ProtocolVersion = 13',
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
  '--contain-pid',
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

$renameBranch=$text.IndexOf('if (eventType == RgEventType.Rename)')
$renameSourceCapture=$text.IndexOf('CapturePreimageAsync(sourcePath, RollbackMutationKind.Rename',$renameBranch)
$renameIntent=$text.IndexOf('renameStore.CaptureIntentAsync(',$renameSourceCapture)
$renameAllow=$text.IndexOf('RgGateDecision.SnapshotCommitted',$renameIntent)
if($renameBranch -lt 0 -or $renameSourceCapture -lt 0 -or $renameIntent -lt 0 -or $renameAllow -lt 0 -or
   $renameSourceCapture -gt $renameIntent -or $renameIntent -gt $renameAllow){
  throw 'RENAME must preserve source/destination state and durably commit rename intent before allow.'
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
foreach($required in @('Directory.EnumerateFiles','Directory.EnumerateDirectories','FileAttributes.ReparsePoint','Native.OpenPreflight','Native.OpenPreflightDirectory','ActivationPreflightStore','ActivationTopologyStore','FileIdentityStore.QueryHandleIdentity','RgEventType.ActivationPreflight','RgEventType.PagingWrite','RgEventType.WritableSection','heldHandles','RgControlCommand.ArmPreflight','RgControlCommand.ActivateGate','RgControlCommand.ActivateAndContainProcess','TargetProcessId = containPid ?? 0','Native.Control')){
  if($preflightBlock -notmatch [regex]::Escape($required)){throw "Activation preflight missing invariant: $required"}
}
$armInPreflight=$preflightBlock.IndexOf('RgControlCommand.ArmPreflight')
$openInPreflight=$preflightBlock.IndexOf('Native.OpenPreflight(path)')
$activateInPreflight=$preflightBlock.IndexOf('RgControlCommand.ActivateGate')
$disposeInPreflight=$preflightBlock.IndexOf('foreach (var handle in heldHandles) handle.Dispose()')
if($armInPreflight -lt 0 -or $openInPreflight -lt 0 -or $armInPreflight -gt $openInPreflight){
  throw 'Every intentional preflight file open must be armed in kernel first.'
}
if($activateInPreflight -lt 0 -or $disposeInPreflight -lt 0 -or $activateInPreflight -gt $disposeInPreflight){
  throw 'Activation must occur while share-read preflight handles are still held.'
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

$fileOpenStart=$text.IndexOf('public static SafeFileHandle OpenPreflight(string path)')
$fileOpenEnd=$text.IndexOf('public static SafeFileHandle OpenPreflightDirectory(string path)',$fileOpenStart)
if($fileOpenStart -lt 0 -or $fileOpenEnd -lt 0){throw 'OpenPreflight source block missing.'}
$fileOpenBlock=$text.Substring($fileOpenStart,$fileOpenEnd-$fileOpenStart)
foreach($required in @('FileReadData','FileReadAttributes','FileReadData | FileReadAttributes','ShareRead','CreateFileW')){
  if($fileOpenBlock -notmatch [regex]::Escape($required)){throw "File activation open missing invariant: $required"}
}
if($fileOpenBlock -match 'CreateFileW\(path, FileReadAttributes, ShareRead'){
  throw 'Activation file open must be share-sensitive; FILE_READ_ATTRIBUTES alone does not enforce the hold.'
}
if($fileOpenBlock -match 'ShareWrite|ShareDelete'){
  throw 'Activation file handles must not share WRITE or DELETE access.'
}

$directoryOpenStart=$text.IndexOf('public static SafeFileHandle OpenPreflightDirectory(string path)')
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
$containPrepareReject=$text.IndexOf('Containment options cannot be combined with --prepare-root')
if($containOption -lt 0 -or $containRejectSystem -lt 0 -or $containRejectSelf -lt 0 -or $containPrepareReject -lt 0){
  throw 'LAB containment CLI must reject system/self PID and prepare-only combinations.'
}

$transitionOption=$text.IndexOf('case "--contain-after-pid"')
$transitionRejectSystem=$text.IndexOf('parsedTransitionPid <= 4',$transitionOption)
$transitionRejectSelf=$text.IndexOf('parsedTransitionPid == Environment.ProcessId',$transitionOption)
$transitionMutualExclusion=$text.IndexOf('--contain-pid and --contain-after-pid are mutually exclusive.')
$transitionThresholdBinding=$text.IndexOf('Containment thresholds require --contain-after-pid.')
if($transitionOption -lt 0 -or $transitionRejectSystem -lt 0 -or $transitionRejectSelf -lt 0 -or
   $transitionMutualExclusion -lt 0 -or $transitionThresholdBinding -lt 0){
  throw 'Event-bound containment CLI must be explicit, single-target and threshold-bounded.'
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

Write-Host 'LAB gate client source check PASSED: protocol-v13 event-bound containment, activation preflight, durable request/activation evidence, bounded workers, identity/restart evidence, no destructive/process-control APIs.'
