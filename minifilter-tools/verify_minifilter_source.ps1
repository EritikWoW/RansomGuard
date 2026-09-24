$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$sourceRoot=if(Test-Path -LiteralPath (Join-Path $root 'driver')){$root}elseif(Test-Path -LiteralPath (Join-Path $root 'MinifilterLab\Source\driver')){Join-Path $root 'MinifilterLab\Source'}else{throw 'Minifilter source tree not found.'}
$c=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
$h=Join-Path $sourceRoot 'native\shared\rg_minifilter_protocol.h'
$inf=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.inf'
if(-not (Test-Path -LiteralPath $c) -or -not (Test-Path -LiteralPath $h) -or -not (Test-Path -LiteralPath $inf)){throw 'Minifilter source/protocol/INF missing.'}
$src=Get-Content -LiteralPath $c -Raw
$proto=Get-Content -LiteralPath $h -Raw
$infText=Get-Content -LiteralPath $inf -Raw

$props=Join-Path $sourceRoot 'Directory.Build.props'
if(Test-Path -LiteralPath $props -PathType Leaf){
    [xml]$propsXml=Get-Content -LiteralPath $props -Raw
    $productVersion=[string]$propsXml.Project.PropertyGroup.Version
    if([string]::IsNullOrWhiteSpace($productVersion) -or $productVersion -notmatch '^\d+\.\d+\.\d+\.\d+$'){
        throw 'Directory.Build.props does not contain a canonical four-part product version.'
    }
    $driverVersionMatch=[regex]::Match($infText,'(?m)^\s*DriverVer\s*=\s*[^,]+,(?<version>\d+\.\d+\.\d+\.\d+)\s*$')
    if(-not $driverVersionMatch.Success){
        throw 'Minifilter INF must contain a four-part DriverVer version.'
    }
    if($driverVersionMatch.Groups['version'].Value -ne $productVersion){
        throw "Minifilter INF DriverVer '$($driverVersionMatch.Groups['version'].Value)' does not match product version '$productVersion'."
    }
}

$vcx=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuard.Minifilter.vcxproj'
$buildScript=Join-Path $PSScriptRoot 'build_minifilter.ps1'
if(-not (Test-Path -LiteralPath $vcx) -or -not (Test-Path -LiteralPath $buildScript)){throw 'Minifilter project/build script missing.'}
$vcxText=Get-Content -LiteralPath $vcx -Raw
$buildText=Get-Content -LiteralPath $buildScript -Raw
if($vcxText -notmatch '<PreferredToolArchitecture>\s*x64\s*</PreferredToolArchitecture>'){throw 'x64 tool architecture invariant missing from vcxproj.'}
if($buildText -notmatch '/p:PreferredToolArchitecture=x64'){throw 'x64 tool architecture invariant missing from build script.'}
if($buildText -notmatch 'MSBuild\\Current\\Bin\\amd64\\MSBuild\.exe'){throw '64-bit MSBuild host invariant missing from build script.'}
if($buildText -match '(?i)ApiValidatorEnabled\s*=\s*false|/p:ApiValidatorEnabled=false'){throw 'ApiValidator must not be disabled in this build.'}

$banned=@('FltWriteFile(','ZwWriteFile(','FltSetInformationFile(','FltCancelFileOpen(','FltDeleteFile(','ZwDeleteFile(','ZwTerminateProcess(','PsTerminateSystemThread(','NtSuspendProcess','SuspendThread(')
foreach($token in $banned){if($src.Contains($token)){throw "Kernel gate invariant violated: banned token '$token' found."}}
foreach($required in @(
    'RgClientLabGate',
    'RgEventIsInsideGateRoot',
    'gClientProcessId',
    'RG_GATE_TIMEOUT_MS',
    'RG_MAX_GATE_INFLIGHT',
    'gGateInFlight',
    'RgAcquireClientPort',
    'RgReleaseClientPort',
    'RgWaitForPortUsers',
    'ExAcquireRundownProtection(&gPortRundown)',
    'ExReleaseRundownProtection(&gPortRundown)',
    'ExReInitializeRundownProtection(&gPortRundown)',
    'FltCloseClientPort(gFilter, &gClientPort)',
    'FltSendMessage',
    'RgGateSnapshotCommitted',
    'FLT_PREOP_COMPLETE',
    'STATUS_ACCESS_DENIED',
    'RgEventTruncate',
    'RgEventTruncateResult',
    'RgCreateTruncatePostContext',
    'RgEventDeleteDisposition',
    'RgEventDeleteDispositionResult',
    'RgEventDeleteFinalized',
    'RgCreateDeletePostContext',
    'RgReadDeleteDispositionFlags',
    'RG_DELETE_DISPOSITION_DELETE',
    'RG_EVENT_FLAG_DELETE_PENDING',
    'RG_EVENT_FLAG_DELETE_STATE_RESOLVED',
    'RG_EVENT_FLAG_DELETE_CANCELLED',
    'RG_EVENT_FLAG_DELETE_CLEANUP',
    'FileDispositionInformation',
    'FileDispositionInformationEx',
    'IRP_MJ_CLEANUP',
    'RgPreCleanup',
    'RgPostCleanup',
    'FLT_STREAMHANDLE_CONTEXT',
    'FltSetStreamHandleContext',
    'FltGetStreamHandleContext',
    'FltDeleteStreamHandleContext',
    'FileEndOfFileInformation',
    'FileAllocationInformation',
    'FileValidDataLengthInformation',
    'FileStandardInformation',
    'IRP_MJ_CREATE',
    'RgPreCreate',
    'RgEventCreate',
    'Parameters.Create.Options',
    'RgGateBaselineCommitted',
    'RgGateNoPreservationRequired',
    'FltGetDestinationFileNameInformation',
    'FltGetTunneledName',
    'FltDoCompletionProcessingWhenSafe',
    'RgPostSetInformation',
    'RgEventRenameResult',
    'RgPostCreate',
    'RgEventCreateResult',
    'RgPopulatePostOperationIdentity',
    'RgPopulatePostOperationIdentity(&event, FltObjects);',
    'KeGetCurrentIrql() == PASSIVE_LEVEL',
    '!KeAreAllApcsDisabled()',
    'FltQueryInformationFile',
    'FileIdInformation',
    'IdentityStatus',
    'RelatedSequence',
    'CompletionStatus',
    'DestinationPathStatus',
    'DestinationPath',
    'RgEventPagingWrite',
    'RG_EVENT_FLAG_PAGING_IO',
    'FLT_STREAM_CONTEXT',
    'FltSetStreamContext',
    'FltGetStreamContext',
    'RgAttachPagingStreamContext',
    'RgObservePagingWrite',
    'RgEventWritableSection',
    'IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION',
    'RgPreAcquireForSectionSynchronization',
    'SyncTypeCreateSection',
    'PAGE_READWRITE',
    'PAGE_EXECUTE_READWRITE',
    'RgObserveWritableSection',
    'PreservationDecision',
    'CreateRequestSequence',
    'FLT_SET_CONTEXT_REPLACE_IF_EXISTS',
    'FLT_SET_CONTEXT_KEEP_IF_EXISTS',
    'RgEventActivationPreflight',
    'RG_EVENT_FLAG_PREFLIGHT_WRITABLE_VIEW',
    'MmDoesFileHaveUserWritableReferences',
    'gGateActivated',
    'gActivationHazard',
    'RgMessage',
    'RgControlActivateGate',
    'RgControlQueryActivation',
    'RgControlArmPreflight',
    'gPreflightProbeArmed',
    'gContainedProcess',
    'gContainedProcessId',
    'RgIsContainedRequestor',
    'RgCreateMayMutate',
    'RgClearContainedProcess',
    'FltGetRequestorProcess',
    'PsLookupProcessByProcessId',
    'ObDereferenceObject',
    'RgControlActivateAndContainProcess',
    'RgControlQueryContainment',
    'RgControlDeactivateGate',
    'RgControlArmScopeAmbiguity',
    'gScopeAmbiguityProcess',
    'gScopeAmbiguityProcessId',
    'RgClearScopeAmbiguityProbe',
    'RgInjectScopeAmbiguityProbe',
    'gProtectionRequired',
    'gDegradedProtected',
    'gMaintenanceRequested',
    'gGracefulDisconnectAuthorized',
    'RgCurrentProtectionState',
    'RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR',
    'RgEventContainmentActivated',
    'RgBindContainedRequestor'
)){
    if($src -notmatch [regex]::Escape($required)){throw "LAB write-gate invariant missing: $required"}
}
if($src -notmatch 'InterlockedIncrement\(&gGateInFlight\)' -or
   $src -notmatch 'inFlight\s*>\s*RG_MAX_GATE_INFLIGHT' -or
   $src -notmatch 'STATUS_DEVICE_BUSY'){
    throw 'Kernel gate must fail closed when the bounded in-flight admission limit is exceeded.'
}
$gateStart=$src.IndexOf('static BOOLEAN RgGateEvent(PFLT_CALLBACK_DATA Data,')
if($gateStart -lt 0){throw 'RgGateEvent source block missing or signature drifted.'}
$gateEnd=$src.IndexOf('static VOID RgQueueEvent(PFLT_CALLBACK_DATA Data',$gateStart)
if($gateEnd -lt 0){throw 'RgQueueEvent boundary after RgGateEvent is missing.'}
$gateBlock=$src.Substring($gateStart,$gateEnd-$gateStart)
if($gateBlock -match 'ExAcquireFastMutex\(&gPortMutex\)'){
    throw 'RgGateEvent must not hold gPortMutex while waiting for user-mode preservation.'
}
if($gateBlock -notmatch 'RgAcquireClientPort\(RgClientLabGate' -or
   $gateBlock -notmatch 'RgReleaseClientPort\(\)'){
    throw 'RgGateEvent must use the short-lived client-port lease around FltSendMessage.'
}
$firstMaintenanceGate=$gateBlock.IndexOf('InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0')
$portLease=$gateBlock.IndexOf('RgAcquireClientPort(RgClientLabGate')
$secondMaintenanceGate=$gateBlock.IndexOf('InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0',$firstMaintenanceGate+1)
if($firstMaintenanceGate -lt 0 -or $portLease -lt 0 -or $secondMaintenanceGate -lt 0 -or
   $firstMaintenanceGate -gt $portLease -or $secondMaintenanceGate -lt $portLease){
    throw 'Maintenance transition must close new gate admission and reject an already-replied request before allow processing.'
}
foreach($required in @(
    'reply.Flags & ~RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR',
    'FlagOn(reply.Flags, RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR)',
    'RgBindContainedRequestor(Data, Event, ErrorCode)'
)){
    if($gateBlock -notmatch [regex]::Escape($required)){throw "Event-bound containment gate invariant missing: $required"}
}
if($gateBlock -notmatch [regex]::Escape('if (!allow && reply.Flags != 0)')){
    throw 'Containment reply flags must never be accepted on a denied/unpreserved operation.'
}

if($gateBlock -notmatch [regex]::Escape('else if (allow && RgIsContainedRequestor(Data))') -or
   $gateBlock -notmatch [regex]::Escape('*ErrorCode = (ULONG)STATUS_ACCESS_DENIED')){
    throw 'Sibling in-flight mutations must be denied if containment becomes active while they wait for user mode.'
}

$queueStart=$src.IndexOf('static VOID RgQueueEvent(PFLT_CALLBACK_DATA Data')
$rawQueueStart=$src.IndexOf('static VOID RgQueueRawEvent(const RG_EVENT *Event',$queueStart)
$sendWorkerStart=$src.IndexOf('static VOID RgSendWorker(PVOID Parameter)',$rawQueueStart)
if($queueStart -lt 0 -or $rawQueueStart -lt 0 -or $sendWorkerStart -lt 0){
    throw 'Evidence queue source boundaries missing.'
}
$queueBlock=$src.Substring($queueStart,$rawQueueStart-$queueStart)
$rawQueueBlock=$src.Substring($rawQueueStart,$sendWorkerStart-$rawQueueStart)
foreach($block in @($queueBlock,$rawQueueBlock)){
    $pendingIncrement=$block.IndexOf('pending = InterlockedIncrement(&gPending)')
    $maintenanceReject=$block.IndexOf('InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0',$pendingIncrement)
    $pendingDecrement=$block.IndexOf('InterlockedDecrement(&gPending)',$maintenanceReject)
    if($pendingIncrement -lt 0 -or $maintenanceReject -lt 0 -or $pendingDecrement -lt 0 -or
       $pendingIncrement -gt $maintenanceReject -or $maintenanceReject -gt $pendingDecrement){
        throw 'Maintenance must close new queued evidence admission after reserving gPending so deactivation cannot miss a racing worker.'
    }
}

if($src -match 'IRP_MJ_WRITE\s*,\s*FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO'){
    throw 'Paging-write visibility requires IRP_MJ_WRITE callbacks to receive paging I/O.'
}
$pagingStart=$src.IndexOf('static VOID RgObservePagingWrite(PFLT_CALLBACK_DATA Data')
if($pagingStart -lt 0){throw 'Paging-write observation source block missing.'}
$pagingEnd=$src.IndexOf('FLT_POSTOP_CALLBACK_STATUS RgPostSetInformation',$pagingStart)
if($pagingEnd -lt 0){throw 'Paging-write observation end boundary missing.'}
$pagingBlock=$src.Substring($pagingStart,$pagingEnd-$pagingStart)
foreach($forbidden in @('RgGateEvent(','FltGetFileNameInformation(','FltGetFileNameInformationUnsafe(','FltQueryInformationFile(')){
    if($pagingBlock.Contains($forbidden)){throw "Paging-write path must remain non-blocking and name-query free: $forbidden"}
}
if($pagingBlock -notmatch [regex]::Escape('FltGetStreamContext') -or
   $pagingBlock -notmatch [regex]::Escape('RgQueueRawEvent(&event, RgClientLabGate)')){
    throw 'Paging-write path must use the pre-established stream context and queue no-reply evidence.'
}

$sectionStart=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreAcquireForSectionSynchronization(')
if($sectionStart -lt 0){throw 'Writable-section synchronization callback source block missing.'}
$sectionEnd=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreWrite(',$sectionStart)
if($sectionEnd -lt 0){throw 'Writable-section synchronization callback end boundary missing.'}
$sectionBlock=$src.Substring($sectionStart,$sectionEnd-$sectionStart)
foreach($forbidden in @('RgGateEvent(','FltGetFileNameInformation(','FltGetFileNameInformationUnsafe(','FltQueryInformationFile(','STATUS_ACCESS_DENIED','FLT_PREOP_COMPLETE')){
    if($sectionBlock.Contains($forbidden)){throw "Writable-section callback must remain no-reply/non-blocking: $forbidden"}
}
foreach($required in @('SyncTypeCreateSection','PAGE_READWRITE','PAGE_EXECUTE_READWRITE','RgObserveWritableSection','FLT_PREOP_SUCCESS_NO_CALLBACK')){
    if($sectionBlock -notmatch [regex]::Escape($required)){throw "Writable-section callback missing invariant: $required"}
}
$sectionObserveStart=$src.IndexOf('static VOID RgObserveWritableSection(PFLT_CALLBACK_DATA Data')
$sectionObserveEnd=$src.IndexOf('FLT_POSTOP_CALLBACK_STATUS RgPostSetInformation',$sectionObserveStart)
if($sectionObserveStart -lt 0 -or $sectionObserveEnd -lt 0){throw 'Writable-section observation helper missing.'}
$sectionObserve=$src.Substring($sectionObserveStart,$sectionObserveEnd-$sectionObserveStart)
foreach($forbidden in @('RgGateEvent(','FltGetFileNameInformation(','FltQueryInformationFile(')){
    if($sectionObserve.Contains($forbidden)){throw "Writable-section observation must use only established stream context: $forbidden"}
}
$attachStart=$src.IndexOf('static VOID RgAttachPagingStreamContext(PCFLT_RELATED_OBJECTS FltObjects')
$attachEnd=$src.IndexOf('static VOID RgObservePagingWrite',$attachStart)
if($attachStart -lt 0 -or $attachEnd -lt 0){throw 'Stream-context attachment helper missing.'}
$attachBlock=$src.Substring($attachStart,$attachEnd-$attachStart)
if($attachBlock -notmatch [regex]::Escape('FLT_SET_CONTEXT_REPLACE_IF_EXISTS') -or
   $attachBlock -notmatch [regex]::Escape('FLT_SET_CONTEXT_KEEP_IF_EXISTS') -or
   $attachBlock -notmatch [regex]::Escape('PreservationDecision == RgGateSnapshotCommitted') -or
   $attachBlock -notmatch [regex]::Escape('PreservationDecision == RgGateBaselineCommitted')){
    throw 'Protected CREATE must upgrade a prior read-only stream context while read-only CREATE must not downgrade it.'
}

if($sectionObserve -notmatch [regex]::Escape('FltGetStreamContext') -or
   $sectionObserve -notmatch [regex]::Escape('event.RelatedSequence = context->CreateRequestSequence') -or
   $sectionObserve -notmatch [regex]::Escape('event.CompletionInformation = context->PreservationDecision') -or
   $sectionObserve -notmatch [regex]::Escape('RgQueueRawEvent(&event, RgClientLabGate)')){
    throw 'Writable-section observation must attest the CREATE baseline through stream context and queue no-reply evidence.'
}

if($src -notmatch [regex]::Escape('postContext->ActivationPreflight = 1') -or
   $src -notmatch [regex]::Escape('MmDoesFileHaveUserWritableReferences') -or
   $src -notmatch [regex]::Escape('RG_EVENT_FLAG_PREFLIGHT_WRITABLE_VIEW')){
    throw 'Gate-client preflight CREATE must query pre-existing user-writable mappings in post-create.'
}
if($src -notmatch [regex]::Escape('InterlockedExchange(&gPreflightProbeArmed, 0) == 1')){
    throw 'Only an explicitly armed gate-client CREATE may become an activation preflight probe.'
}

if($src -notmatch 'InterlockedCompareExchange\(&gGateActivated,\s*0,\s*0\)\s*==\s*0' -or
   $src -notmatch 'InterlockedExchange\(&gActivationHazard,\s*1\)'){
    throw 'LAB gate activation state/hazard invariants are missing.'
}
$messageStart=$src.IndexOf('static NTSTATUS RgMessage(PVOID ConnectionCookie')
if($messageStart -lt 0){throw 'Kernel control-message callback missing.'}
$messageEnd=$src.IndexOf('static VOID RgDisconnect',$messageStart)
if($messageEnd -lt 0){throw 'Kernel control-message callback boundary missing.'}
$messageBlock=$src.Substring($messageStart,$messageEnd-$messageStart)
foreach($required in @('RgControlActivateGate','RgControlQueryActivation','RgControlArmPreflight','RgControlActivateAndContainProcess','RgControlQueryContainment','RgControlDeactivateGate','RgControlArmScopeAmbiguity','TargetProcessId','PsLookupProcessByProcessId','gContainedProcess','gContainedProcessId','gScopeAmbiguityProcess','gScopeAmbiguityProcessId','gPreflightProbeArmed','gActivationHazard','gGateActivated','gProtectionRequired','gDegradedProtected','gGracefulDisconnectAuthorized','RgCurrentProtectionState','ProtectionState','STATUS_DEVICE_BUSY')){
    if($messageBlock -notmatch [regex]::Escape($required)){throw "Activation control callback missing invariant: $required"}
}
$containmentHelperStart=$src.IndexOf('static BOOLEAN RgIsContainedRequestor(PFLT_CALLBACK_DATA Data)')
$containmentHelperEnd=$src.IndexOf('static BOOLEAN RgGateEvent',$containmentHelperStart)
if($containmentHelperStart -lt 0 -or $containmentHelperEnd -lt 0){throw 'Kernel containment helper block missing.'}
$containmentHelpers=$src.Substring($containmentHelperStart,$containmentHelperEnd-$containmentHelperStart)
foreach($required in @(
    'FltGetRequestorProcess(Data)',
    'PsGetProcessId(requestor)',
    '!= Event->ProcessId',
    'gContainedProcess == requestor',
    'RgCreateMayMutate',
    'FILE_WRITE_DATA',
    'FILE_APPEND_DATA',
    'FILE_DELETE_ON_CLOSE',
    'FILE_OVERWRITE_IF',
    'RgClearContainedProcess',
    'RgClearScopeAmbiguityProbe',
    'RgInjectScopeAmbiguityProbe',
    'gScopeAmbiguityProcess == requestor',
    'Event->PathStatus = RgPathQueryFailed',
    "Event->Path[0] = L'\0'",
    'ObDereferenceObject(previous)',
    'RgBindContainedRequestor',
    'ObReferenceObject(requestor)',
    'RgEventContainmentActivated',
    'newlyBound = TRUE',
    'if (newlyBound)',
    'activationEvent.RelatedSequence = Event->Sequence',
    'RgQueueRawEvent(&activationEvent, RgClientLabGate)'
)){
    if($containmentHelpers -notmatch [regex]::Escape($required)){throw "Kernel containment helper invariant missing: $required"}
}

$containCommand=$messageBlock.IndexOf('request->Command == RgControlActivateAndContainProcess')
$lookupProcess=$messageBlock.IndexOf('PsLookupProcessByProcessId',$containCommand)
$bindProcess=$messageBlock.IndexOf('gContainedProcess = targetProcess',$lookupProcess)
$bindPid=$messageBlock.IndexOf('InterlockedExchange64(&gContainedProcessId',$bindProcess)
$activateContained=$messageBlock.IndexOf('InterlockedExchange(&gGateActivated, 1)',$bindPid)
if($containCommand -lt 0 -or $lookupProcess -lt 0 -or $bindProcess -lt 0 -or $bindPid -lt 0 -or $activateContained -lt 0 -or
   $containCommand -gt $lookupProcess -or $lookupProcess -gt $bindProcess -or $bindProcess -gt $bindPid -or $bindPid -gt $activateContained){
    throw 'Containment must bind a referenced process object and PID before atomically activating the LAB gate.'
}

$scopeCommand=$messageBlock.IndexOf('request->Command == RgControlArmScopeAmbiguity')
$scopeLookup=$messageBlock.IndexOf('PsLookupProcessByProcessId',$scopeCommand)
$scopeBind=$messageBlock.IndexOf('gScopeAmbiguityProcess = targetProcess',$scopeLookup)
$scopeBindPid=$messageBlock.IndexOf('InterlockedExchange64(',$scopeBind)
if($scopeCommand -lt 0 -or $scopeLookup -lt 0 -or $scopeBind -lt 0 -or $scopeBindPid -lt 0 -or
   $scopeCommand -gt $scopeLookup -or $scopeLookup -gt $scopeBind -or $scopeBind -gt $scopeBindPid){
    throw 'LAB ambiguity probe must bind a referenced exact process object before it can affect a callback.'
}
foreach($required in @(
    'InterlockedCompareExchange(&gGateActivated, 0, 0) == 0',
    'InterlockedCompareExchange(&gProtectionRequired, 0, 0) == 0',
    'InterlockedCompareExchange(&gDegradedProtected, 0, 0) != 0',
    'InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0'
)){
    if($messageBlock.IndexOf($required,$scopeCommand) -lt 0){throw "Scope ambiguity arm guard missing: $required"}
}
if($messageBlock -notmatch [regex]::Escape('request->TargetProcessId <= 4') -or
   $messageBlock -notmatch [regex]::Escape('request->TargetProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId')){
    throw 'Containment control must reject system PIDs and the GateClient PID.'
}

$deactivateCommand=$messageBlock.IndexOf('request->Command == RgControlDeactivateGate')
$deactivateMaintenance=$messageBlock.IndexOf('InterlockedExchange(&gMaintenanceRequested, 1)',$deactivateCommand)
$deactivateBusy=$messageBlock.IndexOf('InterlockedCompareExchange(&gGateInFlight, 0, 0) != 0',$deactivateCommand)
$deactivatePending=$messageBlock.IndexOf('InterlockedCompareExchange(&gPending, 0, 0) != 0',$deactivateCommand)
$deactivateProtection=$messageBlock.IndexOf('InterlockedExchange(&gProtectionRequired, 0)',$deactivateCommand)
$deactivateAuthorize=$messageBlock.IndexOf('InterlockedExchange(&gGracefulDisconnectAuthorized, 1)',$deactivateCommand)
if($deactivateCommand -lt 0 -or $deactivateMaintenance -lt 0 -or $deactivateBusy -lt 0 -or
   $deactivatePending -lt 0 -or $deactivateProtection -lt 0 -or $deactivateAuthorize -lt 0 -or
   $deactivateCommand -gt $deactivateMaintenance -or $deactivateMaintenance -gt $deactivateBusy -or
   $deactivateBusy -gt $deactivateProtection -or $deactivatePending -gt $deactivateProtection -or
   $deactivateProtection -gt $deactivateAuthorize){
    throw 'Graceful DeactivateGate must close admission before draining, then require zero kernel gate/pending work before authorizing protection release.'
}

$disconnectStart=$src.IndexOf('static VOID RgDisconnect(PVOID ConnectionCookie)')
$disconnectEnd=$src.IndexOf('NTSTATUS RgInstanceSetup(',$disconnectStart)
if($disconnectStart -lt 0 -or $disconnectEnd -lt 0){throw 'Disconnect source block missing.'}
$disconnectBlock=$src.Substring($disconnectStart,$disconnectEnd-$disconnectStart)
foreach($required in @(
    'protectionRequired = InterlockedCompareExchange(&gProtectionRequired, 0, 0)',
    'gracefulDisconnect = InterlockedCompareExchange(&gGracefulDisconnectAuthorized, 0, 0)',
    'InterlockedExchange(&gDegradedProtected, 1)',
    'InterlockedExchange(&gClientConnected, 0)',
    'if (protectionRequired != 0 && gracefulDisconnect == 0)',
    'InterlockedExchange(&gMaintenanceRequested, 0)',
    'releaseVolume = gGateVolume',
    'gGateVolume = NULL',
    'gGateVolumeLengthBytes = 0',
    'gGateRootLengthBytes = 0',
    'FltObjectDereference(releaseVolume)',
    'RtlSecureZeroMemory(gGateRoot, sizeof(gGateRoot))'
)){
    if($disconnectBlock -notmatch [regex]::Escape($required)){throw "Disconnect fail-safe invariant missing: $required"}
}
$publishDegraded=$disconnectBlock.IndexOf('InterlockedExchange(&gDegradedProtected, 1)')
$publishDisconnected=$disconnectBlock.IndexOf('InterlockedExchange(&gClientConnected, 0)')
if($publishDegraded -lt 0 -or $publishDisconnected -lt 0 -or $publishDegraded -gt $publishDisconnected){
    throw 'Unexpected disconnect must publish DEGRADED_PROTECTED before publishing client loss.'
}

$connectStart=$src.IndexOf('static NTSTATUS RgConnect(PFLT_PORT ClientPort')
$connectEnd=$src.IndexOf('static NTSTATUS RgMessage(PVOID ConnectionCookie',$connectStart)
if($connectStart -lt 0 -or $connectEnd -lt 0){throw 'Connect source block missing.'}
$connectBlock=$src.Substring($connectStart,$connectEnd-$connectStart)
foreach($required in @(
    'FltGetVolumeFromName(gFilter, &volumeName, &candidateVolume)',
    'context->GateVolumeLengthBytes',
    'gGateVolumeLengthBytes != (USHORT)volumeBytes',
    'gGateVolume != candidateVolume',
    'InterlockedCompareExchange(&gProtectionRequired, 0, 0) != 0',
    'gGateRootLengthBytes != (USHORT)rootBytes',
    'RtlCompareMemory(gGateRoot, context->GateRoot, rootBytes) != rootBytes',
    'gGateVolume = candidateVolume',
    'candidateVolume = NULL',
    'FltObjectDereference(candidateVolume)',
    'InterlockedExchange(&gClientConnected, 1)',
    'InterlockedExchange(&gDegradedProtected, 0)'
)){
    if($connectBlock -notmatch [regex]::Escape($required)){throw "Degraded reconnect invariant missing: $required"}
}
$publishConnected=$connectBlock.LastIndexOf('InterlockedExchange(&gClientConnected, 1)')
$clearDegraded=$connectBlock.LastIndexOf('InterlockedExchange(&gDegradedProtected, 0)')
if($publishConnected -lt 0 -or $clearDegraded -lt 0 -or $publishConnected -gt $clearDegraded){
    throw 'Reconnect must publish the live client before clearing DEGRADED_PROTECTED.'
}
if($proto -match '(?i)ReleaseContainment|ClearContainment' -or $messageBlock -match '(?i)RgControl(Release|Clear)Contain'){
    throw 'LAB containment must not expose a standalone runtime containment-release/bypass command; whole-session DeactivateGate is the reviewed maintenance transition.'
}

$preCreateStart=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreCreate(')
$preCreateEnd=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreAcquireForSectionSynchronization',$preCreateStart)
$preWriteStart=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreWrite(')
$preWriteEnd=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreSetInformation',$preWriteStart)
$preSetStart=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreSetInformation(')
$preSetEnd=$src.IndexOf('static NTSTATUS RgPopulateEvent',$preSetStart)
if($preCreateStart -lt 0 -or $preCreateEnd -lt 0 -or $preWriteStart -lt 0 -or $preWriteEnd -lt 0 -or $preSetStart -lt 0 -or $preSetEnd -lt 0){
    throw 'Containment callback source boundaries missing.'
}
$preCreateBlock=$src.Substring($preCreateStart,$preCreateEnd-$preCreateStart)
$preWriteBlock=$src.Substring($preWriteStart,$preWriteEnd-$preWriteStart)
$preSetBlock=$src.Substring($preSetStart,$preSetEnd-$preSetStart)
$readOnlyCreateBypass=$preCreateBlock.IndexOf('if (!RgCreateMayMutate(&event))')
$createGateCall=$preCreateBlock.LastIndexOf('RgGateEvent(Data, &event')
if($readOnlyCreateBypass -lt 0 -or $createGateCall -lt 0 -or $readOnlyCreateBypass -gt $createGateCall){
    throw 'Read-only CREATE must bypass the synchronous user-mode gate before RgGateEvent.'
}
if($preCreateBlock -notmatch [regex]::Escape('if (RgIsContainedRequestor(Data))') -or
   $preCreateBlock.IndexOf('if (RgIsContainedRequestor(Data))') -gt $createGateCall){
    throw 'Mutation-capable CREATE must fail in kernel for the contained process before the user-mode gate.'
}
if($preWriteBlock -notmatch [regex]::Escape('if (RgIsContainedRequestor(Data))') -or
   $preWriteBlock.IndexOf('if (RgIsContainedRequestor(Data))') -gt $preWriteBlock.IndexOf('RgGateEvent(Data, &event')){
    throw 'Non-paging WRITE must fail in kernel for the contained process before the user-mode gate.'
}
if($preSetBlock -notmatch [regex]::Escape('if (RgIsContainedRequestor(Data))') -or
   $preSetBlock.IndexOf('if (RgIsContainedRequestor(Data))') -gt $preSetBlock.IndexOf('RgGateEvent(Data, &event')){
    throw 'RENAME/DELETE/TRUNCATE must fail in kernel for the contained process before the user-mode gate.'
}
foreach($block in @($preCreateBlock,$preWriteBlock,$preSetBlock)){
    if($block -notmatch [regex]::Escape('RgClassifyMutationScope(&event, FltObjects)')){
        throw 'Mutation callback must classify source/destination scope through the protocol-v17 volume-aware classifier.'
    }
}
if($preCreateBlock -notmatch [regex]::Escape('scope == RgScopeAmbiguous') -or
   $preCreateBlock -notmatch [regex]::Escape('RgCreateMayMutate(&event)') -or
   $preWriteBlock -notmatch [regex]::Escape('scope == RgScopeAmbiguous') -or
   $preSetBlock -notmatch [regex]::Escape('scope == RgScopeAmbiguous')){
    throw 'Ambiguous protected-volume mutation scope must fail closed while read-only CREATE remains available.'
}

$createMutability=$preCreateBlock.IndexOf('if (RgCreateMayMutate(&event))')
$createInject=$preCreateBlock.IndexOf('RgInjectScopeAmbiguityProbe(Data, &event)',$createMutability)
$createClassify=$preCreateBlock.IndexOf('RgClassifyMutationScope(&event, FltObjects)',$createInject)
if($createMutability -lt 0 -or $createInject -lt 0 -or $createClassify -lt 0 -or
   $createMutability -gt $createInject -or $createInject -gt $createClassify){
    throw 'Scope ambiguity fault probe must be one-shot only on mutation-capable CREATE before scope classification.'
}
foreach($block in @($preWriteBlock,$preSetBlock)){
    $inject=$block.IndexOf('RgInjectScopeAmbiguityProbe(Data, &event)')
    $classify=$block.IndexOf('RgClassifyMutationScope(&event, FltObjects)')
    if($inject -lt 0 -or $classify -lt 0 -or $inject -gt $classify){
        throw 'WRITE/SET_INFORMATION scope ambiguity probe must execute before scope classification.'
    }
}

$scopeStart=$src.IndexOf('static RG_SCOPE_CLASSIFICATION RgClassifyMutationScope(')
$scopeEnd=$src.IndexOf('static BOOLEAN RgIsContainedRequestor',$scopeStart)
if($scopeStart -lt 0 -or $scopeEnd -lt 0){throw 'Volume-aware mutation scope classifier source block missing.'}
$scopeBlock=$src.Substring($scopeStart,$scopeEnd-$scopeStart)
foreach($required in @(
    'RgEventDestinationPathMatchesGateRoot(Event)',
    'sourceScope == RgScopeInside || destinationScope == RgScopeInside',
    'sourceScope == RgScopeOutside && destinationScope == RgScopeOutside',
    'RgIsOnGateVolume(FltObjects) ? RgScopeAmbiguous : RgScopeOutside',
    'Event->ProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId'
)){
    if($scopeBlock -notmatch [regex]::Escape($required)){throw "Protocol-v17 scope classifier invariant missing: $required"}
}
if($src -notmatch 'static VOID RgDisconnect[\s\S]*RgClearContainedProcess\(\)' -or
   $src -notmatch 'NTSTATUS RgUnload[\s\S]*RgClearContainedProcess\(\)'){
    throw 'Disconnect and unload must release the referenced containment process object.'
}
if($src -notmatch 'static VOID RgDisconnect[\s\S]*RgClearScopeAmbiguityProbe\(\)' -or
   $src -notmatch 'NTSTATUS RgUnload[\s\S]*RgClearScopeAmbiguityProbe\(\)'){
    throw 'Disconnect and unload must release the referenced LAB scope-ambiguity process object.'
}

if($src -notmatch 'FltCreateCommunicationPort\([^;]*RgConnect,\s*RgDisconnect,\s*RgMessage,\s*1\)' -and
   $src -notmatch 'RgConnect, RgDisconnect, RgMessage, 1'){
    throw 'Communication port must register RgMessage for activation handshake.'
}
if($proto -notmatch '#define\s+RG_PROTOCOL_VERSION\s+17u'){throw 'Minifilter protocol must be v17 for protected-volume scope binding.'}
if($proto -notmatch 'RG_GATE_ROOT_CHARS'){throw 'Protocol must carry an explicit bounded gate root.'}
foreach($required in @('RgControlActivateAndContainProcess','RgControlQueryContainment','RgControlDeactivateGate','RgControlArmScopeAmbiguity','TargetProcessId','ContainmentActive','ProtectionState','ContainedProcessId','RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR','RgEventContainmentActivated','RgProtectionDegradedProtected','RgProtectionMaintenance')){
    if($proto -notmatch [regex]::Escape($required)){throw "Protocol v17 protection/containment field missing: $required"}
}
if($proto -notmatch 'GateVolumeLengthBytes'){throw 'Protocol v17 must carry the protected NT volume length inside the fixed-size connect context.'}
if($src -notmatch [regex]::Escape('FltGetVolumeFromName(gFilter, &volumeName, &candidateVolume)') -or
   $src -notmatch [regex]::Escape('FltObjectDereference(releaseVolume)')){
    throw 'Protected volume must use a Filter Manager rundown reference with explicit release.'
}
if($src -notmatch [regex]::Escape('Event->ProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId')){
    throw 'Gate client PID must be excluded from ambiguous-volume enforcement to prevent rollback-store self-deadlock.'
}
if($proto -notmatch 'RG_CREATE_DISPOSITION_SHIFT'){throw 'Protocol must carry CREATE disposition/options semantics.'}
if($proto -notmatch 'DestinationPathStatus' -or $proto -notmatch 'DestinationPath\[RG_PATH_CHARS\]'){throw 'Protocol v8 must carry bounded rename destination path metadata.'}
if($proto -notmatch 'RgEventRenameResult' -or $proto -notmatch 'RelatedSequence' -or $proto -notmatch 'CompletionStatus'){throw 'Protocol v8 must carry correlated post-rename completion metadata.'}
if($proto -notmatch 'RgEventCreateResult' -or $proto -notmatch 'RgEventPagingWrite' -or
   $proto -notmatch 'RgEventWritableSection' -or $proto -notmatch 'RgEventActivationPreflight' -or
   $proto -notmatch 'RG_EVENT_FLAG_PAGING_IO' -or $proto -notmatch 'IdentityStatus' -or
   $proto -notmatch 'VolumeSerialNumber' -or $proto -notmatch 'FileIdLow' -or $proto -notmatch 'FileIdHigh'){
    throw 'Protocol v8 must carry correlated post-operation identity metadata.'
}
if($src -notmatch 'RgEventRenameResult' -or
   $src -notmatch 'KeGetCurrentIrql\(\)\s*==\s*PASSIVE_LEVEL' -or
   $src -notmatch '!KeAreAllApcsDisabled\(\)' -or
   $src -notmatch 'RgPopulatePostOperationIdentity\(&event, FltObjects\)'){
    throw 'Successful RENAME completion must guard FltQueryInformationFile by PASSIVE_LEVEL/APC state before emitting RenameResult.'
}

if($proto -notmatch 'RgEventTruncateResult'){
    throw 'Protocol v17 must retain a correlated TruncateResult event.'
}
if($src -notmatch [regex]::Escape('context->PostEventType = RgEventTruncateResult') -or
   $src -notmatch [regex]::Escape('event.EventType = context->PostEventType') -or
   $src -notmatch [regex]::Escape('event.RelatedSequence = context->RequestSequence')){
    throw 'TRUNCATE must carry exact request correlation into authoritative post-operation evidence.'
}
if($src -notmatch [regex]::Escape('((PLARGE_INTEGER)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->QuadPart')){
    throw 'TRUNCATE pre-operation event must carry the exact requested length from SetInformation.'
}
if($src -notmatch [regex]::Escape('context->FileInformationClass == FileEndOfFileInformation') -or
   $src -notmatch [regex]::Escape('context->FileInformationClass == FileAllocationInformation') -or
   $src -notmatch [regex]::Escape('FileStandardInformation')){
    throw 'Successful TRUNCATE result must query authoritative EOF/allocation state when safe.'
}
$truncatePost=$src.IndexOf('context->PostEventType == RgEventTruncateResult')
$truncatePassive=$src.IndexOf('KeGetCurrentIrql() == PASSIVE_LEVEL',$truncatePost)
$truncateApc=$src.IndexOf('!KeAreAllApcsDisabled()',$truncatePost)
$truncateQuery=$src.IndexOf('FltQueryInformationFile(',$truncatePost)
$truncateQueue=$src.IndexOf('RgQueueRawEvent(&event, RgClientLabGate)',$truncatePost)
if($truncatePost -lt 0 -or $truncatePassive -lt 0 -or $truncateApc -lt 0 -or $truncateQuery -lt 0 -or $truncateQueue -lt 0 -or
   $truncatePost -gt $truncatePassive -or $truncatePassive -gt $truncateQuery -or $truncateApc -gt $truncateQuery -or $truncateQuery -gt $truncateQueue){
    throw 'TRUNCATE post-operation FILE_STANDARD_INFO query must remain PASSIVE/APC-safe and precede no-reply result delivery.'
}

if($proto -notmatch 'RgEventDeleteDispositionResult' -or
   $proto -notmatch 'RgEventDeleteFinalized' -or
   $proto -notmatch 'RG_DELETE_DISPOSITION_DELETE' -or
   $proto -notmatch 'RG_EVENT_FLAG_DELETE_CLEANUP'){
    throw 'Protocol v16 must expose correlated DELETE disposition and cleanup lifecycle evidence.'
}
$deletePopulate=$src.IndexOf('} else if (EventType == RgEventDeleteDisposition) {')
$deleteReadFlags=$src.IndexOf('RgReadDeleteDispositionFlags(Data, &Event->Flags)',$deletePopulate)
if($deletePopulate -lt 0 -or $deleteReadFlags -lt 0 -or $deletePopulate -gt $deleteReadFlags){
    throw 'DELETE pre-operation event must carry the exact FileDispositionInformation/Ex flags.'
}
$deletePre=$src.IndexOf('else if (eventType == RgEventDeleteDisposition)')
$deleteContext=$src.IndexOf('RgCreateDeletePostContext(Data, event.Sequence, &postContext)',$deletePre)
$deleteGate=$src.IndexOf('RgGateEvent(Data, &event',$deleteContext)
if($deletePre -lt 0 -or $deleteContext -lt 0 -or $deleteGate -lt 0 -or
   $deletePre -gt $deleteContext -or $deleteContext -gt $deleteGate){
    throw 'DELETE must capture exact post-operation correlation before entering the blocking user-mode gate.'
}
$deletePost=$src.IndexOf('context->PostEventType == RgEventDeleteDispositionResult')
$deleteIdentity=$src.IndexOf('RgPopulatePostOperationIdentity(&event, FltObjects)',$deletePost)
$deleteStateQuery=$src.IndexOf('FileStandardInformation',$deleteIdentity)
$deleteAttach=$src.IndexOf('RgAttachDeleteHandleContext(',$deleteStateQuery)
$deleteQueue=$src.IndexOf('RgQueueRawEvent(&event, RgClientLabGate)',$deleteAttach)
if($deletePost -lt 0 -or $deleteIdentity -lt 0 -or $deleteStateQuery -lt 0 -or
   $deleteAttach -lt 0 -or $deleteQueue -lt 0 -or
   $deletePost -gt $deleteIdentity -or $deleteIdentity -gt $deleteStateQuery -or
   $deleteStateQuery -gt $deleteAttach -or $deleteAttach -gt $deleteQueue){
    throw 'Successful DELETE disposition must query state when safe, bind the exact stream-handle context, then emit no-reply disposition evidence.'
}
if($src -notmatch [regex]::Escape('RgCancelDeleteHandleContext(FltObjects)')){
    throw 'A successful disposition-clear request must cancel the exact handle-scoped DELETE lifecycle context.'
}
$cleanupStart=$src.IndexOf('FLT_PREOP_CALLBACK_STATUS RgPreCleanup(')
$cleanupEnd=$src.IndexOf('static VOID RgAttachPagingStreamContext',$cleanupStart)
if($cleanupStart -lt 0 -or $cleanupEnd -lt 0){throw 'DELETE cleanup callback block missing.'}
$cleanupBlock=$src.Substring($cleanupStart,$cleanupEnd-$cleanupStart)
foreach($forbidden in @('RgGateEvent(','FltGetFileNameInformation(','FltQueryInformationFile(')){
    if($cleanupBlock.Contains($forbidden)){throw "DELETE cleanup lifecycle must remain no-reply and filesystem-query free: $forbidden"}
}
foreach($required in @(
    'FltGetStreamHandleContext',
    'FLT_PREOP_SUCCESS_WITH_CALLBACK',
    'RG_EVENT_FLAG_DELETE_CLEANUP',
    'RgQueueDeleteFinalization(',
    'FltReleaseContext(context)'
)){
    if($cleanupBlock -notmatch [regex]::Escape($required)){throw "DELETE cleanup lifecycle invariant missing: $required"}
}
$deleteFinalizer=$src.IndexOf('static VOID RgQueueDeleteFinalization(')
if($deleteFinalizer -lt 0 -or
   $src.IndexOf('event.EventType = RgEventDeleteFinalized',$deleteFinalizer) -lt 0 -or
   $src.IndexOf('event.RelatedSequence = Context->RequestSequence',$deleteFinalizer) -lt 0){
    throw 'DELETE cleanup/cancellation evidence must remain correlated to the exact disposition request.'
}
if($proto -notmatch 'RgGateBaselineCommitted' -or $proto -notmatch 'RgGateNoPreservationRequired'){throw 'Protocol must distinguish committed absence baselines from no-op create opens.'}
if($infText -notmatch 'StartType\s*=\s*3'){throw 'Driver must remain demand-start in the lab prototype.'}
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){throw 'Automatic volume attachment must remain suppressed.'}
if($infText -notmatch 'Instance1\.Altitude\s*=\s*"370099\.4242"'){throw 'Unexpected LAB altitude. Review altitude policy manually.'}
Write-Host 'LAB pre-write gate source check PASSED, including protocol-v16 disconnect fail-safe state, DELETE/TRUNCATE reconciliation, event-bound PEPROCESS containment, fail-closed activation preflight, bounded admission and paging/section evidence.' -ForegroundColor Green
Write-Host 'Gate scope: one explicit NT root negotiated by the single connected client.'
Write-Host 'In-scope mutations normally require an explicit preservation decision; an activation-bound contained PEPROCESS is denied before the user-mode gate.'
Write-Host 'Out-of-scope/unresolved I/O remains fail-open; no process-control or kernel file-writing APIs are present.'
Write-Host 'Demand start: yes; automatic attachment suppressed: yes.'
Write-Host 'x64 build/validation tools required; ApiValidator remains enabled.'
Write-Warning 'Altitude 370099.4242 is an UNASSIGNED LAB placeholder. Never ship it. Microsoft must allocate the production altitude.'
Write-Warning 'The blocking gate is LAB ONLY. Do not load this prototype on a primary workstation.'
