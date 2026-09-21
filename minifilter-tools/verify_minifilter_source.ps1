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
    'FileEndOfFileInformation',
    'FileAllocationInformation',
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
    'gPreflightProbeArmed'
)){
    if($src -notmatch [regex]::Escape($required)){throw "LAB write-gate invariant missing: $required"}
}
if($src -notmatch 'InterlockedIncrement\(&gGateInFlight\)' -or
   $src -notmatch 'inFlight\s*>\s*RG_MAX_GATE_INFLIGHT' -or
   $src -notmatch 'STATUS_DEVICE_BUSY'){
    throw 'Kernel gate must fail closed when the bounded in-flight admission limit is exceeded.'
}
$gateStart=$src.IndexOf('static BOOLEAN RgGateEvent(const RG_EVENT *Event, PULONG ErrorCode, PULONG Decision)')
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
foreach($required in @('RgControlActivateGate','RgControlQueryActivation','RgControlArmPreflight','gPreflightProbeArmed','gActivationHazard','gGateActivated','STATUS_DEVICE_BUSY')){
    if($messageBlock -notmatch [regex]::Escape($required)){throw "Activation control callback missing invariant: $required"}
}
if($src -notmatch 'FltCreateCommunicationPort\([^;]*RgConnect,\s*RgDisconnect,\s*RgMessage,\s*1\)' -and
   $src -notmatch 'RgConnect, RgDisconnect, RgMessage, 1'){
    throw 'Communication port must register RgMessage for activation handshake.'
}
if($proto -notmatch '#define\s+RG_PROTOCOL_VERSION\s+11u'){throw 'Minifilter protocol must be v11 for activation preflight and writable-section attestation.'}
if($proto -notmatch 'RG_GATE_ROOT_CHARS'){throw 'Protocol must carry an explicit bounded gate root.'}
if($src -notmatch 'Unresolved/out-of-root paths fail open'){throw 'LAB gate must document fail-open behavior outside the explicitly resolved gate root.'}
if($src -notmatch 'requestorPid\s*==\s*\(ULONGLONG\)InterlockedCompareExchange64\(&gClientProcessId'){throw 'Gate client PID must be excluded to prevent rollback-store self-deadlock.'}
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
if($proto -notmatch 'RgGateBaselineCommitted' -or $proto -notmatch 'RgGateNoPreservationRequired'){throw 'Protocol must distinguish committed absence baselines from no-op create opens.'}
if($infText -notmatch 'StartType\s*=\s*3'){throw 'Driver must remain demand-start in the lab prototype.'}
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){throw 'Automatic volume attachment must remain suppressed.'}
if($infText -notmatch 'Instance1\.Altitude\s*=\s*"370099\.4242"'){throw 'Unexpected LAB altitude. Review altitude policy manually.'}
Write-Host 'LAB pre-write gate source check PASSED, including fail-closed activation preflight, bounded admission, paging visibility and no-reply writable-section attestation.' -ForegroundColor Green
Write-Host 'Gate scope: one explicit NT root negotiated by the single connected client.'
Write-Host 'In-scope CREATE/WRITE/RENAME/DELETE/TRUNCATE require an explicit user-mode preservation decision; allowed CREATE/RENAME operations emit correlated post-operation reconciliation.'
Write-Host 'Out-of-scope/unresolved I/O remains fail-open; no process-control or kernel file-writing APIs are present.'
Write-Host 'Demand start: yes; automatic attachment suppressed: yes.'
Write-Host 'x64 build/validation tools required; ApiValidator remains enabled.'
Write-Warning 'Altitude 370099.4242 is an UNASSIGNED LAB placeholder. Never ship it. Microsoft must allocate the production altitude.'
Write-Warning 'The blocking gate is LAB ONLY. Do not load this prototype on a primary workstation.'
