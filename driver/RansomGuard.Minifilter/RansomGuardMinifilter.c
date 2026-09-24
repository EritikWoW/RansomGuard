#include "RansomGuardMinifilter.h"

C_ASSERT(sizeof(RG_EVENT) == 2168);
C_ASSERT(sizeof(RG_CONNECT_CONTEXT) == 544);
C_ASSERT(sizeof(RG_GATE_REPLY) == 24);
C_ASSERT(sizeof(RG_CONTROL_REQUEST) == 16);
C_ASSERT(sizeof(RG_CONTROL_REPLY) == 32);

static PFLT_FILTER gFilter = NULL;
static PFLT_PORT gServerPort = NULL;
static PFLT_PORT gClientPort = NULL;
static PFLT_VOLUME gGateVolume = NULL;
static FAST_MUTEX gPortMutex;
static EX_RUNDOWN_REF gRundown;
static EX_RUNDOWN_REF gPortRundown;
static volatile LONG gPortRundownCompleted = 0;
static volatile LONG gGateInFlight = 0;
static volatile LONG gUnloading = 0;
static volatile LONG gClientConnected = 0;
static volatile LONG gClientMode = 0;
static volatile LONG64 gClientProcessId = 0;
static PEPROCESS gContainedProcess = NULL;
static volatile LONG64 gContainedProcessId = 0;
static volatile LONG gGateActivated = 0;
static volatile LONG gActivationHazard = 0;
static volatile LONG gPreflightProbeArmed = 0;
static volatile LONG gProtectionRequired = 0;
static volatile LONG gDegradedProtected = 0;
static volatile LONG gMaintenanceRequested = 0;
static volatile LONG gGracefulDisconnectAuthorized = 0;
static volatile LONG gPending = 0;
static volatile LONG gDropped = 0;
static volatile LONG64 gSequence = 0;
static WCHAR gGateRoot[RG_GATE_ROOT_CHARS];
static USHORT gGateRootLengthBytes = 0;
static USHORT gGateVolumeLengthBytes = 0;

typedef enum _RG_SCOPE_CLASSIFICATION {
    RgScopeOutside = 0,
    RgScopeInside = 1,
    RgScopeAmbiguous = 2
} RG_SCOPE_CLASSIFICATION;

static VOID RgQueueEvent(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ RG_EVENT_TYPE EventType, _In_ ULONG FileInformationClass);
static VOID RgQueueRawEvent(_In_ const RG_EVENT *Event, _In_ LONG ClientMode);
static VOID RgSendWorker(_In_ PVOID Parameter);
static NTSTATUS RgCreateRenamePostContext(_Inout_ PFLT_CALLBACK_DATA Data,
                                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                          _In_ ULONGLONG RequestSequence,
                                          _Outptr_ PRG_POST_CONTEXT *PostContext);
static NTSTATUS RgCreateTruncatePostContext(_Inout_ PFLT_CALLBACK_DATA Data,
                                            _In_ ULONGLONG RequestSequence,
                                            _Outptr_ PRG_POST_CONTEXT *PostContext);
static NTSTATUS RgCreateDeletePostContext(_Inout_ PFLT_CALLBACK_DATA Data,
                                          _In_ ULONGLONG RequestSequence,
                                          _Outptr_ PRG_POST_CONTEXT *PostContext);
static NTSTATUS RgCreateCreatePostContext(_Inout_ PFLT_CALLBACK_DATA Data,
                                          _In_ ULONGLONG RequestSequence,
                                          _Outptr_ PRG_POST_CONTEXT *PostContext);
static VOID RgFreePostContext(_In_opt_ PRG_POST_CONTEXT PostContext);
static VOID RgPopulatePostOperationIdentity(_Inout_ PRG_EVENT Event,
                                         _In_ PCFLT_RELATED_OBJECTS FltObjects);
static FLT_POSTOP_CALLBACK_STATUS RgPostSetInformationSafe(_Inout_ PFLT_CALLBACK_DATA Data,
                                                           _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                           _In_opt_ PVOID CompletionContext,
                                                           _In_ FLT_POST_OPERATION_FLAGS Flags);
static NTSTATUS RgConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                          _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                          _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);
static VOID RgDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS RgMessage(_In_opt_ PVOID ConnectionCookie,
                          _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
                          _In_ ULONG InputBufferSize,
                          _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
                          _In_ ULONG OutputBufferSize,
                          _Out_ PULONG ReturnOutputBufferLength);
static NTSTATUS RgPopulateEvent(_Out_ PRG_EVENT Event, _Inout_ PFLT_CALLBACK_DATA Data,
                                _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_ RG_EVENT_TYPE EventType, _In_ ULONG FileInformationClass);
static NTSTATUS RgReadDeleteDispositionFlags(_In_ PFLT_CALLBACK_DATA Data, _Out_ PULONG Flags);
static VOID RgPopulateRenameDestination(_Inout_ PRG_EVENT Event, _Inout_ PFLT_CALLBACK_DATA Data,
                                        _In_ PCFLT_RELATED_OBJECTS FltObjects);
static BOOLEAN RgPathMatchesGateRoot(_In_ ULONG PathStatus, _In_reads_z_ const WCHAR *Path);
static BOOLEAN RgEventPathMatchesGateRoot(_In_ const RG_EVENT *Event);
static BOOLEAN RgEventDestinationPathMatchesGateRoot(_In_ const RG_EVENT *Event);
static BOOLEAN RgEventIsInsideGateRoot(_In_ const RG_EVENT *Event);
static BOOLEAN RgIsOnGateVolume(_In_ PCFLT_RELATED_OBJECTS FltObjects);
static RG_SCOPE_CLASSIFICATION RgClassifyMutationScope(
    _In_ const RG_EVENT *Event,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);
static BOOLEAN RgIsContainedRequestor(_In_ PFLT_CALLBACK_DATA Data);
static BOOLEAN RgCreateMayMutate(_In_ const RG_EVENT *Event);
static VOID RgClearContainedProcess(VOID);
static BOOLEAN RgBindContainedRequestor(_In_ PFLT_CALLBACK_DATA Data,
                                        _In_ const RG_EVENT *Event,
                                        _Out_opt_ PULONG ErrorCode);
static BOOLEAN RgGateEvent(_In_ PFLT_CALLBACK_DATA Data,
                           _In_ const RG_EVENT *Event,
                           _Out_opt_ PULONG ErrorCode,
                           _Out_opt_ PULONG Decision);
static BOOLEAN RgAcquireClientPort(_In_ LONG ExpectedMode);
static VOID RgReleaseClientPort(VOID);
static VOID RgWaitForPortUsers(VOID);
static LONG RgCurrentClientMode(VOID);
static ULONG RgCurrentProtectionState(VOID);
static BOOLEAN RgIsDegradedProtected(VOID);
static BOOLEAN RgIsPagingWrite(_In_ PFLT_CALLBACK_DATA Data);
static VOID RgObservePagingWrite(_Inout_ PFLT_CALLBACK_DATA Data,
                                 _In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID RgAttachPagingStreamContext(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ const RG_EVENT *CreateResult,
                                        _In_ ULONG PreservationDecision,
                                        _In_ ULONGLONG CreateRequestSequence);
static VOID RgObserveWritableSection(_Inout_ PFLT_CALLBACK_DATA Data,
                                     _In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID RgAttachDeleteHandleContext(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ ULONGLONG RequestSequence,
                                        _In_ ULONG FileInformationClass,
                                        _In_ ULONG DispositionFlags);
static VOID RgCancelDeleteHandleContext(_In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID RgQueueDeleteFinalization(_In_ PRG_DELETE_HANDLE_CONTEXT Context,
                                      _In_ ULONG EventFlags,
                                      _In_ ULONG CompletionStatus,
                                      _In_ ULONGLONG CompletionInformation,
                                      _In_opt_ PFLT_CALLBACK_DATA Data);
static VOID RgStreamContextCleanup(_In_ PFLT_CONTEXT Context,
                                   _In_ FLT_CONTEXT_TYPE ContextType);
static FLT_PREOP_CALLBACK_STATUS RgCompleteDenied(_Inout_ PFLT_CALLBACK_DATA Data);

static const FLT_CONTEXT_REGISTRATION gContexts[] = {
    { FLT_STREAM_CONTEXT, 0, RgStreamContextCleanup, sizeof(RG_STREAM_CONTEXT), RG_POOL_TAG },
    { FLT_STREAMHANDLE_CONTEXT, 0, RgStreamContextCleanup, sizeof(RG_DELETE_HANDLE_CONTEXT), RG_POOL_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, RgPreCreate, RgPostCreate, NULL },
    { IRP_MJ_WRITE, 0, RgPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, RgPreSetInformation, RgPostSetInformation, NULL },
    { IRP_MJ_CLEANUP, 0, RgPreCleanup, RgPostCleanup, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, RgPreAcquireForSectionSynchronization, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    gContexts,
    gCallbacks,
    RgUnload,
    RgInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static BOOLEAN RgIsInterestingSetInfo(_In_ FILE_INFORMATION_CLASS InformationClass, _Out_ RG_EVENT_TYPE *EventType)
{
    switch (InformationClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        *EventType = RgEventRename;
        return TRUE;
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        *EventType = RgEventDeleteDisposition;
        return TRUE;
    case FileEndOfFileInformation:
    case FileAllocationInformation:
    case FileValidDataLengthInformation:
        *EventType = RgEventTruncate;
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN RgShouldObserve(_In_ PFLT_CALLBACK_DATA Data)
{
    if (InterlockedCompareExchange(&gUnloading, 0, 0) != 0) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&gClientConnected, 0, 0) == 0 &&
        InterlockedCompareExchange(&gDegradedProtected, 0, 0) == 0) {
        return FALSE;
    }

    if (Data->RequestorMode == KernelMode) {
        return FALSE;
    }

    if (FLT_IS_IRP_OPERATION(Data)) {
        const ULONG flags = Data->Iopb->IrpFlags;
        if (FlagOn(flags, IRP_PAGING_IO) || FlagOn(flags, IRP_SYNCHRONOUS_PAGING_IO)) {
            return FALSE;
        }
    }

    return TRUE;
}

static LONG RgCurrentClientMode(VOID)
{
    return InterlockedCompareExchange(&gClientMode, 0, 0);
}

static BOOLEAN RgIsDegradedProtected(VOID)
{
    return InterlockedCompareExchange(&gDegradedProtected, 0, 0) != 0;
}

static ULONG RgCurrentProtectionState(VOID)
{
    if (InterlockedCompareExchange(&gDegradedProtected, 0, 0) != 0) {
        return RgProtectionDegradedProtected;
    }

    if (InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0 ||
        InterlockedCompareExchange(&gGracefulDisconnectAuthorized, 0, 0) != 0) {
        return RgProtectionMaintenance;
    }

    if (InterlockedCompareExchange(&gClientConnected, 0, 0) != 0 &&
        RgCurrentClientMode() == RgClientLabGate) {
        return InterlockedCompareExchange(&gGateActivated, 0, 0) != 0
            ? RgProtectionProtected
            : RgProtectionPreflight;
    }

    return RgProtectionInactive;
}

static BOOLEAN RgIsPagingWrite(PFLT_CALLBACK_DATA Data)
{
    if (!FLT_IS_IRP_OPERATION(Data)) {
        return FALSE;
    }

    return FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
           FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO);
}

static FLT_PREOP_CALLBACK_STATUS RgCompleteDenied(PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS RgPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    RG_EVENT event;
    PRG_POST_CONTEXT postContext = NULL;
    NTSTATUS status;
    LONG mode;
    BOOLEAN degraded;
    RG_SCOPE_CLASSIFICATION scope;
    ULONG gateError = 0;
    ULONG gateDecision = RgGateDeny;

    *CompletionContext = NULL;
    if (!RgShouldObserve(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    degraded = RgIsDegradedProtected();
    mode = RgCurrentClientMode();
    if (mode == RgClientAudit && !degraded) {
        RgQueueEvent(Data, FltObjects, RgEventCreate, 0);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (mode != RgClientLabGate && !degraded) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = RgPopulateEvent(&event, Data, FltObjects, RgEventCreate, 0);

    if (InterlockedCompareExchange(&gGateActivated, 0, 0) == 0 &&
        event.ProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0) &&
        RgEventPathMatchesGateRoot(&event) &&
        InterlockedExchange(&gPreflightProbeArmed, 0) == 1) {
        status = RgCreateCreatePostContext(Data, event.Sequence, &postContext);
        if (!NT_SUCCESS(status)) {
            return RgCompleteDenied(Data);
        }
        postContext->ActivationPreflight = 1;
        *CompletionContext = postContext;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    scope = RgClassifyMutationScope(&event, FltObjects);
    if (scope == RgScopeOutside) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (scope == RgScopeAmbiguous) {
        // Read-only opens cannot mutate protected content. Mutation-capable CREATEs with an
        // unresolved normalized name fail closed only when the callback is on the bound gate volume.
        return RgCreateMayMutate(&event)
            ? RgCompleteDenied(Data)
            : FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (degraded) {
        if (!RgCreateMayMutate(&event)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        return RgCompleteDenied(Data);
    }

    if (InterlockedCompareExchange(&gGateActivated, 0, 0) == 0) {
        // During activation preflight, no external handle may enter the protected root.
        return RgCompleteDenied(Data);
    }

    // Read-only opens do not require preservation and must not enter the synchronous
    // user-mode gate. Besides avoiding needless latency, this prevents metadata probes
    // such as File.Exists/GetAttributes from being converted into 30-second gate waits.
    // Mutation-capable CREATEs remain fail-closed and receive post-create reconciliation.
    if (!RgCreateMayMutate(&event)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (RgIsContainedRequestor(Data)) {
        return RgCompleteDenied(Data);
    }

    status = RgCreateCreatePostContext(Data, event.Sequence, &postContext);
    if (!NT_SUCCESS(status)) {
        return RgCompleteDenied(Data);
    }

    if (!RgGateEvent(Data, &event, &gateError, &gateDecision)) {
        UNREFERENCED_PARAMETER(gateError);
        RgFreePostContext(postContext);
        return RgCompleteDenied(Data);
    }

    postContext->GateDecision = gateDecision;
    *CompletionContext = postContext;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RgPreAcquireForSectionSynchronization(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    ULONG protection;

    *CompletionContext = NULL;

    if (InterlockedCompareExchange(&gUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&gClientConnected, 0, 0) == 0 ||
        RgCurrentClientMode() != RgClientLabGate) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection & 0xFFu;
    if (protection != PAGE_READWRITE && protection != PAGE_EXECUTE_READWRITE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // FSFilter section-synchronization callbacks must not become a blocking user-mode policy gate.
    // Attest the already-committed CREATE baseline through the stream context and let the operation continue.
    RgObserveWritableSection(Data, FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RgPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    RG_EVENT event;
    LONG mode;
    BOOLEAN degraded;
    RG_SCOPE_CLASSIFICATION scope;
    ULONG gateError = 0;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (RgIsPagingWrite(Data)) {
        RgObservePagingWrite(Data, FltObjects);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!RgShouldObserve(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    degraded = RgIsDegradedProtected();
    mode = RgCurrentClientMode();
    if (mode == RgClientAudit && !degraded) {
        RgQueueEvent(Data, FltObjects, RgEventWrite, 0);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (mode != RgClientLabGate && !degraded) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    (void)RgPopulateEvent(&event, Data, FltObjects, RgEventWrite, 0);
    scope = RgClassifyMutationScope(&event, FltObjects);
    if (scope == RgScopeOutside) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (scope == RgScopeAmbiguous) {
        return RgCompleteDenied(Data);
    }

    if (degraded) {
        return RgCompleteDenied(Data);
    }

    if (InterlockedCompareExchange(&gGateActivated, 0, 0) == 0) {
        return RgCompleteDenied(Data);
    }

    if (RgIsContainedRequestor(Data)) {
        return RgCompleteDenied(Data);
    }

    if (!RgGateEvent(Data, &event, &gateError, NULL)) {
        UNREFERENCED_PARAMETER(gateError);
        return RgCompleteDenied(Data);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RgPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    RG_EVENT_TYPE eventType = RgEventInvalid;
    RG_EVENT event;
    PRG_POST_CONTEXT postContext = NULL;
    NTSTATUS status;
    LONG mode;
    BOOLEAN degraded;
    RG_SCOPE_CLASSIFICATION scope;
    ULONG gateError = 0;
    ULONG infoClass;

    *CompletionContext = NULL;
    if (!RgShouldObserve(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (!RgIsInterestingSetInfo((FILE_INFORMATION_CLASS)infoClass, &eventType)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    degraded = RgIsDegradedProtected();
    mode = RgCurrentClientMode();
    if (mode == RgClientAudit && !degraded) {
        RgQueueEvent(Data, FltObjects, eventType, infoClass);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (mode != RgClientLabGate && !degraded) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = RgPopulateEvent(&event, Data, FltObjects, eventType, infoClass);
    scope = RgClassifyMutationScope(&event, FltObjects);
    if (scope == RgScopeOutside) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (scope == RgScopeAmbiguous) {
        return RgCompleteDenied(Data);
    }

    if (degraded) {
        return RgCompleteDenied(Data);
    }

    if (InterlockedCompareExchange(&gGateActivated, 0, 0) == 0) {
        return RgCompleteDenied(Data);
    }

    if (RgIsContainedRequestor(Data)) {
        return RgCompleteDenied(Data);
    }

    if (eventType == RgEventRename) {
        status = RgCreateRenamePostContext(Data, FltObjects, event.Sequence, &postContext);
        if (!NT_SUCCESS(status)) {
            return RgCompleteDenied(Data);
        }
    } else if (eventType == RgEventTruncate) {
        status = RgCreateTruncatePostContext(Data, event.Sequence, &postContext);
        if (!NT_SUCCESS(status)) {
            return RgCompleteDenied(Data);
        }
    } else if (eventType == RgEventDeleteDisposition) {
        status = RgCreateDeletePostContext(Data, event.Sequence, &postContext);
        if (!NT_SUCCESS(status)) {
            return RgCompleteDenied(Data);
        }
    }

    if (!RgGateEvent(Data, &event, &gateError, NULL)) {
        UNREFERENCED_PARAMETER(gateError);
        RgFreePostContext(postContext);
        return RgCompleteDenied(Data);
    }

    if (postContext != NULL) {
        *CompletionContext = postContext;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS RgPopulateEvent(PRG_EVENT Event, PFLT_CALLBACK_DATA Data,
                                PCFLT_RELATED_OBJECTS FltObjects,
                                RG_EVENT_TYPE EventType, ULONG FileInformationClass)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG chars = 0;
    LARGE_INTEGER systemTime;

    RtlZeroMemory(Event, sizeof(*Event));
    Event->ProtocolVersion = RG_PROTOCOL_VERSION;
    Event->EventType = (ULONG)EventType;
    Event->PathStatus = RgPathUnknown;
    Event->Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    KeQuerySystemTimePrecise(&systemTime);
    Event->SystemTime100ns = systemTime.QuadPart;
    Event->ProcessId = (ULONGLONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    Event->ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    Event->FileInformationClass = FileInformationClass;

    if (EventType == RgEventWrite) {
        Event->ByteOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
        Event->Length = Data->Iopb->Parameters.Write.Length;
    } else if (EventType == RgEventCreate) {
        // Parameters.Create.Options carries CreateDisposition in the high byte and CreateOptions in the low 24 bits.
        Event->Flags = Data->Iopb->Parameters.Create.Options;
        if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
            Event->Length = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        }
    } else if (EventType == RgEventTruncate) {
        // FileAllocationInformation, FileEndOfFileInformation and FileValidDataLengthInformation
        // all begin with one LARGE_INTEGER length value. Carry that exact requested value in
        // ByteOffset so user mode can durably bind the intent before allowing the mutation.
        if (Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
            Data->Iopb->Parameters.SetFileInformation.Length < sizeof(LARGE_INTEGER)) {
            return STATUS_INVALID_PARAMETER;
        }
        Event->ByteOffset =
            ((PLARGE_INTEGER)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->QuadPart;
    } else if (EventType == RgEventDeleteDisposition) {
        status = RgReadDeleteDispositionFlags(Data, &Event->Flags);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        Event->PathStatus = RgPathQueryFailed;
        if (EventType == RgEventRename) {
            RgPopulateRenameDestination(Event, Data, FltObjects);
        }
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status)) {
        chars = nameInfo->Name.Length / sizeof(WCHAR);
        if (chars >= RG_PATH_CHARS) {
            chars = RG_PATH_CHARS - 1;
            Event->PathStatus = RgPathTruncated;
        } else {
            Event->PathStatus = RgPathResolved;
        }
        if (chars != 0) {
            RtlCopyMemory(Event->Path, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
        }
        Event->Path[chars] = L'\0';
    } else {
        Event->PathStatus = RgPathQueryFailed;
    }

    FltReleaseFileNameInformation(nameInfo);

    if (EventType == RgEventRename) {
        RgPopulateRenameDestination(Event, Data, FltObjects);
    }

    return status;
}

static NTSTATUS RgReadDeleteDispositionFlags(PFLT_CALLBACK_DATA Data, PULONG Flags)
{
    FILE_INFORMATION_CLASS infoClass;
    PVOID buffer;
    ULONG length;

    if (Data == NULL || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = 0;
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    length = Data->Iopb->Parameters.SetFileInformation.Length;

    if (buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (infoClass == FileDispositionInformation) {
        if (length < sizeof(FILE_DISPOSITION_INFORMATION)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile) {
            *Flags = RG_DELETE_DISPOSITION_DELETE;
        }
        return STATUS_SUCCESS;
    }

    if (infoClass == FileDispositionInformationEx) {
        if (length < sizeof(ULONG)) {
            return STATUS_INVALID_PARAMETER;
        }
        *Flags = *(PULONG)buffer;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_INFO_CLASS;
}

static VOID RgPopulateRenameDestination(PRG_EVENT Event, PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects)
{
    PFILE_RENAME_INFORMATION renameInfo;
    PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
    ULONG bufferLength;
    ULONG minimumLength = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    ULONG chars;
    NTSTATUS status;
    FILE_INFORMATION_CLASS infoClass;

    Event->DestinationPathStatus = RgPathUnknown;
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    bufferLength = Data->Iopb->Parameters.SetFileInformation.Length;
    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (renameInfo == NULL || bufferLength < minimumLength ||
        renameInfo->FileNameLength == 0 ||
        renameInfo->FileNameLength > (bufferLength - minimumLength) ||
        (renameInfo->FileNameLength % sizeof(WCHAR)) != 0) {
        Event->DestinationPathStatus = RgPathQueryFailed;
        return;
    }

    if (infoClass == FileRenameInformationEx) {
        Event->Flags = *(PULONG)renameInfo;
    } else {
        Event->Flags = renameInfo->ReplaceIfExists ? 1u : 0u;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        renameInfo->RootDirectory,
        renameInfo->FileName,
        renameInfo->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationInfo);

    if (!NT_SUCCESS(status) || destinationInfo == NULL) {
        Event->DestinationPathStatus = RgPathQueryFailed;
        return;
    }

    chars = destinationInfo->Name.Length / sizeof(WCHAR);
    if (chars >= RG_PATH_CHARS) {
        chars = RG_PATH_CHARS - 1;
        Event->DestinationPathStatus = RgPathTruncated;
    } else {
        Event->DestinationPathStatus = RgPathResolved;
    }

    if (chars != 0) {
        RtlCopyMemory(Event->DestinationPath, destinationInfo->Name.Buffer, chars * sizeof(WCHAR));
    }
    Event->DestinationPath[chars] = L'\0';
    FltReleaseFileNameInformation(destinationInfo);
}

static NTSTATUS RgCreateRenamePostContext(PFLT_CALLBACK_DATA Data,
                                          PCFLT_RELATED_OBJECTS FltObjects,
                                          ULONGLONG RequestSequence,
                                          PRG_POST_CONTEXT *PostContext)
{
    PFILE_RENAME_INFORMATION renameInfo;
    PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
    PRG_POST_CONTEXT context = NULL;
    ULONG bufferLength;
    ULONG minimumLength = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    NTSTATUS status;

    *PostContext = NULL;
    bufferLength = Data->Iopb->Parameters.SetFileInformation.Length;
    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (renameInfo == NULL || bufferLength < minimumLength ||
        renameInfo->FileNameLength == 0 ||
        renameInfo->FileNameLength > (bufferLength - minimumLength) ||
        (renameInfo->FileNameLength % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        renameInfo->RootDirectory,
        renameInfo->FileName,
        renameInfo->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationInfo);

    if (!NT_SUCCESS(status) || destinationInfo == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    context = (PRG_POST_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_POST_CONTEXT), RG_POOL_TAG);
    if (context == NULL) {
        FltReleaseFileNameInformation(destinationInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->RequestSequence = RequestSequence;
    context->PostEventType = RgEventRenameResult;
    context->FileInformationClass =
        (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    context->PreDestinationNameInfo = destinationInfo;
    *PostContext = context;
    return STATUS_SUCCESS;
}

static NTSTATUS RgCreateTruncatePostContext(PFLT_CALLBACK_DATA Data,
                                            ULONGLONG RequestSequence,
                                            PRG_POST_CONTEXT *PostContext)
{
    PRG_POST_CONTEXT context = NULL;

    *PostContext = NULL;
    context = (PRG_POST_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RG_POST_CONTEXT),
        RG_POOL_TAG);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->RequestSequence = RequestSequence;
    context->PostEventType = RgEventTruncateResult;
    context->FileInformationClass =
        (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    *PostContext = context;
    return STATUS_SUCCESS;
}

static NTSTATUS RgCreateDeletePostContext(PFLT_CALLBACK_DATA Data,
                                          ULONGLONG RequestSequence,
                                          PRG_POST_CONTEXT *PostContext)
{
    PRG_POST_CONTEXT context = NULL;
    ULONG dispositionFlags = 0;
    NTSTATUS status;

    *PostContext = NULL;
    status = RgReadDeleteDispositionFlags(Data, &dispositionFlags);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context = (PRG_POST_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RG_POST_CONTEXT),
        RG_POOL_TAG);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->RequestSequence = RequestSequence;
    context->PostEventType = RgEventDeleteDispositionResult;
    context->FileInformationClass =
        (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    context->DispositionFlags = dispositionFlags;
    *PostContext = context;
    return STATUS_SUCCESS;
}

static NTSTATUS RgCreateCreatePostContext(PFLT_CALLBACK_DATA Data,
                                          ULONGLONG RequestSequence,
                                          PRG_POST_CONTEXT *PostContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PRG_POST_CONTEXT context = NULL;
    NTSTATUS status;

    *PostContext = NULL;
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    context = (PRG_POST_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RG_POST_CONTEXT),
        RG_POOL_TAG);
    if (context == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->RequestSequence = RequestSequence;
    context->PostEventType = RgEventCreateResult;
    context->PreCreateNameInfo = nameInfo;
    *PostContext = context;
    return STATUS_SUCCESS;
}

static VOID RgPopulatePostOperationIdentity(PRG_EVENT Event,
                                         PCFLT_RELATED_OBJECTS FltObjects)
{
    FILE_ID_INFORMATION identity;
    ULONG returned = 0;
    NTSTATUS status;

    Event->IdentityStatus = RgIdentityUnknown;
    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        Event->IdentityStatus = RgIdentityQueryFailed;
        return;
    }

    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &identity,
        sizeof(identity),
        FileIdInformation,
        &returned);

    if (!NT_SUCCESS(status) || returned < (ULONG)sizeof(identity)) {
        Event->IdentityStatus = RgIdentityQueryFailed;
        return;
    }

    Event->VolumeSerialNumber = identity.VolumeSerialNumber;
    RtlCopyMemory(&Event->FileIdLow, identity.FileId.Identifier, sizeof(Event->FileIdLow));
    RtlCopyMemory(&Event->FileIdHigh,
        identity.FileId.Identifier + sizeof(Event->FileIdLow),
        sizeof(Event->FileIdHigh));
    Event->IdentityStatus = RgIdentityResolved;
}

static VOID RgFreePostContext(PRG_POST_CONTEXT PostContext)
{
    if (PostContext == NULL) {
        return;
    }

    if (PostContext->PreDestinationNameInfo != NULL) {
        FltReleaseFileNameInformation(PostContext->PreDestinationNameInfo);
        PostContext->PreDestinationNameInfo = NULL;
    }

    if (PostContext->PreCreateNameInfo != NULL) {
        FltReleaseFileNameInformation(PostContext->PreCreateNameInfo);
        PostContext->PreCreateNameInfo = NULL;
    }

    RtlSecureZeroMemory(PostContext, sizeof(*PostContext));
    ExFreePoolWithTag(PostContext, RG_POOL_TAG);
}

FLT_POSTOP_CALLBACK_STATUS RgPostCreate(PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects,
                                        PVOID CompletionContext,
                                        FLT_POST_OPERATION_FLAGS Flags)
{
    PRG_POST_CONTEXT context = (PRG_POST_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION tunneledInfo = NULL;
    PFLT_FILE_NAME_INFORMATION finalInfo = NULL;
    RG_EVENT event;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG chars = 0;
    LARGE_INTEGER systemTime;

    if (context == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        RgFreePostContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProtocolVersion = RG_PROTOCOL_VERSION;
    event.EventType = context->ActivationPreflight ? RgEventActivationPreflight : RgEventCreateResult;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    event.RelatedSequence = context->RequestSequence;
    event.CompletionStatus = (ULONG)Data->IoStatus.Status;
    event.CompletionInformation = (ULONGLONG)Data->IoStatus.Information;
    event.PathStatus = RgPathUnknown;
    event.IdentityStatus = RgIdentityUnknown;
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = systemTime.QuadPart;

    if (context->ActivationPreflight && context->PreCreateNameInfo != NULL) {
        chars = context->PreCreateNameInfo->Name.Length / sizeof(WCHAR);
        if (chars >= RG_PATH_CHARS) {
            chars = RG_PATH_CHARS - 1;
            event.PathStatus = RgPathTruncated;
        } else {
            event.PathStatus = RgPathResolved;
        }
        if (chars != 0) {
            RtlCopyMemory(event.Path, context->PreCreateNameInfo->Name.Buffer, chars * sizeof(WCHAR));
        }
        event.Path[chars] = L'\0';
    }

    if (NT_SUCCESS(Data->IoStatus.Status)) {
        status = FltGetTunneledName(Data, context->PreCreateNameInfo, &tunneledInfo);
        if (NT_SUCCESS(status)) {
            finalInfo = (tunneledInfo != NULL) ? tunneledInfo : context->PreCreateNameInfo;
            chars = finalInfo->Name.Length / sizeof(WCHAR);
            if (chars >= RG_PATH_CHARS) {
                chars = RG_PATH_CHARS - 1;
                event.PathStatus = RgPathTruncated;
            } else {
                event.PathStatus = RgPathResolved;
            }

            if (chars != 0) {
                RtlCopyMemory(event.Path, finalInfo->Name.Buffer, chars * sizeof(WCHAR));
            }
            event.Path[chars] = L'\0';
        } else {
            event.PathStatus = RgPathQueryFailed;
        }

        RgPopulatePostOperationIdentity(&event, FltObjects);

        if (context->ActivationPreflight) {
            if (FltObjects == NULL || FltObjects->FileObject == NULL ||
                FltObjects->FileObject->SectionObjectPointer == NULL ||
                event.PathStatus != RgPathResolved ||
                event.IdentityStatus != RgIdentityResolved) {
                InterlockedExchange(&gActivationHazard, 1);
            } else if (MmDoesFileHaveUserWritableReferences(
                           FltObjects->FileObject->SectionObjectPointer) != 0) {
                event.Flags |= RG_EVENT_FLAG_PREFLIGHT_WRITABLE_VIEW;
                InterlockedExchange(&gActivationHazard, 1);
            }
        } else {
            RgAttachPagingStreamContext(
                FltObjects, &event, context->GateDecision, context->RequestSequence);
        }
    } else if (context->ActivationPreflight) {
        InterlockedExchange(&gActivationHazard, 1);
    }

    RgQueueRawEvent(&event, RgClientLabGate);

    if (tunneledInfo != NULL) {
        FltReleaseFileNameInformation(tunneledInfo);
    }
    RgFreePostContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID RgStreamContextCleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType)
{
    if (Context == NULL) {
        return;
    }

    if (ContextType == FLT_STREAM_CONTEXT) {
        RtlSecureZeroMemory(Context, sizeof(RG_STREAM_CONTEXT));
    } else if (ContextType == FLT_STREAMHANDLE_CONTEXT) {
        RtlSecureZeroMemory(Context, sizeof(RG_DELETE_HANDLE_CONTEXT));
    }
}

static VOID RgQueueDeleteFinalization(PRG_DELETE_HANDLE_CONTEXT Context,
                                      ULONG EventFlags,
                                      ULONG CompletionStatus,
                                      ULONGLONG CompletionInformation,
                                      PFLT_CALLBACK_DATA Data)
{
    RG_EVENT event;
    LARGE_INTEGER systemTime;

    if (Context == NULL || Context->RequestSequence == 0) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProtocolVersion = RG_PROTOCOL_VERSION;
    event.EventType = RgEventDeleteFinalized;
    event.Flags = EventFlags;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    event.RelatedSequence = Context->RequestSequence;
    event.FileInformationClass = Context->FileInformationClass;
    event.CompletionStatus = CompletionStatus;
    event.CompletionInformation = CompletionInformation;
    if (Data != NULL) {
        event.ProcessId = (ULONGLONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        event.ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    }
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = systemTime.QuadPart;
    RgQueueRawEvent(&event, RgClientLabGate);
}

static VOID RgAttachDeleteHandleContext(PCFLT_RELATED_OBJECTS FltObjects,
                                        ULONGLONG RequestSequence,
                                        ULONG FileInformationClass,
                                        ULONG DispositionFlags)
{
    PRG_DELETE_HANDLE_CONTEXT context = NULL;
    PRG_DELETE_HANDLE_CONTEXT oldContext = NULL;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL ||
        RequestSequence == 0) {
        InterlockedIncrement(&gDropped);
        return;
    }

    status = FltAllocateContext(
        gFilter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(RG_DELETE_HANDLE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == NULL) {
        InterlockedIncrement(&gDropped);
        return;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->RequestSequence = RequestSequence;
    context->FileInformationClass = FileInformationClass;
    context->DispositionFlags = DispositionFlags;

    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
        context,
        (PFLT_CONTEXT *)&oldContext);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&gDropped);
    } else if (oldContext != NULL) {
        // A later delete-disposition request on the same handle supersedes the prior one.
        RgQueueDeleteFinalization(
            oldContext,
            RG_EVENT_FLAG_DELETE_CANCELLED,
            (ULONG)STATUS_SUCCESS,
            0,
            NULL);
    }

    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
    }
    FltReleaseContext(context);
}

static VOID RgCancelDeleteHandleContext(PCFLT_RELATED_OBJECTS FltObjects)
{
    PRG_DELETE_HANDLE_CONTEXT oldContext = NULL;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return;
    }

    status = FltDeleteStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT *)&oldContext);
    if (!NT_SUCCESS(status) || oldContext == NULL) {
        return;
    }

    RgQueueDeleteFinalization(
        oldContext,
        RG_EVENT_FLAG_DELETE_CANCELLED,
        (ULONG)STATUS_SUCCESS,
        0,
        NULL);
    FltReleaseContext(oldContext);
}

FLT_PREOP_CALLBACK_STATUS RgPreCleanup(PFLT_CALLBACK_DATA Data,
                                      PCFLT_RELATED_OBJECTS FltObjects,
                                      PVOID *CompletionContext)
{
    PRG_DELETE_HANDLE_CONTEXT context = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Data);
    *CompletionContext = NULL;

    if (InterlockedCompareExchange(&gUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&gClientConnected, 0, 0) == 0 ||
        RgCurrentClientMode() != RgClientLabGate ||
        FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // FltGetStreamHandleContext returns a referenced context. Pass that reference to post-cleanup.
    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS RgPostCleanup(PFLT_CALLBACK_DATA Data,
                                         PCFLT_RELATED_OBJECTS FltObjects,
                                         PVOID CompletionContext,
                                         FLT_POST_OPERATION_FLAGS Flags)
{
    PRG_DELETE_HANDLE_CONTEXT context = (PRG_DELETE_HANDLE_CONTEXT)CompletionContext;

    UNREFERENCED_PARAMETER(FltObjects);

    if (context == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        RgQueueDeleteFinalization(
            context,
            RG_EVENT_FLAG_DELETE_CLEANUP,
            (ULONG)Data->IoStatus.Status,
            (ULONGLONG)Data->IoStatus.Information,
            Data);
    }

    FltReleaseContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID RgAttachPagingStreamContext(PCFLT_RELATED_OBJECTS FltObjects,
                                        const RG_EVENT *CreateResult,
                                        ULONG PreservationDecision,
                                        ULONGLONG CreateRequestSequence)
{
    PRG_STREAM_CONTEXT context = NULL;
    PRG_STREAM_CONTEXT oldContext = NULL;
    NTSTATUS status;
    FLT_SET_CONTEXT_OPERATION operation;

    if (FltObjects == NULL || FltObjects->FileObject == NULL || CreateResult == NULL ||
        CreateResult->PathStatus != RgPathResolved) {
        return;
    }

    // Stream contexts are shared across handles. A later preservation-sensitive CREATE must
    // upgrade a context that may have been seeded by an earlier read-only open. Conversely,
    // a read-only open must never downgrade an already protected stream.
    operation = (PreservationDecision == RgGateSnapshotCommitted ||
                 PreservationDecision == RgGateBaselineCommitted)
        ? FLT_SET_CONTEXT_REPLACE_IF_EXISTS
        : FLT_SET_CONTEXT_KEEP_IF_EXISTS;

    status = FltAllocateContext(
        gFilter,
        FLT_STREAM_CONTEXT,
        sizeof(RG_STREAM_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == NULL) {
        InterlockedIncrement(&gDropped);
        return;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->PathStatus = CreateResult->PathStatus;
    context->IdentityStatus = CreateResult->IdentityStatus;
    context->PreservationDecision = PreservationDecision;
    context->CreateRequestSequence = CreateRequestSequence;
    context->VolumeSerialNumber = CreateResult->VolumeSerialNumber;
    context->FileIdLow = CreateResult->FileIdLow;
    context->FileIdHigh = CreateResult->FileIdHigh;
    RtlCopyMemory(context->Path, CreateResult->Path, sizeof(context->Path));

    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        operation,
        context,
        (PFLT_CONTEXT *)&oldContext);

    if (!NT_SUCCESS(status) && status != STATUS_FLT_CONTEXT_ALREADY_DEFINED &&
        status != STATUS_NOT_SUPPORTED) {
        InterlockedIncrement(&gDropped);
    }

    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
    }
    FltReleaseContext(context);
}

static VOID RgObservePagingWrite(PFLT_CALLBACK_DATA Data,
                                 PCFLT_RELATED_OBJECTS FltObjects)
{
    PRG_STREAM_CONTEXT context = NULL;
    RG_EVENT event;
    LARGE_INTEGER systemTime;
    NTSTATUS status;

    if (InterlockedCompareExchange(&gUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&gClientConnected, 0, 0) == 0 ||
        RgCurrentClientMode() != RgClientLabGate ||
        FltObjects == NULL || FltObjects->FileObject == NULL) {
        return;
    }

    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == NULL) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProtocolVersion = RG_PROTOCOL_VERSION;
    event.EventType = RgEventPagingWrite;
    event.PathStatus = context->PathStatus;
    event.IdentityStatus = context->IdentityStatus;
    event.Flags = RG_EVENT_FLAG_PAGING_IO;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = systemTime.QuadPart;
    event.ProcessId = (ULONGLONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    event.ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.ByteOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
    event.Length = Data->Iopb->Parameters.Write.Length;
    event.VolumeSerialNumber = context->VolumeSerialNumber;
    event.FileIdLow = context->FileIdLow;
    event.FileIdHigh = context->FileIdHigh;
    RtlCopyMemory(event.Path, context->Path, sizeof(event.Path));

    // Paging I/O can run in memory-manager/cache-manager contexts where filesystem name
    // queries or synchronous user-mode preservation can deadlock. Emit bounded no-reply
    // evidence only; do not call RgGateEvent from the paging path.
    RgQueueRawEvent(&event, RgClientLabGate);
    FltReleaseContext(context);
}

static VOID RgObserveWritableSection(PFLT_CALLBACK_DATA Data,
                                     PCFLT_RELATED_OBJECTS FltObjects)
{
    PRG_STREAM_CONTEXT context = NULL;
    RG_EVENT event;
    LARGE_INTEGER systemTime;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return;
    }

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == NULL) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProtocolVersion = RG_PROTOCOL_VERSION;
    event.EventType = RgEventWritableSection;
    event.PathStatus = context->PathStatus;
    event.IdentityStatus = context->IdentityStatus;
    event.Flags = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    event.RelatedSequence = context->CreateRequestSequence;
    event.CompletionInformation = context->PreservationDecision;
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = systemTime.QuadPart;
    event.ProcessId = (ULONGLONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    event.ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.VolumeSerialNumber = context->VolumeSerialNumber;
    event.FileIdLow = context->FileIdLow;
    event.FileIdHigh = context->FileIdHigh;
    RtlCopyMemory(event.Path, context->Path, sizeof(event.Path));

    RgQueueRawEvent(&event, RgClientLabGate);
    FltReleaseContext(context);
}

FLT_POSTOP_CALLBACK_STATUS RgPostSetInformation(PFLT_CALLBACK_DATA Data,
                                                PCFLT_RELATED_OBJECTS FltObjects,
                                                PVOID CompletionContext,
                                                FLT_POST_OPERATION_FLAGS Flags)
{
    FLT_POSTOP_CALLBACK_STATUS result = FLT_POSTOP_FINISHED_PROCESSING;

    if (CompletionContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        RgFreePostContext((PRG_POST_CONTEXT)CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FLT_IS_IRP_OPERATION(Data)) {
        RgFreePostContext((PRG_POST_CONTEXT)CompletionContext);
        InterlockedIncrement(&gDropped);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FltDoCompletionProcessingWhenSafe(
            Data,
            FltObjects,
            CompletionContext,
            Flags,
            RgPostSetInformationSafe,
            &result)) {
        return result;
    }

    RgFreePostContext((PRG_POST_CONTEXT)CompletionContext);
    InterlockedIncrement(&gDropped);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS RgPostSetInformationSafe(PFLT_CALLBACK_DATA Data,
                                                           PCFLT_RELATED_OBJECTS FltObjects,
                                                           PVOID CompletionContext,
                                                           FLT_POST_OPERATION_FLAGS Flags)
{
    PRG_POST_CONTEXT context = (PRG_POST_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION tunneledInfo = NULL;
    PFLT_FILE_NAME_INFORMATION finalInfo = NULL;
    FILE_STANDARD_INFORMATION standardInfo;
    RG_EVENT event;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG returned = 0;
    ULONG chars = 0;
    LARGE_INTEGER systemTime;

    UNREFERENCED_PARAMETER(Flags);

    if (context == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (context->PostEventType != RgEventRenameResult &&
        context->PostEventType != RgEventTruncateResult &&
        context->PostEventType != RgEventDeleteDispositionResult) {
        RgFreePostContext(context);
        InterlockedIncrement(&gDropped);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProtocolVersion = RG_PROTOCOL_VERSION;
    event.EventType = context->PostEventType;
    event.FileInformationClass = context->FileInformationClass;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
    event.RelatedSequence = context->RequestSequence;
    event.CompletionStatus = (ULONG)Data->IoStatus.Status;
    event.CompletionInformation = (ULONGLONG)Data->IoStatus.Information;
    event.ByteOffset = -1;
    event.DestinationPathStatus = RgPathUnknown;
    event.IdentityStatus = RgIdentityUnknown;
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = systemTime.QuadPart;

    if (context->PostEventType == RgEventRenameResult) {
        if (NT_SUCCESS(Data->IoStatus.Status)) {
            status = FltGetTunneledName(Data, context->PreDestinationNameInfo, &tunneledInfo);
            if (NT_SUCCESS(status)) {
                finalInfo = (tunneledInfo != NULL) ? tunneledInfo : context->PreDestinationNameInfo;
                chars = finalInfo->Name.Length / sizeof(WCHAR);
                if (chars >= RG_PATH_CHARS) {
                    chars = RG_PATH_CHARS - 1;
                    event.DestinationPathStatus = RgPathTruncated;
                } else {
                    event.DestinationPathStatus = RgPathResolved;
                }

                if (chars != 0) {
                    RtlCopyMemory(event.DestinationPath, finalInfo->Name.Buffer, chars * sizeof(WCHAR));
                }
                event.DestinationPath[chars] = L'\0';
            } else {
                event.DestinationPathStatus = RgPathQueryFailed;
            }

            // Safe post-processing guarantees only IRQL <= APC_LEVEL. FltQueryInformationFile
            // requires PASSIVE_LEVEL with special kernel APCs enabled.
            if (KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled()) {
                RgPopulatePostOperationIdentity(&event, FltObjects);
            } else {
                event.IdentityStatus = RgIdentityQueryFailed;
            }
        }
    } else if (context->PostEventType == RgEventTruncateResult &&
               NT_SUCCESS(Data->IoStatus.Status)) {
        // TRUNCATE post-operation evidence keeps the authoritative filesystem status even when
        // a safe identity/length query is unavailable. Missing details remain explicitly unresolved.
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled() &&
            FltObjects != NULL && FltObjects->Instance != NULL && FltObjects->FileObject != NULL) {
            RgPopulatePostOperationIdentity(&event, FltObjects);

            if (context->FileInformationClass == FileEndOfFileInformation ||
                context->FileInformationClass == FileAllocationInformation) {
                RtlZeroMemory(&standardInfo, sizeof(standardInfo));
                status = FltQueryInformationFile(
                    FltObjects->Instance,
                    FltObjects->FileObject,
                    &standardInfo,
                    sizeof(standardInfo),
                    FileStandardInformation,
                    &returned);
                if (NT_SUCCESS(status) && returned >= (ULONG)sizeof(standardInfo)) {
                    event.ByteOffset =
                        (context->FileInformationClass == FileEndOfFileInformation)
                            ? standardInfo.EndOfFile.QuadPart
                            : standardInfo.AllocationSize.QuadPart;
                }
            }
        } else {
            event.IdentityStatus = RgIdentityQueryFailed;
        }
    } else if (context->PostEventType == RgEventDeleteDispositionResult &&
               NT_SUCCESS(Data->IoStatus.Status)) {
        // A successful disposition call is authoritative only for disposition acceptance.
        // Actual pathname deletion is finalized later from the exact handle cleanup context.
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled() &&
            FltObjects != NULL && FltObjects->Instance != NULL && FltObjects->FileObject != NULL) {
            RgPopulatePostOperationIdentity(&event, FltObjects);
            RtlZeroMemory(&standardInfo, sizeof(standardInfo));
            status = FltQueryInformationFile(
                FltObjects->Instance,
                FltObjects->FileObject,
                &standardInfo,
                sizeof(standardInfo),
                FileStandardInformation,
                &returned);
            if (NT_SUCCESS(status) && returned >= (ULONG)sizeof(standardInfo)) {
                event.Flags |= RG_EVENT_FLAG_DELETE_STATE_RESOLVED;
                if (standardInfo.DeletePending) {
                    event.Flags |= RG_EVENT_FLAG_DELETE_PENDING;
                }
            }
        } else {
            event.IdentityStatus = RgIdentityQueryFailed;
        }

        if (FlagOn(context->DispositionFlags, RG_DELETE_DISPOSITION_DELETE)) {
            RgAttachDeleteHandleContext(
                FltObjects,
                context->RequestSequence,
                context->FileInformationClass,
                context->DispositionFlags);
        } else {
            RgCancelDeleteHandleContext(FltObjects);
        }
    }

    RgQueueRawEvent(&event, RgClientLabGate);

    if (tunneledInfo != NULL) {
        FltReleaseFileNameInformation(tunneledInfo);
    }
    RgFreePostContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static BOOLEAN RgPathMatchesGateRoot(ULONG PathStatus, const WCHAR *Path)
{
    UNICODE_STRING eventPath;
    UNICODE_STRING root;
    BOOLEAN result = FALSE;

    if (Path == NULL ||
        (PathStatus != RgPathResolved && PathStatus != RgPathTruncated)) {
        return FALSE;
    }

    RtlInitUnicodeString(&eventPath, Path);

    ExAcquireFastMutex(&gPortMutex);
    if (gGateRootLengthBytes != 0 &&
        (gClientMode == RgClientLabGate ||
         InterlockedCompareExchange(&gProtectionRequired, 0, 0) != 0 ||
         InterlockedCompareExchange(&gDegradedProtected, 0, 0) != 0)) {
        root.Buffer = gGateRoot;
        root.Length = gGateRootLengthBytes;
        root.MaximumLength = (USHORT)(gGateRootLengthBytes + sizeof(WCHAR));

        if (RtlEqualUnicodeString(&eventPath, &root, TRUE)) {
            result = TRUE;
        } else if (eventPath.Length > root.Length && RtlPrefixUnicodeString(&root, &eventPath, TRUE)) {
            USHORT index = root.Length / sizeof(WCHAR);
            if (Path[index] == L'\\') {
                result = TRUE;
            }
        }
    }
    ExReleaseFastMutex(&gPortMutex);
    return result;
}

static BOOLEAN RgEventPathMatchesGateRoot(const RG_EVENT *Event)
{
    return RgPathMatchesGateRoot(Event->PathStatus, Event->Path);
}

static BOOLEAN RgEventDestinationPathMatchesGateRoot(const RG_EVENT *Event)
{
    return RgPathMatchesGateRoot(Event->DestinationPathStatus, Event->DestinationPath);
}

static BOOLEAN RgEventIsInsideGateRoot(const RG_EVENT *Event)
{
    ULONGLONG requestorPid;

    requestorPid = Event->ProcessId;
    if (requestorPid == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0)) {
        return FALSE;
    }

    return RgEventPathMatchesGateRoot(Event);
}

static BOOLEAN RgIsOnGateVolume(PCFLT_RELATED_OBJECTS FltObjects)
{
    BOOLEAN result = FALSE;

    if (FltObjects == NULL || FltObjects->Volume == NULL) {
        return FALSE;
    }

    ExAcquireFastMutex(&gPortMutex);
    result = (gGateVolume != NULL && gGateVolume == FltObjects->Volume);
    ExReleaseFastMutex(&gPortMutex);
    return result;
}

static RG_SCOPE_CLASSIFICATION RgClassifyMutationScope(
    const RG_EVENT *Event,
    PCFLT_RELATED_OBJECTS FltObjects)
{
    RG_SCOPE_CLASSIFICATION sourceScope;
    RG_SCOPE_CLASSIFICATION destinationScope;

    if (Event == NULL) {
        return RgScopeOutside;
    }

    // GateClient owns the rollback store and activation protocol. Never make its own volume I/O
    // depend on the synchronous gate, even if a name query is temporarily unavailable.
    if (Event->ProcessId != 0 &&
        Event->ProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0)) {
        return RgScopeOutside;
    }

    if (Event->PathStatus == RgPathResolved || Event->PathStatus == RgPathTruncated) {
        sourceScope = RgEventPathMatchesGateRoot(Event) ? RgScopeInside : RgScopeOutside;
    } else {
        sourceScope = RgScopeAmbiguous;
    }

    if (Event->EventType == RgEventRename) {
        if (Event->DestinationPathStatus == RgPathResolved ||
            Event->DestinationPathStatus == RgPathTruncated) {
            destinationScope = RgEventDestinationPathMatchesGateRoot(Event)
                ? RgScopeInside
                : RgScopeOutside;
        } else {
            destinationScope = RgScopeAmbiguous;
        }

        if (sourceScope == RgScopeInside || destinationScope == RgScopeInside) {
            return RgScopeInside;
        }
        if (sourceScope == RgScopeOutside && destinationScope == RgScopeOutside) {
            return RgScopeOutside;
        }

        return RgIsOnGateVolume(FltObjects) ? RgScopeAmbiguous : RgScopeOutside;
    }

    if (sourceScope == RgScopeAmbiguous) {
        return RgIsOnGateVolume(FltObjects) ? RgScopeAmbiguous : RgScopeOutside;
    }

    return sourceScope;
}

static BOOLEAN RgIsContainedRequestor(PFLT_CALLBACK_DATA Data)
{
    PEPROCESS requestor;
    BOOLEAN contained = FALSE;

    requestor = FltGetRequestorProcess(Data);
    if (requestor == NULL) {
        return FALSE;
    }

    ExAcquireFastMutex(&gPortMutex);
    contained = (gContainedProcess != NULL && gContainedProcess == requestor);
    ExReleaseFastMutex(&gPortMutex);
    return contained;
}

static BOOLEAN RgCreateMayMutate(const RG_EVENT *Event)
{
    ULONG disposition;
    ULONG options;
    ACCESS_MASK desiredAccess;
    const ACCESS_MASK mutatingAccess =
        FILE_WRITE_DATA |
        FILE_APPEND_DATA |
        FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES |
        DELETE |
        WRITE_DAC |
        WRITE_OWNER |
        GENERIC_WRITE |
        GENERIC_ALL;

    disposition = (Event->Flags & RG_CREATE_DISPOSITION_MASK) >> RG_CREATE_DISPOSITION_SHIFT;
    options = Event->Flags & RG_CREATE_OPTIONS_MASK;
    desiredAccess = (ACCESS_MASK)Event->Length;

    if (FlagOn(options, FILE_DELETE_ON_CLOSE) || FlagOn(desiredAccess, mutatingAccess)) {
        return TRUE;
    }

    return disposition == FILE_SUPERSEDE ||
           disposition == FILE_CREATE ||
           disposition == FILE_OPEN_IF ||
           disposition == FILE_OVERWRITE ||
           disposition == FILE_OVERWRITE_IF;
}

static VOID RgClearContainedProcess(VOID)
{
    PEPROCESS previous = NULL;

    ExAcquireFastMutex(&gPortMutex);
    previous = gContainedProcess;
    gContainedProcess = NULL;
    InterlockedExchange64(&gContainedProcessId, 0);
    ExReleaseFastMutex(&gPortMutex);

    if (previous != NULL) {
        ObDereferenceObject(previous);
    }
}

static BOOLEAN RgBindContainedRequestor(PFLT_CALLBACK_DATA Data,
                                        const RG_EVENT *Event,
                                        PULONG ErrorCode)
{
    PEPROCESS requestor;
    BOOLEAN bound = FALSE;
    BOOLEAN newlyBound = FALSE;
    ULONG failure = (ULONG)STATUS_DEVICE_BUSY;
    RG_EVENT activationEvent;

    requestor = FltGetRequestorProcess(Data);
    if (requestor == NULL ||
        Event->ProcessId <= 4 ||
        (ULONGLONG)(ULONG_PTR)PsGetProcessId(requestor) != Event->ProcessId ||
        Event->ProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0)) {
        if (ErrorCode != NULL) {
            *ErrorCode = (ULONG)STATUS_INVALID_PARAMETER;
        }
        return FALSE;
    }

    ObReferenceObject(requestor);

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort == NULL) {
        failure = (ULONG)STATUS_PORT_DISCONNECTED;
    } else if (gContainedProcess == NULL) {
        gContainedProcess = requestor;
        InterlockedExchange64(&gContainedProcessId, (LONG64)Event->ProcessId);
        requestor = NULL;
        bound = TRUE;
        newlyBound = TRUE;
    } else if (gContainedProcess == requestor) {
        bound = TRUE;
    }
    ExReleaseFastMutex(&gPortMutex);

    if (requestor != NULL) {
        ObDereferenceObject(requestor);
    }
    if (!bound) {
        if (ErrorCode != NULL) {
            *ErrorCode = failure;
        }
        return FALSE;
    }

    if (newlyBound) {
        RtlCopyMemory(&activationEvent, Event, sizeof(activationEvent));
        activationEvent.ProtocolVersion = RG_PROTOCOL_VERSION;
        activationEvent.EventType = RgEventContainmentActivated;
        activationEvent.Sequence = (ULONGLONG)InterlockedIncrement64(&gSequence);
        activationEvent.RelatedSequence = Event->Sequence;
        activationEvent.CompletionStatus = (ULONG)STATUS_SUCCESS;
        activationEvent.CompletionInformation = 0;
        activationEvent.DroppedBeforeThis = 0;
        RgQueueRawEvent(&activationEvent, RgClientLabGate);
        RtlSecureZeroMemory(&activationEvent, sizeof(activationEvent));
    }

    return TRUE;
}

static BOOLEAN RgGateEvent(PFLT_CALLBACK_DATA Data,
                           const RG_EVENT *Event,
                           PULONG ErrorCode,
                           PULONG Decision)
{
    LARGE_INTEGER timeout;
    RG_GATE_REPLY reply;
    ULONG replyLength = sizeof(reply);
    NTSTATUS status = STATUS_PORT_DISCONNECTED;
    BOOLEAN allow = FALSE;
    LONG inFlight;

    RtlZeroMemory(&reply, sizeof(reply));
    if (Decision != NULL) {
        *Decision = RgGateDeny;
    }
    timeout.QuadPart = -(RG_GATE_TIMEOUT_MS * 10LL * 1000LL);

    inFlight = InterlockedIncrement(&gGateInFlight);
    if (InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0) {
        InterlockedDecrement(&gGateInFlight);
        if (ErrorCode != NULL) {
            *ErrorCode = (ULONG)STATUS_DEVICE_NOT_READY;
        }
        return FALSE;
    }
    if (inFlight > RG_MAX_GATE_INFLIGHT) {
        InterlockedDecrement(&gGateInFlight);
        if (ErrorCode != NULL) {
            *ErrorCode = (ULONG)STATUS_DEVICE_BUSY;
        }
        return FALSE;
    }

    if (RgAcquireClientPort(RgClientLabGate)) {
        status = FltSendMessage(gFilter, &gClientPort,
            (PVOID)Event, sizeof(*Event),
            &reply, &replyLength, &timeout);
        RgReleaseClientPort();
    }

    InterlockedDecrement(&gGateInFlight);

    if (InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0) {
        if (ErrorCode != NULL) {
            *ErrorCode = (ULONG)STATUS_DEVICE_NOT_READY;
        }
        return FALSE;
    }

    if (ErrorCode != NULL) {
        *ErrorCode = NT_SUCCESS(status) ? reply.ErrorCode : (ULONG)status;
    }

    if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT || replyLength < sizeof(reply)) {
        return FALSE;
    }
    if (reply.ProtocolVersion != RG_PROTOCOL_VERSION || reply.RequestSequence != Event->Sequence) {
        return FALSE;
    }
    if ((reply.Flags & ~RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR) != 0) {
        return FALSE;
    }

    allow = (reply.Decision == RgGateSnapshotCommitted ||
             reply.Decision == RgGateBaselineCommitted ||
             reply.Decision == RgGateNoPreservationRequired);
    if (!allow && reply.Flags != 0) {
        return FALSE;
    }

    if (allow && FlagOn(reply.Flags, RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR)) {
        if (!RgBindContainedRequestor(Data, Event, ErrorCode)) {
            return FALSE;
        }
    } else if (allow && RgIsContainedRequestor(Data)) {
        // A sibling IRP may already have installed containment while this request waited in user mode.
        // Do not let an older in-flight mutation escape after the latch becomes active.
        if (ErrorCode != NULL) {
            *ErrorCode = (ULONG)STATUS_ACCESS_DENIED;
        }
        return FALSE;
    }

    if (allow && Decision != NULL) {
        *Decision = reply.Decision;
    }
    return allow;
}

static VOID RgQueueEvent(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                         RG_EVENT_TYPE EventType, ULONG FileInformationClass)
{
    PRG_WORK_ITEM work = NULL;
    LONG pending;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    if (!ExAcquireRundownProtection(&gRundown)) {
        return;
    }

    pending = InterlockedIncrement(&gPending);
    if (InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0) {
        InterlockedDecrement(&gPending);
        ExReleaseRundownProtection(&gRundown);
        return;
    }
    if (pending > RG_MAX_PENDING) {
        InterlockedDecrement(&gPending);
        InterlockedIncrement(&gDropped);
        ExReleaseRundownProtection(&gRundown);
        return;
    }

    work = (PRG_WORK_ITEM)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_WORK_ITEM), RG_POOL_TAG);
    if (work == NULL) {
        InterlockedDecrement(&gPending);
        InterlockedIncrement(&gDropped);
        ExReleaseRundownProtection(&gRundown);
        return;
    }

    RtlZeroMemory(work, sizeof(*work));
    work->ClientMode = RgClientAudit;
    status = RgPopulateEvent(&work->Event, Data, FltObjects, EventType, FileInformationClass);
    if (!NT_SUCCESS(status) && work->Event.PathStatus != RgPathQueryFailed) {
        RtlSecureZeroMemory(&work->Event, sizeof(work->Event));
        ExFreePoolWithTag(work, RG_POOL_TAG);
        InterlockedDecrement(&gPending);
        ExReleaseRundownProtection(&gRundown);
        return;
    }

    ExInitializeWorkItem(&work->WorkItem, RgSendWorker, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
}

static VOID RgQueueRawEvent(const RG_EVENT *Event, LONG ClientMode)
{
    PRG_WORK_ITEM work = NULL;
    LONG pending;

    if (Event == NULL || (ClientMode != RgClientAudit && ClientMode != RgClientLabGate)) {
        return;
    }

    if (!ExAcquireRundownProtection(&gRundown)) {
        return;
    }

    pending = InterlockedIncrement(&gPending);
    if (InterlockedCompareExchange(&gMaintenanceRequested, 0, 0) != 0) {
        InterlockedDecrement(&gPending);
        ExReleaseRundownProtection(&gRundown);
        return;
    }
    if (pending > RG_MAX_PENDING) {
        InterlockedDecrement(&gPending);
        InterlockedIncrement(&gDropped);
        ExReleaseRundownProtection(&gRundown);
        return;
    }

    work = (PRG_WORK_ITEM)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RG_WORK_ITEM), RG_POOL_TAG);
    if (work == NULL) {
        InterlockedDecrement(&gPending);
        InterlockedIncrement(&gDropped);
        ExReleaseRundownProtection(&gRundown);
        return;
    }

    RtlZeroMemory(work, sizeof(*work));
    RtlCopyMemory(&work->Event, Event, sizeof(*Event));
    work->ClientMode = ClientMode;
    ExInitializeWorkItem(&work->WorkItem, RgSendWorker, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
}

static VOID RgSendWorker(PVOID Parameter)
{
    PRG_WORK_ITEM work = (PRG_WORK_ITEM)Parameter;
    LARGE_INTEGER timeout;
    NTSTATUS status = STATUS_PORT_DISCONNECTED;

    work->Event.DroppedBeforeThis = (ULONG)InterlockedExchange(&gDropped, 0);
    timeout.QuadPart = -(((work->ClientMode == RgClientLabGate) ?
        RG_RECONCILE_SEND_TIMEOUT_MS : RG_SEND_TIMEOUT_MS) * 10LL * 1000LL);

    if (RgAcquireClientPort(work->ClientMode)) {
        status = FltSendMessage(gFilter, &gClientPort,
            &work->Event, sizeof(work->Event),
            NULL, NULL, &timeout);
        RgReleaseClientPort();
    }

    if (status == STATUS_TIMEOUT) {
        InterlockedIncrement(&gDropped);
    }

    RtlSecureZeroMemory(&work->Event, sizeof(work->Event));
    ExFreePoolWithTag(work, RG_POOL_TAG);
    InterlockedDecrement(&gPending);
    ExReleaseRundownProtection(&gRundown);
}

static BOOLEAN RgAcquireClientPort(LONG ExpectedMode)
{
    BOOLEAN acquired = FALSE;

    if (!ExAcquireRundownProtection(&gPortRundown)) {
        return FALSE;
    }

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL &&
        gClientMode == ExpectedMode &&
        InterlockedCompareExchange(&gClientConnected, 0, 0) != 0 &&
        InterlockedCompareExchange(&gUnloading, 0, 0) == 0) {
        acquired = TRUE;
    }
    ExReleaseFastMutex(&gPortMutex);

    if (!acquired) {
        ExReleaseRundownProtection(&gPortRundown);
    }
    return acquired;
}

static VOID RgReleaseClientPort(VOID)
{
    ExReleaseRundownProtection(&gPortRundown);
}

static VOID RgWaitForPortUsers(VOID)
{
    ExWaitForRundownProtectionRelease(&gPortRundown);
    InterlockedExchange(&gPortRundownCompleted, 1);
}

static NTSTATUS RgConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext,
                          ULONG SizeOfContext, PVOID *ConnectionPortCookie)
{
    PRG_CONNECT_CONTEXT context;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG rootBytes;
    ULONG rootChars;
    ULONG volumeBytes;
    ULONG volumeChars;
    UNICODE_STRING volumeName;
    PFLT_VOLUME candidateVolume = NULL;
    PFLT_VOLUME releaseVolume = NULL;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    *ConnectionPortCookie = NULL;

    if (ConnectionContext == NULL || SizeOfContext != sizeof(RG_CONNECT_CONTEXT)) {
        return STATUS_INVALID_PARAMETER;
    }

    context = (PRG_CONNECT_CONTEXT)ConnectionContext;
    if (context->ProtocolVersion != RG_PROTOCOL_VERSION ||
        (context->ClientMode != RgClientAudit && context->ClientMode != RgClientLabGate)) {
        return STATUS_REVISION_MISMATCH;
    }

    rootBytes = context->GateRootLengthBytes;
    volumeBytes = context->GateVolumeLengthBytes;
    if ((rootBytes % sizeof(WCHAR)) != 0 || rootBytes >= sizeof(context->GateRoot) ||
        (volumeBytes % sizeof(WCHAR)) != 0 || volumeBytes >= sizeof(context->GateRoot)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (context->ClientMode == RgClientLabGate) {
        if (context->ClientProcessId == 0 ||
            rootBytes < (4 * sizeof(WCHAR)) ||
            volumeBytes < (4 * sizeof(WCHAR)) ||
            volumeBytes > rootBytes) {
            return STATUS_INVALID_PARAMETER;
        }

        rootChars = rootBytes / sizeof(WCHAR);
        volumeChars = volumeBytes / sizeof(WCHAR);
        if (context->GateRoot[0] != L'\\' || context->GateRoot[rootChars] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
        if (volumeBytes < rootBytes && context->GateRoot[volumeChars] != L'\\') {
            return STATUS_INVALID_PARAMETER;
        }

        while (rootChars > 1 && context->GateRoot[rootChars - 1] == L'\\') {
            rootChars--;
        }
        rootBytes = rootChars * sizeof(WCHAR);
        if (volumeBytes > rootBytes) {
            return STATUS_INVALID_PARAMETER;
        }

        volumeName.Buffer = context->GateRoot;
        volumeName.Length = (USHORT)volumeBytes;
        volumeName.MaximumLength = (USHORT)volumeBytes;
        status = FltGetVolumeFromName(gFilter, &volumeName, &candidateVolume);
        if (!NT_SUCCESS(status) || candidateVolume == NULL) {
            return NT_SUCCESS(status) ? STATUS_FLT_VOLUME_NOT_FOUND : status;
        }
    } else if (rootBytes != 0 || volumeBytes != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL || gContainedProcess != NULL ||
        InterlockedCompareExchange(&gUnloading, 0, 0) != 0) {
        status = STATUS_DEVICE_BUSY;
    } else if (InterlockedCompareExchange(&gProtectionRequired, 0, 0) != 0 &&
               (context->ClientMode != RgClientLabGate ||
                gGateRootLengthBytes != (USHORT)rootBytes ||
                gGateVolumeLengthBytes != (USHORT)volumeBytes ||
                gGateVolume == NULL ||
                gGateVolume != candidateVolume ||
                RtlCompareMemory(gGateRoot, context->GateRoot, rootBytes) != rootBytes)) {
        // A disconnected protected session may reconnect only to the exact retained root
        // on the same referenced Filter Manager volume object.
        status = STATUS_ACCESS_DENIED;
    } else {
        if (InterlockedExchange(&gPortRundownCompleted, 0) != 0) {
            ExReInitializeRundownProtection(&gPortRundown);
        }

        if (InterlockedCompareExchange(&gProtectionRequired, 0, 0) == 0) {
            releaseVolume = gGateVolume;
            gGateVolume = NULL;
            gGateVolumeLengthBytes = 0;
            RtlZeroMemory(gGateRoot, sizeof(gGateRoot));
            gGateRootLengthBytes = 0;
        }

        gClientPort = ClientPort;
        gClientMode = (LONG)context->ClientMode;
        InterlockedExchange64(&gClientProcessId, (LONG64)context->ClientProcessId);
        InterlockedExchange(&gGateActivated, context->ClientMode == RgClientLabGate ? 0 : 1);
        InterlockedExchange(&gActivationHazard, 0);
        InterlockedExchange(&gPreflightProbeArmed, 0);
        InterlockedExchange(&gMaintenanceRequested, 0);
        InterlockedExchange(&gGracefulDisconnectAuthorized, 0);

        if (context->ClientMode == RgClientLabGate &&
            InterlockedCompareExchange(&gProtectionRequired, 0, 0) == 0) {
            RtlCopyMemory(gGateRoot, context->GateRoot, rootBytes);
            gGateRootLengthBytes = (USHORT)rootBytes;
            gGateRoot[rootBytes / sizeof(WCHAR)] = L'\0';
            gGateVolume = candidateVolume;
            candidateVolume = NULL;
            gGateVolumeLengthBytes = (USHORT)volumeBytes;
        }

        // On degraded reconnect publish the live client before clearing the fail-safe latch,
        // so callbacks never observe both protection indicators false.
        InterlockedExchange(&gClientConnected, 1);
        InterlockedExchange(&gDegradedProtected, 0);
    }
    ExReleaseFastMutex(&gPortMutex);

    if (candidateVolume != NULL) {
        FltObjectDereference(candidateVolume);
    }
    if (releaseVolume != NULL) {
        FltObjectDereference(releaseVolume);
    }
    return status;
}

static NTSTATUS RgMessage(PVOID ConnectionCookie,
                          PVOID InputBuffer,
                          ULONG InputBufferSize,
                          PVOID OutputBuffer,
                          ULONG OutputBufferSize,
                          PULONG ReturnOutputBufferLength)
{
    PRG_CONTROL_REQUEST request;
    PRG_CONTROL_REPLY reply;
    PEPROCESS targetProcess = NULL;
    ULONGLONG containedProcessId;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferSize != sizeof(RG_CONTROL_REQUEST) ||
        OutputBuffer == NULL || OutputBufferSize < sizeof(RG_CONTROL_REPLY)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PRG_CONTROL_REQUEST)InputBuffer;
    reply = (PRG_CONTROL_REPLY)OutputBuffer;
    RtlZeroMemory(reply, sizeof(*reply));
    reply->ProtocolVersion = RG_PROTOCOL_VERSION;
    reply->Command = request->Command;

    if (request->ProtocolVersion != RG_PROTOCOL_VERSION ||
        InterlockedCompareExchange(&gClientConnected, 0, 0) == 0 ||
        RgCurrentClientMode() != RgClientLabGate) {
        status = STATUS_REVISION_MISMATCH;
    } else if (request->Command == RgControlQueryActivation ||
               request->Command == RgControlQueryContainment) {
        if (request->TargetProcessId != 0) {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (request->Command == RgControlArmPreflight) {
        if (request->TargetProcessId != 0) {
            status = STATUS_INVALID_PARAMETER;
        } else if (InterlockedCompareExchange(&gGateActivated, 0, 0) != 0 ||
                   InterlockedCompareExchange(&gActivationHazard, 0, 0) != 0) {
            status = STATUS_DEVICE_BUSY;
        } else {
            InterlockedExchange(&gPreflightProbeArmed, 1);
            status = STATUS_SUCCESS;
        }
    } else if (request->Command == RgControlActivateGate) {
        if (request->TargetProcessId != 0) {
            status = STATUS_INVALID_PARAMETER;
        } else if (InterlockedCompareExchange(&gActivationHazard, 0, 0) != 0 ||
                   InterlockedCompareExchange(&gPreflightProbeArmed, 0, 0) != 0) {
            status = STATUS_DEVICE_BUSY;
        } else {
            InterlockedExchange(&gProtectionRequired, 1);
            InterlockedExchange(&gDegradedProtected, 0);
            InterlockedExchange(&gMaintenanceRequested, 0);
            InterlockedExchange(&gGracefulDisconnectAuthorized, 0);
            InterlockedExchange(&gGateActivated, 1);
            status = STATUS_SUCCESS;
        }
    } else if (request->Command == RgControlActivateAndContainProcess) {
        if (InterlockedCompareExchange(&gGateActivated, 0, 0) != 0 ||
            InterlockedCompareExchange(&gActivationHazard, 0, 0) != 0 ||
            InterlockedCompareExchange(&gPreflightProbeArmed, 0, 0) != 0) {
            status = STATUS_DEVICE_BUSY;
        } else if (request->TargetProcessId <= 4 ||
                   request->TargetProcessId == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0) ||
                   (ULONGLONG)(ULONG_PTR)request->TargetProcessId != request->TargetProcessId) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)request->TargetProcessId,
                &targetProcess);
            if (NT_SUCCESS(status)) {
                ExAcquireFastMutex(&gPortMutex);
                if (gContainedProcess != NULL || gClientPort == NULL) {
                    status = STATUS_DEVICE_BUSY;
                } else {
                    gContainedProcess = targetProcess;
                    targetProcess = NULL;
                    InterlockedExchange64(&gContainedProcessId, (LONG64)request->TargetProcessId);
                    InterlockedExchange(&gProtectionRequired, 1);
                    InterlockedExchange(&gDegradedProtected, 0);
                    InterlockedExchange(&gMaintenanceRequested, 0);
                    InterlockedExchange(&gGracefulDisconnectAuthorized, 0);
                    InterlockedExchange(&gGateActivated, 1);
                    status = STATUS_SUCCESS;
                }
                ExReleaseFastMutex(&gPortMutex);
            }
        }
    } else if (request->Command == RgControlDeactivateGate) {
        if (request->TargetProcessId != 0) {
            status = STATUS_INVALID_PARAMETER;
        } else if (InterlockedCompareExchange(&gGateActivated, 0, 0) == 0 &&
                   InterlockedCompareExchange(&gGracefulDisconnectAuthorized, 0, 0) == 0) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else {
            // Close new gate admission before inspecting outstanding work. This is only a
            // maintenance request, not release authorization: if the client disappears while
            // draining, RgDisconnect still retains the root and enters DegradedProtected.
            InterlockedExchange(&gMaintenanceRequested, 1);

            if (InterlockedCompareExchange(&gGateInFlight, 0, 0) != 0 ||
                InterlockedCompareExchange(&gPending, 0, 0) != 0) {
                status = STATUS_DEVICE_BUSY;
            } else {
                RgClearContainedProcess();
                InterlockedExchange(&gGateActivated, 0);
                InterlockedExchange(&gProtectionRequired, 0);
                InterlockedExchange(&gDegradedProtected, 0);
                InterlockedExchange(&gGracefulDisconnectAuthorized, 1);
                status = STATUS_SUCCESS;
            }
        }
    } else {
        status = STATUS_INVALID_PARAMETER;
    }

    if (targetProcess != NULL) {
        ObDereferenceObject(targetProcess);
    }

    containedProcessId = (ULONGLONG)InterlockedCompareExchange64(&gContainedProcessId, 0, 0);
    reply->Status = (ULONG)status;
    reply->GateActivated = (ULONG)InterlockedCompareExchange(&gGateActivated, 0, 0);
    reply->ContainmentActive = containedProcessId != 0 ? 1u : 0u;
    reply->ProtectionState = RgCurrentProtectionState();
    reply->ContainedProcessId = containedProcessId;
    *ReturnOutputBufferLength = sizeof(*reply);
    return STATUS_SUCCESS;
}

static VOID RgDisconnect(PVOID ConnectionCookie)
{
    LONG protectionRequired;
    LONG gracefulDisconnect;

    UNREFERENCED_PARAMETER(ConnectionCookie);

    protectionRequired = InterlockedCompareExchange(&gProtectionRequired, 0, 0);
    gracefulDisconnect = InterlockedCompareExchange(&gGracefulDisconnectAuthorized, 0, 0);

    RgClearContainedProcess();

    ExAcquireFastMutex(&gPortMutex);
    if (protectionRequired != 0 && gracefulDisconnect == 0) {
        // Publish the fail-safe latch before publishing client loss. This avoids a transient
        // connected=0/degraded=0 window that could otherwise let a racing mutation escape.
        InterlockedExchange(&gDegradedProtected, 1);
    }

    InterlockedExchange(&gClientConnected, 0);
    InterlockedExchange(&gClientMode, 0);
    InterlockedExchange64(&gClientProcessId, 0);
    InterlockedExchange(&gGateActivated, 0);
    InterlockedExchange(&gActivationHazard, 0);
    InterlockedExchange(&gPreflightProbeArmed, 0);

    if (protectionRequired != 0 && gracefulDisconnect == 0) {
        // Keep the negotiated root and fail safe for resolved user-mode mutations.
        // A replacement v16 GateClient may reconnect only to this exact root and must rerun preflight.
    } else {
        InterlockedExchange(&gProtectionRequired, 0);
        InterlockedExchange(&gDegradedProtected, 0);
        gGateRootLengthBytes = 0;
        RtlSecureZeroMemory(gGateRoot, sizeof(gGateRoot));
    }
    InterlockedExchange(&gMaintenanceRequested, 0);
    InterlockedExchange(&gGracefulDisconnectAuthorized, 0);

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilter, &gClientPort);
    }
    ExReleaseFastMutex(&gPortMutex);

    RgWaitForPortUsers();
}

NTSTATUS RgInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                         DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    // Lab prototype: local NTFS/ReFS only. No network, optical, RAW, FAT/exFAT or removable-specific handling.
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS && VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS RgUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    InterlockedExchange(&gUnloading, 1);
    InterlockedExchange(&gClientConnected, 0);
    InterlockedExchange(&gClientMode, 0);
    InterlockedExchange(&gProtectionRequired, 0);
    InterlockedExchange(&gDegradedProtected, 0);
    InterlockedExchange(&gMaintenanceRequested, 0);
    InterlockedExchange(&gGracefulDisconnectAuthorized, 0);
    RgClearContainedProcess();

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilter, &gClientPort);
    }
    ExReleaseFastMutex(&gPortMutex);
    RgWaitForPortUsers();

    ExWaitForRundownProtectionRelease(&gRundown);
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeFastMutex(&gPortMutex);
    ExInitializeRundownProtection(&gRundown);
    ExInitializeRundownProtection(&gPortRundown);
    RtlZeroMemory(gGateRoot, sizeof(gGateRoot));

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, RG_PORT_NAME);
    InitializeObjectAttributes(&objectAttributes, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor);

    status = FltCreateCommunicationPort(gFilter, &gServerPort, &objectAttributes,
        NULL, RgConnect, RgDisconnect, RgMessage, 1);
    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }

    return status;
}
