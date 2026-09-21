#include "RansomGuardMinifilter.h"

C_ASSERT(sizeof(RG_EVENT) == 1096);
C_ASSERT(sizeof(RG_CONNECT_CONTEXT) == 544);
C_ASSERT(sizeof(RG_GATE_REPLY) == 24);

static PFLT_FILTER gFilter = NULL;
static PFLT_PORT gServerPort = NULL;
static PFLT_PORT gClientPort = NULL;
static FAST_MUTEX gPortMutex;
static EX_RUNDOWN_REF gRundown;
static volatile LONG gUnloading = 0;
static volatile LONG gClientConnected = 0;
static volatile LONG gClientMode = 0;
static volatile LONG64 gClientProcessId = 0;
static volatile LONG gPending = 0;
static volatile LONG gDropped = 0;
static volatile LONG64 gSequence = 0;
static WCHAR gGateRoot[RG_GATE_ROOT_CHARS];
static USHORT gGateRootLengthBytes = 0;

static VOID RgQueueEvent(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ RG_EVENT_TYPE EventType, _In_ ULONG FileInformationClass);
static VOID RgSendWorker(_In_ PVOID Parameter);
static NTSTATUS RgConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                          _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                          _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);
static VOID RgDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS RgPopulateEvent(_Out_ PRG_EVENT Event, _Inout_ PFLT_CALLBACK_DATA Data,
                                _In_ RG_EVENT_TYPE EventType, _In_ ULONG FileInformationClass);
static BOOLEAN RgEventIsInsideGateRoot(_In_ const RG_EVENT *Event);
static BOOLEAN RgGateEvent(_In_ const RG_EVENT *Event, _Out_opt_ PULONG ErrorCode);
static LONG RgCurrentClientMode(VOID);
static FLT_PREOP_CALLBACK_STATUS RgCompleteDenied(_Inout_ PFLT_CALLBACK_DATA Data);

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, RgPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, RgPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
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
    default:
        return FALSE;
    }
}

static BOOLEAN RgShouldObserve(_In_ PFLT_CALLBACK_DATA Data)
{
    if (InterlockedCompareExchange(&gUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&gClientConnected, 0, 0) == 0) {
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

static FLT_PREOP_CALLBACK_STATUS RgCompleteDenied(PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS RgPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    RG_EVENT event;
    NTSTATUS status;
    LONG mode;
    ULONG gateError = 0;

    UNREFERENCED_PARAMETER(CompletionContext);
    if (!RgShouldObserve(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    mode = RgCurrentClientMode();
    if (mode == RgClientAudit) {
        RgQueueEvent(Data, FltObjects, RgEventWrite, 0);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (mode != RgClientLabGate) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = RgPopulateEvent(&event, Data, RgEventWrite, 0);
    if (!NT_SUCCESS(status) || !RgEventIsInsideGateRoot(&event)) {
        // LAB gate is intentionally scoped. Unresolved/out-of-root paths fail open rather than risking OS-wide I/O loss.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!RgGateEvent(&event, &gateError)) {
        UNREFERENCED_PARAMETER(gateError);
        return RgCompleteDenied(Data);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RgPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    RG_EVENT_TYPE eventType = RgEventInvalid;
    RG_EVENT event;
    NTSTATUS status;
    LONG mode;
    ULONG gateError = 0;
    ULONG infoClass;

    UNREFERENCED_PARAMETER(CompletionContext);
    if (!RgShouldObserve(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (!RgIsInterestingSetInfo((FILE_INFORMATION_CLASS)infoClass, &eventType)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    mode = RgCurrentClientMode();
    if (mode == RgClientAudit) {
        RgQueueEvent(Data, FltObjects, eventType, infoClass);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (mode != RgClientLabGate) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = RgPopulateEvent(&event, Data, eventType, infoClass);
    if (!NT_SUCCESS(status) || !RgEventIsInsideGateRoot(&event)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!RgGateEvent(&event, &gateError)) {
        UNREFERENCED_PARAMETER(gateError);
        return RgCompleteDenied(Data);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS RgPopulateEvent(PRG_EVENT Event, PFLT_CALLBACK_DATA Data,
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
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        Event->PathStatus = RgPathQueryFailed;
        return status;
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
    return status;
}

static BOOLEAN RgEventIsInsideGateRoot(const RG_EVENT *Event)
{
    UNICODE_STRING eventPath;
    UNICODE_STRING root;
    BOOLEAN result = FALSE;
    ULONGLONG requestorPid;

    if (Event->PathStatus != RgPathResolved && Event->PathStatus != RgPathTruncated) {
        return FALSE;
    }

    requestorPid = Event->ProcessId;
    if (requestorPid == (ULONGLONG)InterlockedCompareExchange64(&gClientProcessId, 0, 0)) {
        return FALSE;
    }

    RtlInitUnicodeString(&eventPath, Event->Path);

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL && gClientMode == RgClientLabGate && gGateRootLengthBytes != 0) {
        root.Buffer = gGateRoot;
        root.Length = gGateRootLengthBytes;
        root.MaximumLength = (USHORT)(gGateRootLengthBytes + sizeof(WCHAR));

        if (RtlEqualUnicodeString(&eventPath, &root, TRUE)) {
            result = TRUE;
        } else if (eventPath.Length > root.Length && RtlPrefixUnicodeString(&root, &eventPath, TRUE)) {
            USHORT index = root.Length / sizeof(WCHAR);
            if (Event->Path[index] == L'\\') {
                result = TRUE;
            }
        }
    }
    ExReleaseFastMutex(&gPortMutex);
    return result;
}

static BOOLEAN RgGateEvent(const RG_EVENT *Event, PULONG ErrorCode)
{
    LARGE_INTEGER timeout;
    RG_GATE_REPLY reply;
    ULONG replyLength = sizeof(reply);
    NTSTATUS status = STATUS_PORT_DISCONNECTED;
    BOOLEAN allow = FALSE;

    RtlZeroMemory(&reply, sizeof(reply));
    timeout.QuadPart = -(RG_GATE_TIMEOUT_MS * 10LL * 1000LL);

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL && gClientMode == RgClientLabGate &&
        InterlockedCompareExchange(&gUnloading, 0, 0) == 0) {
        status = FltSendMessage(gFilter, &gClientPort,
            (PVOID)Event, sizeof(*Event),
            &reply, &replyLength, &timeout);
    }
    ExReleaseFastMutex(&gPortMutex);

    if (ErrorCode != NULL) {
        *ErrorCode = NT_SUCCESS(status) ? reply.ErrorCode : (ULONG)status;
    }

    if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT || replyLength < sizeof(reply)) {
        return FALSE;
    }
    if (reply.ProtocolVersion != RG_PROTOCOL_VERSION || reply.RequestSequence != Event->Sequence) {
        return FALSE;
    }

    allow = (reply.Decision == RgGateSnapshotCommitted);
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
    status = RgPopulateEvent(&work->Event, Data, EventType, FileInformationClass);
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

static VOID RgSendWorker(PVOID Parameter)
{
    PRG_WORK_ITEM work = (PRG_WORK_ITEM)Parameter;
    LARGE_INTEGER timeout;
    NTSTATUS status = STATUS_PORT_DISCONNECTED;

    work->Event.DroppedBeforeThis = (ULONG)InterlockedExchange(&gDropped, 0);
    timeout.QuadPart = -(RG_SEND_TIMEOUT_MS * 10LL * 1000LL);

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL && gClientMode == RgClientAudit &&
        InterlockedCompareExchange(&gUnloading, 0, 0) == 0) {
        status = FltSendMessage(gFilter, &gClientPort,
            &work->Event, sizeof(work->Event),
            NULL, NULL, &timeout);
    }
    ExReleaseFastMutex(&gPortMutex);

    if (status == STATUS_TIMEOUT) {
        InterlockedIncrement(&gDropped);
    }

    RtlSecureZeroMemory(&work->Event, sizeof(work->Event));
    ExFreePoolWithTag(work, RG_POOL_TAG);
    InterlockedDecrement(&gPending);
    ExReleaseRundownProtection(&gRundown);
}

static NTSTATUS RgConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext,
                          ULONG SizeOfContext, PVOID *ConnectionPortCookie)
{
    PRG_CONNECT_CONTEXT context;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG rootBytes;
    ULONG rootChars;

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
    if ((rootBytes % sizeof(WCHAR)) != 0 || rootBytes >= sizeof(context->GateRoot)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (context->ClientMode == RgClientLabGate) {
        if (context->ClientProcessId == 0 || rootBytes < (4 * sizeof(WCHAR))) {
            return STATUS_INVALID_PARAMETER;
        }
        rootChars = rootBytes / sizeof(WCHAR);
        if (context->GateRoot[0] != L'\\' || context->GateRoot[rootChars] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
    } else if (rootBytes != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL || InterlockedCompareExchange(&gUnloading, 0, 0) != 0) {
        status = STATUS_DEVICE_BUSY;
    } else {
        RtlZeroMemory(gGateRoot, sizeof(gGateRoot));
        gGateRootLengthBytes = 0;
        gClientPort = ClientPort;
        gClientMode = (LONG)context->ClientMode;
        InterlockedExchange64(&gClientProcessId, (LONG64)context->ClientProcessId);

        if (context->ClientMode == RgClientLabGate) {
            RtlCopyMemory(gGateRoot, context->GateRoot, rootBytes);
            rootChars = rootBytes / sizeof(WCHAR);
            while (rootChars > 1 && gGateRoot[rootChars - 1] == L'\\') {
                gGateRoot[rootChars - 1] = L'\0';
                rootChars--;
            }
            gGateRootLengthBytes = (USHORT)(rootChars * sizeof(WCHAR));
        }
        InterlockedExchange(&gClientConnected, 1);
    }
    ExReleaseFastMutex(&gPortMutex);
    return status;
}

static VOID RgDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    ExAcquireFastMutex(&gPortMutex);
    InterlockedExchange(&gClientConnected, 0);
    InterlockedExchange(&gClientMode, 0);
    InterlockedExchange64(&gClientProcessId, 0);
    gGateRootLengthBytes = 0;
    RtlSecureZeroMemory(gGateRoot, sizeof(gGateRoot));
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilter, &gClientPort);
    }
    ExReleaseFastMutex(&gPortMutex);
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

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    ExAcquireFastMutex(&gPortMutex);
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilter, &gClientPort);
    }
    ExReleaseFastMutex(&gPortMutex);

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
        NULL, RgConnect, RgDisconnect, NULL, 1);
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
