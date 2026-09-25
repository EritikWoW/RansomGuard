#pragma once
#include <fltKernel.h>
#include "..\\..\\native\\shared\\rg_minifilter_protocol.h"

#define RG_POOL_TAG 'GmGR'
#define RG_MAX_PENDING 1024L
#define RG_MAX_GATE_INFLIGHT 8L
#define RG_SEND_TIMEOUT_MS 20LL
#define RG_RECONCILE_SEND_TIMEOUT_MS 2000LL
#define RG_GATE_TIMEOUT_MS 30000LL

typedef struct _RG_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    RG_EVENT Event;
    LONG ClientMode;
    LONG ClientGeneration;
} RG_WORK_ITEM, *PRG_WORK_ITEM;

typedef struct _RG_POST_CONTEXT {
    ULONGLONG RequestSequence;
    ULONG GateDecision;
    ULONG ActivationPreflight;
    ULONG ProtectionGeneration;
    LONG ClientGeneration;
    ULONG PostEventType;
    ULONG FileInformationClass;
    ULONG DispositionFlags;
    PFLT_FILE_NAME_INFORMATION PreDestinationNameInfo;
    PFLT_FILE_NAME_INFORMATION PreCreateNameInfo;
} RG_POST_CONTEXT, *PRG_POST_CONTEXT;

typedef struct _RG_DELETE_HANDLE_CONTEXT {
    ULONGLONG RequestSequence;
    ULONG FileInformationClass;
    ULONG DispositionFlags;
    ULONG ProtectionGeneration;
    LONG ClientGeneration;
} RG_DELETE_HANDLE_CONTEXT, *PRG_DELETE_HANDLE_CONTEXT;

typedef struct _RG_STREAM_CONTEXT {
    ULONG PathStatus;
    ULONG IdentityStatus;
    ULONG PreservationDecision;
    ULONG ProtectionGeneration;
    ULONGLONG CreateRequestSequence;
    ULONGLONG VolumeSerialNumber;
    ULONGLONG FileIdLow;
    ULONGLONG FileIdHigh;
    WCHAR Path[RG_PATH_CHARS];
} RG_STREAM_CONTEXT, *PRG_STREAM_CONTEXT;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS RgUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS RgInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                         _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
FLT_PREOP_CALLBACK_STATUS RgPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                      _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS RgPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_opt_ PVOID CompletionContext,
                                        _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS RgPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS RgPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                              _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS RgPreFileSystemControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS RgPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS RgPostSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                _In_opt_ PVOID CompletionContext,
                                                _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS RgPreCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                      _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS RgPostCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                         _In_opt_ PVOID CompletionContext,
                                         _In_ FLT_POST_OPERATION_FLAGS Flags);
