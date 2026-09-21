#pragma once

// Wire protocol between the RansomGuard lab minifilter and user-mode clients.
// v5 adds post-create reconciliation evidence. Mutation-capable CREATEs receive a post-operation
// event carrying the related pre-create sequence, actual CreateAction, completion status and
// FILE_ID_INFORMATION identity from the completed kernel FileObject.
// The production bundle still does not install or enable the driver.

#define RG_PROTOCOL_VERSION 5u
#define RG_PATH_CHARS 512u
#define RG_GATE_ROOT_CHARS 260u
#define RG_PORT_NAME L"\\RansomGuardMinifilterPort"

#define RG_CREATE_DISPOSITION_SHIFT 24u
#define RG_CREATE_DISPOSITION_MASK 0xFF000000u
#define RG_CREATE_OPTIONS_MASK 0x00FFFFFFu

typedef enum _RG_EVENT_TYPE {
    RgEventInvalid = 0,
    RgEventWrite = 1,
    RgEventRename = 2,
    RgEventDeleteDisposition = 3,
    RgEventTruncate = 4,
    RgEventCreate = 5,
    RgEventCreateResult = 6
} RG_EVENT_TYPE;

typedef enum _RG_PATH_STATUS {
    RgPathUnknown = 0,
    RgPathResolved = 1,
    RgPathQueryFailed = 2,
    RgPathTruncated = 3
} RG_PATH_STATUS;

typedef enum _RG_CLIENT_MODE {
    RgClientAudit = 1,
    RgClientLabGate = 2
} RG_CLIENT_MODE;

typedef enum _RG_GATE_DECISION {
    RgGateInvalid = 0,
    RgGateSnapshotCommitted = 1,
    RgGateDeny = 2,
    RgGateBaselineCommitted = 3,
    RgGateNoPreservationRequired = 4,
    RgGateReconciliationCommitted = 5
} RG_GATE_DECISION;

#pragma pack(push, 1)
typedef struct _RG_CONNECT_CONTEXT {
    unsigned long ProtocolVersion;
    unsigned long ClientMode;
    unsigned long long ClientProcessId;
    unsigned long GateRootLengthBytes;
    unsigned long Reserved;
    wchar_t GateRoot[RG_GATE_ROOT_CHARS];
} RG_CONNECT_CONTEXT, *PRG_CONNECT_CONTEXT;

typedef struct _RG_EVENT {
    unsigned long ProtocolVersion;
    unsigned long EventType;
    unsigned long PathStatus;
    unsigned long Flags;
    unsigned long long Sequence;
    long long SystemTime100ns;
    unsigned long long ProcessId;
    unsigned long long ThreadId;
    long long ByteOffset;
    unsigned long Length;
    unsigned long FileInformationClass;
    unsigned long DroppedBeforeThis;
    unsigned long Reserved;
    unsigned long long RelatedSequence;
    unsigned long long VolumeSerialNumber;
    unsigned long long FileIdPart0;
    unsigned long long FileIdPart1;
    unsigned long CompletionStatus;
    unsigned long CreateAction;
    unsigned long IdentityStatus;
    unsigned long Reserved2;
    wchar_t Path[RG_PATH_CHARS];
} RG_EVENT, *PRG_EVENT;

typedef struct _RG_GATE_REPLY {
    unsigned long ProtocolVersion;
    unsigned long Decision;
    unsigned long long RequestSequence;
    unsigned long ErrorCode;
    unsigned long Reserved;
} RG_GATE_REPLY, *PRG_GATE_REPLY;
#pragma pack(pop)
