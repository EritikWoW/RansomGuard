#pragma once

// Wire protocol between the RansomGuard lab minifilter and user-mode clients.
// v17 keeps the v16 protection-state machine and repurposes the former reserved connect field
// as GateVolumeLengthBytes so the kernel can bind the exact protected PFLT_VOLUME. This lets
// path-query ambiguity fail safe only on the protected volume while other volumes remain outside scope.
// The driver binds the exact requestor PEPROCESS for containment before allowing that IRP to continue.
// The production bundle still does not install or enable the driver.

#define RG_PROTOCOL_VERSION 17u
#define RG_PATH_CHARS 512u
#define RG_GATE_ROOT_CHARS 260u
#define RG_PORT_NAME L"\\RansomGuardMinifilterPort"

#define RG_CREATE_DISPOSITION_SHIFT 24u
#define RG_CREATE_DISPOSITION_MASK 0xFF000000u
#define RG_CREATE_OPTIONS_MASK 0x00FFFFFFu
#define RG_EVENT_FLAG_PAGING_IO 0x00000001u
#define RG_EVENT_FLAG_PREFLIGHT_WRITABLE_VIEW 0x00000002u
#define RG_EVENT_FLAG_DELETE_PENDING 0x00000004u
#define RG_EVENT_FLAG_DELETE_CANCELLED 0x00000008u
#define RG_EVENT_FLAG_DELETE_CLEANUP 0x00000010u
#define RG_EVENT_FLAG_DELETE_STATE_RESOLVED 0x00000020u
#define RG_DELETE_DISPOSITION_DELETE 0x00000001u

typedef enum _RG_EVENT_TYPE {
    RgEventInvalid = 0,
    RgEventWrite = 1,
    RgEventRename = 2,
    RgEventDeleteDisposition = 3,
    RgEventTruncate = 4,
    RgEventCreate = 5,
    RgEventRenameResult = 6,
    RgEventCreateResult = 7,
    RgEventPagingWrite = 8,
    RgEventWritableSection = 9,
    RgEventActivationPreflight = 10,
    RgEventContainmentActivated = 11,
    RgEventTruncateResult = 12,
    RgEventDeleteDispositionResult = 13,
    RgEventDeleteFinalized = 14
} RG_EVENT_TYPE;

typedef enum _RG_PATH_STATUS {
    RgPathUnknown = 0,
    RgPathResolved = 1,
    RgPathQueryFailed = 2,
    RgPathTruncated = 3
} RG_PATH_STATUS;

typedef enum _RG_IDENTITY_STATUS {
    RgIdentityUnknown = 0,
    RgIdentityResolved = 1,
    RgIdentityQueryFailed = 2
} RG_IDENTITY_STATUS;

typedef enum _RG_CLIENT_MODE {
    RgClientAudit = 1,
    RgClientLabGate = 2
} RG_CLIENT_MODE;

typedef enum _RG_PROTECTION_STATE {
    RgProtectionInactive = 0,
    RgProtectionPreflight = 1,
    RgProtectionProtected = 2,
    RgProtectionDegradedProtected = 3,
    RgProtectionMaintenance = 4
} RG_PROTECTION_STATE;

typedef enum _RG_GATE_DECISION {
    RgGateInvalid = 0,
    RgGateSnapshotCommitted = 1,
    RgGateDeny = 2,
    RgGateBaselineCommitted = 3,
    RgGateNoPreservationRequired = 4
} RG_GATE_DECISION;

#define RG_GATE_REPLY_FLAG_CONTAIN_REQUESTOR 0x00000001u

typedef enum _RG_CONTROL_COMMAND {
    RgControlInvalid = 0,
    RgControlActivateGate = 1,
    RgControlQueryActivation = 2,
    RgControlArmPreflight = 3,
    RgControlActivateAndContainProcess = 4,
    RgControlQueryContainment = 5,
    RgControlDeactivateGate = 6
} RG_CONTROL_COMMAND;

#pragma pack(push, 1)
typedef struct _RG_CONNECT_CONTEXT {
    unsigned long ProtocolVersion;
    unsigned long ClientMode;
    unsigned long long ClientProcessId;
    unsigned long GateRootLengthBytes;
    unsigned long GateVolumeLengthBytes;
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
    unsigned long DestinationPathStatus;
    unsigned long long RelatedSequence;
    unsigned long CompletionStatus;
    unsigned long long CompletionInformation;
    unsigned long IdentityStatus;
    unsigned long long VolumeSerialNumber;
    unsigned long long FileIdLow;
    unsigned long long FileIdHigh;
    wchar_t Path[RG_PATH_CHARS];
    wchar_t DestinationPath[RG_PATH_CHARS];
} RG_EVENT, *PRG_EVENT;

typedef struct _RG_GATE_REPLY {
    unsigned long ProtocolVersion;
    unsigned long Decision;
    unsigned long long RequestSequence;
    unsigned long ErrorCode;
    unsigned long Flags;
} RG_GATE_REPLY, *PRG_GATE_REPLY;

typedef struct _RG_CONTROL_REQUEST {
    unsigned long ProtocolVersion;
    unsigned long Command;
    unsigned long long TargetProcessId;
} RG_CONTROL_REQUEST, *PRG_CONTROL_REQUEST;

typedef struct _RG_CONTROL_REPLY {
    unsigned long ProtocolVersion;
    unsigned long Command;
    unsigned long Status;
    unsigned long GateActivated;
    unsigned long ContainmentActive;
    unsigned long ProtectionState;
    unsigned long long ContainedProcessId;
} RG_CONTROL_REPLY, *PRG_CONTROL_REPLY;
#pragma pack(pop)
