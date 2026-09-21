namespace RansomGuard.Rollback;

/// <summary>
/// Pure policy for IRP_MJ_CREATE preservation decisions. It contains no filesystem or driver calls,
/// which keeps the create-disposition/options matrix directly testable.
/// </summary>
public static class CreateGatePolicy
{
    public const uint FileWriteData = 0x00000002;
    public const uint FileDeleteOnClose = 0x00001000;
    public const uint MaximumAllowed = 0x02000000;
    public const uint GenericAll = 0x10000000;
    public const uint GenericWrite = 0x40000000;

    public static bool TryParseDisposition(uint raw, out CreateDisposition disposition)
    {
        if (raw <= (uint)CreateDisposition.OverwriteIf)
        {
            disposition = (CreateDisposition)raw;
            return true;
        }

        disposition = default;
        return false;
    }

    public static bool RequestsWriteCapableHandle(uint desiredAccess) =>
        (desiredAccess & (FileWriteData | MaximumAllowed | GenericAll | GenericWrite)) != 0;

    public static CreatePreservationAction Decide(CreateDisposition disposition, CreateTargetState target,
        uint createOptions = 0, uint desiredAccess = 0)
    {
        var deleteOnClose = (createOptions & FileDeleteOnClose) != 0;

        if (target == CreateTargetState.Directory)
            return deleteOnClose
                ? CreatePreservationAction.DenyUnsupported
                : CreatePreservationAction.NoPreservationRequired;

        if (target == CreateTargetState.File)
        {
            var destructiveDisposition =
                disposition is CreateDisposition.Supersede or CreateDisposition.Overwrite or CreateDisposition.OverwriteIf;
            var successfulOpenMayWrite =
                (disposition is CreateDisposition.Open or CreateDisposition.OpenIf) &&
                RequestsWriteCapableHandle(desiredAccess);

            return deleteOnClose || destructiveDisposition || successfulOpenMayWrite
                ? CreatePreservationAction.CaptureExistingPreimage
                : CreatePreservationAction.NoPreservationRequired;
        }

        return disposition is CreateDisposition.Supersede or CreateDisposition.Create or
            CreateDisposition.OpenIf or CreateDisposition.OverwriteIf
            ? CreatePreservationAction.RecordOriginallyAbsent
            : CreatePreservationAction.NoPreservationRequired;
    }
}

public enum CreateDisposition : uint
{
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5
}

public enum CreateTargetState
{
    Missing = 0,
    File = 1,
    Directory = 2
}

public enum CreatePreservationAction
{
    NoPreservationRequired = 0,
    CaptureExistingPreimage = 1,
    RecordOriginallyAbsent = 2,
    DenyUnsupported = 3
}
