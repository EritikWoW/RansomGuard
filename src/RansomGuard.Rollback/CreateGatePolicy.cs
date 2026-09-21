namespace RansomGuard.Rollback;

/// <summary>
/// Pure policy for IRP_MJ_CREATE preservation decisions. It contains no filesystem or driver calls,
/// which keeps the create-disposition matrix directly testable.
/// </summary>
public static class CreateGatePolicy
{
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

    public static CreatePreservationAction Decide(CreateDisposition disposition, CreateTargetState target)
    {
        if (target == CreateTargetState.Directory)
            return CreatePreservationAction.NoPreservationRequired;

        if (target == CreateTargetState.File)
        {
            return disposition is CreateDisposition.Supersede or CreateDisposition.Overwrite or CreateDisposition.OverwriteIf
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
    RecordOriginallyAbsent = 2
}
