namespace RansomGuard.Core;

// UI review conditions only. Windows ACL, identity and service checks are STILL
// enforced again by Management when the administrator clicks the action button.
// A review token is not an authentication credential. It is never accepted over IPC.
public enum SetupStorage { Unknown, Missing, Private, NeedsReview, Unreadable }
public sealed record SetupReview(bool ServiceQuerySucceeded, bool Installed, string ServiceState,
    bool PackageVerified, bool FoldersVerified, SetupStorage Storage, bool CanArchive, string? StorageRevision);
public static class SetupReviewPolicy
{
    public static bool CanInstall(SetupReview? review, bool busy) => !busy && review is
        { ServiceQuerySucceeded: true, Installed: false, PackageVerified: true, FoldersVerified: true,
          Storage: SetupStorage.Missing or SetupStorage.Private };
    public static bool CanReset(SetupReview? review, bool acknowledged, bool busy) =>
        !busy && acknowledged && review is { ServiceQuerySucceeded: true, CanArchive: true,
            Storage: SetupStorage.NeedsReview or SetupStorage.Missing, StorageRevision: not null } &&
        !string.IsNullOrWhiteSpace(review.StorageRevision) && (!review.Installed || review.ServiceState == "Stopped");
    public static bool CanControl(SetupReview? review, string action, bool acknowledged, bool busy)
    {
        if (busy || review is not { ServiceQuerySucceeded: true, Installed: true, PackageVerified: true,
                Storage: SetupStorage.Private or SetupStorage.Missing }) return false;
        return action switch
        {
            "start" => review.ServiceState == "Stopped",
            "stop" or "restart" => acknowledged && review.ServiceState == "Running",
            "uninstall" => acknowledged && review.ServiceState == "Stopped",
            _ => false
        };
    }
}
