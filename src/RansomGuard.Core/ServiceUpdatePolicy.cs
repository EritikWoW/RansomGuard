namespace RansomGuard.Core;

public static class ServiceUpdatePolicy
{
    public static bool IsForwardVersion(string? currentText, string? targetText)
    {
        if (!Version.TryParse(currentText, out var current) ||
            !Version.TryParse(targetText, out var target))
            return false;
        return target.CompareTo(current) > 0;
    }
}
