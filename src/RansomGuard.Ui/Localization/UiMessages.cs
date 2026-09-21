namespace RansomGuard.Ui;

internal static class UiMessages
{
    public static string YesNo(bool value) => L.T(value ? "Bool.True" : "Bool.False");
    public static string State(string? code) => code switch
    {
        "NotInstalled" => L.T("T170"), "Running" => L.T("State.Running"), "Stopped" => L.T("State.Stopped"),
        "Starting" or "StartPending" => L.T("State.Starting"), "Stopping" or "StopPending" => L.T("State.Stopping"),
        "Valid" or "ValidCached" => L.T("T154"), "NoEmbeddedSignatureOrCatalogOnly" => L.T("T155"), "BadDigest" => L.T("Signature.BadDigest"),
        "Failed" => L.T("State.Failed"), "Automatic" => L.T("State.Automatic"), "Manual" => L.T("State.Manual"),
        null or "Unknown" => L.T("T037"), _ => code
    };
    public static string Operation(string value) => value switch
    { "Write" => L.T("Admin.Writes"), "Rename" => L.T("Admin.Renames"), "Delete" => L.T("Admin.Deletes"), _ => value };
    public static string Effect(string? value) => value == "QuietRepeat" ? L.T("T163") : value == "AnnotateOnly" ? L.T("T164") : value ?? L.T("T037");
    // Known engine messages are translated for display only; raw JSON/protocol is retained verbatim.
    public static string Message(string? message) => message switch
    {
        "many write operations; may include new-file creation" => L.T("Reason.Writes"),
        "write+rename pattern across several files; heuristic, not proof of encryption" => L.T("Reason.Renames"),
        "LAB ONLY fast synthetic write+rename threshold; not a production blocking rule" => L.T("Reason.Lab"),
        "Synthetic UI fixture. No real process was scanned." => L.T("Preview.NoScan"),
        "Synthetic UI fixture only. No dump opened by this UI test." => L.T("Preview.NoDump"),
        "Synthetic negative case: no authenticated candidate." => L.T("Preview.NoKey"),
        "NotChecked" => L.T("T168"), null => L.T("T037"), _ => message
    };
    public static string ErrorSummary(Exception ex)
    {
        string m = ex.Message;
        if (ex.GetBaseException() is System.ComponentModel.Win32Exception native && native.NativeErrorCode == 5)
            return L.T("Error.StateArchiveAccess");
        if (m.StartsWith("StateRecoveryPartial", StringComparison.Ordinal)) return L.T("Error.StatePartial");
        if (m.StartsWith("StateChanged", StringComparison.Ordinal)) return L.T("Error.StateChanged");
        if (m.StartsWith("StateBusy", StringComparison.Ordinal)) return L.T("Error.BusyStore");
        if (m.Contains("state directory", StringComparison.OrdinalIgnoreCase) || m.Contains("state root", StringComparison.OrdinalIgnoreCase))
            return L.T("Error.UnsafeStore");
        return ex switch
        {
            UnauthorizedAccessException => L.T("Error.Access"),
            OperationCanceledException => L.T("Error.Cancelled"),
            FormatException or ArgumentException or OverflowException => L.T("Error.Input"),
            _ => L.T("Error.General")
        };
    }
}
