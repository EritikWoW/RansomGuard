using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RansomGuard.Core;

// Service/IPC liveness is separate from file monitoring availability.
public sealed record MonitoringHealthDto(
    string State,
    DateTime ObservedUtc,
    string SessionName,
    string? ErrorCode = null,
    int? Win32Error = null,
    string? ErrorMessage = null,
    string? RecoveryHint = null);

public static class MonitoringHealth
{
    public static bool IsRunning(MonitoringHealthDto? value) => value?.State == "Running";
    public static string ProtectionMode(MonitoringHealthDto value) =>
        IsRunning(value) ? "AuditOnly" : "MonitoringUnavailable";

    public static bool IsOperationalFailure(Exception error) =>
        error is COMException or Win32Exception or UnauthorizedAccessException or System.IO.IOException;

    public static int? Win32Code(Exception error)
    {
        if (error is Win32Exception win32) return win32.NativeErrorCode;
        uint hr = unchecked((uint)error.HResult);
        return (hr & 0xffff0000u) == 0x80070000u ? (int)(hr & 0xffffu) : null;
    }

    public static MonitoringHealthDto Failed(Exception error, string sessionName, DateTime now)
    {
        int? code = Win32Code(error);
        string hint = code switch
        {
            1450 => "ETW session or system-logger limits may be exhausted. Run diagnose_etw.cmd elevated. Do not stop unrelated sessions or increase EtwMaxLoggers automatically. Restart RansomGuard only after diagnosis.",
            183 => "A trace session with this name already exists. It was NOT stopped or attached. Inspect existing sessions before restarting.",
            5 => "Windows denied ETW access. Use the elevated audit launcher; do not change directory ACLs or disable security software.",
            _ => "Run diagnose_etw.cmd elevated and review the audit log. The read-only UI remains available, but file monitoring is unavailable."
        };
        string message = error.Message;
        if (message.Length > 768) message = message[..768];
        return new("Failed", now, sessionName, $"0x{unchecked((uint)error.HResult):X8}", code, message, hint);
    }
}
