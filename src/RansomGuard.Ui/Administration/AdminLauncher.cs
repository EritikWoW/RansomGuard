using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using RansomGuard.Core;

namespace RansomGuard.Ui.Administration;

internal static class AdminLauncher
{
    // Launch only THIS application, only a closed list of verbs, never cmd/PowerShell/user EXEs.
    internal static async Task<bool> OpenAsync(string action, string? ruleId, string theme, string language)
    {
        AdminContract.ValidateIntent(action, ruleId);
        if (!L.Supported(language)) throw new ArgumentException("Unsupported UI language.");
        if (theme is not ("Dark" or "Light" or "System")) throw new ArgumentException("Invalid theme.");
        string executable = Environment.ProcessPath ?? throw new IOException("Application executable unavailable.");
        if (!string.Equals(Path.GetFileName(executable), "RansomGuard.Ui.exe", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Run the published RansomGuard.Ui.exe to use administrator actions.");
        // Keep the actual image path read-locked through the UAC invocation/lifetime.
        using var imageLease = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        var info = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
        info.ArgumentList.Add("--admin-ui"); info.ArgumentList.Add(action); info.ArgumentList.Add(ruleId ?? "-"); info.ArgumentList.Add(theme); info.ArgumentList.Add(language);
        try
        {
            using var child = Process.Start(info) ?? throw new IOException("Administrator window did not start.");
            await child.WaitForExitAsync(); // NO timeout kill; the administrator may still be reviewing an operation.
            return child.ExitCode switch { 0 => true, 2 => false, _ => throw new IOException("Administrator dialog exited with code " + child.ExitCode + ". Review its error message.") };
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return false; }
    }
}
