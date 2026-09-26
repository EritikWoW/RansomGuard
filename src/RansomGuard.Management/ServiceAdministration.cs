using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record ManagedServiceStatus(bool QuerySucceeded, bool Installed, string State, string ImagePath,
    string Account, string StartMode, uint Pid, string? Error);
internal sealed record InstallRecord(int Schema, string Version, string ImageSha256, DateTime CreatedUtc);

public static partial class ServiceAdministration
{
    public static string InstallRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RansomGuardV03");
    private const uint QueryConfig = 1, QueryStatus = 4, StartAccess = 16, StopAccess = 32, DeleteAccess = 0x10000;
    public static ManagedServiceStatus Query()
    {
        try
        {
            using var scm = Scm.OpenSCManagerW(null, null, 1);
            if (scm.IsInvalid) throw Error();
            using var service = Scm.OpenServiceW(scm, AdminContract.ServiceName, QueryConfig | QueryStatus);
            if (service.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 1060) return new(true, false, "NotInstalled", "", "", "", 0, null);
                throw new Win32Exception(e);
            }
            var state = Status(service);
            var config = Configuration(service);
            return new(true, true, StateName(state.CurrentState), config.ImagePath, config.Account,
                config.StartType == 2 ? "Automatic" : config.StartType == 3 ? "Manual" : "Other", state.ProcessId, null);
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException)
        { return new(false, false, "Unknown", "", "", "", 0, ex.Message); }
    }
    public static string GetPackageRoot(string uiDirectory)
    {
        var directory = Path.GetFullPath(uiDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(Path.GetFileName(directory), "UI", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Launch the published UI in its UI folder, not a source/build temporary EXE.");
        return Path.GetDirectoryName(directory) ?? throw new IOException("Package layout missing.");
    }
    // Read-only preflight. The actual install independently repeats all checks;
    // opening a wizard or pressing Next does not create directories or register a service.
    public static void ReviewInstallInput(string packageRoot, string expectedServiceHash, string[] roots)
    {
        RuleAdministration.DemandAdministrator();
        ValidateRoots(roots);
        var before = Query();
        if (!before.QuerySucceeded) throw new IOException(before.Error);
        if (before.Installed) throw new IOException("RansomGuardV03 is already registered. No silent overwrite or upgrade.");
        var source = Path.Combine(packageRoot, "RansomGuard.Service.exe");
        FileSafety.NoReparse(source);
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        var version = typeof(ServiceAdministration).Assembly.GetName().Version?.ToString();
        if (input.Length is < 4096 or > 256L * 1024 * 1024 ||
            !WinPaths.Equal(source, Native.FinalFilePath(input.SafeFileHandle)) ||
            !string.Equals(FileVersionInfo.GetVersionInfo(source).FileVersion, version, StringComparison.Ordinal) ||
            !DecisionPolicy.HashEqual(Convert.ToHexString(SHA256.HashData(input)), expectedServiceHash))
            throw new IOException("Service bytes do not match the SHA-256 embedded in this UI. Use one complete release.");

        _ = InspectUpdateProtectionPackage(
            packageRoot,
            version ?? throw new IOException("Version missing."));
    }
    public static string Install(string packageRoot, string expectedServiceHash, string[] roots, bool automatic, string confirmation)
    {
        using var maintenance = StateMaintenanceGate.Acquire();
        RuleAdministration.DemandAdministrator(); AdminContract.CheckConfirmation("install", confirmation);
        var store = new SecureStore(); // Refuse an untrusted security store before registering a privileged service.
        ValidateRoots(roots);
        var before = Query();
        if (!before.QuerySucceeded) throw new IOException(before.Error);
        if (before.Installed) throw new IOException("RansomGuardV03 is already registered. No silent overwrite or upgrade.");
        using var scm = Scm.OpenSCManagerW(null, null, 3);
        if (scm.IsInvalid) throw Error();
        // Source path is derived from THIS approved package, never from command-line/user JSON.
        var source = Path.Combine(packageRoot, "RansomGuard.Service.exe");
        FileSafety.NoReparse(source);
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 4096 or > 256L * 1024 * 1024) throw new IOException("Service executable size rejected.");
        if (!WinPaths.Equal(source, Native.FinalFilePath(input.SafeFileHandle))) throw new IOException("Source path redirected.");
        var productVersion = typeof(ServiceAdministration).Assembly.GetName().Version?.ToString() ?? throw new IOException("Version missing.");
        if (!string.Equals(FileVersionInfo.GetVersionInfo(source).FileVersion, productVersion, StringComparison.Ordinal))
            throw new IOException("UI and service versions differ. Use one complete release.");
        string hash = Convert.ToHexString(SHA256.HashData(input)); input.Position = 0;
        if (!DecisionPolicy.HashEqual(hash, expectedServiceHash))
            throw new IOException("Service bytes do not match the SHA-256 embedded in this UI. Rebuild/use one complete release; no installation performed.");
        var sourceProtection = InspectUpdateProtectionPackage(packageRoot, productVersion);
        EnsureInstallDirectory(InstallRoot);
        string dest = Path.Combine(InstallRoot, "v" + productVersion + "-" + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(dest)) throw new IOException("Destination already exists.");
        EnsureInstallDirectory(dest);
        string image = Path.Combine(dest, "RansomGuard.Service.exe");
        bool registered = false;
        try
        {
            using (var output = new FileStream(image, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { input.CopyTo(output); output.Flush(true); }
            SetInstallFileAcl(image);
            using (var copied = File.OpenRead(image))
                if (!DecisionPolicy.HashEqual(hash, Convert.ToHexString(SHA256.HashData(copied)))) throw new IOException("Service copy hash mismatch.");
            var settings = new GuardSettings { ProtectedRoots = roots.ToArray(), Mode = "Audit" };
            settings.Validate();
            WriteNew(Path.Combine(dest, "appsettings.json"), settings);
            WriteNew(Path.Combine(dest, "install.json"), new InstallRecord(1, productVersion, hash, DateTime.UtcNow));
            StageUpdateProtectionPackage(sourceProtection, dest);
            store.Audit(new { Utc = DateTime.UtcNow, Event = "ServiceInstallPrepared", Service = AdminContract.ServiceName,
                Image = image, Sha256 = hash, Roots = roots, Automatic = automatic,
                ProtectionPackage = sourceProtection is not null, Actor = CurrentActor() });
            using var service = Scm.CreateServiceW(scm, AdminContract.ServiceName, "RansomGuard - audit monitoring",
                QueryConfig | QueryStatus, 0x10, automatic ? 2u : 3u, 1, "\"" + image + "\"", null, IntPtr.Zero, null, "LocalSystem", null);
            if (service.IsInvalid) throw Error();
            registered = true;
            store.Audit(new { Utc = DateTime.UtcNow, Event = "ServiceInstalled", Image = image, Started = false });
            return image;
        }
        catch (Exception ex)
        {
            if (registered) throw new IOException("Service WAS registered, but a follow-up check/audit failed. Inspect current service status; it was NOT started. " + ex.Message, ex);
            CleanupStagedProtectionPackage(dest);
            // Only the three known non-Protection files in the newly-created directory. No recursive deletion.
            foreach (string file in new[] { image, Path.Combine(dest, "appsettings.json"), Path.Combine(dest, "install.json") })
                try { if (File.Exists(file)) { FileSafety.NoReparse(file); File.Delete(file); } } catch (IOException) { }
            try { Directory.Delete(dest, false); } catch (IOException) { }
            throw;
        }
    }
    public static void Execute(string action, string confirmation)
    {
        using var maintenance = StateMaintenanceGate.Acquire();
        RuleAdministration.DemandAdministrator();
        if (action is not ("start" or "stop" or "restart" or "uninstall")) throw new ArgumentException("Unsupported service operation.");
        AdminContract.CheckConfirmation(action, confirmation);
        var store = new SecureStore();
        using var scm = Scm.OpenSCManagerW(null, null, 1);
        if (scm.IsInvalid) throw Error();
        uint access = QueryConfig | QueryStatus;
        if (action is "start" or "restart") access |= StartAccess;
        if (action is "stop" or "restart") access |= StopAccess;
        if (action == "uninstall") access |= DeleteAccess;
        using var service = Scm.OpenServiceW(scm, AdminContract.ServiceName, access);
        if (service.IsInvalid) throw Error();
        var config = Configuration(service);
        VerifyRegistration(config.ImagePath, config.Account, config.ServiceType, action is "start" or "restart");
        // Legacy registrations may only be stopped/unregistered after path/ACL checks.
        // Starting/restarting requires the new install record and exact stored image hash.
        using var imageLease = action is "start" or "restart" ? VerifyInstalledImage(config.ImagePath) : null;
        store.Audit(new { Utc = DateTime.UtcNow, Event = "ServiceControlPrepared", Action = action, Service = AdminContract.ServiceName, Actor = CurrentActor() });
        if (action is "stop" or "restart")
        {
            var state = Status(service);
            if (state.CurrentState == 2) WaitFor(service, 4);
            if (Status(service).CurrentState != 1)
            {
                if (Status(service).CurrentState != 3 && !Scm.ControlService(service, 1, out _)) throw Error();
                WaitFor(service, 1);
            }
        }
        if (action is "start" or "restart")
        {
            // The new service must acquire its own startup/maintenance lease.
            // Never retain this thread-affine lease while waiting for a different process to start.
            maintenance.Dispose();
            var state = Status(service);
            if (state.CurrentState != 4) RejectOtherAuditInstance();
            if (state.CurrentState == 3) WaitFor(service, 1);
            if (Status(service).CurrentState != 4)
            {
                if (Status(service).CurrentState != 2 && !Scm.StartServiceW(service, 0, IntPtr.Zero)) throw Error();
                WaitFor(service, 4);
            }
        }
        if (action == "uninstall")
        {
            if (Status(service).CurrentState != 1) throw new IOException("Stop the service first. No automatic forced termination.");
            if (!Scm.DeleteService(service)) throw Error();
        }
        try { store.Audit(new { Utc = DateTime.UtcNow, Event = "ServiceControlCompleted", Action = action }); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new IOException("Service operation was applied, but audit append failed. Check current status before repeating. " + ex.Message, ex); }
    }
    private static void RejectOtherAuditInstance()
    {
        // No Stop/Kill by process name. Refuse a duplicate console instead.
        foreach (var p in Process.GetProcessesByName("RansomGuard.Service"))
            using (p) { if (!p.HasExited) throw new IOException("An audit console/service is already running. Close its console with Ctrl+C before starting another engine."); }
    }
    public static bool MatchesInstalledPeer(uint serverPid, string expectedServiceHash)
    {
        // A normal desktop UI must not need OpenProcess access to a LocalSystem service.
        // Bind the pipe endpoint to the fixed SCM registration + current service PID, then
        // verify the protected installed image and the SHA-256 embedded in this UI build.
        var registration = Query();
        if (!registration.QuerySucceeded || !registration.Installed ||
            registration.State != "Running" || registration.Pid == 0 || registration.Pid != serverPid) return false;
        try
        {
            VerifyRegistration(registration.ImagePath, registration.Account, 0x10);
            using var installed = VerifyInstalledImage(registration.ImagePath);
            installed.Position = 0;
            return DecisionPolicy.HashEqual(Convert.ToHexString(SHA256.HashData(installed)), expectedServiceHash);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException) { return false; }
    }
    public static bool MatchesInstalledPeer(string actual, string expectedServiceHash)
    {
        // Kept for setup/status code that already has a trusted image path.
        var registration = Query();
        if (!registration.QuerySucceeded || !registration.Installed || !WinPaths.Equal(registration.ImagePath, actual)) return false;
        try
        {
            VerifyRegistration(actual, registration.Account, 0x10);
            using var installed = VerifyInstalledImage(actual);
            installed.Position = 0;
            return DecisionPolicy.HashEqual(Convert.ToHexString(SHA256.HashData(installed)), expectedServiceHash);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException) { return false; }
    }
    public static bool MatchesPackageImage(string path, string expectedServiceHash)
    {
        try
        {
            FileSafety.NoReparse(path);
            using var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (image.Length is < 4096 or > 256L * 1024 * 1024 || !WinPaths.Equal(path, Native.FinalFilePath(image.SafeFileHandle))) return false;
            return DecisionPolicy.HashEqual(Convert.ToHexString(SHA256.HashData(image)), expectedServiceHash);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException) { return false; }
    }
    private static bool IsSha256Hex(string? value) =>
        value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    private static FileStream VerifyInstalledImage(string path)
    {
        string folder = Path.GetDirectoryName(path) ?? throw new IOException("Installed path missing.");
        string recordPath = Path.Combine(folder, "install.json"); VerifyInstallAcl(recordPath, false);
        using var recordFile = new FileStream(recordPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (recordFile.Length > 4096) throw new IOException("Install record too large.");
        var record = JsonSerializer.Deserialize<InstallRecord>(recordFile) ?? throw new IOException("Install record unavailable; reinstall using this UI.");
        if (record.Schema != 1 || !IsSha256Hex(record.ImageSha256)) throw new IOException("Install record invalid.");
        FileSafety.NoReparse(path);
        var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (image.Length > 256L * 1024 * 1024 || !WinPaths.Equal(Native.FinalFilePath(image.SafeFileHandle), path) ||
                !DecisionPolicy.HashEqual(record.ImageSha256, Convert.ToHexString(SHA256.HashData(image)))) throw new IOException("Installed service integrity check failed.");
            image.Position = 0; return image;
        }
        catch { image.Dispose(); throw; }
    }
    private static void VerifyRegistration(string image, string account, uint type, bool checkConfiguration = true)
    {
        if (type != 0x10 || !string.Equals(account, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            !WinPaths.Under(image, InstallRoot) || Path.GetFileName(image) != "RansomGuard.Service.exe")
            throw new IOException("Existing registration is not the expected RansomGuard service. No operation performed.");
        VerifyInstallAcl(InstallRoot);
        string folder = Path.GetDirectoryName(image) ?? throw new IOException("Missing service folder.");
        if (!WinPaths.Equal(folder, InstallRoot)) VerifyInstallAcl(folder);
        if (checkConfiguration || File.Exists(image)) VerifyInstallAcl(image, false);
        if (!checkConfiguration) return;
        var config = Path.Combine(folder, "appsettings.json"); VerifyInstallAcl(config, false);
        if (new FileInfo(config).Length > 65536) throw new IOException("Installed configuration exceeds limit.");
        using var f = new FileStream(config, FileMode.Open, FileAccess.Read, FileShare.Read);
        var settings = JsonSerializer.Deserialize<GuardSettings>(f) ?? throw new IOException("Configuration missing.");
        settings.Validate(); if (settings.ProtectedRoots.Length == 0) throw new IOException("Explicit monitored roots required.");
    }
    private static void ValidateRoots(string[] roots)
    {
        if (roots.Length is < 1 or > 64 || roots.Distinct(StringComparer.OrdinalIgnoreCase).Count() != roots.Length)
            throw new ArgumentException("Select 1-64 unique monitored directories.");
        string[] denied = [Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)];
        foreach (var root in roots)
        {
            ScopedRuleVerifier.CheckDirectory(root);
            if (root.Length <= 3 || denied.Where(x => x.Length > 0).Any(x => WinPaths.Equal(root, x) || WinPaths.Under(root, x) || WinPaths.Under(x, root)))
                throw new ArgumentException("Do not monitor drive/system/program/state roots. Select explicit data folders.");
        }
    }
    private static void WriteNew(string path, object data)
    {
        using var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        JsonSerializer.Serialize(f, data, new JsonSerializerOptions { WriteIndented = true }); f.Flush(true);
        f.Dispose();
        SetInstallFileAcl(path);
    }
    private static void SetInstallFileAcl(string path)
    {
        var acl = new FileSecurity(); acl.SetAccessRuleProtection(true, false);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null); acl.SetOwner(admins);
        foreach (var sid in new[] { admins, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
    }
    private static void EnsureInstallDirectory(string path)
    {
        FileSafety.NoReparse(path);
        if (Directory.Exists(path)) { VerifyInstallAcl(path); return; }
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null); acl.SetOwner(admins);
        foreach (var sid in new[] { admins, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(acl); VerifyInstallAcl(path);
    }
    private static void VerifyInstallAcl(string path, bool directory = true)
    {
        FileSafety.NoReparse(path);
        FileSystemSecurity acl = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        string owner = acl.GetOwner(typeof(SecurityIdentifier))?.Value ?? "";
        if (owner is not ("S-1-5-18" or "S-1-5-32-544")) throw new UnauthorizedAccessException("Installed object owner not trusted: " + path);
        const FileSystemRights writes = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule r in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & writes) != 0 && r.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new UnauthorizedAccessException("Installed object writable by another principal: " + path);
    }
    private static Scm.ServiceStatus Status(Scm.Handle h)
    {
        if (!Scm.QueryServiceStatusEx(h, 0, out var s, Marshal.SizeOf<Scm.ServiceStatus>(), out _)) throw Error();
        return s;
    }
    private sealed record ServiceConfig(string ImagePath, string Account, uint StartType, uint ServiceType);
    private static ServiceConfig Configuration(Scm.Handle h)
    {
        _ = Scm.QueryServiceConfigW(h, IntPtr.Zero, 0, out uint needed);
        if (needed is 0 or > 65536) throw Error();
        var memory = Marshal.AllocHGlobal(checked((int)needed));
        try
        {
            if (!Scm.QueryServiceConfigW(h, memory, needed, out _)) throw Error();
            var c = Marshal.PtrToStructure<Scm.Config>(memory);
            string raw = Marshal.PtrToStringUni(c.BinaryPath) ?? "";
            if (raw.Contains(' ') && !(raw.StartsWith('"') && raw.EndsWith('"')))
                throw new IOException("Unquoted service image path rejected.");
            // A sole fully quoted executable or an unquoted no-space executable; NO arbitrary arguments.
            string path = raw.StartsWith('"') && raw.EndsWith('"') && raw.Length > 2 ? raw[1..^1] : raw;
            if (path.Contains('"') || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !ScopedTrustPolicy.ExactLocalPath(path))
                throw new IOException("Unexpected service command line.");
            return new(path, Marshal.PtrToStringUni(c.Account) ?? "", c.StartType, c.ServiceType);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    private static void WaitFor(Scm.Handle handle, uint desired)
    {
        var timer = Stopwatch.StartNew();
        while (timer.Elapsed < TimeSpan.FromSeconds(30))
        {
            var s = Status(handle);
            if (s.CurrentState == desired) return;
            if (desired == 4 && s.CurrentState == 1) throw new IOException("Service stopped during startup. Win32 exit=" + s.Win32ExitCode + ". Check the Application event log. Monitoring is NOT confirmed.");
            Thread.Sleep(200);
        }
        throw new TimeoutException("SCM did not reach the requested state in 30 seconds. No force-kill attempted; refresh status before retrying.");
    }
    private static string StateName(uint state) => state switch { 1 => "Stopped", 2 => "StartPending", 3 => "StopPending", 4 => "Running", 7 => "Paused", _ => "Unknown" };
    private static string CurrentActor()
    { using var identity = WindowsIdentity.GetCurrent(); return identity.User?.Value ?? "Unavailable"; }
    private static Win32Exception Error() => new(Marshal.GetLastWin32Error());
}

internal static class Scm
{
    internal sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    { public Handle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
    [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus
    { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, Flags; }
    [StructLayout(LayoutKind.Sequential)] internal struct BasicStatus
    { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }
    [StructLayout(LayoutKind.Sequential)] internal struct Config
    { public uint ServiceType, StartType, ErrorControl; public IntPtr BinaryPath, Group; public uint Tag; public IntPtr Dependencies, Account, DisplayName; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle OpenSCManagerW(string? machine, string? database, uint rights);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle OpenServiceW(Handle scm, string name, uint rights);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceStatusEx(Handle h, int level, out ServiceStatus status, int size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool QueryServiceConfigW(Handle h, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle CreateServiceW(Handle scm, string name, string display, uint access, uint type, uint start, uint error, string image, string? group, IntPtr tag, string? dependencies, string? account, string? password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool StartServiceW(Handle service, uint count, IntPtr arguments);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool ControlService(Handle service, uint code, out BasicStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool DeleteService(Handle service);
}
