using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("RansomGuard minifilter runtime harness is Windows-only.");

if (args.Length == 0)
    throw new ArgumentException("Use: connect-spoof --root <path> --claimed-pid <pid> --result <marker> | hold-map --file <path> --ready <marker> --release <marker> | hold-map-mutate --file <path> --ready <marker> --go <marker> --release <marker> --result <marker> | hold-map-dirty-flush --file <path> --ready <marker> --go <marker> --release <marker> --result <marker> | hold-write-handle --file <path> --ready <marker> --release <marker> | hold-dir-delete --directory <path> --ready <marker> --release <marker> | hard-link --existing <path> --link <path> --result <marker> [--ready <marker> --go <marker>] | hard-link-ex --existing <path> --link <path> --result <marker> [--ready <marker> --go <marker>] | fsctl-zero --file <path> --offset <bytes> --length <bytes> --result <marker> | map-write --file <path> [--ready <marker> --go <marker>] | create-new --file <path> [--ready <marker> --go <marker>] | rename-file --source <path> --destination <path> [--ready <marker> --go <marker>] | truncate-eof --file <path> --length <bytes> --ready <marker> --go <marker> | delete-file --file <path> --ready <marker> --go <marker> | containment-probe --file <path> --ready <marker> --go <marker> --result <marker> | containment-transition --file-a <path> --file-b <path> --ready <marker> --go <marker> --result <marker>");

var command = args[0].ToLowerInvariant();
var options = Parse(args.Skip(1).ToArray());

try
{
    switch (command)
    {
        case "connect-spoof":
            ConnectSpoof(
                Require(options, "--root"),
                RequireUInt64(options, "--claimed-pid"),
                Require(options, "--result"));
            break;
        case "hold-map":
            HoldMappedView(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--release"));
            break;
        case "hold-map-mutate":
            HoldMappedMutation(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--go"),
                Require(options, "--release"),
                Require(options, "--result"),
                dirtyBeforeGo: false);
            break;
        case "hold-map-dirty-flush":
            HoldMappedMutation(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--go"),
                Require(options, "--release"),
                Require(options, "--result"),
                dirtyBeforeGo: true);
            break;
        case "hold-write-handle":
            HoldWritableHandle(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--release"));
            break;
        case "hold-dir-delete":
            HoldDirectoryDeleteHandle(
                Require(options, "--directory"),
                Require(options, "--ready"),
                Require(options, "--release"));
            break;
        case "hard-link":
            HardLinkProbe(
                Require(options, "--existing"),
                Require(options, "--link"),
                Require(options, "--result"),
                OptionalPath(options, "--ready"),
                OptionalPath(options, "--go"));
            break;
        case "hard-link-ex":
            HardLinkExProbe(
                Require(options, "--existing"),
                Require(options, "--link"),
                Require(options, "--result"),
                OptionalPath(options, "--ready"),
                OptionalPath(options, "--go"));
            break;
        case "fsctl-zero":
            FsctlZeroData(
                Require(options, "--file"),
                RequireInt64(options, "--offset"),
                RequireInt64(options, "--length"),
                Require(options, "--result"));
            break;
        case "map-write":
            MapAndWrite(
                Require(options, "--file"),
                OptionalPath(options, "--ready"),
                OptionalPath(options, "--go"));
            break;
        case "create-new":
            CreateNewFile(
                Require(options, "--file"),
                OptionalPath(options, "--ready"),
                OptionalPath(options, "--go"));
            break;
        case "rename-file":
            RenameFile(
                Require(options, "--source"),
                Require(options, "--destination"),
                OptionalPath(options, "--ready"),
                OptionalPath(options, "--go"));
            break;
        case "truncate-eof":
            TruncateEndOfFile(
                Require(options, "--file"),
                RequireInt64(options, "--length"),
                Require(options, "--ready"),
                Require(options, "--go"));
            break;
        case "delete-file":
            DeleteFileByDisposition(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--go"));
            break;
        case "containment-probe":
            ContainmentProbe(
                Require(options, "--file"),
                Require(options, "--ready"),
                Require(options, "--go"),
                Require(options, "--result"));
            break;
        case "containment-transition":
            ContainmentTransitionProbe(
                Require(options, "--file-a"),
                Require(options, "--file-b"),
                Require(options, "--ready"),
                Require(options, "--go"),
                Require(options, "--result"));
            break;
        default:
            throw new ArgumentException($"Unknown command: {args[0]}");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine("RUNTIME HARNESS ERROR");
    Console.Error.WriteLine($"Command: {command}");
    Console.Error.WriteLine($"Type: {ex.GetType().FullName}");
    Console.Error.WriteLine($"HResult: 0x{ex.HResult:X8}");
    if (ex is System.ComponentModel.Win32Exception win32)
        Console.Error.WriteLine($"Win32Error: {win32.NativeErrorCode}");
    Console.Error.WriteLine(ex.ToString());
    Environment.ExitCode = 20;
}

static Dictionary<string, string> Parse(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
        result[args[i]] = args[++i];
    }
    return result;
}

static string Require(Dictionary<string, string> options, string name) =>
    options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? Path.GetFullPath(value)
        : throw new ArgumentException($"Missing {name}.");

static string? OptionalPath(Dictionary<string, string> options, string name) =>
    options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? Path.GetFullPath(value)
        : null;

static void WaitForOptionalBarrier(string? readyMarker, string? goMarker, string stage)
{
    if (readyMarker is null && goMarker is null)
        return;
    if (readyMarker is null || goMarker is null)
        throw new ArgumentException($"{stage} requires both --ready and --go when a barrier is requested.");

    foreach (var marker in new[] { readyMarker, goMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
    }
    if (File.Exists(readyMarker)) File.Delete(readyMarker);

    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};stage={stage};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddSeconds(45);
    while (!File.Exists(goMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException($"Timed out waiting for {stage} start barrier.");
        Thread.Sleep(10);
    }
}

static long RequireInt64(Dictionary<string, string> options, string name) =>
    options.TryGetValue(name, out var value) &&
    long.TryParse(value, System.Globalization.NumberStyles.None,
        System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
    parsed >= 0
        ? parsed
        : throw new ArgumentException($"Missing/invalid nonnegative {name}.");

static ulong RequireUInt64(Dictionary<string, string> options, string name) =>
    options.TryGetValue(name, out var value) &&
    ulong.TryParse(value, System.Globalization.NumberStyles.None,
        System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
    parsed != 0
        ? parsed
        : throw new ArgumentException($"Missing/invalid nonzero {name}.");


static void ConnectSpoof(string rootPath, ulong claimedPid, string resultMarker)
{
    var resultParent = Path.GetDirectoryName(resultMarker);
    if (!string.IsNullOrWhiteSpace(resultParent)) Directory.CreateDirectory(resultParent);
    if (File.Exists(resultMarker)) File.Delete(resultMarker);

    var full = Path.GetFullPath(rootPath).TrimEnd('\\');
    var drive = Path.GetPathRoot(full)?.TrimEnd('\\')
        ?? throw new InvalidOperationException("Spoof probe root has no local drive.");
    if (drive.Length != 2 || drive[1] != ':')
        throw new InvalidOperationException("Spoof probe requires a local drive root.");

    var sb = new System.Text.StringBuilder(1024);
    if (Native.QueryDosDevice(drive, sb, sb.Capacity) == 0)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), "QueryDosDevice failed for spoof probe.");
    var volume = sb.ToString().Split('\0')[0];
    if (string.IsNullOrWhiteSpace(volume) ||
        !volume.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException($"Unexpected NT volume for spoof probe: '{volume}'.");

    var ntRoot = volume + full[drive.Length..];
    var context = new Native.RgConnectContext
    {
        ProtocolVersion = 18,
        ClientMode = 2,
        ClientProcessId = claimedPid,
        GateRootLengthBytes = checked((uint)(ntRoot.Length * 2)),
        GateVolumeLengthBytes = checked((uint)(volume.Length * 2)),
        GateRoot = ntRoot
    };

    var hr = Native.TryConnect(@"\RansomGuardMinifilterPort", context, out var handle);
    using (handle)
    {
        if (hr == 0 && handle is not null && !handle.IsInvalid)
        {
            File.WriteAllText(resultMarker, "accepted");
            Environment.ExitCode = 13;
            return;
        }
    }

    File.WriteAllText(resultMarker, $"rejected:0x{unchecked((uint)hr):X8}");
}

static void HoldMappedView(string filePath, string readyMarker, string releaseMarker)
{
    EnsureFile(filePath);
    Directory.CreateDirectory(Path.GetDirectoryName(readyMarker)!);
    if (File.Exists(readyMarker)) File.Delete(readyMarker);
    if (File.Exists(releaseMarker)) File.Delete(releaseMarker);

    var (file, mapping, view) = CreateWritableView(filePath);
    try
    {
        // A mapped view keeps the section/file reference alive even after both handles are closed.
        Native.CloseHandle(mapping);
        mapping = IntPtr.Zero;
        file.Dispose();

        File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};file={filePath};utc={DateTime.UtcNow:O}");
        var deadline = DateTime.UtcNow.AddMinutes(5);
        while (!File.Exists(releaseMarker))
        {
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException("Timed out waiting for mapped-view release marker.");
            Thread.Sleep(100);
        }
    }
    finally
    {
        if (view != IntPtr.Zero) _ = Native.UnmapViewOfFile(view);
        if (mapping != IntPtr.Zero) _ = Native.CloseHandle(mapping);
        file.Dispose();
    }
}

static void HoldMappedMutation(
    string filePath,
    string readyMarker,
    string goMarker,
    string releaseMarker,
    string resultMarker,
    bool dirtyBeforeGo)
{
    EnsureFile(filePath);
    foreach (var marker in new[] { readyMarker, goMarker, releaseMarker, resultMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
    }
    foreach (var marker in new[] { readyMarker, goMarker, releaseMarker, resultMarker })
        if (File.Exists(marker)) File.Delete(marker);

    var (file, mapping, view) = CreateWritableView(filePath);
    try
    {
        var payload = System.Text.Encoding.ASCII.GetBytes(
            dirtyBeforeGo
                ? "RANSOMGUARD-MAPPED-DIRTY-BEFORE-RECONNECT-V1"
                : "RANSOMGUARD-MAPPED-MUTATION-AFTER-LOSS-V1");

        if (dirtyBeforeGo)
            Marshal.Copy(payload, 0, view, payload.Length);

        File.WriteAllText(
            readyMarker,
            $"pid={Environment.ProcessId};file={filePath};dirtyBeforeGo={dirtyBeforeGo};utc={DateTime.UtcNow:O}");

        var goDeadline = DateTime.UtcNow.AddMinutes(5);
        while (!File.Exists(goMarker))
        {
            if (DateTime.UtcNow >= goDeadline)
                throw new TimeoutException("Timed out waiting for mapped mutation go marker.");
            Thread.Sleep(50);
        }

        if (!dirtyBeforeGo)
            Marshal.Copy(payload, 0, view, payload.Length);

        var flushViewOk = Native.FlushViewOfFile(view, (UIntPtr)(uint)payload.Length);
        var flushViewError = flushViewOk ? 0 : Marshal.GetLastWin32Error();
        var flushFileOk = Native.FlushFileBuffers(file);
        var flushFileError = flushFileOk ? 0 : Marshal.GetLastWin32Error();

        File.WriteAllText(
            resultMarker,
            $"flushViewOk={flushViewOk};flushViewError={flushViewError};flushFileOk={flushFileOk};flushFileError={flushFileError}");

        var releaseDeadline = DateTime.UtcNow.AddMinutes(5);
        while (!File.Exists(releaseMarker))
        {
            if (DateTime.UtcNow >= releaseDeadline)
                throw new TimeoutException("Timed out waiting for mapped mutation release marker.");
            Thread.Sleep(50);
        }
    }
    finally
    {
        if (view != IntPtr.Zero) _ = Native.UnmapViewOfFile(view);
        if (mapping != IntPtr.Zero) _ = Native.CloseHandle(mapping);
        file.Dispose();
    }
}

static void HoldWritableHandle(string filePath, string readyMarker, string releaseMarker)
{
    EnsureFile(filePath);
    Directory.CreateDirectory(Path.GetDirectoryName(readyMarker)!);
    if (File.Exists(readyMarker)) File.Delete(readyMarker);
    if (File.Exists(releaseMarker)) File.Delete(releaseMarker);

    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;

    using var file = Native.CreateFileW(
        filePath,
        GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal,
        IntPtr.Zero);
    if (file.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW writable handle failed for '{filePath}'.");

    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};file={filePath};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddMinutes(5);
    while (!File.Exists(releaseMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for writable-handle release marker.");
        Thread.Sleep(100);
    }
}

static void HoldDirectoryDeleteHandle(string directoryPath, string readyMarker, string releaseMarker)
{
    if (!Directory.Exists(directoryPath))
        throw new DirectoryNotFoundException(directoryPath);
    if ((File.GetAttributes(directoryPath) & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Runtime harness refuses reparse-point directories.");

    Directory.CreateDirectory(Path.GetDirectoryName(readyMarker)!);
    if (File.Exists(readyMarker)) File.Delete(readyMarker);
    if (File.Exists(releaseMarker)) File.Delete(releaseMarker);

    const uint DeleteAccess = 0x00010000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileFlagBackupSemantics = 0x02000000;

    using var directory = Native.CreateFileW(
        directoryPath,
        DeleteAccess,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileFlagBackupSemantics,
        IntPtr.Zero);
    if (directory.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW DELETE directory handle failed for '{directoryPath}'.");

    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};directory={directoryPath};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddMinutes(5);
    while (!File.Exists(releaseMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for directory-handle release marker.");
        Thread.Sleep(100);
    }
}

static void HardLinkProbe(
    string existingPath,
    string linkPath,
    string resultMarker,
    string? readyMarker,
    string? goMarker)
{
    EnsureFile(existingPath);
    var linkParent = Path.GetDirectoryName(linkPath);
    if (!string.IsNullOrWhiteSpace(linkParent)) Directory.CreateDirectory(linkParent);
    var resultParent = Path.GetDirectoryName(resultMarker);
    if (!string.IsNullOrWhiteSpace(resultParent)) Directory.CreateDirectory(resultParent);
    if (File.Exists(linkPath)) File.Delete(linkPath);
    if (File.Exists(resultMarker)) File.Delete(resultMarker);

    WaitForOptionalBarrier(readyMarker, goMarker, "hard-link");

    if (Native.CreateHardLinkW(linkPath, existingPath, IntPtr.Zero))
    {
        File.WriteAllText(resultMarker, "allowed");
        return;
    }

    var error = Marshal.GetLastWin32Error();
    if (error == 5)
    {
        File.WriteAllText(resultMarker, "denied");
        return;
    }

    File.WriteAllText(resultMarker, "win32-error:" + error.ToString(System.Globalization.CultureInfo.InvariantCulture));
    throw new System.ComponentModel.Win32Exception(
        error, $"CreateHardLinkW failed unexpectedly. existing='{existingPath}', link='{linkPath}'.");
}

static void HardLinkExProbe(
    string existingPath,
    string linkPath,
    string resultMarker,
    string? readyMarker,
    string? goMarker)
{
    EnsureFile(existingPath);
    var linkParent = Path.GetDirectoryName(linkPath);
    if (string.IsNullOrWhiteSpace(linkParent))
        throw new ArgumentException("Hard-link destination must have a parent directory.", nameof(linkPath));
    Directory.CreateDirectory(linkParent);

    var resultParent = Path.GetDirectoryName(resultMarker);
    if (!string.IsNullOrWhiteSpace(resultParent)) Directory.CreateDirectory(resultParent);
    if (File.Exists(linkPath)) File.Delete(linkPath);
    if (File.Exists(resultMarker)) File.Delete(resultMarker);

    WaitForOptionalBarrier(readyMarker, goMarker, "hard-link-ex");

    const uint GenericRead = 0x80000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const uint FileFlagBackupSemantics = 0x02000000;
    const int FileLinkInformationEx = 72;

    using var source = Native.CreateFileW(
        existingPath,
        GenericRead,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal,
        IntPtr.Zero);
    if (source.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW source failed for FileLinkInformationEx '{existingPath}'.");

    using var directory = Native.CreateFileW(
        linkParent,
        GenericRead,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileFlagBackupSemantics,
        IntPtr.Zero);
    if (directory.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW destination directory failed for FileLinkInformationEx '{linkParent}'.");

    var leaf = Path.GetFileName(linkPath);
    var nameBytes = System.Text.Encoding.Unicode.GetBytes(leaf);
    var rootDirectoryOffset = IntPtr.Size == 8 ? 8 : 4;
    var fileNameLengthOffset = rootDirectoryOffset + IntPtr.Size;
    var fileNameOffset = fileNameLengthOffset + sizeof(uint);
    var bufferLength = checked(fileNameOffset + nameBytes.Length);
    var buffer = Marshal.AllocHGlobal(bufferLength);
    try
    {
        Marshal.Copy(new byte[bufferLength], 0, buffer, bufferLength);

        // FILE_LINK_INFORMATION on RS5+ starts with the ULONG Flags member when used
        // with FileLinkInformationEx. RootDirectory then scopes the relative FileName.
        Marshal.WriteInt32(buffer, 0, 0);
        Marshal.WriteIntPtr(buffer, rootDirectoryOffset, directory.DangerousGetHandle());
        Marshal.WriteInt32(buffer, fileNameLengthOffset, nameBytes.Length);
        Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, fileNameOffset), nameBytes.Length);

        var status = Native.NtSetInformationFile(
            source,
            out _,
            buffer,
            checked((uint)bufferLength),
            FileLinkInformationEx);

        if (status >= 0)
        {
            File.WriteAllText(resultMarker, "allowed-ex");
            return;
        }

        var error = Native.RtlNtStatusToDosError(status);
        if (error == 5)
        {
            File.WriteAllText(resultMarker, "denied-ex");
            return;
        }

        File.WriteAllText(
            resultMarker,
            $"ntstatus:0x{unchecked((uint)status):X8};win32:{error}");
        throw new System.ComponentModel.Win32Exception(
            checked((int)error),
            $"NtSetInformationFile(FileLinkInformationEx) failed unexpectedly. status=0x{unchecked((uint)status):X8}; existing='{existingPath}', link='{linkPath}'.");
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
    }
}

static void FsctlZeroData(string filePath, long offset, long length, string resultMarker)
{
    EnsureFile(filePath);
    if (length <= 0)
        throw new ArgumentOutOfRangeException(nameof(length), "FSCTL zero length must be positive.");

    var resultParent = Path.GetDirectoryName(resultMarker);
    if (!string.IsNullOrWhiteSpace(resultParent)) Directory.CreateDirectory(resultParent);
    if (File.Exists(resultMarker)) File.Delete(resultMarker);

    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const uint FileFlagWriteThrough = 0x80000000;
    const uint FsctlSetZeroData = 0x000980C8;

    using var file = Native.CreateFileW(
        filePath,
        GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal | FileFlagWriteThrough,
        IntPtr.Zero);
    if (file.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW writable FSCTL handle failed for '{filePath}'.");

    var info = new Native.FileZeroDataInformation
    {
        FileOffset = offset,
        BeyondFinalZero = checked(offset + length)
    };
    if (!Native.DeviceIoControl(
            file,
            FsctlSetZeroData,
            ref info,
            checked((uint)Marshal.SizeOf<Native.FileZeroDataInformation>()),
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero))
    {
        var error = Marshal.GetLastWin32Error();
        File.WriteAllText(resultMarker, "win32-error:" + error.ToString(System.Globalization.CultureInfo.InvariantCulture));
        throw new System.ComponentModel.Win32Exception(
            error, $"FSCTL_SET_ZERO_DATA failed for '{filePath}'.");
    }

    if (!Native.FlushFileBuffers(file))
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"FlushFileBuffers failed after FSCTL_SET_ZERO_DATA for '{filePath}'.");

    File.WriteAllText(resultMarker, "allowed");
}

static void ContainmentProbe(string filePath, string readyMarker, string goMarker, string resultMarker)
{
    EnsureFile(filePath);
    foreach (var marker in new[] { readyMarker, goMarker, resultMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        if (File.Exists(marker)) File.Delete(marker);
    }

    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};file={filePath};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddMinutes(5);
    while (!File.Exists(goMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for containment probe trigger.");
        Thread.Sleep(100);
    }

    try
    {
        File.AppendAllText(filePath, "RANSOMGUARD-CONTAINMENT-PROBE-SHOULD-NOT-WRITE");
        File.WriteAllText(resultMarker, "allowed");
        Environment.ExitCode = 9;
    }
    catch (UnauthorizedAccessException)
    {
        File.WriteAllText(resultMarker, "denied");
    }
    catch (IOException ex) when ((ex.HResult & 0xFFFF) == 5)
    {
        File.WriteAllText(resultMarker, "denied");
    }
    catch (IOException ex)
    {
        File.WriteAllText(resultMarker, "io-error:" + ex.HResult.ToString("X8"));
        Environment.ExitCode = 10;
    }
}

static void ContainmentTransitionProbe(
    string fileA,
    string fileB,
    string readyMarker,
    string goMarker,
    string resultMarker)
{
    EnsureFile(fileA);
    EnsureFile(fileB);
    foreach (var marker in new[] { readyMarker, goMarker, resultMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        if (File.Exists(marker)) File.Delete(marker);
    }

    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};fileA={fileA};fileB={fileB};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddMinutes(5);
    while (!File.Exists(goMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for event-bound containment transition trigger.");
        Thread.Sleep(100);
    }

    try
    {
        using var a = OpenTransitionWriteHandle(fileA);
        using var b = OpenTransitionWriteHandle(fileB);

        // Keep this scenario kernel-deterministic: the two CREATEs above are mutation events 1/2,
        // and these two direct synchronous WriteFile calls are events 3/4. The fourth event is the
        // authorized trigger event that installs the containment latch. The next WriteFile must fail.
        WriteTransitionByte(a, 0, 0xA1, "transition-a trigger write");
        WriteTransitionByte(b, 0, 0xB2, "transition-b trigger write");

        if (TryWriteTransitionByte(a, 1, 0xC3, out var error))
        {
            File.WriteAllText(resultMarker, "allowed-after-threshold");
            Environment.ExitCode = 11;
        }
        else if (error == 5)
        {
            File.WriteAllText(resultMarker, "denied-after-threshold");
        }
        else
        {
            throw new System.ComponentModel.Win32Exception(
                error, "Post-threshold WriteFile failed with an unexpected Win32 error.");
        }
    }
    catch (Exception ex)
    {
        File.WriteAllText(resultMarker, "unexpected:" + ex.GetType().Name + ":" + ex.HResult.ToString("X8"));
        Environment.ExitCode = 12;
    }
}

static SafeFileHandle OpenTransitionWriteHandle(string path)
{
    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const uint FileFlagWriteThrough = 0x80000000;

    var handle = Native.CreateFileW(
        path,
        GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal | FileFlagWriteThrough,
        IntPtr.Zero);
    if (handle.IsInvalid)
    {
        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new System.ComponentModel.Win32Exception(
            error, $"Containment transition CreateFileW failed for '{path}'.");
    }
    return handle;
}

static void WriteTransitionByte(SafeFileHandle handle, long offset, byte value, string stage)
{
    if (!TryWriteTransitionByte(handle, offset, value, out var error))
        throw new System.ComponentModel.Win32Exception(error, $"WriteFile failed during {stage}.");
}

static bool TryWriteTransitionByte(SafeFileHandle handle, long offset, byte value, out int error)
{
    const uint FileBegin = 0;
    if (!Native.SetFilePointerEx(handle, offset, out _, FileBegin))
    {
        error = Marshal.GetLastWin32Error();
        return false;
    }

    var payload = new[] { value };
    if (!Native.WriteFile(handle, payload, 1, out var written, IntPtr.Zero))
    {
        error = Marshal.GetLastWin32Error();
        return false;
    }
    if (written != 1)
        throw new IOException($"WriteFile completed a partial transition write: {written} byte(s).");

    error = 0;
    return true;
}

static void CreateNewFile(string filePath, string? readyMarker, string? goMarker)
{
    if (File.Exists(filePath) || Directory.Exists(filePath))
        throw new IOException("create-new requires an absent path: " + filePath);

    var parent = Path.GetDirectoryName(filePath);
    if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        throw new DirectoryNotFoundException("create-new parent directory does not exist: " + parent);

    WaitForOptionalBarrier(readyMarker, goMarker, "create-new");

    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint CreateNew = 1;
    const uint FileAttributeNormal = 0x00000080;
    const uint FileFlagWriteThrough = 0x80000000;

    using var file = Native.CreateFileW(
        filePath,
        GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        CreateNew,
        FileAttributeNormal | FileFlagWriteThrough,
        IntPtr.Zero);
    if (file.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW(CREATE_NEW) failed for '{filePath}'.");

    // The completion-loss scenario is about CREATE transaction reconciliation only.
    // Do not issue a follow-up WRITE: dropping CreateResult intentionally begins gate shutdown,
    // and a second mutation would test shutdown timing instead of lost CREATE completion.
}

static void RenameFile(
    string sourcePath,
    string destinationPath,
    string? readyMarker,
    string? goMarker)
{
    if (!File.Exists(sourcePath))
        throw new FileNotFoundException("rename-file source does not exist.", sourcePath);
    if (File.Exists(destinationPath) || Directory.Exists(destinationPath))
        throw new IOException("rename-file destination must start absent: " + destinationPath);

    var sourceParent = Path.GetDirectoryName(sourcePath);
    var destinationParent = Path.GetDirectoryName(destinationPath);
    if (string.IsNullOrWhiteSpace(sourceParent) ||
        string.IsNullOrWhiteSpace(destinationParent) ||
        !Directory.Exists(sourceParent) ||
        !Directory.Exists(destinationParent))
        throw new DirectoryNotFoundException("rename-file requires existing source/destination parent directories.");

    WaitForOptionalBarrier(readyMarker, goMarker, "rename-file");
    File.Move(sourcePath, destinationPath, overwrite: false);
}

static void TruncateEndOfFile(string filePath, long length, string readyMarker, string goMarker)
{
    EnsureFile(filePath);
    var originalLength = new FileInfo(filePath).Length;
    if (length >= originalLength)
        throw new ArgumentOutOfRangeException(nameof(length),
            "truncate-eof requires a target length smaller than the current file.");

    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const int FileEndOfFileInfo = 6;

    using var file = Native.CreateFileW(
        filePath,
        GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal,
        IntPtr.Zero);
    if (file.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW for truncate failed for '{filePath}'.");

    // The write-capable open itself has a correlated CREATE result. Do not race that no-reply
    // completion with the deliberate TRUNCATE loss point: advertise the open, then wait until
    // the external harness confirms CreateResult persistence before issuing SetInformation.
    foreach (var marker in new[] { readyMarker, goMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        if (File.Exists(marker)) File.Delete(marker);
    }
    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};file={filePath};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddSeconds(45);
    while (!File.Exists(goMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for durable CREATE completion before TRUNCATE.");
        Thread.Sleep(50);
    }

    var info = new Native.FileEndOfFileInfo { EndOfFile = length };
    if (!Native.SetFileInformationByHandle(
            file,
            FileEndOfFileInfo,
            ref info,
            checked((uint)Marshal.SizeOf<Native.FileEndOfFileInfo>())))
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"SetFileInformationByHandle(FileEndOfFileInfo) failed for '{filePath}'.");

    // This helper must perform no follow-up WRITE. The completion-loss scenario validates
    // exactly one successful EOF mutation followed by a deliberately lost TruncateResult.
}

static void DeleteFileByDisposition(string filePath, string readyMarker, string goMarker)
{
    EnsureFile(filePath);

    const uint DeleteAccess = 0x00010000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const int FileDispositionInfo = 4;

    using var file = Native.CreateFileW(
        filePath,
        DeleteAccess,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal,
        IntPtr.Zero);
    if (file.IsInvalid)
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), $"CreateFileW DELETE handle failed for '{filePath}'.");

    // Opening with DELETE access is itself mutation-capable and receives a correlated CREATE
    // transaction. Do not race that CreateResult with the deliberate DELETE loss point.
    foreach (var marker in new[] { readyMarker, goMarker })
    {
        var parent = Path.GetDirectoryName(marker);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        if (File.Exists(marker)) File.Delete(marker);
    }
    File.WriteAllText(readyMarker, $"pid={Environment.ProcessId};file={filePath};utc={DateTime.UtcNow:O}");
    var deadline = DateTime.UtcNow.AddSeconds(45);
    while (!File.Exists(goMarker))
    {
        if (DateTime.UtcNow >= deadline)
            throw new TimeoutException("Timed out waiting for durable CREATE completion before DELETE disposition.");
        Thread.Sleep(50);
    }

    var info = new Native.FileDispositionInfo { DeleteFile = true };
    if (!Native.SetFileInformationByHandle(
            file,
            FileDispositionInfo,
            ref info,
            checked((uint)Marshal.SizeOf<Native.FileDispositionInfo>())))
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(),
            $"SetFileInformationByHandle(FileDispositionInfo) failed for '{filePath}'.");

    // No follow-up mutation is allowed here. Disposing this exact handle drives IRP_MJ_CLEANUP
    // and lets the filesystem finalize (or refuse) the previously accepted disposition.
}

static void MapAndWrite(string filePath, string? readyMarker, string? goMarker)
{
    EnsureFile(filePath);
    WaitForOptionalBarrier(readyMarker, goMarker, "map-write");
    var (file, mapping, view) = CreateWritableView(filePath);
    try
    {
        var payload = System.Text.Encoding.ASCII.GetBytes("RANSOMGUARD-RUNTIME-MAPPED-WRITE-V1");
        Marshal.Copy(payload, 0, view, payload.Length);
        if (!Native.FlushViewOfFile(view, (UIntPtr)(uint)payload.Length))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "FlushViewOfFile failed.");
        if (!Native.FlushFileBuffers(file))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "FlushFileBuffers failed.");
        Thread.Sleep(750); // Give the modified-page path time to surface before teardown.
    }
    finally
    {
        if (view != IntPtr.Zero) _ = Native.UnmapViewOfFile(view);
        if (mapping != IntPtr.Zero) _ = Native.CloseHandle(mapping);
        file.Dispose();
    }
}

static (SafeFileHandle File, IntPtr Mapping, IntPtr View) CreateWritableView(string filePath)
{
    const uint GenericRead = 0x80000000;
    const uint GenericWrite = 0x40000000;
    const uint ShareRead = 0x00000001;
    const uint ShareWrite = 0x00000002;
    const uint ShareDelete = 0x00000004;
    const uint OpenExisting = 3;
    const uint FileAttributeNormal = 0x00000080;
    const uint PageReadWrite = 0x04;
    const uint FileMapWrite = 0x0002;
    const uint FileMapRead = 0x0004;

    var file = Native.CreateFileW(
        filePath,
        GenericRead | GenericWrite,
        ShareRead | ShareWrite | ShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileAttributeNormal,
        IntPtr.Zero);
    if (file.IsInvalid)
    {
        var error = Marshal.GetLastWin32Error();
        file.Dispose();
        throw new System.ComponentModel.Win32Exception(error, $"CreateFileW failed for '{filePath}'.");
    }

    var mapping = Native.CreateFileMappingW(file, IntPtr.Zero, PageReadWrite, 0, 0, null);
    if (mapping == IntPtr.Zero)
    {
        var error = Marshal.GetLastWin32Error();
        file.Dispose();
        throw new System.ComponentModel.Win32Exception(error, "CreateFileMappingW(PAGE_READWRITE) failed.");
    }

    var view = Native.MapViewOfFile(mapping, FileMapRead | FileMapWrite, 0, 0, UIntPtr.Zero);
    if (view == IntPtr.Zero)
    {
        var error = Marshal.GetLastWin32Error();
        _ = Native.CloseHandle(mapping);
        file.Dispose();
        throw new System.ComponentModel.Win32Exception(error, "MapViewOfFile(FILE_MAP_WRITE) failed.");
    }

    return (file, mapping, view);
}

static void EnsureFile(string path)
{
    if (!File.Exists(path))
        throw new FileNotFoundException("Runtime harness file does not exist.", path);
    if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Runtime harness refuses reparse-point files.");
    if (new FileInfo(path).Length < 4096)
        throw new InvalidOperationException("Runtime harness requires a test file of at least 4096 bytes.");
}

static class Native
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct RgConnectContext
    {
        public uint ProtocolVersion;
        public uint ClientMode;
        public ulong ClientProcessId;
        public uint GateRootLengthBytes;
        public uint GateVolumeLengthBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string GateRoot;
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out SafeFileHandle hPort);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(
        string lpDeviceName,
        System.Text.StringBuilder lpTargetPath,
        int ucchMax);

    public static int TryConnect(string portName, RgConnectContext context, out SafeFileHandle? handle)
    {
        const uint FltPortFlagSyncHandle = 0x00000001;
        var size = Marshal.SizeOf<RgConnectContext>();
        if (size != 544)
            throw new InvalidOperationException($"Unexpected spoof connect context size: {size}.");

        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(context, ptr, false);
            var hr = FilterConnectCommunicationPort(
                portName,
                FltPortFlagSyncHandle,
                ptr,
                checked((ushort)size),
                IntPtr.Zero,
                out var connected);
            handle = connected;
            return hr;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileEndOfFileInfo
    {
        public long EndOfFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLinkW(
        string lpFileName,
        string lpExistingFileName,
        IntPtr lpSecurityAttributes);

    [StructLayout(LayoutKind.Sequential)]
    public struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationFile(
        SafeFileHandle fileHandle,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        int fileInformationClass);

    [DllImport("ntdll.dll")]
    public static extern uint RtlNtStatusToDosError(int status);

    [StructLayout(LayoutKind.Sequential)]
    public struct FileZeroDataInformation
    {
        public long FileOffset;
        public long BeyondFinalZero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref FileZeroDataInformation lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileEndOfFileInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileDispositionInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileMappingW(
        SafeFileHandle hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushViewOfFile(IntPtr lpBaseAddress, UIntPtr dwNumberOfBytesToFlush);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushFileBuffers(SafeFileHandle hFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
