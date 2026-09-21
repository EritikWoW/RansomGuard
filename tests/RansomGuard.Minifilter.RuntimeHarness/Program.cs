using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("RansomGuard minifilter runtime harness is Windows-only.");

if (args.Length == 0)
    throw new ArgumentException("Use: hold-map --file <path> --ready <marker> --release <marker> | hold-dir-delete --directory <path> --ready <marker> --release <marker> | map-write --file <path>");

var command = args[0].ToLowerInvariant();
var options = Parse(args.Skip(1).ToArray());

switch (command)
{
    case "hold-map":
        HoldMappedView(
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
    case "map-write":
        MapAndWrite(Require(options, "--file"));
        break;
    default:
        throw new ArgumentException($"Unknown command: {args[0]}");
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

static void MapAndWrite(string filePath)
{
    EnsureFile(filePath);
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
    public static extern bool CloseHandle(IntPtr hObject);
}
