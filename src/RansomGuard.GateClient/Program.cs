using Microsoft.Win32.SafeHandles;
using RansomGuard.Rollback;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

const string PortName = @"\RansomGuardMinifilterPort";
var options = Options.Parse(args);
if (options.PrepareOnly)
{
    LabRootPolicy.Prepare(options.Root);
    Console.WriteLine($"Prepared LAB root: {options.Root}");
    Console.WriteLine("No driver connection was made.");
    return;
}

LabRootPolicy.Validate(options.Root);
if (PathPolicy.Under(options.StoreRoot, options.Root))
    throw new InvalidOperationException("Rollback store must be outside the protected LAB root.");
Directory.CreateDirectory(options.StoreRoot);
var repository = new RollbackRepository(options.StoreRoot);
var sessionId = options.SessionId ?? $"gate-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
var store = repository.CreateSession(sessionId);
var writeStore = new RangeRollbackStore(Path.Combine(store.Root, "write-cow"));
var ntRoot = DevicePathResolver.ToNtRoot(options.Root);

Console.WriteLine("RansomGuard LAB pre-write gate v0.7.2.0");
Console.WriteLine("LAB ONLY: use only inside a disposable test directory on a test machine/VM.");
Console.WriteLine($"Protected LAB root : {options.Root}");
Console.WriteLine($"Kernel NT root     : {ntRoot}");
Console.WriteLine($"Rollback session   : {sessionId}");
Console.WriteLine($"Rollback store     : {store.Root}");
Console.WriteLine("Writes/rename/delete/truncate in this root are denied unless a durable pre-image commit succeeds.");
Console.WriteLine("Press Ctrl+C to disconnect. The driver then stops gating because no client is connected.");

var context = new RgConnectContext
{
    ProtocolVersion = 3,
    ClientMode = (uint)RgClientMode.LabGate,
    ClientProcessId = (ulong)Environment.ProcessId,
    GateRootLengthBytes = checked((uint)(ntRoot.Length * 2)),
    GateRoot = ntRoot
};

using var port = Native.Connect(PortName, context);
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Native.Cancel(port); };

var headerSize = Marshal.SizeOf<FilterMessageHeader>();
var eventSize = Marshal.SizeOf<RgEvent>();
var replyHeaderSize = Marshal.SizeOf<FilterReplyHeader>();
var gateReplySize = Marshal.SizeOf<RgGateReply>();
if (headerSize != 16 || eventSize != 1096 || replyHeaderSize != 16 || gateReplySize != 24)
    throw new InvalidOperationException($"Unexpected protocol sizes: message={headerSize}, event={eventSize}, replyHeader={replyHeaderSize}, gateReply={gateReplySize}");

var resolver = new DevicePathResolver();
var buffer = Marshal.AllocHGlobal(checked(headerSize + eventSize));
try
{
    while (!cts.IsCancellationRequested)
    {
        var hr = Native.FilterGetMessage(port, buffer, (uint)(headerSize + eventSize), IntPtr.Zero);
        if (hr != 0)
        {
            if (cts.IsCancellationRequested) break;
            throw new InvalidOperationException($"FilterGetMessage failed HRESULT=0x{hr:X8}");
        }

        var header = Marshal.PtrToStructure<FilterMessageHeader>(buffer);
        var ev = Marshal.PtrToStructure<RgEvent>(IntPtr.Add(buffer, headerSize));
        var reply = await GateDecision.EvaluateAsync(ev, resolver, options.Root, store, writeStore, cts.Token);
        Native.Reply(port, header.MessageId, reply);

        var path = resolver.Resolve(ev.Path) ?? ev.Path ?? "<unresolved>";
        Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {((RgEventType)ev.EventType),-20} pid={ev.ProcessId,-7} {reply.Decision,-18} {path}");
    }
}
finally
{
    Marshal.FreeHGlobal(buffer);
}

static class GateDecision
{
    public static async Task<RgGateReply> EvaluateAsync(RgEvent ev, DevicePathResolver resolver, string root,
        RollbackStore store, RangeRollbackStore writeStore, CancellationToken cancellationToken)
    {
        try
        {
            if (ev.ProtocolVersion != 3 || (ev.PathStatus != (uint)RgPathStatus.Resolved && ev.PathStatus != (uint)RgPathStatus.Truncated))
                return Deny(ev.Sequence, 1);

            var path = resolver.Resolve(ev.Path);
            if (string.IsNullOrWhiteSpace(path) || !PathPolicy.Under(path, root))
                return Deny(ev.Sequence, 2);

            if (!File.Exists(path))
            {
                // v0.7.2 does not yet model file creation. Fail closed inside the explicit LAB root.
                return Deny(ev.Sequence, 3);
            }

            var eventType = (RgEventType)ev.EventType;
            if (eventType == RgEventType.Write)
            {
                if (ev.ByteOffset < 0)
                    return Deny(ev.Sequence, 6);
                await writeStore.CaptureWritePreimageAsync(path, ev.ByteOffset, ev.Length, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                var mutation = eventType switch
                {
                    RgEventType.Rename => RollbackMutationKind.Rename,
                    RgEventType.DeleteDisposition => RollbackMutationKind.Delete,
                    RgEventType.Truncate => RollbackMutationKind.Write,
                    _ => throw new InvalidOperationException("Unsupported gate event type.")
                };
                _ = await store.CapturePreimageAsync(path, mutation, cancellationToken).ConfigureAwait(false);
            }

            return new RgGateReply
            {
                ProtocolVersion = 3,
                Decision = RgGateDecision.SnapshotCommitted,
                RequestSequence = ev.Sequence,
                ErrorCode = 0
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Deny(ev.Sequence, 4);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Gate capture failed: {ex.GetType().Name}: {ex.Message}");
            return Deny(ev.Sequence, 5);
        }
    }

    private static RgGateReply Deny(ulong sequence, uint errorCode) => new()
    {
        ProtocolVersion = 3,
        Decision = RgGateDecision.Deny,
        RequestSequence = sequence,
        ErrorCode = errorCode
    };
}

sealed record Options(string Root, string StoreRoot, string? SessionId, bool PrepareOnly)
{
    public static Options Parse(string[] args)
    {
        string? root = null;
        string? store = null;
        string? session = null;
        var prepare = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--root" when i + 1 < args.Length: root = Path.GetFullPath(args[++i]).TrimEnd('\\'); break;
                case "--store" when i + 1 < args.Length: store = Path.GetFullPath(args[++i]); break;
                case "--session" when i + 1 < args.Length: session = args[++i]; break;
                case "--prepare-root": prepare = true; break;
                default: throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
            }
        }
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Pass --root <disposable-test-directory>.");
        store ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomGuardV072", "GateRollback");
        return new Options(root, store, session, prepare);
    }
}

static class LabRootPolicy
{
    private const string MarkerName = ".ransomguard-gate-lab-root";
    private const string MarkerText = "RANSOMGUARD-LAB-GATE-V1";

    public static void Prepare(string root)
    {
        ValidateShape(root, requireMarker: false);
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, MarkerName), MarkerText, Encoding.ASCII);
    }

    public static void Validate(string root) => ValidateShape(root, requireMarker: true);

    private static void ValidateShape(string root, bool requireMarker)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\');
        if (string.IsNullOrWhiteSpace(drive) || full.Equals(drive, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("LAB gate root cannot be an entire drive.");
        if (!Directory.Exists(full) && requireMarker) throw new DirectoryNotFoundException(full);
        if (Directory.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("LAB gate root cannot be a reparse point.");

        foreach (var systemPath in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        }.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            if (PathPolicy.Under(full, systemPath))
                throw new InvalidOperationException("LAB gate root must not be inside Windows, Program Files, or ProgramData.");
        }

        if (requireMarker)
        {
            var marker = Path.Combine(full, MarkerName);
            if (!File.Exists(marker) || File.ReadAllText(marker, Encoding.ASCII).Trim() != MarkerText)
                throw new InvalidOperationException($"LAB marker missing. Run once with --prepare-root --root \"{full}\".");
        }
    }
}

static class PathPolicy
{
    public static bool Under(string? path, string root)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = Path.GetFullPath(path).TrimEnd('\\');
        var r = Path.GetFullPath(root).TrimEnd('\\');
        return p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }
}

sealed class DevicePathResolver
{
    private readonly (string Device, string Drive)[] _map;

    public DevicePathResolver()
    {
        var list = new List<(string, string)>();
        foreach (var d in DriveInfo.GetDrives())
        {
            var drive = d.Name.TrimEnd('\\');
            if (drive.Length != 2 || drive[1] != ':') continue;
            var sb = new StringBuilder(1024);
            if (Native.QueryDosDevice(drive, sb, sb.Capacity) != 0)
                list.Add((sb.ToString().Split('\0')[0], drive));
        }
        _map = list.OrderByDescending(x => x.Item1.Length).ToArray();
    }

    public string? Resolve(string? ntPath)
    {
        if (string.IsNullOrWhiteSpace(ntPath)) return null;
        var p = ntPath;
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && p[2] == '\\') return p;
        foreach (var (device, drive) in _map)
            if (p.StartsWith(device, StringComparison.OrdinalIgnoreCase)) return drive + p[device.Length..];
        return null;
    }

    public static string ToNtRoot(string dosRoot)
    {
        var full = Path.GetFullPath(dosRoot).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\') ?? throw new InvalidOperationException("No drive root.");
        if (drive.Length != 2 || drive[1] != ':') throw new InvalidOperationException("LAB gate supports local drive paths only.");
        var sb = new StringBuilder(1024);
        if (Native.QueryDosDevice(drive, sb, sb.Capacity) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "QueryDosDevice failed.");
        var device = sb.ToString().Split('\0')[0];
        return device + full[drive.Length..];
    }
}

enum RgClientMode : uint { Audit = 1, LabGate = 2 }
enum RgEventType : uint { Invalid = 0, Write = 1, Rename = 2, DeleteDisposition = 3, Truncate = 4 }
enum RgPathStatus : uint { Unknown = 0, Resolved = 1, QueryFailed = 2, Truncated = 3 }
enum RgGateDecision : uint { Invalid = 0, SnapshotCommitted = 1, Deny = 2 }

[StructLayout(LayoutKind.Sequential)]
struct FilterMessageHeader { public uint ReplyLength; public ulong MessageId; }

[StructLayout(LayoutKind.Sequential)]
struct FilterReplyHeader { public int Status; public ulong MessageId; }

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
struct RgConnectContext
{
    public uint ProtocolVersion, ClientMode;
    public ulong ClientProcessId;
    public uint GateRootLengthBytes, Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string GateRoot;
}

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
struct RgEvent
{
    public uint ProtocolVersion, EventType, PathStatus, Flags;
    public ulong Sequence;
    public long SystemTime100ns;
    public ulong ProcessId, ThreadId;
    public long ByteOffset;
    public uint Length, FileInformationClass, DroppedBeforeThis, Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string? Path;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgGateReply
{
    public uint ProtocolVersion;
    public RgGateDecision Decision;
    public ulong RequestSequence;
    public uint ErrorCode;
    public uint Reserved;
}

static class Native
{
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string lpPortName, uint dwOptions, IntPtr lpContext,
        ushort wSizeOfContext, IntPtr lpSecurityAttributes, out SafeFileHandle hPort);
    [DllImport("fltlib.dll")]
    public static extern int FilterGetMessage(SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);
    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(SafeFileHandle hFile, IntPtr lpOverlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    public static SafeFileHandle Connect(string name, RgConnectContext context)
    {
        const uint FltPortFlagSyncHandle = 0x00000001;
        var size = Marshal.SizeOf<RgConnectContext>();
        if (size != 544) throw new InvalidOperationException($"Unexpected connect context size: {size}");
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(context, ptr, false);
            var hr = FilterConnectCommunicationPort(name, FltPortFlagSyncHandle, ptr, checked((ushort)size), IntPtr.Zero, out var handle);
            if (hr != 0 || handle.IsInvalid) throw new InvalidOperationException($"FilterConnectCommunicationPort failed HRESULT=0x{hr:X8}.");
            return handle;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static void Reply(SafeFileHandle port, ulong messageId, RgGateReply payload)
    {
        var headerSize = Marshal.SizeOf<FilterReplyHeader>();
        var payloadSize = Marshal.SizeOf<RgGateReply>();
        var total = checked(headerSize + payloadSize);
        var ptr = Marshal.AllocHGlobal(total);
        try
        {
            Marshal.StructureToPtr(new FilterReplyHeader { Status = 0, MessageId = messageId }, ptr, false);
            Marshal.StructureToPtr(payload, IntPtr.Add(ptr, headerSize), false);
            var hr = FilterReplyMessage(port, ptr, (uint)total);
            if (hr != 0) throw new InvalidOperationException($"FilterReplyMessage failed HRESULT=0x{hr:X8}");
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static void Cancel(SafeFileHandle handle) { if (!handle.IsInvalid) _ = CancelIoEx(handle, IntPtr.Zero); }
}
