using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

const string PortName = @"\RansomGuardMinifilterPort";
const int ProtocolVersion = 8;

var options = Options.Parse(args);
Console.WriteLine("RansomGuard Minifilter AUDIT client v0.7.8.0");
Console.WriteLine("READ-ONLY: this client cannot block, suspend, kill, rename, delete, or modify files.");
Console.WriteLine("It only receives metadata emitted by the lab minifilter.");
Console.WriteLine();
foreach (var root in options.Roots) Console.WriteLine($"Audit root: {root}");

SecureOutput.Ensure(options.OutputDirectory);
var logPath = Path.Combine(options.OutputDirectory, $"minifilter-{DateTime.UtcNow:yyyyMMdd-HHmmss}.jsonl");
var summaryPath = Path.Combine(options.OutputDirectory, $"minifilter-{DateTime.UtcNow:yyyyMMdd-HHmmss}-summary.json");

using var port = Native.Connect(PortName, (ulong)Environment.ProcessId);
Console.WriteLine($"Connected to {PortName}");
Console.WriteLine($"JSONL: {logPath}");
Console.WriteLine("Press Ctrl+C to stop.");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Native.Cancel(port); };

var resolver = new DevicePathResolver();
var stats = new AuditStats();
using var writer = new StreamWriter(new FileStream(logPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
    64 * 1024, FileOptions.SequentialScan)) { AutoFlush = false };

var headerSize = Marshal.SizeOf<FilterMessageHeader>();
var eventSize = Marshal.SizeOf<RgEvent>();
if (headerSize != 16) throw new InvalidOperationException($"Unexpected FILTER_MESSAGE_HEADER size: {headerSize}");
if (eventSize != 2168) throw new InvalidOperationException($"Protocol struct size mismatch: {eventSize}, expected 2168");
var bufferSize = checked(headerSize + eventSize);
var buffer = Marshal.AllocHGlobal(bufferSize);
var lastFlush = Stopwatch.StartNew();
var lastSummary = Stopwatch.StartNew();

try
{
    while (!cts.IsCancellationRequested)
    {
        var hr = Native.FilterGetMessage(port, buffer, (uint)bufferSize, IntPtr.Zero);
        if (hr != 0)
        {
            if (cts.IsCancellationRequested) break;
            throw new InvalidOperationException($"FilterGetMessage failed HRESULT=0x{hr:X8}");
        }

        var ev = Marshal.PtrToStructure<RgEvent>(IntPtr.Add(buffer, headerSize));
        if (ev.ProtocolVersion != ProtocolVersion)
            throw new InvalidOperationException($"Protocol mismatch. Driver={ev.ProtocolVersion}, client={ProtocolVersion}.");

        var received = DateTime.UtcNow;
        DateTime occurred;
        try { occurred = DateTime.FromFileTimeUtc(ev.SystemTime100ns); }
        catch { occurred = received; }
        var lag = Math.Max(0, (received - occurred).TotalMilliseconds);
        var ntPath = ev.Path ?? string.Empty;
        var dosPath = resolver.Resolve(ntPath);
        var destinationNtPath = ev.DestinationPath ?? string.Empty;
        var destinationPath = ev.EventType == (uint)RgEventType.Rename ? resolver.Resolve(destinationNtPath) : null;
        var inScope = options.AllLocal || options.Roots.Any(r => PathPolicy.Under(dosPath, r));
        stats.Observe(ev, lag, inScope, dosPath is not null);

        if (inScope)
        {
            var record = new
            {
                Schema = 1,
                Sequence = ev.Sequence,
                OccurredUtc = occurred,
                ReceivedUtc = received,
                DeliveryMs = Math.Round(lag, 3),
                Type = ((RgEventType)ev.EventType).ToString(),
                ev.ProcessId,
                Process = ProcessInfo.TryGet(ev.ProcessId),
                ev.ThreadId,
                NtPath = ntPath,
                Path = dosPath,
                PathStatus = ((RgPathStatus)ev.PathStatus).ToString(),
                DestinationNtPath = ev.EventType == (uint)RgEventType.Rename ? destinationNtPath : null,
                DestinationPath = destinationPath,
                DestinationPathStatus = ev.EventType == (uint)RgEventType.Rename
                    ? ((RgPathStatus)ev.DestinationPathStatus).ToString()
                    : null,
                ev.ByteOffset,
                ev.Length,
                ev.FileInformationClass,
                ev.Flags,
                CreateDisposition = ev.EventType == (uint)RgEventType.Create ? (uint?)((ev.Flags >> 24) & 0xFF) : null,
                CreateOptions = ev.EventType == (uint)RgEventType.Create ? (uint?)(ev.Flags & 0x00FFFFFF) : null,
                DesiredAccess = ev.EventType == (uint)RgEventType.Create ? (uint?)ev.Length : null,
                ev.DroppedBeforeThis
            };
            writer.WriteLine(JsonSerializer.Serialize(record));
            if (options.Verbose)
                Console.WriteLine($"{record.OccurredUtc:HH:mm:ss.fff} {record.Type,-20} pid={record.ProcessId,-6} lag={record.DeliveryMs,8:F1}ms {record.Path ?? record.NtPath}");
        }

        if (lastFlush.ElapsedMilliseconds >= 1000)
        {
            writer.Flush();
            lastFlush.Restart();
        }
        if (lastSummary.ElapsedMilliseconds >= 5000)
        {
            Console.WriteLine(stats.OneLine());
            lastSummary.Restart();
        }
    }
}
finally
{
    Marshal.FreeHGlobal(buffer);
    writer.Flush();
    var summary = stats.Snapshot(options, logPath);
    File.WriteAllText(summaryPath, JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine(stats.OneLine());
    Console.WriteLine($"Summary: {summaryPath}");
}

sealed class Options
{
    public required string[] Roots { get; init; }
    public required string OutputDirectory { get; init; }
    public bool AllLocal { get; init; }
    public bool Verbose { get; init; }

    public static Options Parse(string[] args)
    {
        var roots = new List<string>();
        var verbose = false;
        var allLocal = false;
        string? output = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--root" when i + 1 < args.Length:
                    roots.Add(Path.GetFullPath(args[++i]).TrimEnd('\\'));
                    break;
                case "--output" when i + 1 < args.Length:
                    output = Path.GetFullPath(args[++i]);
                    break;
                case "--verbose": verbose = true; break;
                case "--all-local": allLocal = true; break;
                default: throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
            }
        }
        if (!allLocal && roots.Count == 0)
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            foreach (var name in new[] { "Desktop", "Documents", "Pictures" })
            {
                var p = Path.Combine(home, name);
                if (Directory.Exists(p)) roots.Add(p.TrimEnd('\\'));
            }
        }
        if (!allLocal && roots.Count == 0) throw new InvalidOperationException("No audit roots found. Pass --root explicitly.");
        output ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomGuardV04", "MinifilterAudit");
        return new Options { Roots = roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), OutputDirectory = output, Verbose = verbose, AllLocal = allLocal };
    }
}

static class SecureOutput
{
    public static void Ensure(string path)
    {
        Directory.CreateDirectory(path);
        var info = new DirectoryInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Audit directory must not be a reparse point.");
        // Audit metadata contains paths but no file contents or memory. Keep it in the invoking user's profile by default.
        // Full forensic evidence remains in the separately hardened RansomGuard state store.
    }
}

static class PathPolicy
{
    public static bool Under(string? path, string root)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = Path.GetFullPath(path).TrimEnd('\\');
        var r = Path.GetFullPath(root).TrimEnd('\\');
        return p.Equals(r, StringComparison.OrdinalIgnoreCase) ||
               p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }
}

sealed class DevicePathResolver
{
    private readonly (string Device, string Drive)[] _map;
    public DevicePathResolver()
    {
        var m = new List<(string, string)>();
        foreach (var d in DriveInfo.GetDrives())
        {
            var drive = d.Name.TrimEnd('\\');
            if (drive.Length != 2 || drive[1] != ':') continue;
            var sb = new System.Text.StringBuilder(1024);
            if (Native.QueryDosDevice(drive, sb, sb.Capacity) != 0)
                m.Add((sb.ToString().Split('\0')[0], drive));
        }
        _map = m.OrderByDescending(x => x.Item1.Length).ToArray();
    }
    public string? Resolve(string? ntPath)
    {
        if (string.IsNullOrWhiteSpace(ntPath)) return null;
        var p = ntPath;
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && p[2] == '\\') return p;
        foreach (var (device, drive) in _map)
            if (p.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return drive + p[device.Length..];
        return null;
    }
}

static class ProcessInfo
{
    public static object? TryGet(ulong pid)
    {
        if (pid == 0 || pid > int.MaxValue) return null;
        try
        {
            using var p = Process.GetProcessById((int)pid);
            string? path = null;
            try { path = p.MainModule?.FileName; } catch { }
            DateTime? started = null;
            try { started = p.StartTime.ToUniversalTime(); } catch { }
            return new { Name = p.ProcessName, Path = path, StartedUtc = started };
        }
        catch { return null; }
    }
}

sealed class AuditStats
{
    private long _events, _inScope, _create, _write, _rename, _delete, _truncate, _driverDropped, _resolved, _unresolved;
    private readonly Queue<double> _lag = new();
    public void Observe(RgEvent e, double lag, bool inScope, bool resolved)
    {
        _events++; if (inScope) _inScope++;
        if (resolved) _resolved++; else _unresolved++;
        _driverDropped += e.DroppedBeforeThis;
        switch ((RgEventType)e.EventType) { case RgEventType.Create: _create++; break; case RgEventType.Write: _write++; break; case RgEventType.Rename: _rename++; break; case RgEventType.DeleteDisposition: _delete++; break; case RgEventType.Truncate: _truncate++; break; }
        _lag.Enqueue(lag); while (_lag.Count > 10000) _lag.Dequeue();
    }
    private double P(double q)
    {
        if (_lag.Count == 0) return 0;
        var a = _lag.OrderBy(x => x).ToArray();
        return a[(int)Math.Clamp(Math.Ceiling(q * a.Length) - 1, 0, a.Length - 1)];
    }
    public string OneLine() => $"events={_events} scope={_inScope} create={_create} write={_write} rename={_rename} delete={_delete} truncate={_truncate} driverDropped={_driverDropped} unresolved={_unresolved} lag p50={P(.50):F1} p95={P(.95):F1} p99={P(.99):F1} max={(_lag.Count == 0 ? 0 : _lag.Max()):F1}ms";
    public object Snapshot(Options o, string logPath) => new
    {
        Schema = 1, CapturedUtc = DateTime.UtcNow, ReadOnly = true,
        o.Roots, o.AllLocal, LogPath = logPath,
        Events = _events, InScope = _inScope, Creates = _create, Writes = _write, Renames = _rename, DeleteDispositions = _delete, Truncates = _truncate,
        DriverReportedDropped = _driverDropped, ResolvedPaths = _resolved, UnresolvedPaths = _unresolved,
        DeliveryMs = new { P50 = P(.50), P95 = P(.95), P99 = P(.99), Max = _lag.Count == 0 ? 0 : _lag.Max() }
    };
}

enum RgEventType : uint { Invalid = 0, Write = 1, Rename = 2, DeleteDisposition = 3, Truncate = 4, Create = 5, RenameResult = 6, CreateResult = 7 }
enum RgPathStatus : uint { Unknown = 0, Resolved = 1, QueryFailed = 2, Truncated = 3 }
enum RgIdentityStatus : uint { Unknown = 0, Resolved = 1, QueryFailed = 2 }

[StructLayout(LayoutKind.Sequential)]
struct FilterMessageHeader { public uint ReplyLength; public ulong MessageId; }

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
    public uint Length, FileInformationClass, DroppedBeforeThis, DestinationPathStatus;
    public ulong RelatedSequence;
    public uint CompletionStatus;
    public ulong CompletionInformation;
    public uint IdentityStatus;
    public ulong VolumeSerialNumber, FileIdLow, FileIdHigh;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string? Path;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string? DestinationPath;
}

static class Native
{
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string lpPortName, uint dwOptions, IntPtr lpContext,
        ushort wSizeOfContext, IntPtr lpSecurityAttributes, out SafeFileHandle hPort);
    [DllImport("fltlib.dll")]
    public static extern int FilterGetMessage(SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(SafeFileHandle hFile, IntPtr lpOverlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);

    public static SafeFileHandle Connect(string name, ulong processId)
    {
        const uint FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001;
        var context = new RgConnectContext
        {
            ProtocolVersion = 8,
            ClientMode = 1,
            ClientProcessId = processId,
            GateRootLengthBytes = 0,
            GateRoot = string.Empty
        };
        var size = Marshal.SizeOf<RgConnectContext>();
        if (size != 544) throw new InvalidOperationException($"Unexpected connect context size: {size}");
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(context, ptr, false);
            var hr = FilterConnectCommunicationPort(name, FLT_PORT_FLAG_SYNC_HANDLE, ptr, checked((ushort)size), IntPtr.Zero, out var handle);
            if (hr != 0 || handle.IsInvalid) throw new InvalidOperationException($"FilterConnectCommunicationPort failed HRESULT=0x{hr:X8}. Is the lab minifilter loaded and attached?");
            return handle;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
    public static void Cancel(SafeFileHandle handle) { if (!handle.IsInvalid) _ = CancelIoEx(handle, IntPtr.Zero); }
}
