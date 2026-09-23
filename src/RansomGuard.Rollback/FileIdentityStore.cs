using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Incident-scoped durable mapping from a canonical path to Windows file identity.
/// The identity is the FILE_ID_INFO pair (volume serial + 128-bit file id).
/// It does not replace post-create/post-rename reconciliation; it prevents a path from
/// silently changing to a different file after the first identity observation.
/// </summary>
public sealed class FileIdentityStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<string, FileIdentityBaseline> _byPath =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyCollection<FileIdentityBaseline> Baselines =>
        _byPath.Values.OrderBy(x => x.Sequence).ToArray();

    public FileIdentityStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("File identity root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "identity-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<FileIdentityBaseline> CaptureOrVerifyAsync(string path,
        CancellationToken cancellationToken = default)
    {
        var full = NormalizeSource(path);
        RejectReparse(full);

        using var input = new FileStream(full, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Write | FileShare.Delete, 4096, FileOptions.None);
        var identity = QueryHandleIdentity(input.SafeFileHandle);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_byPath.TryGetValue(full, out var existing))
            {
                if (!existing.Identity.Equals(identity))
                    throw new InvalidDataException(
                        "File identity changed for a path already observed in this incident: " + full);
                return existing;
            }

            var sequence = checked(++_nextSequence);
            var payload = new FileIdentityJournalPayload(sequence, DateTime.UtcNow, full,
                identity.VolumeSerialHex, identity.FileIdHex, _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new FileIdentityJournalLine(payload.Sequence, payload.CapturedUtc, payload.OriginalPath,
                payload.VolumeSerialHex, payload.FileIdHex, payload.PreviousRecordSha256, recordHash);
            AppendJournalLine(line);
            _lastRecordHash = recordHash;

            var baseline = line.ToBaseline();
            if (!_byPath.TryAdd(full, baseline))
                throw new InvalidOperationException("Concurrent file identity baseline commit collision.");
            return baseline;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGet(string path, out FileIdentityBaseline? baseline) =>
        _byPath.TryGetValue(NormalizeSource(path), out baseline);

    public string[] PathsFor(DurableFileIdentity identity) =>
        _byPath.Values.Where(x => x.Identity.Equals(identity))
            .OrderBy(x => x.Sequence)
            .Select(x => x.OriginalPath)
            .ToArray();

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                _byPath.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var rebuilt = new Dictionary<string, FileIdentityBaseline>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank file identity journal record.");

            FileIdentityJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<FileIdentityJournalLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid file identity journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid file identity journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("File identity journal sequence gap.");
            if (!IsFixedHex(line.VolumeSerialHex, 16) || !IsFixedHex(line.FileIdHex, 32) ||
                !IsFixedHex(line.PreviousRecordSha256, 64) || !IsFixedHex(line.RecordSha256, 64))
                throw new InvalidDataException("Invalid file identity journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("File identity journal hash chain mismatch.");

            var calculated = HashPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("File identity journal record hash mismatch.");

            var full = NormalizeSource(line.OriginalPath);
            if (!rebuilt.TryAdd(full, line.ToBaseline() with { OriginalPath = full }))
                throw new InvalidDataException("Duplicate file identity baseline for path.");

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            _byPath.Clear();
            foreach (var pair in rebuilt) _byPath[pair.Key] = pair.Value;
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(FileIdentityJournalLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(FileIdentityJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    public static DurableFileIdentity QueryHandleIdentity(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Durable file identity requires Windows FILE_ID_INFO.");

        if (!GetFileInformationByHandleExFileId(handle, FileIdInfo, out var info,
                checked((uint)Marshal.SizeOf<NativeFileIdInfo>())))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "GetFileInformationByHandleEx(FileIdInfo) failed.");

        return new DurableFileIdentity(
            info.VolumeSerialNumber.ToString("X16"),
            info.FileId.Part0.ToString("X16") + info.FileId.Part1.ToString("X16"));
    }

    public static DurableFileStandardInfo QueryPathStandardInfo(
        string path,
        DurableFileIdentity expectedIdentity)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path is required.", nameof(path));

        using var input = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Write | FileShare.Delete, 4096, FileOptions.None);
        var actualIdentity = QueryHandleIdentity(input.SafeFileHandle);
        if (!actualIdentity.Equals(expectedIdentity))
            throw new InvalidDataException(
                "File standard-info handle identity does not match the expected incident identity.");

        return QueryHandleStandardInfo(input.SafeFileHandle);
    }

    public static DurableFileStandardInfo QueryHandleStandardInfo(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Durable file standard information requires Windows.");

        if (!GetFileInformationByHandleExStandard(handle, FileStandardInfo, out var info,
                checked((uint)Marshal.SizeOf<NativeFileStandardInfo>())))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "GetFileInformationByHandleEx(FileStandardInfo) failed.");

        if (info.AllocationSize < 0 || info.EndOfFile < 0)
            throw new InvalidDataException("Windows returned a negative file length/allocation size.");

        return new DurableFileStandardInfo(info.AllocationSize, info.EndOfFile);
    }

    private static string NormalizeSource(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Source path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full))
            throw new ArgumentException("Source path must be absolute.", nameof(path));
        return full;
    }

    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("File identity path/store must not be a reparse point: " + path);
    }

    private const int FileStandardInfo = 1;
    private const int FileIdInfo = 18;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileId128
    {
        public ulong Part0;
        public ulong Part1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileIdInfo
    {
        public ulong VolumeSerialNumber;
        public NativeFileId128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileStandardInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.Bool)] public bool DeletePending;
        [MarshalAs(UnmanagedType.Bool)] public bool Directory;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    private static extern bool GetFileInformationByHandleExFileId(
        SafeFileHandle hFile,
        int fileInformationClass,
        out NativeFileIdInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    private static extern bool GetFileInformationByHandleExStandard(
        SafeFileHandle hFile,
        int fileInformationClass,
        out NativeFileStandardInfo fileInformation,
        uint bufferSize);
}

public sealed record DurableFileIdentity(string VolumeSerialHex, string FileIdHex);

public sealed record DurableFileStandardInfo(long AllocationSize, long EndOfFile);

public sealed record FileIdentityBaseline(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity Identity => new(VolumeSerialHex, FileIdHex);
}

internal sealed record FileIdentityJournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256);

internal sealed record FileIdentityJournalLine(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public FileIdentityJournalPayload Payload =>
        new(Sequence, CapturedUtc, OriginalPath, VolumeSerialHex, FileIdHex, PreviousRecordSha256);

    public FileIdentityBaseline ToBaseline() =>
        new(Sequence, CapturedUtc, OriginalPath, VolumeSerialHex, FileIdHex,
            PreviousRecordSha256, RecordSha256);
}
