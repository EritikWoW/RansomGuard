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
    private readonly string _transitionJournal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<string, FileIdentityBaseline> _byPath =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DurableFileIdentity> _currentByPath =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);
    private long _nextTransitionSequence;
    private string _lastTransitionHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public string TransitionJournalPath => _transitionJournal;
    public IReadOnlyCollection<FileIdentityBaseline> Baselines =>
        _byPath.Values.OrderBy(x => x.Sequence).ToArray();

    public FileIdentityStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("File identity root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "identity-journal.jsonl");
        _transitionJournal = Path.Combine(_root, "identity-transition-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
        LoadAndValidateTransitions();
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
                if (!_currentByPath.TryGetValue(full, out var current) || !current.Equals(identity))
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
            if (!_byPath.TryAdd(full, baseline) || !_currentByPath.TryAdd(full, identity))
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

    public bool TryGetCurrent(string path, out DurableFileIdentity? identity) =>
        _currentByPath.TryGetValue(NormalizeSource(path), out identity);

    public string[] PathsFor(DurableFileIdentity identity) =>
        _currentByPath.Where(x => x.Value.Equals(identity))
            .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.Key)
            .ToArray();

    public async Task<FileIdentityTransition> TransitionAsync(
        string path,
        DurableFileIdentity expectedCurrent,
        DurableFileIdentity next,
        ulong relatedSequence,
        CancellationToken cancellationToken = default)
    {
        if (relatedSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(relatedSequence));
        ValidateIdentity(expectedCurrent);
        ValidateIdentity(next);
        if (expectedCurrent.Equals(next))
            throw new InvalidOperationException("File identity transition must change the identity.");

        var full = NormalizeSource(path);
        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_currentByPath.TryGetValue(full, out var current))
                throw new InvalidDataException("Cannot transition an unobserved file identity.");
            if (!current.Equals(expectedCurrent))
                throw new InvalidDataException("File identity transition does not match current incident identity.");

            var sequence = checked(++_nextTransitionSequence);
            var payload = new FileIdentityTransitionPayload(
                sequence, DateTime.UtcNow, full, relatedSequence,
                expectedCurrent.VolumeSerialHex, expectedCurrent.FileIdHex,
                next.VolumeSerialHex, next.FileIdHex, _lastTransitionHash);
            var recordHash = HashTransitionPayload(payload);
            var line = FileIdentityTransitionLine.FromPayload(payload, recordHash);
            AppendTransitionLine(line);
            _lastTransitionHash = recordHash;
            _currentByPath[full] = next;
            return line.ToTransition();
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public void VerifyAll()
    {
        LoadAndValidateJournal(rebuildState: false);
        LoadAndValidateTransitions(rebuildState: false);
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                _byPath.Clear();
                _currentByPath.Clear();
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
            _currentByPath.Clear();
            foreach (var pair in rebuilt)
            {
                _byPath[pair.Key] = pair.Value;
                _currentByPath[pair.Key] = pair.Value.Identity;
            }
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void LoadAndValidateTransitions(bool rebuildState = true)
    {
        if (!File.Exists(_transitionJournal))
        {
            if (rebuildState)
            {
                _nextTransitionSequence = 0;
                _lastTransitionHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_transitionJournal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var working = _byPath.ToDictionary(x => x.Key, x => x.Value.Identity, StringComparer.OrdinalIgnoreCase);

        foreach (var raw in File.ReadLines(_transitionJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank file identity transition record.");

            FileIdentityTransitionLine line;
            try
            {
                line = JsonSerializer.Deserialize<FileIdentityTransitionLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid file identity transition record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid file identity transition JSON.", ex);
            }

            if (line.Sequence != expectedSequence || line.RelatedSequence == 0)
                throw new InvalidDataException("File identity transition sequence is invalid.");
            if (!IsFixedHex(line.PreviousRecordSha256, 64) ||
                !line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase) ||
                !IsFixedHex(line.RecordSha256, 64))
                throw new InvalidDataException("File identity transition hash chain is invalid.");

            var oldIdentity = new DurableFileIdentity(line.OldVolumeSerialHex, line.OldFileIdHex);
            var newIdentity = new DurableFileIdentity(line.NewVolumeSerialHex, line.NewFileIdHex);
            ValidateIdentity(oldIdentity);
            ValidateIdentity(newIdentity);
            if (oldIdentity.Equals(newIdentity))
                throw new InvalidDataException("File identity transition does not change identity.");

            var calculated = HashTransitionPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("File identity transition record hash mismatch.");

            var full = NormalizeSource(line.OriginalPath);
            if (!working.TryGetValue(full, out var current) || !current.Equals(oldIdentity))
                throw new InvalidDataException("File identity transition does not continue from current identity.");
            working[full] = newIdentity;

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            _currentByPath.Clear();
            foreach (var pair in working) _currentByPath[pair.Key] = pair.Value;
            _nextTransitionSequence = expectedSequence - 1;
            _lastTransitionHash = expectedPrevious;
        }
    }

    private void AppendTransitionLine(FileIdentityTransitionLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_transitionJournal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashTransitionPayload(FileIdentityTransitionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid durable file identity.");
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

        if (!GetFileInformationByHandleEx(handle, FileIdInfo, out var info,
                checked((uint)Marshal.SizeOf<NativeFileIdInfo>())))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "GetFileInformationByHandleEx(FileIdInfo) failed.");

        return new DurableFileIdentity(
            info.VolumeSerialNumber.ToString("X16"),
            info.FileId.Part0.ToString("X16") + info.FileId.Part1.ToString("X16"));
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        out NativeFileIdInfo fileInformation,
        uint bufferSize);
}

public sealed record DurableFileIdentity(string VolumeSerialHex, string FileIdHex);

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


public sealed record FileIdentityTransition(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    ulong RelatedSequence,
    string OldVolumeSerialHex,
    string OldFileIdHex,
    string NewVolumeSerialHex,
    string NewFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity OldIdentity => new(OldVolumeSerialHex, OldFileIdHex);

    [JsonIgnore]
    public DurableFileIdentity NewIdentity => new(NewVolumeSerialHex, NewFileIdHex);
}

internal sealed record FileIdentityTransitionPayload(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    ulong RelatedSequence,
    string OldVolumeSerialHex,
    string OldFileIdHex,
    string NewVolumeSerialHex,
    string NewFileIdHex,
    string PreviousRecordSha256);

internal sealed record FileIdentityTransitionLine(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    ulong RelatedSequence,
    string OldVolumeSerialHex,
    string OldFileIdHex,
    string NewVolumeSerialHex,
    string NewFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public FileIdentityTransitionPayload Payload => new(
        Sequence, CapturedUtc, OriginalPath, RelatedSequence,
        OldVolumeSerialHex, OldFileIdHex, NewVolumeSerialHex, NewFileIdHex,
        PreviousRecordSha256);

    public static FileIdentityTransitionLine FromPayload(
        FileIdentityTransitionPayload payload,
        string recordHash) => new(
            payload.Sequence, payload.CapturedUtc, payload.OriginalPath, payload.RelatedSequence,
            payload.OldVolumeSerialHex, payload.OldFileIdHex,
            payload.NewVolumeSerialHex, payload.NewFileIdHex,
            payload.PreviousRecordSha256, recordHash);

    public FileIdentityTransition ToTransition() => new(
        Sequence, CapturedUtc, OriginalPath, RelatedSequence,
        OldVolumeSerialHex, OldFileIdHex, NewVolumeSerialHex, NewFileIdHex,
        PreviousRecordSha256, RecordSha256);
}
