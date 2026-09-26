using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable evidence that the minifilter observed a paging write on a stream previously established
/// inside the explicit LAB gate root. This store does not claim that paging I/O was preserved or blocked.
/// </summary>
public sealed class PagingWriteEvidenceStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<PagingWriteEvidence> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<PagingWriteEvidence> Records
    {
        get
        {
            lock (_records) return _records.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public PagingWriteEvidenceStore(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Paging evidence root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "paging-write-journal.jsonl");
        if (createIfMissing)
        {
            Directory.CreateDirectory(_root);
        }
        else if (!Directory.Exists(_root))
        {
            if (File.Exists(_root)) throw new IOException("Paging-write evidence root is not a directory: " + _root);
            throw new DirectoryNotFoundException("Paging-write evidence root does not exist: " + _root);
        }
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<PagingWriteEvidence> RecordAsync(
        ulong kernelSequence,
        string trackedPath,
        long byteOffset,
        uint length,
        DurableFileIdentity? identity,
        uint eventFlags,
        CancellationToken cancellationToken = default)
    {
        if (kernelSequence == 0) throw new ArgumentOutOfRangeException(nameof(kernelSequence));
        if (byteOffset < 0) throw new ArgumentOutOfRangeException(nameof(byteOffset));
        _ = checked(byteOffset + (long)length);

        var full = NormalizePath(trackedPath);
        if (identity is not null) ValidateIdentity(identity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records.SingleOrDefault(x => x.KernelSequence == kernelSequence);
                if (existing is not null)
                {
                    if (existing.TrackedPath.Equals(full, StringComparison.OrdinalIgnoreCase) &&
                        existing.ByteOffset == byteOffset &&
                        existing.Length == length &&
                        Nullable.Equals(existing.Identity, identity) &&
                        existing.EventFlags == eventFlags)
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate paging-write kernel sequence.");
                }
            }

            var sequence = checked(++_nextSequence);
            var payload = new PagingWritePayload(
                sequence,
                DateTime.UtcNow,
                kernelSequence,
                full,
                byteOffset,
                length,
                identity?.VolumeSerialHex ?? string.Empty,
                identity?.FileIdHex ?? string.Empty,
                eventFlags,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new PagingWriteLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.KernelSequence,
                payload.TrackedPath,
                payload.ByteOffset,
                payload.Length,
                payload.VolumeSerialHex,
                payload.FileIdHex,
                payload.EventFlags,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(line);
            _lastRecordHash = recordHash;
            var record = line.ToEvidence();
            lock (_records) _records.Add(record);
            return record;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                lock (_records) _records.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<PagingWriteEvidence>();
        var kernelSequences = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank paging-write journal record.");

            PagingWriteLine line;
            try
            {
                line = JsonSerializer.Deserialize<PagingWriteLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid paging-write journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid paging-write journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Paging-write journal sequence gap.");
            if (line.KernelSequence == 0 || !kernelSequences.Add(line.KernelSequence) ||
                line.ByteOffset < 0 || !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid paging-write journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Paging-write journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Paging-write journal record hash mismatch.");

            var path = NormalizePath(line.TrackedPath);
            DurableFileIdentity? identity = string.IsNullOrEmpty(line.VolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.VolumeSerialHex, line.FileIdHex);
            if (identity is not null) ValidateIdentity(identity);

            rebuilt.Add(line.ToEvidence() with { TrackedPath = path });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_records)
            {
                _records.Clear();
                _records.AddRange(rebuilt);
            }
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendLine(PagingWriteLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(PagingWritePayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Paging evidence path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid paging-write durable file identity.");
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);

    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Paging evidence store must not be a reparse point: " + path);
    }
}

public sealed record PagingWriteEvidence(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    string TrackedPath,
    long ByteOffset,
    uint Length,
    string VolumeSerialHex,
    string FileIdHex,
    uint EventFlags,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? Identity =>
        string.IsNullOrEmpty(VolumeSerialHex)
            ? null
            : new DurableFileIdentity(VolumeSerialHex, FileIdHex);
}

internal sealed record PagingWritePayload(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    string TrackedPath,
    long ByteOffset,
    uint Length,
    string VolumeSerialHex,
    string FileIdHex,
    uint EventFlags,
    string PreviousRecordSha256);

internal sealed record PagingWriteLine(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    string TrackedPath,
    long ByteOffset,
    uint Length,
    string VolumeSerialHex,
    string FileIdHex,
    uint EventFlags,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public PagingWritePayload Payload => new(
        Sequence, ObservedUtc, KernelSequence, TrackedPath, ByteOffset, Length,
        VolumeSerialHex, FileIdHex, EventFlags, PreviousRecordSha256);

    public PagingWriteEvidence ToEvidence() => new(
        Sequence, ObservedUtc, KernelSequence, TrackedPath, ByteOffset, Length,
        VolumeSerialHex, FileIdHex, EventFlags, PreviousRecordSha256, RecordSha256);
}
