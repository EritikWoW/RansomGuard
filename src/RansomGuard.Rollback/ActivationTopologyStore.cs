using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable evidence that activation held each ordinary directory with read-only sharing until
/// the kernel gate became active. This prevents pre-existing write/delete directory handles
/// from crossing the activation boundary unnoticed.
/// </summary>
public sealed class ActivationTopologyStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<ActivationTopologyEvidence> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<ActivationTopologyEvidence> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public ActivationTopologyStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Activation topology root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "activation-topology-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<ActivationTopologyEvidence> RecordAsync(
        string directoryPath,
        DurableFileIdentity identity,
        bool isRoot,
        CancellationToken cancellationToken = default)
    {
        var full = NormalizeDirectory(directoryPath);
        ValidateIdentity(identity);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records.SingleOrDefault(x =>
                    x.DirectoryPath.Equals(full, StringComparison.OrdinalIgnoreCase));
                if (existing is not null)
                {
                    if (existing.Identity.Equals(identity) && existing.IsRoot == isRoot)
                        return existing;
                    throw new InvalidDataException("Conflicting activation-topology record for directory path.");
                }
            }

            var sequence = checked(++_nextSequence);
            var payload = new ActivationTopologyPayload(
                sequence,
                DateTime.UtcNow,
                full,
                identity.VolumeSerialHex,
                identity.FileIdHex,
                isRoot,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new ActivationTopologyLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.DirectoryPath,
                payload.VolumeSerialHex,
                payload.FileIdHex,
                payload.IsRoot,
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
            _gate.Release();
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
        var rebuilt = new List<ActivationTopologyEvidence>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank activation-topology journal record.");

            ActivationTopologyLine line;
            try
            {
                line = JsonSerializer.Deserialize<ActivationTopologyLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid activation-topology journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid activation-topology journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid activation-topology journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Activation-topology journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Activation-topology journal record hash mismatch.");

            var full = NormalizeDirectory(line.DirectoryPath);
            if (!seenPaths.Add(full))
                throw new InvalidDataException("Duplicate activation-topology directory path.");
            var identity = new DurableFileIdentity(line.VolumeSerialHex, line.FileIdHex);
            ValidateIdentity(identity);

            rebuilt.Add(line.ToEvidence() with { DirectoryPath = full });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuilt.Count(x => x.IsRoot) > 1)
            throw new InvalidDataException("Activation-topology journal has multiple root records.");

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

    private void AppendLine(ActivationTopologyLine line)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(ActivationTopologyPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Activation topology directory is required.", nameof(path));
        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid activation-topology durable directory identity.");
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);
    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Activation topology store must not be a reparse point: " + path);
    }
}

public sealed record ActivationTopologyEvidence(
    long Sequence,
    DateTime ObservedUtc,
    string DirectoryPath,
    string VolumeSerialHex,
    string FileIdHex,
    bool IsRoot,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity Identity => new(VolumeSerialHex, FileIdHex);
}

internal sealed record ActivationTopologyPayload(
    long Sequence,
    DateTime ObservedUtc,
    string DirectoryPath,
    string VolumeSerialHex,
    string FileIdHex,
    bool IsRoot,
    string PreviousRecordSha256);

internal sealed record ActivationTopologyLine(
    long Sequence,
    DateTime ObservedUtc,
    string DirectoryPath,
    string VolumeSerialHex,
    string FileIdHex,
    bool IsRoot,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public ActivationTopologyPayload Payload => new(
        Sequence, ObservedUtc, DirectoryPath, VolumeSerialHex, FileIdHex, IsRoot, PreviousRecordSha256);

    public ActivationTopologyEvidence ToEvidence() => new(
        Sequence, ObservedUtc, DirectoryPath, VolumeSerialHex, FileIdHex, IsRoot,
        PreviousRecordSha256, RecordSha256);
}
