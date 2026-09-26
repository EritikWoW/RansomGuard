using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable evidence collected before the LAB gate is activated. Each record corresponds to a file
/// opened by the gate client while the kernel keeps the protected root in fail-closed preflight mode.
/// </summary>
public sealed class ActivationPreflightStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<ActivationPreflightEvidence> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<ActivationPreflightEvidence> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public ActivationPreflightStore(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Activation preflight root is required.", nameof(root));
        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "activation-preflight-journal.jsonl");
        if (createIfMissing)
        {
            Directory.CreateDirectory(_root);
        }
        else if (!Directory.Exists(_root))
        {
            if (File.Exists(_root)) throw new IOException("Activation preflight root is not a directory: " + _root);
            throw new DirectoryNotFoundException("Activation preflight root does not exist: " + _root);
        }
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<ActivationPreflightEvidence> RecordAsync(
        ulong kernelSequence,
        string path,
        uint completionStatus,
        bool writableViewPresent,
        DurableFileIdentity? identity,
        CancellationToken cancellationToken = default)
    {
        if (kernelSequence == 0) throw new ArgumentOutOfRangeException(nameof(kernelSequence));
        var full = Path.GetFullPath(path);
        if (identity is not null) ValidateIdentity(identity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records.SingleOrDefault(x => x.KernelSequence == kernelSequence);
                if (existing is not null)
                {
                    if (existing.Path.Equals(full, StringComparison.OrdinalIgnoreCase) &&
                        existing.CompletionStatus == completionStatus &&
                        existing.WritableViewPresent == writableViewPresent &&
                        Equals(existing.Identity, identity))
                        return existing;
                    throw new InvalidDataException("Conflicting duplicate activation-preflight kernel sequence.");
                }
            }

            var seq = checked(++_nextSequence);
            var payload = new ActivationPreflightPayload(
                seq, DateTime.UtcNow, kernelSequence, full, completionStatus,
                writableViewPresent, identity?.VolumeSerialHex ?? string.Empty,
                identity?.FileIdHex ?? string.Empty, _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new ActivationPreflightLine(
                payload.Sequence, payload.ObservedUtc, payload.KernelSequence, payload.Path,
                payload.CompletionStatus, payload.WritableViewPresent, payload.VolumeSerialHex,
                payload.FileIdHex, payload.PreviousRecordSha256, recordHash);
            AppendLine(line);
            _lastRecordHash = recordHash;
            var record = line.ToEvidence();
            lock (_records) _records.Add(record);
            return record;
        }
        finally { _appendGate.Release(); }
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
        var rebuilt = new List<ActivationPreflightEvidence>();
        var seenKernel = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank activation-preflight journal record.");

            ActivationPreflightLine line;
            try
            {
                line = JsonSerializer.Deserialize<ActivationPreflightLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid activation-preflight journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid activation-preflight journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence || line.KernelSequence == 0 ||
                !seenKernel.Add(line.KernelSequence) || !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid activation-preflight journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Activation-preflight journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Activation-preflight journal record hash mismatch.");

            var path = Path.GetFullPath(line.Path);
            DurableFileIdentity? identity = string.IsNullOrEmpty(line.VolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.VolumeSerialHex, line.FileIdHex);
            if (identity is not null) ValidateIdentity(identity);

            rebuilt.Add(line.ToEvidence() with { Path = path });
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

    private void AppendLine(ActivationPreflightLine line)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(ActivationPreflightPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid activation-preflight durable file identity.");
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);
    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Activation preflight store must not be a reparse point: " + path);
    }
}

public sealed record ActivationPreflightEvidence(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    string Path,
    uint CompletionStatus,
    bool WritableViewPresent,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? Identity =>
        string.IsNullOrEmpty(VolumeSerialHex) ? null : new DurableFileIdentity(VolumeSerialHex, FileIdHex);
}

internal sealed record ActivationPreflightPayload(
    long Sequence, DateTime ObservedUtc, ulong KernelSequence, string Path, uint CompletionStatus,
    bool WritableViewPresent, string VolumeSerialHex, string FileIdHex, string PreviousRecordSha256);

internal sealed record ActivationPreflightLine(
    long Sequence, DateTime ObservedUtc, ulong KernelSequence, string Path, uint CompletionStatus,
    bool WritableViewPresent, string VolumeSerialHex, string FileIdHex,
    string PreviousRecordSha256, string RecordSha256)
{
    [JsonIgnore]
    public ActivationPreflightPayload Payload => new(
        Sequence, ObservedUtc, KernelSequence, Path, CompletionStatus, WritableViewPresent,
        VolumeSerialHex, FileIdHex, PreviousRecordSha256);

    public ActivationPreflightEvidence ToEvidence() => new(
        Sequence, ObservedUtc, KernelSequence, Path, CompletionStatus, WritableViewPresent,
        VolumeSerialHex, FileIdHex, PreviousRecordSha256, RecordSha256);
}
