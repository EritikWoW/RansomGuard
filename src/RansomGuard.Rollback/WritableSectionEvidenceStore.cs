using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

public sealed class WritableSectionEvidenceStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<WritableSectionEvidence> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<WritableSectionEvidence> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public WritableSectionEvidenceStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Writable-section evidence root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "writable-section-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<WritableSectionEvidence> RecordAsync(
        ulong kernelSequence,
        ulong createRequestSequence,
        string trackedPath,
        uint pageProtection,
        uint preservationDecision,
        WritableSectionAttestationState state,
        DurableFileIdentity? identity,
        CancellationToken cancellationToken = default)
    {
        if (kernelSequence == 0) throw new ArgumentOutOfRangeException(nameof(kernelSequence));
        if (createRequestSequence == 0) throw new ArgumentOutOfRangeException(nameof(createRequestSequence));
        if (!Enum.IsDefined(state)) throw new InvalidDataException("Invalid writable-section attestation state.");

        var full = NormalizePath(trackedPath);
        if (identity is not null) ValidateIdentity(identity);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records.SingleOrDefault(x => x.KernelSequence == kernelSequence);
                if (existing is not null)
                {
                    if (existing.CreateRequestSequence == createRequestSequence &&
                        existing.TrackedPath.Equals(full, StringComparison.OrdinalIgnoreCase) &&
                        existing.PageProtection == pageProtection &&
                        existing.PreservationDecision == preservationDecision &&
                        existing.State == state &&
                        Nullable.Equals(existing.Identity, identity))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate writable-section kernel sequence.");
                }
            }

            var sequence = checked(++_nextSequence);
            var payload = new WritableSectionPayload(
                sequence,
                DateTime.UtcNow,
                kernelSequence,
                createRequestSequence,
                full,
                pageProtection,
                preservationDecision,
                state,
                identity?.VolumeSerialHex ?? string.Empty,
                identity?.FileIdHex ?? string.Empty,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new WritableSectionLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.KernelSequence,
                payload.CreateRequestSequence,
                payload.TrackedPath,
                payload.PageProtection,
                payload.PreservationDecision,
                payload.State,
                payload.VolumeSerialHex,
                payload.FileIdHex,
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
        var rebuilt = new List<WritableSectionEvidence>();
        var kernelSequences = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank writable-section journal record.");

            WritableSectionLine line;
            try
            {
                line = JsonSerializer.Deserialize<WritableSectionLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid writable-section journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid writable-section journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                line.KernelSequence == 0 ||
                line.CreateRequestSequence == 0 ||
                !kernelSequences.Add(line.KernelSequence) ||
                !Enum.IsDefined(line.State) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid writable-section journal fields.");

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Writable-section journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Writable-section journal record hash mismatch.");

            var full = NormalizePath(line.TrackedPath);
            DurableFileIdentity? identity = string.IsNullOrEmpty(line.VolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.VolumeSerialHex, line.FileIdHex);
            if (identity is not null) ValidateIdentity(identity);

            rebuilt.Add(line.ToEvidence() with { TrackedPath = full });
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

    private void AppendLine(WritableSectionLine line)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(WritableSectionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Writable-section path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid writable-section durable file identity.");
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);
    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Writable-section evidence store must not be a reparse point: " + path);
    }
}

public static class WritableSectionAttestation
{
    public const uint SnapshotCommitted = 1;
    public const uint BaselineCommitted = 2;
    public const uint NoPreservationRequired = 3;

    public static WritableSectionAttestationState Evaluate(
        CreateOperationIntent? intent,
        string trackedPath,
        uint preservationDecision)
    {
        if (intent is null)
            return WritableSectionAttestationState.MissingCreateIntent;

        var full = Path.GetFullPath(trackedPath);
        if (!intent.OriginalPath.Equals(full, StringComparison.OrdinalIgnoreCase))
            return WritableSectionAttestationState.PathMismatch;

        return intent.PreservationAction switch
        {
            CreatePreservationAction.CaptureExistingPreimage when preservationDecision == SnapshotCommitted
                => WritableSectionAttestationState.BaselineVerified,
            CreatePreservationAction.RecordOriginallyAbsent when preservationDecision == BaselineCommitted
                => WritableSectionAttestationState.BaselineVerified,
            CreatePreservationAction.NoPreservationRequired when preservationDecision == NoPreservationRequired
                => WritableSectionAttestationState.Unprotected,
            _ => WritableSectionAttestationState.DecisionMismatch
        };
    }
}

public enum WritableSectionAttestationState
{
    BaselineVerified = 1,
    Unprotected = 2,
    MissingCreateIntent = 3,
    DecisionMismatch = 4,
    PathMismatch = 5
}

public sealed record WritableSectionEvidence(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    ulong CreateRequestSequence,
    string TrackedPath,
    uint PageProtection,
    uint PreservationDecision,
    WritableSectionAttestationState State,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public DurableFileIdentity? Identity =>
        string.IsNullOrEmpty(VolumeSerialHex)
            ? null
            : new DurableFileIdentity(VolumeSerialHex, FileIdHex);
}

internal sealed record WritableSectionPayload(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    ulong CreateRequestSequence,
    string TrackedPath,
    uint PageProtection,
    uint PreservationDecision,
    WritableSectionAttestationState State,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256);

internal sealed record WritableSectionLine(
    long Sequence,
    DateTime ObservedUtc,
    ulong KernelSequence,
    ulong CreateRequestSequence,
    string TrackedPath,
    uint PageProtection,
    uint PreservationDecision,
    WritableSectionAttestationState State,
    string VolumeSerialHex,
    string FileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public WritableSectionPayload Payload => new(
        Sequence, ObservedUtc, KernelSequence, CreateRequestSequence, TrackedPath,
        PageProtection, PreservationDecision, State, VolumeSerialHex, FileIdHex,
        PreviousRecordSha256);

    public WritableSectionEvidence ToEvidence() => new(
        Sequence, ObservedUtc, KernelSequence, CreateRequestSequence, TrackedPath,
        PageProtection, PreservationDecision, State, VolumeSerialHex, FileIdHex,
        PreviousRecordSha256, RecordSha256);
}
