using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable post-rename kernel identity reconciliation. This is intentionally separate from the
/// v0.7.5 rename completion journal so older sessions remain readable without rewriting their hashes.
/// A resolved identity is authoritative only when it matches the source FILE_ID_INFO committed in
/// the pre-operation rename intent.
/// </summary>
public sealed class RenameIdentityStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly RenameRollbackStore _renameStore;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly Dictionary<ulong, RenameIdentityReconciliation> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;

    public IReadOnlyList<RenameIdentityReconciliation> Records
    {
        get
        {
            lock (_records) return _records.Values.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<RenameRollbackCompletion> PendingSuccessfulCompletions
    {
        get
        {
            lock (_records)
                return _renameStore.Completions
                    .Where(x => x.State != RenameCompletionState.Failed &&
                                !_records.ContainsKey(x.RequestSequence))
                    .OrderBy(x => x.Sequence)
                    .ToArray();
        }
    }

    public RenameIdentityStore(string root, RenameRollbackStore renameStore)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Rename identity root is required.", nameof(root));

        _renameStore = renameStore ?? throw new ArgumentNullException(nameof(renameStore));
        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "rename-identity-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<RenameIdentityReconciliation> RecordAsync(
        ulong requestSequence,
        RenameIdentityState state,
        DurableFileIdentity? finalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        var intent = FindIntent(requestSequence);
        if (!_renameStore.TryGetCompletion(requestSequence, out var completion) || completion is null)
            throw new InvalidDataException("Rename identity reconciliation requires a committed completion.");
        if (completion.State == RenameCompletionState.Failed)
            throw new InvalidDataException("Failed rename completion must not claim post-operation file identity.");

        ValidateState(state, finalIdentity, intent.SourceIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                if (_records.TryGetValue(requestSequence, out var existing))
                {
                    if (existing.State == state && Nullable.Equals(existing.FinalIdentity, finalIdentity) &&
                        existing.CompletionRecordSha256.Equals(completion.RecordSha256, StringComparison.OrdinalIgnoreCase))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate rename identity reconciliation.");
                }
            }

            var sequence = checked(++_nextSequence);
            var payload = new RenameIdentityPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                state,
                finalIdentity?.VolumeSerialHex ?? string.Empty,
                finalIdentity?.FileIdHex ?? string.Empty,
                completion.RecordSha256,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new RenameIdentityLine(
                payload.Sequence,
                payload.ReconciledUtc,
                payload.RequestSequence,
                payload.State,
                payload.FinalVolumeSerialHex,
                payload.FinalFileIdHex,
                payload.CompletionRecordSha256,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(line);
            _lastRecordHash = recordHash;
            var record = line.ToRecord();
            lock (_records) _records.Add(requestSequence, record);
            return record;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGet(ulong requestSequence, out RenameIdentityReconciliation? record)
    {
        lock (_records) return _records.TryGetValue(requestSequence, out record);
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
        var rebuilt = new Dictionary<ulong, RenameIdentityReconciliation>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rename identity journal record.");

            RenameIdentityLine line;
            try
            {
                line = JsonSerializer.Deserialize<RenameIdentityLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rename identity journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rename identity journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Rename identity journal sequence gap.");
            if (line.RequestSequence == 0)
                throw new InvalidDataException("Rename identity request sequence is invalid.");
            if (!IsSha256(line.CompletionRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid rename identity journal hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename identity journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename identity journal record hash mismatch.");

            var intent = FindIntent(line.RequestSequence);
            if (!_renameStore.TryGetCompletion(line.RequestSequence, out var completion) || completion is null)
                throw new InvalidDataException("Rename identity journal references a missing completion.");
            if (completion.State == RenameCompletionState.Failed)
                throw new InvalidDataException("Failed rename completion has an identity reconciliation record.");
            if (!line.CompletionRecordSha256.Equals(completion.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename identity completion hash mismatch.");

            DurableFileIdentity? identity = string.IsNullOrEmpty(line.FinalVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.FinalVolumeSerialHex, line.FinalFileIdHex);
            ValidateState(line.State, identity, intent.SourceIdentity);

            if (!rebuilt.TryAdd(line.RequestSequence, line.ToRecord()))
                throw new InvalidDataException("Duplicate rename identity reconciliation.");

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_records)
            {
                _records.Clear();
                foreach (var pair in rebuilt) _records[pair.Key] = pair.Value;
            }
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private RenameRollbackIntent FindIntent(ulong requestSequence) =>
        _renameStore.Intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
        ?? throw new InvalidDataException("Rename identity reconciliation references a missing intent.");

    private static void ValidateState(
        RenameIdentityState state,
        DurableFileIdentity? finalIdentity,
        DurableFileIdentity sourceIdentity)
    {
        switch (state)
        {
            case RenameIdentityState.Resolved:
                ValidateIdentity(finalIdentity
                    ?? throw new InvalidDataException("Resolved rename identity requires FILE_ID_INFO."));
                if (!finalIdentity.Equals(sourceIdentity))
                    throw new InvalidDataException("Resolved rename identity does not match source intent identity.");
                break;

            case RenameIdentityState.QueryFailed:
                if (finalIdentity is not null)
                    throw new InvalidDataException("Query-failed rename identity must not claim FILE_ID_INFO.");
                break;

            case RenameIdentityState.Mismatch:
                ValidateIdentity(finalIdentity
                    ?? throw new InvalidDataException("Mismatched rename identity requires observed FILE_ID_INFO."));
                if (finalIdentity.Equals(sourceIdentity))
                    throw new InvalidDataException("Mismatched rename identity unexpectedly equals source identity.");
                break;

            default:
                throw new InvalidDataException("Unknown rename identity reconciliation state.");
        }
    }

    private void AppendLine(RenameIdentityLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(RenameIdentityPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid durable identity in rename reconciliation.");
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);

    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rename identity store must not be a reparse point: " + path);
    }
}

public enum RenameIdentityState
{
    Resolved = 1,
    QueryFailed = 2,
    Mismatch = 3
}

public sealed record RenameIdentityReconciliation(
    long Sequence,
    DateTime ReconciledUtc,
    ulong RequestSequence,
    RenameIdentityState State,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string CompletionRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? FinalIdentity =>
        string.IsNullOrEmpty(FinalVolumeSerialHex)
            ? null
            : new DurableFileIdentity(FinalVolumeSerialHex, FinalFileIdHex);
}

internal sealed record RenameIdentityPayload(
    long Sequence,
    DateTime ReconciledUtc,
    ulong RequestSequence,
    RenameIdentityState State,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string CompletionRecordSha256,
    string PreviousRecordSha256);

internal sealed record RenameIdentityLine(
    long Sequence,
    DateTime ReconciledUtc,
    ulong RequestSequence,
    RenameIdentityState State,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string CompletionRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RenameIdentityPayload Payload => new(
        Sequence, ReconciledUtc, RequestSequence, State,
        FinalVolumeSerialHex, FinalFileIdHex,
        CompletionRecordSha256, PreviousRecordSha256);

    public RenameIdentityReconciliation ToRecord() => new(
        Sequence, ReconciledUtc, RequestSequence, State,
        FinalVolumeSerialHex, FinalFileIdHex,
        CompletionRecordSha256, PreviousRecordSha256, RecordSha256);
}
