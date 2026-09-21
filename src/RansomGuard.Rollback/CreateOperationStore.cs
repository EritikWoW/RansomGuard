using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable correlation for gated IRP_MJ_CREATE operations. The intent journal proves which
/// preservation decision was committed before CREATE was allowed; the completion journal records
/// the later filesystem outcome, tunneled final name and post-create kernel file identity.
/// </summary>
public sealed class CreateOperationStore
{
    private readonly string _root;
    private readonly string _intentJournal;
    private readonly string _completionJournal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<CreateOperationIntent> _intents = new();
    private readonly Dictionary<ulong, CreateOperationCompletion> _completions = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextIntentSequence;
    private string _lastIntentHash = new('0', 64);
    private long _nextCompletionSequence;
    private string _lastCompletionHash = new('0', 64);

    public string Root => _root;
    public string IntentJournalPath => _intentJournal;
    public string CompletionJournalPath => _completionJournal;

    public IReadOnlyList<CreateOperationIntent> Intents
    {
        get
        {
            lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<CreateOperationCompletion> Completions
    {
        get
        {
            lock (_intents) return _completions.Values.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<CreateOperationIntent> PendingIntents
    {
        get
        {
            lock (_intents)
                return _intents
                    .Where(x => !_completions.ContainsKey(x.RequestSequence))
                    .OrderBy(x => x.Sequence)
                    .ToArray();
        }
    }

    public CreateOperationStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Create operation root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _intentJournal = Path.Combine(_root, "create-intent-journal.jsonl");
        _completionJournal = Path.Combine(_root, "create-completion-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateIntents();
        LoadAndValidateCompletions();
    }

    public async Task<CreateOperationIntent> RecordIntentAsync(
        ulong requestSequence,
        string originalPath,
        CreateDisposition disposition,
        uint createOptions,
        uint desiredAccess,
        CreateTargetState observedTargetState,
        CreatePreservationAction preservationAction,
        string preservationRecordSha256,
        DurableFileIdentity? originalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        if (preservationAction == CreatePreservationAction.DenyUnsupported)
            throw new InvalidDataException("Denied CREATE operations must not be recorded as allowed intents.");

        var full = NormalizePath(originalPath);
        ValidateIntentFields(observedTargetState, preservationAction, preservationRecordSha256, originalIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                if (_intents.Any(x => x.RequestSequence == requestSequence))
                    throw new InvalidDataException("Duplicate CREATE request sequence.");
            }

            var sequence = checked(++_nextIntentSequence);
            var payload = new CreateIntentPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                full,
                disposition,
                createOptions,
                desiredAccess,
                observedTargetState,
                preservationAction,
                preservationRecordSha256,
                originalIdentity?.VolumeSerialHex ?? string.Empty,
                originalIdentity?.FileIdHex ?? string.Empty,
                _lastIntentHash);
            var recordHash = HashIntentPayload(payload);
            var line = new CreateIntentLine(
                payload.Sequence,
                payload.CapturedUtc,
                payload.RequestSequence,
                payload.OriginalPath,
                payload.Disposition,
                payload.CreateOptions,
                payload.DesiredAccess,
                payload.ObservedTargetState,
                payload.PreservationAction,
                payload.PreservationRecordSha256,
                payload.OriginalVolumeSerialHex,
                payload.OriginalFileIdHex,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(_intentJournal, line);
            _lastIntentHash = recordHash;
            var intent = line.ToIntent();
            lock (_intents) _intents.Add(intent);
            return intent;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public async Task<CreateOperationCompletion> RecordCompletionAsync(
        ulong requestSequence,
        CreateCompletionState state,
        uint completionStatus,
        ulong completionInformation,
        string? finalPath,
        DurableFileIdentity? finalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        var normalizedFinalPath = NormalizeCompletion(state, completionStatus, finalPath, finalIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CreateOperationIntent intent;
            lock (_intents)
            {
                intent = _intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
                    ?? throw new InvalidDataException("CREATE completion does not reference a committed intent.");

                if (_completions.TryGetValue(requestSequence, out var existing))
                {
                    if (existing.State == state &&
                        existing.CompletionStatus == completionStatus &&
                        existing.CompletionInformation == completionInformation &&
                        existing.FinalPath.Equals(normalizedFinalPath, StringComparison.OrdinalIgnoreCase) &&
                        Nullable.Equals(existing.FinalIdentity, finalIdentity))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate CREATE completion.");
                }
            }

            var sequence = checked(++_nextCompletionSequence);
            var payload = new CreateCompletionPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                state,
                completionStatus,
                completionInformation,
                normalizedFinalPath,
                finalIdentity?.VolumeSerialHex ?? string.Empty,
                finalIdentity?.FileIdHex ?? string.Empty,
                intent.RecordSha256,
                _lastCompletionHash);
            var recordHash = HashCompletionPayload(payload);
            var line = new CreateCompletionLine(
                payload.Sequence,
                payload.CompletedUtc,
                payload.RequestSequence,
                payload.State,
                payload.CompletionStatus,
                payload.CompletionInformation,
                payload.FinalPath,
                payload.FinalVolumeSerialHex,
                payload.FinalFileIdHex,
                payload.IntentRecordSha256,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(_completionJournal, line);
            _lastCompletionHash = recordHash;
            var completion = line.ToCompletion();
            lock (_intents) _completions.Add(requestSequence, completion);
            return completion;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGetCompletion(ulong requestSequence, out CreateOperationCompletion? completion)
    {
        lock (_intents) return _completions.TryGetValue(requestSequence, out completion);
    }

    public void VerifyAll()
    {
        LoadAndValidateIntents(rebuildState: false);
        LoadAndValidateCompletions(rebuildState: false);
    }

    private void LoadAndValidateIntents(bool rebuildState = true)
    {
        if (!File.Exists(_intentJournal))
        {
            if (rebuildState)
            {
                lock (_intents) _intents.Clear();
                _nextIntentSequence = 0;
                _lastIntentHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_intentJournal);
        var rebuilt = new List<CreateOperationIntent>();
        var requestSequences = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_intentJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank CREATE intent journal record.");

            CreateIntentLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateIntentLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid CREATE intent journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid CREATE intent journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("CREATE intent journal sequence gap.");
            if (line.RequestSequence == 0 || !requestSequences.Add(line.RequestSequence))
                throw new InvalidDataException("CREATE intent request sequence is invalid or duplicated.");
            if (!Enum.IsDefined(line.Disposition) || !Enum.IsDefined(line.ObservedTargetState) ||
                !Enum.IsDefined(line.PreservationAction) ||
                line.PreservationAction == CreatePreservationAction.DenyUnsupported)
                throw new InvalidDataException("Invalid CREATE intent enum fields.");
            if (!IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid CREATE intent hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE intent journal hash chain mismatch.");
            if (!HashIntentPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE intent journal record hash mismatch.");

            var full = NormalizePath(line.OriginalPath);
            DurableFileIdentity? originalIdentity = string.IsNullOrEmpty(line.OriginalVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.OriginalVolumeSerialHex, line.OriginalFileIdHex);
            ValidateIntentFields(
                line.ObservedTargetState,
                line.PreservationAction,
                line.PreservationRecordSha256,
                originalIdentity);

            rebuilt.Add(line.ToIntent() with { OriginalPath = full });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _intents.Clear();
                _intents.AddRange(rebuilt);
            }
            _nextIntentSequence = expectedSequence - 1;
            _lastIntentHash = expectedPrevious;
        }
    }

    private void LoadAndValidateCompletions(bool rebuildState = true)
    {
        if (!File.Exists(_completionJournal))
        {
            if (rebuildState)
            {
                lock (_intents) _completions.Clear();
                _nextCompletionSequence = 0;
                _lastCompletionHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_completionJournal);

        CreateOperationIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var intentByRequest = intents.ToDictionary(x => x.RequestSequence);

        var rebuilt = new Dictionary<ulong, CreateOperationCompletion>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_completionJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank CREATE completion journal record.");

            CreateCompletionLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateCompletionLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid CREATE completion journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid CREATE completion journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("CREATE completion journal sequence gap.");
            if (!intentByRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("CREATE completion references a missing intent.");
            if (!IsSha256(line.IntentRecordSha256) ||
                !line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion intent hash mismatch.");
            if (!IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid CREATE completion hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion journal hash chain mismatch.");
            if (!HashCompletionPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion journal record hash mismatch.");

            DurableFileIdentity? finalIdentity = string.IsNullOrEmpty(line.FinalVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.FinalVolumeSerialHex, line.FinalFileIdHex);
            var normalized = NormalizeCompletion(
                line.State,
                line.CompletionStatus,
                line.FinalPath,
                finalIdentity);
            var completion = line.ToCompletion() with { FinalPath = normalized };
            if (!rebuilt.TryAdd(line.RequestSequence, completion))
                throw new InvalidDataException("Duplicate CREATE completion for request sequence.");

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _completions.Clear();
                foreach (var pair in rebuilt) _completions[pair.Key] = pair.Value;
            }
            _nextCompletionSequence = expectedSequence - 1;
            _lastCompletionHash = expectedPrevious;
        }
    }

    private static void ValidateIntentFields(
        CreateTargetState targetState,
        CreatePreservationAction preservationAction,
        string preservationRecordSha256,
        DurableFileIdentity? originalIdentity)
    {
        if (!Enum.IsDefined(targetState) || !Enum.IsDefined(preservationAction))
            throw new InvalidDataException("Invalid CREATE intent state.");

        switch (preservationAction)
        {
            case CreatePreservationAction.CaptureExistingPreimage:
                if (targetState != CreateTargetState.File)
                    throw new InvalidDataException("Existing-file CREATE preservation requires a file target.");
                if (!IsSha256(preservationRecordSha256))
                    throw new InvalidDataException("Existing-file CREATE preservation requires a committed pre-image hash.");
                ValidateIdentity(originalIdentity
                    ?? throw new InvalidDataException("Existing-file CREATE preservation requires original identity."));
                break;

            case CreatePreservationAction.RecordOriginallyAbsent:
                if (!IsSha256(preservationRecordSha256))
                    throw new InvalidDataException("Originally-absent CREATE preservation requires a baseline record hash.");
                if (originalIdentity is not null)
                    throw new InvalidDataException("Originally-absent CREATE preservation must not claim original identity.");
                break;

            case CreatePreservationAction.NoPreservationRequired:
                if (!string.IsNullOrEmpty(preservationRecordSha256) || originalIdentity is not null)
                    throw new InvalidDataException("No-preservation CREATE intent must not claim preservation proof or identity.");
                break;

            default:
                throw new InvalidDataException("Unsupported CREATE preservation action in committed intent.");
        }
    }

    private static string NormalizeCompletion(
        CreateCompletionState state,
        uint completionStatus,
        string? finalPath,
        DurableFileIdentity? finalIdentity)
    {
        switch (state)
        {
            case CreateCompletionState.Succeeded:
                if (!NtSuccess(completionStatus) || finalIdentity is null)
                    throw new InvalidDataException("Authoritative CREATE success requires successful NTSTATUS and durable identity.");
                ValidateIdentity(finalIdentity);
                return NormalizePath(finalPath
                    ?? throw new InvalidDataException("Authoritative CREATE success requires final path."));

            case CreateCompletionState.SucceededNameUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is null || !string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Name-unresolved CREATE success requires identity and no final path.");
                ValidateIdentity(finalIdentity);
                return string.Empty;

            case CreateCompletionState.SucceededIdentityUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is not null)
                    throw new InvalidDataException("Identity-unresolved CREATE success must not claim durable identity.");
                return NormalizePath(finalPath
                    ?? throw new InvalidDataException("Identity-unresolved CREATE success requires final path."));

            case CreateCompletionState.SucceededNameAndIdentityUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is not null || !string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Fully unresolved CREATE success must not claim name or identity.");
                return string.Empty;

            case CreateCompletionState.Failed:
                if (NtSuccess(completionStatus) || finalIdentity is not null || !string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Failed CREATE completion must not claim final name or identity.");
                return string.Empty;

            default:
                throw new InvalidDataException("Unknown CREATE completion state.");
        }
    }

    private void AppendLine<T>(string path, T line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashIntentPayload(CreateIntentPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private string HashCompletionPayload(CreateCompletionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("CREATE path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (identity.VolumeSerialHex.Length != 16 || identity.FileIdHex.Length != 32 ||
            !identity.VolumeSerialHex.All(char.IsAsciiHexDigit) ||
            !identity.FileIdHex.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("Invalid durable file identity in CREATE reconciliation.");
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("CREATE operation store must not be a reparse point: " + path);
    }
}

public enum CreateCompletionState
{
    Succeeded = 1,
    SucceededNameUnresolved = 2,
    SucceededIdentityUnresolved = 3,
    SucceededNameAndIdentityUnresolved = 4,
    Failed = 5
}

public sealed record CreateOperationIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState ObservedTargetState,
    CreatePreservationAction PreservationAction,
    string PreservationRecordSha256,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? OriginalIdentity =>
        string.IsNullOrEmpty(OriginalVolumeSerialHex)
            ? null
            : new DurableFileIdentity(OriginalVolumeSerialHex, OriginalFileIdHex);
}

public sealed record CreateOperationCompletion(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? FinalIdentity =>
        string.IsNullOrEmpty(FinalVolumeSerialHex)
            ? null
            : new DurableFileIdentity(FinalVolumeSerialHex, FinalFileIdHex);
}

internal sealed record CreateIntentPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState ObservedTargetState,
    CreatePreservationAction PreservationAction,
    string PreservationRecordSha256,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    string PreviousRecordSha256);

internal sealed record CreateIntentLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState ObservedTargetState,
    CreatePreservationAction PreservationAction,
    string PreservationRecordSha256,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateIntentPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, Disposition,
        CreateOptions, DesiredAccess, ObservedTargetState, PreservationAction,
        PreservationRecordSha256, OriginalVolumeSerialHex, OriginalFileIdHex,
        PreviousRecordSha256);

    public CreateOperationIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, Disposition,
        CreateOptions, DesiredAccess, ObservedTargetState, PreservationAction,
        PreservationRecordSha256, OriginalVolumeSerialHex, OriginalFileIdHex,
        PreviousRecordSha256, RecordSha256);
}

internal sealed record CreateCompletionPayload(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256);

internal sealed record CreateCompletionLine(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateCompletionPayload Payload => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalPath, FinalVolumeSerialHex, FinalFileIdHex,
        IntentRecordSha256, PreviousRecordSha256);

    public CreateOperationCompletion ToCompletion() => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalPath, FinalVolumeSerialHex, FinalFileIdHex,
        IntentRecordSha256, PreviousRecordSha256, RecordSha256);
}
