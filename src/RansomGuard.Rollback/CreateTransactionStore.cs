using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable two-phase record for CREATE-class operations that can create, replace or delete-on-close.
/// The intent is committed only after required preservation state exists; completion is recorded later
/// from the minifilter post-operation result. Missing completion always means pending/unknown.
/// </summary>
public sealed class CreateTransactionStore
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
        get { lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<CreateOperationCompletion> Completions
    {
        get { lock (_intents) return _completions.Values.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<CreateOperationIntent> PendingIntents
    {
        get
        {
            lock (_intents)
                return _intents.Where(x => !_completions.ContainsKey(x.RequestSequence))
                    .OrderBy(x => x.Sequence).ToArray();
        }
    }

    public CreateTransactionStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Create transaction root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _intentJournal = Path.Combine(_root, "create-operation-journal.jsonl");
        _completionJournal = Path.Combine(_root, "create-operation-completion-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateIntents();
        LoadAndValidateCompletions();
    }

    public async Task<CreateOperationIntent> CaptureIntentAsync(
        ulong requestSequence,
        string requestedPath,
        CreateDisposition disposition,
        uint createOptions,
        uint desiredAccess,
        CreateTargetState targetState,
        bool originallyAbsent,
        CreatePreservationAction preservationAction,
        DurableFileIdentity? currentIdentity,
        string preservationRecordSha256,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        var full = NormalizePath(requestedPath);
        ValidateIntentFields(disposition, targetState, originallyAbsent, preservationAction,
            currentIdentity, preservationRecordSha256);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                if (_intents.Any(x => x.RequestSequence == requestSequence))
                    throw new InvalidDataException("Duplicate CREATE request sequence.");
            }

            var sequence = checked(++_nextIntentSequence);
            var payload = new CreateOperationIntentPayload(
                sequence, DateTime.UtcNow, requestSequence, full, disposition, createOptions, desiredAccess,
                targetState, originallyAbsent, preservationAction,
                currentIdentity?.VolumeSerialHex ?? string.Empty,
                currentIdentity?.FileIdHex ?? string.Empty,
                preservationRecordSha256, _lastIntentHash);
            var hash = HashIntent(payload);
            var line = new CreateOperationIntentLine(
                payload.Sequence, payload.CapturedUtc, payload.RequestSequence, payload.RequestedPath,
                payload.Disposition, payload.CreateOptions, payload.DesiredAccess, payload.TargetState,
                payload.OriginallyAbsent, payload.PreservationAction, payload.CurrentVolumeSerialHex,
                payload.CurrentFileIdHex, payload.PreservationRecordSha256, payload.PreviousRecordSha256, hash);

            AppendLine(_intentJournal, line);
            _lastIntentHash = hash;
            var intent = line.ToIntent();
            lock (_intents) _intents.Add(intent);
            return intent;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGetIntent(ulong requestSequence, out CreateOperationIntent? intent)
    {
        lock (_intents)
        {
            intent = _intents.SingleOrDefault(x => x.RequestSequence == requestSequence);
            return intent is not null;
        }
    }

    public async Task<CreateOperationCompletion> RecordCompletionAsync(
        ulong requestSequence,
        CreateCompletionState state,
        uint completionStatus,
        ulong completionInformation,
        string? finalPath,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        var normalizedFinalPath = ValidateAndNormalizeCompletion(state, completionStatus, finalPath);

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
                        existing.FinalPath.Equals(normalizedFinalPath, StringComparison.OrdinalIgnoreCase))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate CREATE completion.");
                }
            }

            var sequence = checked(++_nextCompletionSequence);
            var payload = new CreateOperationCompletionPayload(
                sequence, DateTime.UtcNow, requestSequence, state, completionStatus,
                completionInformation, normalizedFinalPath, intent.RecordSha256, _lastCompletionHash);
            var hash = HashCompletion(payload);
            var line = new CreateOperationCompletionLine(
                payload.Sequence, payload.CompletedUtc, payload.RequestSequence, payload.State,
                payload.CompletionStatus, payload.CompletionInformation, payload.FinalPath,
                payload.IntentRecordSha256, payload.PreviousRecordSha256, hash);

            AppendLine(_completionJournal, line);
            _lastCompletionHash = hash;
            var completion = line.ToCompletion();
            lock (_intents) _completions.Add(requestSequence, completion);
            return completion;
        }
        finally
        {
            _appendGate.Release();
        }
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
        var requests = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_intentJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank CREATE operation intent record.");

            CreateOperationIntentLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateOperationIntentLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid CREATE operation intent record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid CREATE operation intent JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("CREATE operation intent sequence gap.");
            if (line.RequestSequence == 0 || !requests.Add(line.RequestSequence))
                throw new InvalidDataException("CREATE operation request sequence is invalid or duplicated.");
            if (!IsHash(line.PreviousRecordSha256) || !IsHash(line.RecordSha256))
                throw new InvalidDataException("Invalid CREATE operation intent hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE operation intent hash chain mismatch.");
            if (!HashIntent(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE operation intent record hash mismatch.");

            var full = NormalizePath(line.RequestedPath);
            DurableFileIdentity? identity = string.IsNullOrEmpty(line.CurrentVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.CurrentVolumeSerialHex, line.CurrentFileIdHex);
            ValidateIntentFields(line.Disposition, line.TargetState, line.OriginallyAbsent,
                line.PreservationAction, identity, line.PreservationRecordSha256);

            rebuilt.Add(line.ToIntent() with { RequestedPath = full });
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
                throw new InvalidDataException("Blank CREATE completion record.");

            CreateOperationCompletionLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateOperationCompletionLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid CREATE completion record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid CREATE completion JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("CREATE completion sequence gap.");
            if (!intentByRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("CREATE completion references a missing intent.");
            if (!IsHash(line.IntentRecordSha256) ||
                !line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion intent hash mismatch.");
            if (!IsHash(line.PreviousRecordSha256) || !IsHash(line.RecordSha256))
                throw new InvalidDataException("Invalid CREATE completion hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion hash chain mismatch.");
            if (!HashCompletion(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE completion record hash mismatch.");

            _ = ValidateAndNormalizeCompletion(line.State, line.CompletionStatus, line.FinalPath);
            if (!rebuilt.TryAdd(line.RequestSequence, line.ToCompletion()))
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
        CreateDisposition disposition,
        CreateTargetState targetState,
        bool originallyAbsent,
        CreatePreservationAction preservationAction,
        DurableFileIdentity? identity,
        string preservationRecordSha256)
    {
        if (!Enum.IsDefined(disposition) || !Enum.IsDefined(targetState) || !Enum.IsDefined(preservationAction))
            throw new InvalidDataException("Invalid CREATE operation intent enum value.");
        if (preservationAction == CreatePreservationAction.DenyUnsupported)
            throw new InvalidDataException("Denied CREATE operations must not be journaled as allowed intents.");

        if (targetState == CreateTargetState.File)
        {
            if (identity is null) throw new InvalidDataException("Existing CREATE target requires a durable identity.");
            ValidateIdentity(identity);
        }
        else if (identity is not null)
        {
            throw new InvalidDataException("Missing/directory CREATE target must not carry a file identity.");
        }

        if (preservationAction == CreatePreservationAction.CaptureExistingPreimage)
        {
            if (targetState != CreateTargetState.File || originallyAbsent || !IsHash(preservationRecordSha256))
                throw new InvalidDataException("Existing-file CREATE pre-image intent is inconsistent.");
        }
        else if (preservationAction == CreatePreservationAction.RecordOriginallyAbsent)
        {
            if (!originallyAbsent || !IsHash(preservationRecordSha256))
                throw new InvalidDataException("Originally-absent CREATE intent is missing its durable baseline.");
        }
        else if (!string.IsNullOrEmpty(preservationRecordSha256))
        {
            throw new InvalidDataException("No-preservation CREATE intent must not claim a preservation hash.");
        }
    }

    private static string ValidateAndNormalizeCompletion(
        CreateCompletionState state,
        uint completionStatus,
        string? finalPath)
    {
        switch (state)
        {
            case CreateCompletionState.Succeeded:
                if (!NtSuccess(completionStatus) || string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Invalid successful CREATE completion.");
                return NormalizePath(finalPath);

            case CreateCompletionState.SucceededNameUnresolved:
                if (!NtSuccess(completionStatus) || !string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Invalid unresolved CREATE completion.");
                return string.Empty;

            case CreateCompletionState.Failed:
                if (NtSuccess(completionStatus) || !string.IsNullOrWhiteSpace(finalPath))
                    throw new InvalidDataException("Invalid failed CREATE completion.");
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

    private string HashIntent(CreateOperationIntentPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private string HashCompletion(CreateOperationCompletionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("CREATE path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (identity.VolumeSerialHex.Length != 16 || !identity.VolumeSerialHex.All(char.IsAsciiHexDigit) ||
            identity.FileIdHex.Length != 32 || !identity.FileIdHex.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("Invalid CREATE target durable identity.");
    }

    private static bool IsHash(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("CREATE transaction store must not be a reparse point: " + path);
    }
}

public enum CreateCompletionState
{
    Succeeded = 1,
    SucceededNameUnresolved = 2,
    Failed = 3
}

public sealed record CreateOperationIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string RequestedPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState TargetState,
    bool OriginallyAbsent,
    CreatePreservationAction PreservationAction,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreservationRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? CurrentIdentity =>
        string.IsNullOrEmpty(CurrentVolumeSerialHex)
            ? null
            : new DurableFileIdentity(CurrentVolumeSerialHex, CurrentFileIdHex);
}

public sealed record CreateOperationCompletion(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record CreateOperationIntentPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string RequestedPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState TargetState,
    bool OriginallyAbsent,
    CreatePreservationAction PreservationAction,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreservationRecordSha256,
    string PreviousRecordSha256);

internal sealed record CreateOperationIntentLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string RequestedPath,
    CreateDisposition Disposition,
    uint CreateOptions,
    uint DesiredAccess,
    CreateTargetState TargetState,
    bool OriginallyAbsent,
    CreatePreservationAction PreservationAction,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreservationRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateOperationIntentPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, RequestedPath, Disposition, CreateOptions, DesiredAccess,
        TargetState, OriginallyAbsent, PreservationAction, CurrentVolumeSerialHex, CurrentFileIdHex,
        PreservationRecordSha256, PreviousRecordSha256);

    public CreateOperationIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, RequestedPath, Disposition, CreateOptions, DesiredAccess,
        TargetState, OriginallyAbsent, PreservationAction, CurrentVolumeSerialHex, CurrentFileIdHex,
        PreservationRecordSha256, PreviousRecordSha256, RecordSha256);
}

internal sealed record CreateOperationCompletionPayload(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string IntentRecordSha256,
    string PreviousRecordSha256);

internal sealed record CreateOperationCompletionLine(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    CreateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalPath,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateOperationCompletionPayload Payload => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalPath, IntentRecordSha256, PreviousRecordSha256);

    public CreateOperationCompletion ToCompletion() => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalPath, IntentRecordSha256, PreviousRecordSha256, RecordSha256);
}
