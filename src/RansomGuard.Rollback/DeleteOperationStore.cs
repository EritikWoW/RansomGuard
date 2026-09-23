using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable DELETE lifecycle:
/// intent -> authoritative disposition result -> cleanup/restart finalization evidence.
/// A successful FileDispositionInformation request is never treated as proof that the path
/// has already disappeared.
/// </summary>
public sealed class DeleteOperationStore
{
    public const uint FileDispositionInformation = 13;
    public const uint FileDispositionInformationEx = 64;
    public const uint FileDispositionDelete = 0x00000001;

    private readonly string _root;
    private readonly string _intentJournal;
    private readonly string _completionJournal;
    private readonly string _finalizationJournal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<DeleteOperationIntent> _intents = new();
    private readonly Dictionary<ulong, DeleteDispositionCompletion> _completions = new();
    private readonly List<DeleteFinalizationObservation> _finalizations = new();
    private long _nextIntentSequence;
    private long _nextCompletionSequence;
    private long _nextFinalizationSequence;
    private string _lastIntentHash = new('0', 64);
    private string _lastCompletionHash = new('0', 64);
    private string _lastFinalizationHash = new('0', 64);

    public string Root => _root;
    public string IntentJournalPath => _intentJournal;
    public string CompletionJournalPath => _completionJournal;
    public string FinalizationJournalPath => _finalizationJournal;

    public IReadOnlyList<DeleteOperationIntent> Intents
    {
        get { lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<DeleteDispositionCompletion> Completions
    {
        get { lock (_intents) return _completions.Values.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<DeleteFinalizationObservation> Finalizations
    {
        get { lock (_intents) return _finalizations.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<DeleteOperationIntent> PendingIntents
    {
        get
        {
            lock (_intents)
                return _intents.Where(x => !_completions.ContainsKey(x.RequestSequence))
                    .OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<DeleteOperationIntent> UnsettledIntents
    {
        get
        {
            lock (_intents)
            {
                return _intents.Where(IsUnsettledUnsafe)
                    .OrderBy(x => x.Sequence).ToArray();
            }
        }
    }

    public DeleteOperationStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Delete operation root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _intentJournal = Path.Combine(_root, "delete-intent-journal.jsonl");
        _completionJournal = Path.Combine(_root, "delete-completion-journal.jsonl");
        _finalizationJournal = Path.Combine(_root, "delete-finalization-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateIntents();
        LoadAndValidateCompletions();
        LoadAndValidateFinalizations();
    }

    public async Task<DeleteOperationIntent> RecordIntentAsync(
        ulong requestSequence,
        string originalPath,
        uint fileInformationClass,
        uint dispositionFlags,
        DurableFileIdentity originalIdentity,
        bool sourceOriginallyAbsent,
        string preservationRecordSha256,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        if (fileInformationClass is not (FileDispositionInformation or FileDispositionInformationEx))
            throw new InvalidDataException("Unsupported DELETE disposition information class.");

        var full = NormalizePath(originalPath);
        var requestDelete = (dispositionFlags & FileDispositionDelete) != 0;
        ValidateIntentFields(requestDelete, originalIdentity, sourceOriginallyAbsent, preservationRecordSha256);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                if (_intents.Any(x => x.RequestSequence == requestSequence))
                    throw new InvalidDataException("Duplicate DELETE request sequence.");
            }

            var sequence = checked(++_nextIntentSequence);
            var payload = new DeleteIntentPayload(
                sequence, DateTime.UtcNow, requestSequence, full, fileInformationClass,
                dispositionFlags, requestDelete,
                originalIdentity.VolumeSerialHex, originalIdentity.FileIdHex,
                sourceOriginallyAbsent, preservationRecordSha256, _lastIntentHash);
            var recordHash = Hash(payload);
            var line = new DeleteIntentLine(
                payload.Sequence, payload.CapturedUtc, payload.RequestSequence, payload.OriginalPath,
                payload.FileInformationClass, payload.DispositionFlags, payload.RequestDelete,
                payload.OriginalVolumeSerialHex, payload.OriginalFileIdHex,
                payload.SourceOriginallyAbsent, payload.PreservationRecordSha256,
                payload.PreviousRecordSha256, recordHash);

            AppendLine(_intentJournal, line);
            _lastIntentHash = recordHash;
            var intent = line.ToIntent();
            lock (_intents) _intents.Add(intent);
            return intent;
        }
        finally { _appendGate.Release(); }
    }

    public async Task<DeleteDispositionCompletion> RecordCompletionAsync(
        ulong requestSequence,
        DeleteDispositionCompletionState state,
        uint completionStatus,
        ulong completionInformation,
        bool? deletePending,
        DurableFileIdentity? finalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DeleteOperationIntent intent;
            lock (_intents)
            {
                intent = _intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
                    ?? throw new InvalidDataException("DELETE completion does not reference a committed intent.");
                ValidateCompletionFields(intent, state, completionStatus, deletePending, finalIdentity);

                if (_completions.TryGetValue(requestSequence, out var existing))
                {
                    if (existing.State == state &&
                        existing.CompletionStatus == completionStatus &&
                        existing.CompletionInformation == completionInformation &&
                        existing.DeletePending == deletePending &&
                        object.Equals(existing.FinalIdentity, finalIdentity))
                        return existing;
                    throw new InvalidDataException("Conflicting duplicate DELETE completion.");
                }
            }

            var sequence = checked(++_nextCompletionSequence);
            var payload = new DeleteCompletionPayload(
                sequence, DateTime.UtcNow, requestSequence, state, completionStatus,
                completionInformation, deletePending,
                finalIdentity?.VolumeSerialHex ?? string.Empty,
                finalIdentity?.FileIdHex ?? string.Empty,
                intent.RecordSha256, _lastCompletionHash);
            var recordHash = Hash(payload);
            var line = new DeleteCompletionLine(
                payload.Sequence, payload.CompletedUtc, payload.RequestSequence, payload.State,
                payload.CompletionStatus, payload.CompletionInformation, payload.DeletePending,
                payload.FinalVolumeSerialHex, payload.FinalFileIdHex,
                payload.IntentRecordSha256, payload.PreviousRecordSha256, recordHash);

            AppendLine(_completionJournal, line);
            _lastCompletionHash = recordHash;
            var completion = line.ToCompletion();
            lock (_intents) _completions.Add(requestSequence, completion);
            return completion;
        }
        finally { _appendGate.Release(); }
    }

    public async Task<DeleteFinalizationObservation> RecordFinalizationAsync(
        DeleteOperationIntent intent,
        DeleteFinalizationSource source,
        DeleteFinalizationState state,
        RestartPathState pathState,
        DurableFileIdentity? currentIdentity,
        CancellationToken cancellationToken = default)
    {
        if (intent.RequestSequence == 0 || !IsSha256(intent.RecordSha256))
            throw new InvalidDataException("DELETE finalization requires a committed intent.");

        DeleteOperationIntent committedIntent;
        lock (_intents)
        {
            committedIntent = _intents.SingleOrDefault(x => x.RequestSequence == intent.RequestSequence)
                ?? throw new InvalidDataException("DELETE finalization references a missing intent.");
        }

        if (!committedIntent.RecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
            !committedIntent.OriginalPath.Equals(
                NormalizePath(intent.OriginalPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("DELETE finalization intent binding mismatch.");

        ValidateFinalizationFields(committedIntent, source, state, pathState, currentIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                var duplicate = _finalizations.LastOrDefault(x =>
                    x.RequestSequence == committedIntent.RequestSequence &&
                    x.IntentRecordSha256.Equals(committedIntent.RecordSha256, StringComparison.OrdinalIgnoreCase) &&
                    x.Source == source &&
                    x.State == state &&
                    x.PathState == pathState &&
                    object.Equals(x.CurrentIdentity, currentIdentity));
                if (duplicate is not null) return duplicate;
            }

            var sequence = checked(++_nextFinalizationSequence);
            var payload = new DeleteFinalizationPayload(
                sequence, DateTime.UtcNow, committedIntent.RequestSequence,
                committedIntent.RecordSha256, source, state, committedIntent.OriginalPath,
                pathState,
                currentIdentity?.VolumeSerialHex ?? string.Empty,
                currentIdentity?.FileIdHex ?? string.Empty,
                _lastFinalizationHash);
            var recordHash = Hash(payload);
            var line = new DeleteFinalizationLine(
                payload.Sequence, payload.ObservedUtc, payload.RequestSequence,
                payload.IntentRecordSha256, payload.Source, payload.State, payload.OriginalPath,
                payload.PathState, payload.CurrentVolumeSerialHex, payload.CurrentFileIdHex,
                payload.PreviousRecordSha256, recordHash);

            AppendLine(_finalizationJournal, line);
            _lastFinalizationHash = recordHash;
            var observation = line.ToObservation();
            lock (_intents) _finalizations.Add(observation);
            return observation;
        }
        finally { _appendGate.Release(); }
    }

    public bool TryGetCompletion(ulong requestSequence, out DeleteDispositionCompletion? completion)
    {
        lock (_intents) return _completions.TryGetValue(requestSequence, out completion);
    }

    public DeleteFinalizationAssessment AssessFinalization(DeleteOperationIntent intent)
    {
        DeleteOperationIntent committedIntent;
        DeleteFinalizationObservation[] matches;
        lock (_intents)
        {
            committedIntent = _intents.SingleOrDefault(x => x.RequestSequence == intent.RequestSequence)
                ?? throw new InvalidDataException("DELETE finalization assessment references a missing intent.");
            if (!committedIntent.RecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
                !committedIntent.OriginalPath.Equals(
                    NormalizePath(intent.OriginalPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DELETE finalization assessment intent binding mismatch.");

            matches = _finalizations.Where(x =>
                    x.RequestSequence == committedIntent.RequestSequence &&
                    x.IntentRecordSha256.Equals(
                        committedIntent.RecordSha256, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => x.Sequence).ToArray();
        }

        if (matches.Length == 0)
            return new DeleteFinalizationAssessment(
                DeleteFinalizationAssessmentState.NoEvidence, 0, string.Empty);

        if (matches.Any(x => x.State == DeleteFinalizationState.Ambiguous))
            return new DeleteFinalizationAssessment(
                DeleteFinalizationAssessmentState.Unresolved, matches.Length, matches[^1].RecordSha256);

        var last = matches[^1];
        if (last.State == DeleteFinalizationState.Cancelled)
            return new DeleteFinalizationAssessment(
                DeleteFinalizationAssessmentState.ConsistentCancelled, matches.Length, last.RecordSha256);

        var topologyStates = matches
            .Where(x => x.State != DeleteFinalizationState.Cancelled)
            .Select(x => x.State)
            .Distinct()
            .ToArray();
        if (topologyStates.Length != 1)
            return new DeleteFinalizationAssessment(
                DeleteFinalizationAssessmentState.Unresolved, matches.Length, last.RecordSha256);

        return new DeleteFinalizationAssessment(
            topologyStates[0] == DeleteFinalizationState.DeletedObserved
                ? DeleteFinalizationAssessmentState.ConsistentDeletedObserved
                : DeleteFinalizationAssessmentState.ConsistentStillPresent,
            matches.Length,
            last.RecordSha256);
    }

    public static DeleteFinalizationState ClassifyPathObservation(
        DeleteOperationIntent intent,
        RestartPathState pathState,
        DurableFileIdentity? currentIdentity)
    {
        if (!intent.RequestDelete)
            return DeleteFinalizationState.Ambiguous;

        if (pathState == RestartPathState.Missing)
            return DeleteFinalizationState.DeletedObserved;

        if (pathState == RestartPathState.File &&
            currentIdentity is not null &&
            currentIdentity.Equals(intent.OriginalIdentity))
            return DeleteFinalizationState.StillPresentSameIdentity;

        return DeleteFinalizationState.Ambiguous;
    }

    public void VerifyAll()
    {
        LoadAndValidateIntents(rebuildState: false);
        LoadAndValidateCompletions(rebuildState: false);
        LoadAndValidateFinalizations(rebuildState: false);
    }

    private bool IsUnsettledUnsafe(DeleteOperationIntent intent)
    {
        if (!_completions.TryGetValue(intent.RequestSequence, out var completion))
            return true;
        if (completion.State == DeleteDispositionCompletionState.Failed)
            return false;
        if (!intent.RequestDelete)
            return false;

        var matches = _finalizations.Where(x =>
                x.RequestSequence == intent.RequestSequence &&
                x.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Sequence).ToArray();
        if (matches.Length == 0)
            return true;

        var last = matches[^1].State;
        return last == DeleteFinalizationState.Ambiguous;
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
        var rebuilt = new List<DeleteOperationIntent>();
        var requests = new HashSet<ulong>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_intentJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank DELETE intent journal record.");
            var line = Deserialize<DeleteIntentLine>(raw, "DELETE intent");
            if (line.Sequence != expected || line.RequestSequence == 0 || !requests.Add(line.RequestSequence))
                throw new InvalidDataException("DELETE intent sequence/request correlation is invalid.");
            if (!IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DELETE intent hash chain mismatch.");
            if (line.FileInformationClass is not (FileDispositionInformation or FileDispositionInformationEx) ||
                line.RequestDelete != ((line.DispositionFlags & FileDispositionDelete) != 0))
                throw new InvalidDataException("DELETE intent disposition metadata mismatch.");

            var identity = new DurableFileIdentity(line.OriginalVolumeSerialHex, line.OriginalFileIdHex);
            ValidateIntentFields(line.RequestDelete, identity, line.SourceOriginallyAbsent,
                line.PreservationRecordSha256);
            rebuilt.Add(line.ToIntent() with { OriginalPath = NormalizePath(line.OriginalPath) });
            previous = line.RecordSha256;
            expected++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _intents.Clear();
                _intents.AddRange(rebuilt);
            }
            _nextIntentSequence = expected - 1;
            _lastIntentHash = previous;
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
        DeleteOperationIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var byRequest = intents.ToDictionary(x => x.RequestSequence);
        var rebuilt = new Dictionary<ulong, DeleteDispositionCompletion>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_completionJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank DELETE completion journal record.");
            var line = Deserialize<DeleteCompletionLine>(raw, "DELETE completion");
            if (line.Sequence != expected || !byRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("DELETE completion sequence/request correlation is invalid.");
            if (!line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
                !IsSha256(line.IntentRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DELETE completion hash chain mismatch.");

            DurableFileIdentity? identity = string.IsNullOrEmpty(line.FinalVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.FinalVolumeSerialHex, line.FinalFileIdHex);
            ValidateCompletionFields(intent, line.State, line.CompletionStatus, line.DeletePending, identity);
            if (!rebuilt.TryAdd(line.RequestSequence, line.ToCompletion()))
                throw new InvalidDataException("Duplicate DELETE completion.");
            previous = line.RecordSha256;
            expected++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _completions.Clear();
                foreach (var pair in rebuilt) _completions[pair.Key] = pair.Value;
            }
            _nextCompletionSequence = expected - 1;
            _lastCompletionHash = previous;
        }
    }

    private void LoadAndValidateFinalizations(bool rebuildState = true)
    {
        if (!File.Exists(_finalizationJournal))
        {
            if (rebuildState)
            {
                lock (_intents) _finalizations.Clear();
                _nextFinalizationSequence = 0;
                _lastFinalizationHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_finalizationJournal);
        DeleteOperationIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var byRequest = intents.ToDictionary(x => x.RequestSequence);
        var rebuilt = new List<DeleteFinalizationObservation>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_finalizationJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank DELETE finalization journal record.");
            var line = Deserialize<DeleteFinalizationLine>(raw, "DELETE finalization");
            if (line.Sequence != expected || !byRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("DELETE finalization sequence/request correlation is invalid.");
            if (!line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
                !IsSha256(line.IntentRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DELETE finalization hash chain mismatch.");

            var normalizedPath = NormalizePath(line.OriginalPath);
            if (!normalizedPath.Equals(intent.OriginalPath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DELETE finalization path does not match its committed intent.");
            DurableFileIdentity? identity = string.IsNullOrEmpty(line.CurrentVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.CurrentVolumeSerialHex, line.CurrentFileIdHex);
            ValidateFinalizationFields(intent, line.Source, line.State, line.PathState, identity);
            rebuilt.Add(line.ToObservation() with { OriginalPath = normalizedPath });
            previous = line.RecordSha256;
            expected++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _finalizations.Clear();
                _finalizations.AddRange(rebuilt);
            }
            _nextFinalizationSequence = expected - 1;
            _lastFinalizationHash = previous;
        }
    }

    private static void ValidateIntentFields(
        bool requestDelete,
        DurableFileIdentity identity,
        bool sourceOriginallyAbsent,
        string preservationRecordSha256)
    {
        ValidateIdentity(identity);

        if (!requestDelete)
        {
            if (!string.IsNullOrEmpty(preservationRecordSha256))
                throw new InvalidDataException("DELETE-clear intent must not claim a preservation pre-image.");
            return;
        }

        if (sourceOriginallyAbsent)
        {
            if (!string.IsNullOrEmpty(preservationRecordSha256))
                throw new InvalidDataException("Incident-created DELETE intent must not claim a pre-incident pre-image.");
        }
        else if (!IsSha256(preservationRecordSha256))
        {
            throw new InvalidDataException("Pre-existing DELETE intent requires committed full-preimage proof.");
        }
    }

    private static void ValidateCompletionFields(
        DeleteOperationIntent intent,
        DeleteDispositionCompletionState state,
        uint status,
        bool? deletePending,
        DurableFileIdentity? identity)
    {
        if (!Enum.IsDefined(state))
            throw new InvalidDataException("Unknown DELETE completion state.");

        if (state == DeleteDispositionCompletionState.Failed)
        {
            if (NtSuccess(status) || deletePending is not null || identity is not null)
                throw new InvalidDataException("Failed DELETE completion must not claim post-operation state.");
            return;
        }

        if (!NtSuccess(status))
            throw new InvalidDataException("Successful DELETE completion requires successful NTSTATUS.");

        if (identity is not null)
        {
            ValidateIdentity(identity);
            if (!identity.Equals(intent.OriginalIdentity))
                throw new InvalidDataException("DELETE post-operation identity differs from the committed intent.");
        }

        switch (state)
        {
            case DeleteDispositionCompletionState.AcceptedDeletePending:
                if (!intent.RequestDelete || deletePending != true || identity is null)
                    throw new InvalidDataException("DeletePending completion requires a delete request, true state and identity.");
                break;
            case DeleteDispositionCompletionState.AcceptedDeleteNotPending:
                if (deletePending != false)
                    throw new InvalidDataException("Delete-not-pending completion requires explicit false state.");
                break;
            case DeleteDispositionCompletionState.AcceptedStateUnresolved:
                if (deletePending is not null)
                    throw new InvalidDataException("Unresolved DELETE completion must not claim DeletePending.");
                break;
            default:
                throw new InvalidDataException("Unsupported DELETE completion state.");
        }
    }

    private static void ValidateFinalizationFields(
        DeleteOperationIntent intent,
        DeleteFinalizationSource source,
        DeleteFinalizationState state,
        RestartPathState pathState,
        DurableFileIdentity? identity)
    {
        if (!Enum.IsDefined(source) || !Enum.IsDefined(state) || !Enum.IsDefined(pathState))
            throw new InvalidDataException("Invalid DELETE finalization enum state.");

        if (state == DeleteFinalizationState.Cancelled)
        {
            if (source != DeleteFinalizationSource.DispositionCancellation ||
                pathState != RestartPathState.QueryFailed || identity is not null)
                throw new InvalidDataException("DELETE cancellation finalization has invalid fields.");
            return;
        }

        if (!intent.RequestDelete || source == DeleteFinalizationSource.DispositionCancellation)
            throw new InvalidDataException("DELETE topology finalization requires an actual delete request.");

        if (pathState == RestartPathState.File)
        {
            ValidateIdentity(identity
                ?? throw new InvalidDataException("DELETE file finalization requires identity."));
        }
        else if (identity is not null)
        {
            throw new InvalidDataException("Non-file DELETE finalization must not claim identity.");
        }

        var expected = ClassifyPathObservation(intent, pathState, identity);
        if (expected != state)
            throw new InvalidDataException("DELETE finalization state does not match the conservative classifier.");
    }

    private T Deserialize<T>(string raw, string label) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(raw, _json)
                ?? throw new InvalidDataException($"Invalid {label} journal record.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Invalid {label} journal JSON.", ex);
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

    private string Hash<T>(T payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("DELETE path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (identity.VolumeSerialHex.Length != 16 || identity.FileIdHex.Length != 32 ||
            !identity.VolumeSerialHex.All(char.IsAsciiHexDigit) ||
            !identity.FileIdHex.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("Invalid durable identity in DELETE reconciliation.");
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("DELETE transaction store must not be a reparse point: " + path);
    }
}

public enum DeleteDispositionCompletionState
{
    Failed = 1,
    AcceptedDeletePending = 2,
    AcceptedDeleteNotPending = 3,
    AcceptedStateUnresolved = 4
}

public enum DeleteFinalizationSource
{
    KernelCleanup = 1,
    RestartProbe = 2,
    DispositionCancellation = 3
}

public enum DeleteFinalizationState
{
    DeletedObserved = 1,
    StillPresentSameIdentity = 2,
    Cancelled = 3,
    Ambiguous = 4
}

public enum DeleteFinalizationAssessmentState
{
    NoEvidence = 0,
    ConsistentDeletedObserved = 1,
    ConsistentStillPresent = 2,
    ConsistentCancelled = 3,
    Unresolved = 4
}

public sealed record DeleteFinalizationAssessment(
    DeleteFinalizationAssessmentState State,
    int ObservationCount,
    string LatestRecordSha256);

public sealed record DeleteOperationIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    uint DispositionFlags,
    bool RequestDelete,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    bool SourceOriginallyAbsent,
    string PreservationRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity OriginalIdentity => new(OriginalVolumeSerialHex, OriginalFileIdHex);
}

public sealed record DeleteDispositionCompletion(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    DeleteDispositionCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    bool? DeletePending,
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

public sealed record DeleteFinalizationObservation(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    DeleteFinalizationSource Source,
    DeleteFinalizationState State,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? CurrentIdentity =>
        string.IsNullOrEmpty(CurrentVolumeSerialHex)
            ? null
            : new DurableFileIdentity(CurrentVolumeSerialHex, CurrentFileIdHex);
}

internal sealed record DeleteIntentPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    uint DispositionFlags,
    bool RequestDelete,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    bool SourceOriginallyAbsent,
    string PreservationRecordSha256,
    string PreviousRecordSha256);

internal sealed record DeleteIntentLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    uint DispositionFlags,
    bool RequestDelete,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    bool SourceOriginallyAbsent,
    string PreservationRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DeleteIntentPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FileInformationClass,
        DispositionFlags, RequestDelete, OriginalVolumeSerialHex, OriginalFileIdHex,
        SourceOriginallyAbsent, PreservationRecordSha256, PreviousRecordSha256);

    public DeleteOperationIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FileInformationClass,
        DispositionFlags, RequestDelete, OriginalVolumeSerialHex, OriginalFileIdHex,
        SourceOriginallyAbsent, PreservationRecordSha256, PreviousRecordSha256, RecordSha256);
}

internal sealed record DeleteCompletionPayload(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    DeleteDispositionCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    bool? DeletePending,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256);

internal sealed record DeleteCompletionLine(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    DeleteDispositionCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    bool? DeletePending,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DeleteCompletionPayload Payload => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus, CompletionInformation,
        DeletePending, FinalVolumeSerialHex, FinalFileIdHex, IntentRecordSha256,
        PreviousRecordSha256);

    public DeleteDispositionCompletion ToCompletion() => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus, CompletionInformation,
        DeletePending, FinalVolumeSerialHex, FinalFileIdHex, IntentRecordSha256,
        PreviousRecordSha256, RecordSha256);
}

internal sealed record DeleteFinalizationPayload(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    DeleteFinalizationSource Source,
    DeleteFinalizationState State,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreviousRecordSha256);

internal sealed record DeleteFinalizationLine(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    DeleteFinalizationSource Source,
    DeleteFinalizationState State,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DeleteFinalizationPayload Payload => new(
        Sequence, ObservedUtc, RequestSequence, IntentRecordSha256, Source, State,
        OriginalPath, PathState, CurrentVolumeSerialHex, CurrentFileIdHex,
        PreviousRecordSha256);

    public DeleteFinalizationObservation ToObservation() => new(
        Sequence, ObservedUtc, RequestSequence, IntentRecordSha256, Source, State,
        OriginalPath, PathState, CurrentVolumeSerialHex, CurrentFileIdHex,
        PreviousRecordSha256, RecordSha256);
}
