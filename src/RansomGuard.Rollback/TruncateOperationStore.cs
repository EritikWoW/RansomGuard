using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable two-phase state for destructive IRP_MJ_SET_INFORMATION length mutations.
/// The intent is committed only after preservation/identity proof and before the kernel operation
/// is allowed. The completion journal records the later authoritative post-operation result.
/// Restart observations never manufacture a completion record.
/// </summary>
public sealed class TruncateOperationStore
{
    public const uint FileAllocationInformation = 19;
    public const uint FileEndOfFileInformation = 20;
    public const uint FileValidDataLengthInformation = 39;

    private readonly string _root;
    private readonly string _intentJournal;
    private readonly string _completionJournal;
    private readonly string _restartJournal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<TruncateOperationIntent> _intents = new();
    private readonly Dictionary<ulong, TruncateOperationCompletion> _completions = new();
    private readonly List<TruncateRestartObservation> _restart = new();
    private long _nextIntentSequence;
    private long _nextCompletionSequence;
    private long _nextRestartSequence;
    private string _lastIntentHash = new('0', 64);
    private string _lastCompletionHash = new('0', 64);
    private string _lastRestartHash = new('0', 64);

    public string Root => _root;
    public string IntentJournalPath => _intentJournal;
    public string CompletionJournalPath => _completionJournal;
    public string RestartJournalPath => _restartJournal;

    public IReadOnlyList<TruncateOperationIntent> Intents
    {
        get { lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<TruncateOperationCompletion> Completions
    {
        get { lock (_intents) return _completions.Values.OrderBy(x => x.Sequence).ToArray(); }
    }

    public IReadOnlyList<TruncateOperationIntent> PendingIntents
    {
        get
        {
            lock (_intents)
                return _intents.Where(x => !_completions.ContainsKey(x.RequestSequence))
                    .OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<TruncateRestartObservation> RestartObservations
    {
        get { lock (_intents) return _restart.OrderBy(x => x.Sequence).ToArray(); }
    }

    public TruncateOperationStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Truncate operation root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _intentJournal = Path.Combine(_root, "truncate-intent-journal.jsonl");
        _completionJournal = Path.Combine(_root, "truncate-completion-journal.jsonl");
        _restartJournal = Path.Combine(_root, "truncate-restart-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateIntents();
        LoadAndValidateCompletions();
        LoadAndValidateRestart();
    }

    public async Task<TruncateOperationIntent> RecordIntentAsync(
        ulong requestSequence,
        string originalPath,
        uint fileInformationClass,
        long requestedLength,
        long originalObservedLength,
        DurableFileIdentity originalIdentity,
        bool sourceOriginallyAbsent,
        string preservationRecordSha256,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        var full = NormalizePath(originalPath);
        var metric = MetricFor(fileInformationClass);
        ValidateIntentFields(metric, requestedLength, originalObservedLength, originalIdentity,
            sourceOriginallyAbsent, preservationRecordSha256);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                if (_intents.Any(x => x.RequestSequence == requestSequence))
                    throw new InvalidDataException("Duplicate TRUNCATE request sequence.");
            }

            var sequence = checked(++_nextIntentSequence);
            var payload = new TruncateIntentPayload(
                sequence, DateTime.UtcNow, requestSequence, full, fileInformationClass, metric,
                requestedLength, originalObservedLength,
                originalIdentity.VolumeSerialHex, originalIdentity.FileIdHex,
                sourceOriginallyAbsent, preservationRecordSha256, _lastIntentHash);
            var recordHash = Hash(payload);
            var line = new TruncateIntentLine(
                payload.Sequence, payload.CapturedUtc, payload.RequestSequence, payload.OriginalPath,
                payload.FileInformationClass, payload.Metric, payload.RequestedLength,
                payload.OriginalObservedLength, payload.OriginalVolumeSerialHex,
                payload.OriginalFileIdHex, payload.SourceOriginallyAbsent,
                payload.PreservationRecordSha256, payload.PreviousRecordSha256, recordHash);

            AppendLine(_intentJournal, line);
            _lastIntentHash = recordHash;
            var intent = line.ToIntent();
            lock (_intents) _intents.Add(intent);
            return intent;
        }
        finally { _appendGate.Release(); }
    }

    public async Task<TruncateOperationCompletion> RecordCompletionAsync(
        ulong requestSequence,
        TruncateCompletionState state,
        uint completionStatus,
        ulong completionInformation,
        long observedLength,
        DurableFileIdentity? finalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TruncateOperationIntent intent;
            lock (_intents)
            {
                intent = _intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
                    ?? throw new InvalidDataException("TRUNCATE completion does not reference a committed intent.");

                ValidateCompletionFields(intent, state, completionStatus, observedLength, finalIdentity);

                if (_completions.TryGetValue(requestSequence, out var existing))
                {
                    if (existing.State == state &&
                        existing.CompletionStatus == completionStatus &&
                        existing.CompletionInformation == completionInformation &&
                        existing.ObservedLength == observedLength &&
                        object.Equals(existing.FinalIdentity, finalIdentity))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate TRUNCATE completion.");
                }
            }

            var sequence = checked(++_nextCompletionSequence);
            var payload = new TruncateCompletionPayload(
                sequence, DateTime.UtcNow, requestSequence, state, completionStatus,
                completionInformation, observedLength,
                finalIdentity?.VolumeSerialHex ?? string.Empty,
                finalIdentity?.FileIdHex ?? string.Empty,
                intent.RecordSha256, _lastCompletionHash);
            var recordHash = Hash(payload);
            var line = new TruncateCompletionLine(
                payload.Sequence, payload.CompletedUtc, payload.RequestSequence, payload.State,
                payload.CompletionStatus, payload.CompletionInformation, payload.ObservedLength,
                payload.FinalVolumeSerialHex, payload.FinalFileIdHex, payload.IntentRecordSha256,
                payload.PreviousRecordSha256, recordHash);

            AppendLine(_completionJournal, line);
            _lastCompletionHash = recordHash;
            var completion = line.ToCompletion();
            lock (_intents) _completions.Add(requestSequence, completion);
            return completion;
        }
        finally { _appendGate.Release(); }
    }

    public bool TryGetCompletion(ulong requestSequence, out TruncateOperationCompletion? completion)
    {
        lock (_intents) return _completions.TryGetValue(requestSequence, out completion);
    }

    public async Task<TruncateRestartObservation> RecordRestartObservationAsync(
        TruncateOperationIntent intent,
        RestartEvidenceState evidence,
        RestartPathState pathState,
        DurableFileIdentity? currentIdentity,
        long observedLength,
        CancellationToken cancellationToken = default)
    {
        if (intent.RequestSequence == 0 || !IsSha256(intent.RecordSha256))
            throw new InvalidDataException("TRUNCATE restart observation requires a committed intent.");

        TruncateOperationIntent committedIntent;
        lock (_intents)
        {
            committedIntent = _intents.SingleOrDefault(x => x.RequestSequence == intent.RequestSequence)
                ?? throw new InvalidDataException("TRUNCATE restart observation references a missing intent.");
        }

        if (!committedIntent.RecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
            !committedIntent.OriginalPath.Equals(
                NormalizePath(intent.OriginalPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("TRUNCATE restart observation intent binding mismatch.");

        ValidateRestartFields(committedIntent, evidence, pathState, currentIdentity, observedLength);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                var duplicate = _restart.LastOrDefault(x =>
                    x.RequestSequence == committedIntent.RequestSequence &&
                    x.IntentRecordSha256.Equals(committedIntent.RecordSha256, StringComparison.OrdinalIgnoreCase) &&
                    x.Evidence == evidence &&
                    x.PathState == pathState &&
                    object.Equals(x.CurrentIdentity, currentIdentity) &&
                    x.ObservedLength == observedLength);
                if (duplicate is not null) return duplicate;
            }

            var sequence = checked(++_nextRestartSequence);
            var payload = new TruncateRestartPayload(
                sequence, DateTime.UtcNow, committedIntent.RequestSequence, committedIntent.RecordSha256,
                evidence, committedIntent.OriginalPath, pathState,
                currentIdentity?.VolumeSerialHex ?? string.Empty,
                currentIdentity?.FileIdHex ?? string.Empty,
                observedLength, _lastRestartHash);
            var recordHash = Hash(payload);
            var line = new TruncateRestartLine(
                payload.Sequence, payload.ObservedUtc, payload.RequestSequence,
                payload.IntentRecordSha256, payload.Evidence, payload.OriginalPath,
                payload.PathState, payload.CurrentVolumeSerialHex, payload.CurrentFileIdHex,
                payload.ObservedLength, payload.PreviousRecordSha256, recordHash);

            AppendLine(_restartJournal, line);
            _lastRestartHash = recordHash;
            var observation = line.ToObservation();
            lock (_intents) _restart.Add(observation);
            return observation;
        }
        finally { _appendGate.Release(); }
    }

    public RestartEvidenceAssessment AssessRestart(TruncateOperationIntent intent)
    {
        TruncateRestartObservation[] matches;
        lock (_intents)
        {
            matches = _restart.Where(x =>
                    x.RequestSequence == committedIntent.RequestSequence &&
                    x.IntentRecordSha256.Equals(committedIntent.RecordSha256, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => x.Sequence).ToArray();
        }

        if (matches.Length == 0)
            return new RestartEvidenceAssessment(RestartEvidenceAssessmentState.NoEvidence, 0, string.Empty);

        if (matches.Any(x => x.Evidence is not
                (RestartEvidenceState.SupportsCompleted or RestartEvidenceState.SupportsNotCompleted)))
            return new RestartEvidenceAssessment(
                RestartEvidenceAssessmentState.Unresolved, matches.Length, matches[^1].RecordSha256);

        var first = matches[0];
        if (matches.Any(x =>
                x.Evidence != first.Evidence ||
                x.PathState != first.PathState ||
                !object.Equals(x.CurrentIdentity, first.CurrentIdentity) ||
                x.ObservedLength != first.ObservedLength))
            return new RestartEvidenceAssessment(
                RestartEvidenceAssessmentState.Unresolved, matches.Length, matches[^1].RecordSha256);

        return new RestartEvidenceAssessment(
            first.Evidence == RestartEvidenceState.SupportsCompleted
                ? RestartEvidenceAssessmentState.ConsistentSupportsCompleted
                : RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted,
            matches.Length,
            matches[^1].RecordSha256);
    }

    public static RestartEvidenceState ClassifyRestart(
        TruncateOperationIntent intent,
        RestartPathState pathState,
        DurableFileIdentity? currentIdentity,
        long observedLength)
    {
        if (pathState is RestartPathState.QueryFailed or RestartPathState.ReparsePoint or
            RestartPathState.Directory or RestartPathState.Missing)
            return RestartEvidenceState.Ambiguous;

        if (pathState != RestartPathState.File ||
            currentIdentity is null ||
            !currentIdentity.Equals(intent.OriginalIdentity))
            return RestartEvidenceState.Ambiguous;

        // EOF is the only length class whose post-restart value is exact and queryable without
        // guessing. Allocation size may be filesystem/cluster rounded, and valid-data length has
        // no symmetric FILE_STANDARD_INFO restart query, so lost completion remains indeterminate.
        if (intent.Metric != TruncateMetric.EndOfFile || observedLength < 0)
            return RestartEvidenceState.Indeterminate;

        if (intent.RequestedLength == intent.OriginalObservedLength)
            return RestartEvidenceState.Indeterminate;

        if (observedLength == intent.RequestedLength)
            return RestartEvidenceState.SupportsCompleted;

        if (observedLength == intent.OriginalObservedLength)
            return RestartEvidenceState.SupportsNotCompleted;

        return RestartEvidenceState.Ambiguous;
    }

    public void VerifyAll()
    {
        LoadAndValidateIntents(rebuildState: false);
        LoadAndValidateCompletions(rebuildState: false);
        LoadAndValidateRestart(rebuildState: false);
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
        var rebuilt = new List<TruncateOperationIntent>();
        var requests = new HashSet<ulong>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_intentJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank TRUNCATE intent journal record.");
            var line = Deserialize<TruncateIntentLine>(raw, "TRUNCATE intent");
            if (line.Sequence != expected || line.RequestSequence == 0 || !requests.Add(line.RequestSequence))
                throw new InvalidDataException("TRUNCATE intent sequence/request correlation is invalid.");
            if (!IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("TRUNCATE intent hash chain mismatch.");

            var metric = MetricFor(line.FileInformationClass);
            if (metric != line.Metric)
                throw new InvalidDataException("TRUNCATE intent information-class/metric mismatch.");
            var identity = new DurableFileIdentity(line.OriginalVolumeSerialHex, line.OriginalFileIdHex);
            ValidateIntentFields(metric, line.RequestedLength, line.OriginalObservedLength, identity,
                line.SourceOriginallyAbsent, line.PreservationRecordSha256);
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
        TruncateOperationIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var byRequest = intents.ToDictionary(x => x.RequestSequence);
        var rebuilt = new Dictionary<ulong, TruncateOperationCompletion>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_completionJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank TRUNCATE completion journal record.");
            var line = Deserialize<TruncateCompletionLine>(raw, "TRUNCATE completion");
            if (line.Sequence != expected || !byRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("TRUNCATE completion sequence/request correlation is invalid.");
            if (!line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
                !IsSha256(line.IntentRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("TRUNCATE completion hash chain mismatch.");

            DurableFileIdentity? identity = string.IsNullOrEmpty(line.FinalVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.FinalVolumeSerialHex, line.FinalFileIdHex);
            ValidateCompletionFields(intent, line.State, line.CompletionStatus, line.ObservedLength, identity);
            if (!rebuilt.TryAdd(line.RequestSequence, line.ToCompletion()))
                throw new InvalidDataException("Duplicate TRUNCATE completion.");
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

    private void LoadAndValidateRestart(bool rebuildState = true)
    {
        if (!File.Exists(_restartJournal))
        {
            if (rebuildState)
            {
                lock (_intents) _restart.Clear();
                _nextRestartSequence = 0;
                _lastRestartHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_restartJournal);
        TruncateOperationIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var byRequest = intents.ToDictionary(x => x.RequestSequence);
        var rebuilt = new List<TruncateRestartObservation>();
        var previous = new string('0', 64);
        long expected = 1;

        foreach (var raw in File.ReadLines(_restartJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank TRUNCATE restart journal record.");
            var line = Deserialize<TruncateRestartLine>(raw, "TRUNCATE restart");
            if (line.Sequence != expected || !byRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("TRUNCATE restart sequence/request correlation is invalid.");
            if (!line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase) ||
                !IsSha256(line.IntentRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256) ||
                !line.PreviousRecordSha256.Equals(previous, StringComparison.OrdinalIgnoreCase) ||
                !Hash(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("TRUNCATE restart hash chain mismatch.");

            var normalizedPath = NormalizePath(line.OriginalPath);
            if (!normalizedPath.Equals(intent.OriginalPath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("TRUNCATE restart observation path does not match its committed intent.");

            DurableFileIdentity? identity = string.IsNullOrEmpty(line.CurrentVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.CurrentVolumeSerialHex, line.CurrentFileIdHex);
            ValidateRestartFields(intent, line.Evidence, line.PathState, identity, line.ObservedLength);
            rebuilt.Add(line.ToObservation() with { OriginalPath = normalizedPath });
            previous = line.RecordSha256;
            expected++;
        }

        if (rebuildState)
        {
            lock (_intents)
            {
                _restart.Clear();
                _restart.AddRange(rebuilt);
            }
            _nextRestartSequence = expected - 1;
            _lastRestartHash = previous;
        }
    }

    private static TruncateMetric MetricFor(uint informationClass) => informationClass switch
    {
        FileEndOfFileInformation => TruncateMetric.EndOfFile,
        FileAllocationInformation => TruncateMetric.AllocationSize,
        FileValidDataLengthInformation => TruncateMetric.ValidDataLength,
        _ => throw new InvalidDataException($"Unsupported TRUNCATE information class {informationClass}.")
    };

    private static void ValidateIntentFields(
        TruncateMetric metric,
        long requestedLength,
        long originalObservedLength,
        DurableFileIdentity identity,
        bool sourceOriginallyAbsent,
        string preservationRecordSha256)
    {
        if (!Enum.IsDefined(metric) || requestedLength < 0)
            throw new InvalidDataException("Invalid TRUNCATE intent length/metric.");
        ValidateIdentity(identity);

        if (metric == TruncateMetric.ValidDataLength)
        {
            if (originalObservedLength != -1)
                throw new InvalidDataException("Valid-data-length intent must keep original metric unresolved.");
        }
        else if (originalObservedLength < 0)
        {
            throw new InvalidDataException("EOF/allocation TRUNCATE intent requires original observed length.");
        }

        if (sourceOriginallyAbsent)
        {
            if (!string.IsNullOrEmpty(preservationRecordSha256))
                throw new InvalidDataException("Incident-created TRUNCATE intent must not claim a pre-incident pre-image.");
        }
        else if (!IsSha256(preservationRecordSha256))
        {
            throw new InvalidDataException("Pre-existing TRUNCATE intent requires committed full-preimage proof.");
        }
    }

    private static void ValidateCompletionFields(
        TruncateOperationIntent intent,
        TruncateCompletionState state,
        uint status,
        long observedLength,
        DurableFileIdentity? identity)
    {
        if (!Enum.IsDefined(state))
            throw new InvalidDataException("Unknown TRUNCATE completion state.");

        if (state == TruncateCompletionState.Failed)
        {
            if (NtSuccess(status) || observedLength != -1 || identity is not null)
                throw new InvalidDataException("Failed TRUNCATE completion must not claim post-operation state.");
            return;
        }

        if (!NtSuccess(status))
            throw new InvalidDataException("Successful TRUNCATE completion requires successful NTSTATUS.");

        var metricResolved = state is TruncateCompletionState.Succeeded or
            TruncateCompletionState.SucceededIdentityUnresolved;
        var identityResolved = state is TruncateCompletionState.Succeeded or
            TruncateCompletionState.SucceededMetricUnresolved;

        if (metricResolved)
        {
            if (observedLength < 0)
                throw new InvalidDataException("Resolved TRUNCATE completion metric must be nonnegative.");
        }
        else if (observedLength != -1)
        {
            throw new InvalidDataException("Unresolved TRUNCATE completion metric must be -1.");
        }

        if (identityResolved)
        {
            ValidateIdentity(identity
                ?? throw new InvalidDataException("Resolved TRUNCATE completion requires identity."));
            if (!identity.Equals(intent.OriginalIdentity))
                throw new InvalidDataException("TRUNCATE post-operation identity differs from the committed intent.");
        }
        else if (identity is not null)
        {
            throw new InvalidDataException("Identity-unresolved TRUNCATE completion must not claim identity.");
        }

        if (intent.Metric == TruncateMetric.ValidDataLength && metricResolved)
            throw new InvalidDataException("Valid-data-length completion metric cannot be authoritatively queried.");
    }

    private static void ValidateRestartFields(
        TruncateOperationIntent intent,
        RestartEvidenceState evidence,
        RestartPathState pathState,
        DurableFileIdentity? identity,
        long observedLength)
    {
        if (!Enum.IsDefined(evidence) || !Enum.IsDefined(pathState))
            throw new InvalidDataException("Invalid TRUNCATE restart enum state.");

        if (pathState == RestartPathState.File)
        {
            ValidateIdentity(identity
                ?? throw new InvalidDataException("TRUNCATE restart file observation requires identity."));
            if (intent.Metric == TruncateMetric.EndOfFile)
            {
                if (observedLength < 0)
                    throw new InvalidDataException("EOF restart observation requires an observed length.");
            }
            else if (observedLength != -1)
            {
                throw new InvalidDataException("Non-EOF restart observation must keep the metric unresolved.");
            }
        }
        else
        {
            if (identity is not null || observedLength != -1)
                throw new InvalidDataException("Non-file TRUNCATE restart observation must not claim identity/length.");
        }

        var expected = ClassifyRestart(intent, pathState, identity, observedLength);
        if (expected != evidence)
            throw new InvalidDataException("TRUNCATE restart evidence does not match the conservative classifier.");
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
            throw new ArgumentException("TRUNCATE path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (identity.VolumeSerialHex.Length != 16 || identity.FileIdHex.Length != 32 ||
            !identity.VolumeSerialHex.All(char.IsAsciiHexDigit) ||
            !identity.FileIdHex.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("Invalid durable identity in TRUNCATE reconciliation.");
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("TRUNCATE transaction store must not be a reparse point: " + path);
    }
}

public enum TruncateMetric
{
    EndOfFile = 1,
    AllocationSize = 2,
    ValidDataLength = 3
}

public enum TruncateCompletionState
{
    Succeeded = 1,
    SucceededMetricUnresolved = 2,
    SucceededIdentityUnresolved = 3,
    SucceededMetricAndIdentityUnresolved = 4,
    Failed = 5
}

public sealed record TruncateOperationIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    TruncateMetric Metric,
    long RequestedLength,
    long OriginalObservedLength,
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

public sealed record TruncateOperationCompletion(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    TruncateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    long ObservedLength,
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

public sealed record TruncateRestartObservation(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    long ObservedLength,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? CurrentIdentity =>
        string.IsNullOrEmpty(CurrentVolumeSerialHex)
            ? null
            : new DurableFileIdentity(CurrentVolumeSerialHex, CurrentFileIdHex);
}

internal sealed record TruncateIntentPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    TruncateMetric Metric,
    long RequestedLength,
    long OriginalObservedLength,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    bool SourceOriginallyAbsent,
    string PreservationRecordSha256,
    string PreviousRecordSha256);

internal sealed record TruncateIntentLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    uint FileInformationClass,
    TruncateMetric Metric,
    long RequestedLength,
    long OriginalObservedLength,
    string OriginalVolumeSerialHex,
    string OriginalFileIdHex,
    bool SourceOriginallyAbsent,
    string PreservationRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public TruncateIntentPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FileInformationClass, Metric,
        RequestedLength, OriginalObservedLength, OriginalVolumeSerialHex, OriginalFileIdHex,
        SourceOriginallyAbsent, PreservationRecordSha256, PreviousRecordSha256);

    public TruncateOperationIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FileInformationClass, Metric,
        RequestedLength, OriginalObservedLength, OriginalVolumeSerialHex, OriginalFileIdHex,
        SourceOriginallyAbsent, PreservationRecordSha256, PreviousRecordSha256, RecordSha256);
}

internal sealed record TruncateCompletionPayload(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    TruncateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    long ObservedLength,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256);

internal sealed record TruncateCompletionLine(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    TruncateCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    long ObservedLength,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public TruncateCompletionPayload Payload => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus, CompletionInformation,
        ObservedLength, FinalVolumeSerialHex, FinalFileIdHex, IntentRecordSha256,
        PreviousRecordSha256);

    public TruncateOperationCompletion ToCompletion() => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus, CompletionInformation,
        ObservedLength, FinalVolumeSerialHex, FinalFileIdHex, IntentRecordSha256,
        PreviousRecordSha256, RecordSha256);
}

internal sealed record TruncateRestartPayload(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    long ObservedLength,
    string PreviousRecordSha256);

internal sealed record TruncateRestartLine(
    long Sequence,
    DateTime ObservedUtc,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string OriginalPath,
    RestartPathState PathState,
    string CurrentVolumeSerialHex,
    string CurrentFileIdHex,
    long ObservedLength,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public TruncateRestartPayload Payload => new(
        Sequence, ObservedUtc, RequestSequence, IntentRecordSha256, Evidence, OriginalPath,
        PathState, CurrentVolumeSerialHex, CurrentFileIdHex, ObservedLength,
        PreviousRecordSha256);

    public TruncateRestartObservation ToObservation() => new(
        Sequence, ObservedUtc, RequestSequence, IntentRecordSha256, Evidence, OriginalPath,
        PathState, CurrentVolumeSerialHex, CurrentFileIdHex, ObservedLength,
        PreviousRecordSha256, RecordSha256);
}
