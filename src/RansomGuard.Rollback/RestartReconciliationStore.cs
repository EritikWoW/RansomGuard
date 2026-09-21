using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Append-only evidence captured after a gate-client restart for CREATE/RENAME intents that have no
/// authoritative completion record. Restart evidence never promotes an intent to completed.
/// </summary>
public sealed class RestartReconciliationStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<RestartOperationObservation> _observations = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;

    public IReadOnlyList<RestartOperationObservation> Observations
    {
        get
        {
            lock (_observations) return _observations.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public RestartReconciliationStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Restart reconciliation root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "restart-reconciliation-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<RestartOperationObservation> RecordObservationAsync(
        RestartOperationKind operationKind,
        ulong requestSequence,
        string intentRecordSha256,
        RestartEvidenceState evidence,
        string sourcePath,
        RestartPathObservation source,
        string? destinationPath = null,
        RestartPathObservation? destination = null,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        if (!IsSha256(intentRecordSha256))
            throw new InvalidDataException("Restart observation requires a valid intent record hash.");

        var normalizedSource = NormalizePath(sourcePath);
        var normalizedDestination = string.IsNullOrWhiteSpace(destinationPath)
            ? string.Empty
            : NormalizePath(destinationPath);

        var destinationValue = destination ?? RestartPathObservation.NotApplicable;
        ValidateObservation(operationKind, evidence, normalizedSource, source,
            normalizedDestination, destinationValue);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_observations)
            {
                var duplicate = _observations.LastOrDefault(x =>
                    x.OperationKind == operationKind &&
                    x.RequestSequence == requestSequence &&
                    x.IntentRecordSha256.Equals(intentRecordSha256, StringComparison.OrdinalIgnoreCase) &&
                    x.Evidence == evidence &&
                    x.SourcePath.Equals(normalizedSource, StringComparison.OrdinalIgnoreCase) &&
                    x.SourceState == source.State &&
                    x.SourceVolumeSerialHex.Equals(source.Identity?.VolumeSerialHex ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                    x.SourceFileIdHex.Equals(source.Identity?.FileIdHex ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                    x.DestinationPath.Equals(normalizedDestination, StringComparison.OrdinalIgnoreCase) &&
                    x.DestinationState == destinationValue.State &&
                    x.DestinationVolumeSerialHex.Equals(destinationValue.Identity?.VolumeSerialHex ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                    x.DestinationFileIdHex.Equals(destinationValue.Identity?.FileIdHex ?? string.Empty, StringComparison.OrdinalIgnoreCase));
                if (duplicate is not null) return duplicate;
            }

            var sequence = checked(++_nextSequence);
            var payload = new RestartObservationPayload(
                sequence,
                DateTime.UtcNow,
                operationKind,
                requestSequence,
                intentRecordSha256,
                evidence,
                normalizedSource,
                source.State,
                source.Identity?.VolumeSerialHex ?? string.Empty,
                source.Identity?.FileIdHex ?? string.Empty,
                normalizedDestination,
                destinationValue.State,
                destinationValue.Identity?.VolumeSerialHex ?? string.Empty,
                destinationValue.Identity?.FileIdHex ?? string.Empty,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new RestartObservationLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.OperationKind,
                payload.RequestSequence,
                payload.IntentRecordSha256,
                payload.Evidence,
                payload.SourcePath,
                payload.SourceState,
                payload.SourceVolumeSerialHex,
                payload.SourceFileIdHex,
                payload.DestinationPath,
                payload.DestinationState,
                payload.DestinationVolumeSerialHex,
                payload.DestinationFileIdHex,
                payload.PreviousRecordSha256,
                recordHash);

            AppendJournalLine(line);
            _lastRecordHash = recordHash;
            var observation = line.ToObservation();
            lock (_observations) _observations.Add(observation);
            return observation;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public RestartEvidenceAssessment Assess(
        RestartOperationKind operationKind,
        ulong requestSequence,
        string intentRecordSha256)
    {
        if (!Enum.IsDefined(operationKind))
            throw new InvalidDataException("Invalid restart reconciliation operation kind.");
        if (requestSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(requestSequence));
        if (!IsSha256(intentRecordSha256))
            throw new InvalidDataException("Restart assessment requires a valid intent record hash.");

        var matches = Observations
            .Where(x =>
                x.OperationKind == operationKind &&
                x.RequestSequence == requestSequence &&
                x.IntentRecordSha256.Equals(intentRecordSha256, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Sequence)
            .ToArray();

        if (matches.Length == 0)
            return new RestartEvidenceAssessment(
                RestartEvidenceAssessmentState.NoEvidence,
                0,
                string.Empty);

        var firstObservation = matches[0];
        var first = firstObservation.Evidence;
        var firstIsDecisive =
            first is RestartEvidenceState.SupportsCompleted or RestartEvidenceState.SupportsNotCompleted;
        var decisive = firstIsDecisive &&
            matches.All(x =>
                x.Evidence == first &&
                SameObservedTopology(x, firstObservation));

        var state = decisive
            ? first == RestartEvidenceState.SupportsCompleted
                ? RestartEvidenceAssessmentState.ConsistentSupportsCompleted
                : RestartEvidenceAssessmentState.ConsistentSupportsNotCompleted
            : RestartEvidenceAssessmentState.Unresolved;

        return new RestartEvidenceAssessment(
            state,
            matches.Length,
            matches[^1].RecordSha256);
    }

    private static bool SameObservedTopology(
        RestartOperationObservation left,
        RestartOperationObservation right) =>
        left.SourcePath.Equals(right.SourcePath, StringComparison.OrdinalIgnoreCase) &&
        left.SourceState == right.SourceState &&
        left.SourceVolumeSerialHex.Equals(right.SourceVolumeSerialHex, StringComparison.OrdinalIgnoreCase) &&
        left.SourceFileIdHex.Equals(right.SourceFileIdHex, StringComparison.OrdinalIgnoreCase) &&
        left.DestinationPath.Equals(right.DestinationPath, StringComparison.OrdinalIgnoreCase) &&
        left.DestinationState == right.DestinationState &&
        left.DestinationVolumeSerialHex.Equals(right.DestinationVolumeSerialHex, StringComparison.OrdinalIgnoreCase) &&
        left.DestinationFileIdHex.Equals(right.DestinationFileIdHex, StringComparison.OrdinalIgnoreCase);

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                lock (_observations) _observations.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<RestartOperationObservation>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank restart reconciliation journal record.");

            RestartObservationLine line;
            try
            {
                line = JsonSerializer.Deserialize<RestartObservationLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid restart reconciliation journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid restart reconciliation journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Restart reconciliation journal sequence gap.");
            if (line.RequestSequence == 0 || !IsSha256(line.IntentRecordSha256) ||
                !IsSha256(line.PreviousRecordSha256) || !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid restart reconciliation journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Restart reconciliation journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Restart reconciliation journal record hash mismatch.");

            var sourcePath = NormalizePath(line.SourcePath);
            var destinationPath = string.IsNullOrEmpty(line.DestinationPath)
                ? string.Empty
                : NormalizePath(line.DestinationPath);
            var source = BuildObservation(line.SourceState, line.SourceVolumeSerialHex, line.SourceFileIdHex);
            var destination = BuildObservation(line.DestinationState,
                line.DestinationVolumeSerialHex, line.DestinationFileIdHex);
            ValidateObservation(line.OperationKind, line.Evidence, sourcePath, source,
                destinationPath, destination);

            rebuilt.Add(line.ToObservation() with
            {
                SourcePath = sourcePath,
                DestinationPath = destinationPath
            });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_observations)
            {
                _observations.Clear();
                _observations.AddRange(rebuilt);
            }
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private static RestartPathObservation BuildObservation(
        RestartPathState state,
        string volumeSerialHex,
        string fileIdHex)
    {
        DurableFileIdentity? identity = string.IsNullOrEmpty(volumeSerialHex)
            ? null
            : new DurableFileIdentity(volumeSerialHex, fileIdHex);
        return new RestartPathObservation(state, identity);
    }

    private static void ValidateObservation(
        RestartOperationKind operationKind,
        RestartEvidenceState evidence,
        string sourcePath,
        RestartPathObservation source,
        string destinationPath,
        RestartPathObservation destination)
    {
        if (!Enum.IsDefined(operationKind) || !Enum.IsDefined(evidence))
            throw new InvalidDataException("Invalid restart reconciliation enum value.");
        ValidatePathObservation(source, allowNotApplicable: false);

        if (operationKind == RestartOperationKind.Create)
        {
            if (!string.IsNullOrEmpty(destinationPath) ||
                destination.State != RestartPathState.NotApplicable ||
                destination.Identity is not null)
                throw new InvalidDataException("CREATE restart observation must not claim a destination.");
        }
        else if (operationKind == RestartOperationKind.Rename)
        {
            if (string.IsNullOrEmpty(destinationPath))
                throw new InvalidDataException("RENAME restart observation requires a destination path.");
            ValidatePathObservation(destination, allowNotApplicable: false);
        }
        else
        {
            throw new InvalidDataException("Unsupported restart operation kind.");
        }

        _ = sourcePath;
    }

    private static void ValidatePathObservation(RestartPathObservation observation, bool allowNotApplicable)
    {
        if (!Enum.IsDefined(observation.State))
            throw new InvalidDataException("Invalid restart path state.");

        if (observation.State == RestartPathState.NotApplicable)
        {
            if (!allowNotApplicable || observation.Identity is not null)
                throw new InvalidDataException("Invalid not-applicable restart path state.");
            return;
        }

        if (observation.State == RestartPathState.File)
        {
            ValidateIdentity(observation.Identity
                ?? throw new InvalidDataException("Observed file requires durable identity."));
        }
        else if (observation.Identity is not null)
        {
            throw new InvalidDataException("Non-file restart path state must not claim durable identity.");
        }
    }

    private static void ValidateIdentity(DurableFileIdentity identity)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException("Invalid restart observation durable file identity.");
    }

    private void AppendJournalLine(RestartObservationLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(RestartObservationPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Restart reconciliation path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsSha256(string? value) => IsFixedHex(value, 64);

    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Restart reconciliation store must not be a reparse point: " + path);
    }
}

public static class RestartReconciliationClassifier
{
    public static RestartEvidenceState ClassifyCreate(
        CreateOperationIntent intent,
        RestartPathObservation current)
    {
        if (current.State is RestartPathState.QueryFailed or RestartPathState.ReparsePoint or RestartPathState.Directory)
            return RestartEvidenceState.Ambiguous;

        if (intent.ObservedTargetState == CreateTargetState.Missing)
            return current.State == RestartPathState.Missing
                ? RestartEvidenceState.SupportsNotCompleted
                : current.State == RestartPathState.File
                    ? RestartEvidenceState.SupportsCompleted
                    : RestartEvidenceState.Ambiguous;

        if (intent.ObservedTargetState == CreateTargetState.File && current.State == RestartPathState.File)
            return RestartEvidenceState.Indeterminate;

        return RestartEvidenceState.Ambiguous;
    }

    public static RestartEvidenceState ClassifyRename(
        RenameRollbackIntent intent,
        RestartPathObservation source,
        RestartPathObservation destination)
    {
        if (source.State is RestartPathState.QueryFailed or RestartPathState.ReparsePoint or RestartPathState.Directory ||
            destination.State is RestartPathState.QueryFailed or RestartPathState.ReparsePoint or RestartPathState.Directory)
            return RestartEvidenceState.Ambiguous;

        var sourceAtSource = source.State == RestartPathState.File &&
            source.Identity is not null && source.Identity.Equals(intent.SourceIdentity);
        var sourceAtDestination = destination.State == RestartPathState.File &&
            destination.Identity is not null && destination.Identity.Equals(intent.SourceIdentity);

        if (source.State == RestartPathState.Missing && sourceAtDestination)
            return RestartEvidenceState.SupportsCompleted;

        if (sourceAtSource)
        {
            if (intent.DestinationState == RenameDestinationState.OriginallyAbsent &&
                destination.State == RestartPathState.Missing)
                return RestartEvidenceState.SupportsNotCompleted;

            if (intent.DestinationState == RenameDestinationState.ExistingFile &&
                destination.State == RestartPathState.File &&
                intent.DestinationIdentity is not null &&
                destination.Identity is not null &&
                destination.Identity.Equals(intent.DestinationIdentity))
                return RestartEvidenceState.SupportsNotCompleted;
        }

        if (intent.DestinationState == RenameDestinationState.SameAsSource)
            return RestartEvidenceState.Indeterminate;

        return RestartEvidenceState.Ambiguous;
    }
}

public enum RestartOperationKind
{
    Create = 1,
    Rename = 2
}

public enum RestartEvidenceState
{
    SupportsCompleted = 1,
    SupportsNotCompleted = 2,
    Indeterminate = 3,
    Ambiguous = 4
}

public enum RestartEvidenceAssessmentState
{
    NoEvidence = 0,
    ConsistentSupportsCompleted = 1,
    ConsistentSupportsNotCompleted = 2,
    Unresolved = 3
}

public sealed record RestartEvidenceAssessment(
    RestartEvidenceAssessmentState State,
    int ObservationCount,
    string LatestRecordSha256);

public enum RestartPathState
{
    NotApplicable = 0,
    Missing = 1,
    File = 2,
    Directory = 3,
    ReparsePoint = 4,
    QueryFailed = 5
}

public sealed record RestartPathObservation(RestartPathState State, DurableFileIdentity? Identity)
{
    public static RestartPathObservation NotApplicable { get; } =
        new(RestartPathState.NotApplicable, null);
}

public sealed record RestartOperationObservation(
    long Sequence,
    DateTime ObservedUtc,
    RestartOperationKind OperationKind,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string SourcePath,
    RestartPathState SourceState,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    string DestinationPath,
    RestartPathState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? SourceIdentity =>
        string.IsNullOrEmpty(SourceVolumeSerialHex)
            ? null
            : new DurableFileIdentity(SourceVolumeSerialHex, SourceFileIdHex);

    [JsonIgnore]
    public DurableFileIdentity? DestinationIdentity =>
        string.IsNullOrEmpty(DestinationVolumeSerialHex)
            ? null
            : new DurableFileIdentity(DestinationVolumeSerialHex, DestinationFileIdHex);
}

internal sealed record RestartObservationPayload(
    long Sequence,
    DateTime ObservedUtc,
    RestartOperationKind OperationKind,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string SourcePath,
    RestartPathState SourceState,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    string DestinationPath,
    RestartPathState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    string PreviousRecordSha256);

internal sealed record RestartObservationLine(
    long Sequence,
    DateTime ObservedUtc,
    RestartOperationKind OperationKind,
    ulong RequestSequence,
    string IntentRecordSha256,
    RestartEvidenceState Evidence,
    string SourcePath,
    RestartPathState SourceState,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    string DestinationPath,
    RestartPathState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RestartObservationPayload Payload => new(
        Sequence, ObservedUtc, OperationKind, RequestSequence, IntentRecordSha256,
        Evidence, SourcePath, SourceState, SourceVolumeSerialHex, SourceFileIdHex,
        DestinationPath, DestinationState, DestinationVolumeSerialHex, DestinationFileIdHex,
        PreviousRecordSha256);

    public RestartOperationObservation ToObservation() => new(
        Sequence, ObservedUtc, OperationKind, RequestSequence, IntentRecordSha256,
        Evidence, SourcePath, SourceState, SourceVolumeSerialHex, SourceFileIdHex,
        DestinationPath, DestinationState, DestinationVolumeSerialHex, DestinationFileIdHex,
        PreviousRecordSha256, RecordSha256);
}
