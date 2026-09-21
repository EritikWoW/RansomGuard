using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable rename transaction state. The intent journal proves what source/destination preservation
/// completed before the kernel rename was allowed. The completion journal records the later filesystem
/// outcome without ever assuming that a pre-operation intent actually completed.
/// </summary>
public sealed class RenameRollbackStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly string _completionJournal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<RenameRollbackIntent> _intents = new();
    private readonly Dictionary<ulong, RenameRollbackCompletion> _completions = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);
    private long _nextCompletionSequence;
    private string _lastCompletionRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public string CompletionJournalPath => _completionJournal;

    public IReadOnlyList<RenameRollbackIntent> Intents
    {
        get
        {
            lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<RenameRollbackCompletion> Completions
    {
        get
        {
            lock (_intents) return _completions.Values.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public IReadOnlyList<RenameRollbackIntent> PendingIntents
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

    public RenameRollbackStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Rename rollback root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "rename-journal.jsonl");
        _completionJournal = Path.Combine(_root, "rename-completion-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
        LoadAndValidateCompletions();
    }

    public async Task<RenameRollbackIntent> CaptureIntentAsync(
        ulong requestSequence,
        string sourcePath,
        string destinationPath,
        DurableFileIdentity sourceIdentity,
        bool sourceOriginallyAbsent,
        RenameDestinationState destinationState,
        DurableFileIdentity? destinationIdentity,
        uint renameFlags,
        uint fileInformationClass,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        var source = NormalizePath(sourcePath);
        var destination = NormalizePath(destinationPath);
        ValidateState(source, destination, sourceIdentity, destinationState, destinationIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_intents)
            {
                if (_intents.Any(x => x.RequestSequence == requestSequence))
                    throw new InvalidDataException("Duplicate rename request sequence.");
            }

            var sequence = checked(++_nextSequence);
            var payload = new RenameJournalPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                source,
                destination,
                sourceIdentity.VolumeSerialHex,
                sourceIdentity.FileIdHex,
                sourceOriginallyAbsent,
                destinationState,
                destinationIdentity?.VolumeSerialHex ?? string.Empty,
                destinationIdentity?.FileIdHex ?? string.Empty,
                renameFlags,
                fileInformationClass,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new RenameJournalLine(
                payload.Sequence, payload.CapturedUtc, payload.RequestSequence,
                payload.SourcePath, payload.DestinationPath,
                payload.SourceVolumeSerialHex, payload.SourceFileIdHex,
                payload.SourceOriginallyAbsent, payload.DestinationState,
                payload.DestinationVolumeSerialHex, payload.DestinationFileIdHex,
                payload.RenameFlags, payload.FileInformationClass,
                payload.PreviousRecordSha256, recordHash);

            AppendLine(_journal, line);
            _lastRecordHash = recordHash;
            var intent = line.ToIntent();
            lock (_intents) _intents.Add(intent);
            return intent;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public async Task<RenameRollbackCompletion> RecordCompletionAsync(
        ulong requestSequence,
        RenameCompletionState state,
        uint completionStatus,
        ulong completionInformation,
        string? finalDestinationPath,
        DurableFileIdentity? finalIdentity,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));

        var finalPath = NormalizeCompletion(
            state,
            completionStatus,
            finalDestinationPath,
            finalIdentity);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RenameRollbackIntent intent;
            lock (_intents)
            {
                intent = _intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
                    ?? throw new InvalidDataException("Rename completion does not reference a committed intent.");

                if (_completions.TryGetValue(requestSequence, out var existing))
                {
                    if (existing.State == state &&
                        existing.CompletionStatus == completionStatus &&
                        existing.CompletionInformation == completionInformation &&
                        existing.FinalDestinationPath.Equals(finalPath, StringComparison.OrdinalIgnoreCase) &&
                        Nullable.Equals(existing.FinalIdentity, finalIdentity))
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate rename completion.");
                }
            }

            var sequence = checked(++_nextCompletionSequence);
            var payload = new RenameCompletionJournalPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                state,
                completionStatus,
                completionInformation,
                finalPath,
                finalIdentity?.VolumeSerialHex ?? string.Empty,
                finalIdentity?.FileIdHex ?? string.Empty,
                intent.RecordSha256,
                _lastCompletionRecordHash);
            var recordHash = HashCompletionPayload(payload);
            var line = new RenameCompletionJournalLine(
                payload.Sequence,
                payload.CompletedUtc,
                payload.RequestSequence,
                payload.State,
                payload.CompletionStatus,
                payload.CompletionInformation,
                payload.FinalDestinationPath,
                payload.FinalVolumeSerialHex,
                payload.FinalFileIdHex,
                payload.IntentRecordSha256,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(_completionJournal, line);
            _lastCompletionRecordHash = recordHash;
            var completion = line.ToCompletion();
            lock (_intents) _completions.Add(requestSequence, completion);
            return completion;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGetCompletion(ulong requestSequence, out RenameRollbackCompletion? completion)
    {
        lock (_intents) return _completions.TryGetValue(requestSequence, out completion);
    }

    public void VerifyAll()
    {
        LoadAndValidateJournal(rebuildState: false);
        LoadAndValidateCompletions(rebuildState: false);
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                lock (_intents) _intents.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<RenameRollbackIntent>();
        var requestSequences = new HashSet<ulong>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rename rollback journal record.");

            RenameJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<RenameJournalLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rename rollback journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rename rollback journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Rename rollback journal sequence gap.");
            if (line.RequestSequence == 0 || !requestSequences.Add(line.RequestSequence))
                throw new InvalidDataException("Rename rollback request sequence is invalid or duplicated.");
            if (!IsFixedHex(line.PreviousRecordSha256, 64) || !IsFixedHex(line.RecordSha256, 64))
                throw new InvalidDataException("Invalid rename rollback journal hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename rollback journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename rollback journal record hash mismatch.");

            var source = NormalizePath(line.SourcePath);
            var destination = NormalizePath(line.DestinationPath);
            var sourceIdentity = new DurableFileIdentity(line.SourceVolumeSerialHex, line.SourceFileIdHex);
            DurableFileIdentity? destinationIdentity = string.IsNullOrEmpty(line.DestinationVolumeSerialHex)
                ? null
                : new DurableFileIdentity(line.DestinationVolumeSerialHex, line.DestinationFileIdHex);
            ValidateState(source, destination, sourceIdentity, line.DestinationState, destinationIdentity);

            rebuilt.Add(line.ToIntent() with { SourcePath = source, DestinationPath = destination });
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
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
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
                _lastCompletionRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_completionJournal);

        RenameRollbackIntent[] intents;
        lock (_intents) intents = _intents.ToArray();
        var intentByRequest = intents.ToDictionary(x => x.RequestSequence);

        var rebuilt = new Dictionary<ulong, RenameRollbackCompletion>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_completionJournal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rename completion journal record.");

            RenameCompletionJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<RenameCompletionJournalLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rename completion journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rename completion journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Rename completion journal sequence gap.");
            if (!intentByRequest.TryGetValue(line.RequestSequence, out var intent))
                throw new InvalidDataException("Rename completion references a missing intent.");
            if (!IsFixedHex(line.IntentRecordSha256, 64) ||
                !line.IntentRecordSha256.Equals(intent.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename completion intent hash mismatch.");
            if (!IsFixedHex(line.PreviousRecordSha256, 64) || !IsFixedHex(line.RecordSha256, 64))
                throw new InvalidDataException("Invalid rename completion journal hash fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename completion journal hash chain mismatch.");
            if (!HashCompletionPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rename completion journal record hash mismatch.");

            ValidateCompletion(
                line.State,
                line.CompletionStatus,
                line.FinalDestinationPath,
                ReadIdentity(line.FinalVolumeSerialHex, line.FinalFileIdHex));
            if (!rebuilt.TryAdd(line.RequestSequence, line.ToCompletion()))
                throw new InvalidDataException("Duplicate rename completion for request sequence.");

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
            _lastCompletionRecordHash = expectedPrevious;
        }
    }

    private static string NormalizeCompletion(
        RenameCompletionState state,
        uint completionStatus,
        string? finalDestinationPath,
        DurableFileIdentity? finalIdentity)
    {
        switch (state)
        {
            case RenameCompletionState.Succeeded:
                if (!NtSuccess(completionStatus) || finalIdentity is null)
                    throw new InvalidDataException("Authoritative rename success requires successful NTSTATUS and durable identity.");
                ValidateIdentity(finalIdentity, "final");
                return NormalizePath(finalDestinationPath
                    ?? throw new InvalidDataException("Authoritative rename success requires final destination path."));

            case RenameCompletionState.SucceededNameUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is null || !string.IsNullOrWhiteSpace(finalDestinationPath))
                    throw new InvalidDataException("Name-unresolved rename success requires identity and no final path.");
                ValidateIdentity(finalIdentity, "final");
                return string.Empty;

            case RenameCompletionState.SucceededIdentityUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is not null)
                    throw new InvalidDataException("Identity-unresolved rename success must not claim durable identity.");
                return NormalizePath(finalDestinationPath
                    ?? throw new InvalidDataException("Identity-unresolved rename success requires final destination path."));

            case RenameCompletionState.SucceededNameAndIdentityUnresolved:
                if (!NtSuccess(completionStatus) || finalIdentity is not null || !string.IsNullOrWhiteSpace(finalDestinationPath))
                    throw new InvalidDataException("Fully unresolved rename success must not claim name or identity.");
                return string.Empty;

            case RenameCompletionState.Failed:
                if (NtSuccess(completionStatus) || finalIdentity is not null || !string.IsNullOrWhiteSpace(finalDestinationPath))
                    throw new InvalidDataException("Failed rename completion must not claim final name or identity.");
                return string.Empty;

            default:
                throw new InvalidDataException("Unknown rename completion state.");
        }
    }

    private static void ValidateCompletion(
        RenameCompletionState state,
        uint completionStatus,
        string finalDestinationPath,
        DurableFileIdentity? finalIdentity)
    {
        _ = NormalizeCompletion(state, completionStatus, finalDestinationPath, finalIdentity);
    }

    private static DurableFileIdentity? ReadIdentity(string volumeSerialHex, string fileIdHex)
    {
        if (string.IsNullOrEmpty(volumeSerialHex) && string.IsNullOrEmpty(fileIdHex))
            return null;
        if (string.IsNullOrEmpty(volumeSerialHex) || string.IsNullOrEmpty(fileIdHex))
            throw new InvalidDataException("Rename completion contains a partial durable identity.");
        var identity = new DurableFileIdentity(volumeSerialHex, fileIdHex);
        ValidateIdentity(identity, "final");
        return identity;
    }

    private static void ValidateState(
        string source,
        string destination,
        DurableFileIdentity sourceIdentity,
        RenameDestinationState destinationState,
        DurableFileIdentity? destinationIdentity)
    {
        ValidateIdentity(sourceIdentity, "source");

        switch (destinationState)
        {
            case RenameDestinationState.OriginallyAbsent:
                if (destinationIdentity is not null)
                    throw new InvalidDataException("Absent rename destination must not have a durable identity.");
                break;
            case RenameDestinationState.ExistingFile:
                if (destinationIdentity is null)
                    throw new InvalidDataException("Existing rename destination requires a durable identity.");
                ValidateIdentity(destinationIdentity, "destination");
                if (destinationIdentity.Equals(sourceIdentity))
                    throw new InvalidDataException("Existing rename destination identity must differ from source identity.");
                break;
            case RenameDestinationState.SameAsSource:
                if (!source.Equals(destination, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Same-source rename state requires equivalent source and destination paths.");
                if (destinationIdentity is null || !destinationIdentity.Equals(sourceIdentity))
                    throw new InvalidDataException("Same-source rename state requires the source identity.");
                break;
            default:
                throw new InvalidDataException("Unknown rename destination state.");
        }
    }

    private static void ValidateIdentity(DurableFileIdentity identity, string label)
    {
        if (!IsFixedHex(identity.VolumeSerialHex, 16) || !IsFixedHex(identity.FileIdHex, 32))
            throw new InvalidDataException($"Invalid {label} durable file identity.");
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

    private string HashPayload(RenameJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private string HashCompletionPayload(RenameCompletionJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Rename path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsFixedHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rename rollback store must not be a reparse point: " + path);
    }
}

public enum RenameDestinationState
{
    OriginallyAbsent = 1,
    ExistingFile = 2,
    SameAsSource = 3
}

public enum RenameCompletionState
{
    Succeeded = 1,
    SucceededNameUnresolved = 2,
    SucceededIdentityUnresolved = 3,
    SucceededNameAndIdentityUnresolved = 4,
    Failed = 5
}

public sealed record RenameRollbackIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string SourcePath,
    string DestinationPath,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    bool SourceOriginallyAbsent,
    RenameDestinationState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    uint RenameFlags,
    uint FileInformationClass,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity SourceIdentity => new(SourceVolumeSerialHex, SourceFileIdHex);

    [JsonIgnore]
    public DurableFileIdentity? DestinationIdentity =>
        string.IsNullOrEmpty(DestinationVolumeSerialHex)
            ? null
            : new DurableFileIdentity(DestinationVolumeSerialHex, DestinationFileIdHex);
}

public sealed record RenameRollbackCompletion(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    RenameCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalDestinationPath,
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

internal sealed record RenameJournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string SourcePath,
    string DestinationPath,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    bool SourceOriginallyAbsent,
    RenameDestinationState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    uint RenameFlags,
    uint FileInformationClass,
    string PreviousRecordSha256);

internal sealed record RenameJournalLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string SourcePath,
    string DestinationPath,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
    bool SourceOriginallyAbsent,
    RenameDestinationState DestinationState,
    string DestinationVolumeSerialHex,
    string DestinationFileIdHex,
    uint RenameFlags,
    uint FileInformationClass,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RenameJournalPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, SourcePath, DestinationPath,
        SourceVolumeSerialHex, SourceFileIdHex, SourceOriginallyAbsent, DestinationState,
        DestinationVolumeSerialHex, DestinationFileIdHex,
        RenameFlags, FileInformationClass, PreviousRecordSha256);

    public RenameRollbackIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, SourcePath, DestinationPath,
        SourceVolumeSerialHex, SourceFileIdHex, SourceOriginallyAbsent, DestinationState,
        DestinationVolumeSerialHex, DestinationFileIdHex,
        RenameFlags, FileInformationClass, PreviousRecordSha256, RecordSha256);
}

internal sealed record RenameCompletionJournalPayload(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    RenameCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalDestinationPath,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256);

internal sealed record RenameCompletionJournalLine(
    long Sequence,
    DateTime CompletedUtc,
    ulong RequestSequence,
    RenameCompletionState State,
    uint CompletionStatus,
    ulong CompletionInformation,
    string FinalDestinationPath,
    string FinalVolumeSerialHex,
    string FinalFileIdHex,
    string IntentRecordSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RenameCompletionJournalPayload Payload => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalDestinationPath, FinalVolumeSerialHex, FinalFileIdHex,
        IntentRecordSha256, PreviousRecordSha256);

    public RenameRollbackCompletion ToCompletion() => new(
        Sequence, CompletedUtc, RequestSequence, State, CompletionStatus,
        CompletionInformation, FinalDestinationPath, FinalVolumeSerialHex, FinalFileIdHex,
        IntentRecordSha256, PreviousRecordSha256, RecordSha256);
}
