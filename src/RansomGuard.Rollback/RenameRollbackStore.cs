using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable pre-rename intent journal. It records the exact normalized source/destination names and
/// the incident identities whose preservation completed before the kernel rename was allowed.
/// It deliberately does not claim that the rename completed; post-operation reconciliation is a
/// separate milestone.
/// </summary>
public sealed class RenameRollbackStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly List<RenameRollbackIntent> _intents = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RenameRollbackIntent> Intents
    {
        get
        {
            lock (_intents) return _intents.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public RenameRollbackStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Rename rollback root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "rename-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<RenameRollbackIntent> CaptureIntentAsync(
        ulong requestSequence,
        string sourcePath,
        string destinationPath,
        DurableFileIdentity sourceIdentity,
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
            var sequence = checked(++_nextSequence);
            var payload = new RenameJournalPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                source,
                destination,
                sourceIdentity.VolumeSerialHex,
                sourceIdentity.FileIdHex,
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
                payload.DestinationState, payload.DestinationVolumeSerialHex, payload.DestinationFileIdHex,
                payload.RenameFlags, payload.FileInformationClass,
                payload.PreviousRecordSha256, recordHash);

            AppendJournalLine(line);
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

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

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
            if (line.RequestSequence == 0)
                throw new InvalidDataException("Rename rollback request sequence is invalid.");
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

    private void AppendJournalLine(RenameJournalLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(RenameJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

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

public sealed record RenameRollbackIntent(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string SourcePath,
    string DestinationPath,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
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

internal sealed record RenameJournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string SourcePath,
    string DestinationPath,
    string SourceVolumeSerialHex,
    string SourceFileIdHex,
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
        SourceVolumeSerialHex, SourceFileIdHex, DestinationState,
        DestinationVolumeSerialHex, DestinationFileIdHex,
        RenameFlags, FileInformationClass, PreviousRecordSha256);

    public RenameRollbackIntent ToIntent() => new(
        Sequence, CapturedUtc, RequestSequence, SourcePath, DestinationPath,
        SourceVolumeSerialHex, SourceFileIdHex, DestinationState,
        DestinationVolumeSerialHex, DestinationFileIdHex,
        RenameFlags, FileInformationClass, PreviousRecordSha256, RecordSha256);
}
