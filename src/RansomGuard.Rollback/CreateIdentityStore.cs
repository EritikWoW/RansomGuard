using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable post-CREATE identity observations. This journal is intentionally separate from the
/// originally-absent baseline journal so v0.7.3 create-state stores remain readable.
/// </summary>
public sealed class CreateIdentityStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<ulong, CreateIdentityObservation> _observations = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyCollection<CreateIdentityObservation> Observations =>
        _observations.Values.OrderBy(x => x.Sequence).ToArray();

    public CreateIdentityStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Create identity root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "identity-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public bool HasRequest(ulong requestSequence) => _observations.ContainsKey(requestSequence);

    public async Task<CreateIdentityObservation> RecordAsync(
        ulong requestSequence,
        string originalPath,
        string finalPath,
        CreateDisposition disposition,
        CreateTargetState preTargetState,
        CreatePreservationAction preservationAction,
        CreateResult createResult,
        ulong volumeSerialNumber,
        string fileId128Hex,
        RollbackFileIdentity? preIdentity = null,
        CancellationToken cancellationToken = default)
    {
        if (requestSequence == 0) throw new ArgumentOutOfRangeException(nameof(requestSequence));
        var original = NormalizePath(originalPath);
        var final = NormalizePath(finalPath);
        ValidateFileId(fileId128Hex);

        if (!CreateGatePolicy.IsSuccessfulResultConsistent(disposition, preTargetState, createResult))
            throw new InvalidDataException("Post-create result is inconsistent with the pre-create target state.");

        if (CreateGatePolicy.RequiresStableExistingIdentity(disposition, preTargetState))
        {
            if (preIdentity is null)
                throw new InvalidDataException("Stable existing-file CREATE requires a pre-create file identity.");
            if (preIdentity.VolumeSerialNumber != volumeSerialNumber ||
                !preIdentity.FileId128Hex.Equals(fileId128Hex, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Post-create file identity does not match the preserved existing file.");
        }

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_observations.TryGetValue(requestSequence, out var existing)) return existing;

            var sequence = checked(++_nextSequence);
            var payload = new CreateIdentityPayload(
                sequence,
                DateTime.UtcNow,
                requestSequence,
                original,
                final,
                disposition,
                preTargetState,
                preservationAction,
                createResult,
                volumeSerialNumber,
                fileId128Hex.ToUpperInvariant(),
                preIdentity?.VolumeSerialNumber ?? 0,
                preIdentity?.FileId128Hex?.ToUpperInvariant() ?? string.Empty,
                _lastRecordHash);
            var hash = HashPayload(payload);
            var line = new CreateIdentityLine(
                payload.Sequence,
                payload.CapturedUtc,
                payload.RequestSequence,
                payload.OriginalPath,
                payload.FinalPath,
                payload.Disposition,
                payload.PreTargetState,
                payload.PreservationAction,
                payload.CreateResult,
                payload.VolumeSerialNumber,
                payload.FileId128Hex,
                payload.PreVolumeSerialNumber,
                payload.PreFileId128Hex,
                payload.PreviousRecordSha256,
                hash);
            AppendJournalLine(line);
            _lastRecordHash = hash;

            var observation = line.ToObservation();
            if (!_observations.TryAdd(requestSequence, observation))
                throw new InvalidOperationException("Concurrent create identity commit collision.");
            return observation;
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
                _observations.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var rebuilt = new Dictionary<ulong, CreateIdentityObservation>();

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank create identity journal record.");

            CreateIdentityLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateIdentityLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid create identity journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid create identity journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Create identity journal sequence gap.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Create identity journal hash chain mismatch.");
            if (!IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid create identity record hash.");
            if (line.RequestSequence == 0)
                throw new InvalidDataException("Create identity request sequence must be nonzero.");
            ValidateFileId(line.FileId128Hex);
            if (!Enum.IsDefined(line.Disposition) || !Enum.IsDefined(line.PreTargetState) ||
                !Enum.IsDefined(line.PreservationAction) || !Enum.IsDefined(line.CreateResult))
                throw new InvalidDataException("Invalid create identity enum field.");

            var original = NormalizePath(line.OriginalPath);
            var final = NormalizePath(line.FinalPath);
            var calculated = HashPayload(line.Payload with { OriginalPath = original, FinalPath = final });
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Create identity journal record hash mismatch.");

            var preIdentity = string.IsNullOrEmpty(line.PreFileId128Hex)
                ? null
                : new RollbackFileIdentity(line.PreVolumeSerialNumber, NormalizeFileId(line.PreFileId128Hex));

            if (!CreateGatePolicy.IsSuccessfulResultConsistent(line.Disposition, line.PreTargetState, line.CreateResult))
                throw new InvalidDataException("Stored create identity result is inconsistent with its pre-create state.");
            if (CreateGatePolicy.RequiresStableExistingIdentity(line.Disposition, line.PreTargetState))
            {
                if (preIdentity is null ||
                    preIdentity.VolumeSerialNumber != line.VolumeSerialNumber ||
                    !preIdentity.FileId128Hex.Equals(line.FileId128Hex, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Stored create identity changed across a stable existing-file operation.");
            }

            var normalized = line with
            {
                OriginalPath = original,
                FinalPath = final,
                FileId128Hex = NormalizeFileId(line.FileId128Hex),
                PreFileId128Hex = preIdentity?.FileId128Hex ?? string.Empty
            };
            if (!rebuilt.TryAdd(line.RequestSequence, normalized.ToObservation()))
                throw new InvalidDataException("Duplicate create identity request sequence.");

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            _observations.Clear();
            foreach (var pair in rebuilt) _observations[pair.Key] = pair.Value;
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(CreateIdentityLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(CreateIdentityPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full)) throw new ArgumentException("Path must be absolute.", nameof(path));
        return full;
    }

    private static string NormalizeFileId(string value) => value.ToUpperInvariant();

    private static void ValidateFileId(string value)
    {
        if (value.Length != 32 || !value.All(char.IsAsciiHexDigit) || value.All(c => c == '0'))
            throw new InvalidDataException("CREATE reconciliation requires a nonzero 128-bit file ID.");
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Create identity store must not be a reparse point: " + path);
    }
}

public sealed record RollbackFileIdentity(ulong VolumeSerialNumber, string FileId128Hex);

public sealed record CreateIdentityObservation(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    string FinalPath,
    CreateDisposition Disposition,
    CreateTargetState PreTargetState,
    CreatePreservationAction PreservationAction,
    CreateResult CreateResult,
    ulong VolumeSerialNumber,
    string FileId128Hex,
    ulong PreVolumeSerialNumber,
    string PreFileId128Hex,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record CreateIdentityPayload(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    string FinalPath,
    CreateDisposition Disposition,
    CreateTargetState PreTargetState,
    CreatePreservationAction PreservationAction,
    CreateResult CreateResult,
    ulong VolumeSerialNumber,
    string FileId128Hex,
    ulong PreVolumeSerialNumber,
    string PreFileId128Hex,
    string PreviousRecordSha256);

internal sealed record CreateIdentityLine(
    long Sequence,
    DateTime CapturedUtc,
    ulong RequestSequence,
    string OriginalPath,
    string FinalPath,
    CreateDisposition Disposition,
    CreateTargetState PreTargetState,
    CreatePreservationAction PreservationAction,
    CreateResult CreateResult,
    ulong VolumeSerialNumber,
    string FileId128Hex,
    ulong PreVolumeSerialNumber,
    string PreFileId128Hex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateIdentityPayload Payload => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FinalPath, Disposition, PreTargetState,
        PreservationAction, CreateResult, VolumeSerialNumber, FileId128Hex, PreVolumeSerialNumber,
        PreFileId128Hex, PreviousRecordSha256);

    public CreateIdentityObservation ToObservation() => new(
        Sequence, CapturedUtc, RequestSequence, OriginalPath, FinalPath, Disposition, PreTargetState,
        PreservationAction, CreateResult, VolumeSerialNumber, FileId128Hex, PreVolumeSerialNumber,
        PreFileId128Hex, PreviousRecordSha256, RecordSha256);
}
