using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable incident-scoped baseline for paths that did not exist before a create/open operation.
/// Recovery orchestration can later treat these paths as "originally absent" without inventing file contents.
/// This store records metadata only and never deletes a created file automatically.
/// </summary>
public sealed class CreateRollbackStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<string, CreateRollbackBaseline> _baselines =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyCollection<CreateRollbackBaseline> Baselines =>
        _baselines.Values.OrderBy(x => x.Sequence).ToArray();

    public CreateRollbackStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Create rollback root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "create-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public bool WasOriginallyAbsent(string path) => _baselines.ContainsKey(NormalizeSource(path));

    public async Task<CreateRollbackBaseline> CaptureAbsentAsync(string path,
        CancellationToken cancellationToken = default)
    {
        var full = NormalizeSource(path);
        if (_baselines.TryGetValue(full, out var existing)) return existing;
        RejectReparseAncestors(full);
        EnsureMissing(full);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_baselines.TryGetValue(full, out existing)) return existing;
            RejectReparseAncestors(full);
            EnsureMissing(full);

            var sequence = checked(++_nextSequence);
            var payload = new CreateJournalPayload(sequence, DateTime.UtcNow, full, _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new CreateJournalLine(payload.Sequence, payload.CapturedUtc, payload.OriginalPath,
                payload.PreviousRecordSha256, recordHash);
            AppendJournalLine(line);
            _lastRecordHash = recordHash;

            var baseline = line.ToBaseline();
            if (!_baselines.TryAdd(full, baseline))
                throw new InvalidOperationException("Concurrent create rollback baseline commit collision.");
            return baseline;
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
                _baselines.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var rebuilt = new Dictionary<string, CreateRollbackBaseline>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank create rollback journal record.");

            CreateJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateJournalLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid create rollback journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid create rollback journal JSON.", ex);
            }

            if (line.Sequence != expectedSequence)
                throw new InvalidDataException("Create rollback journal sequence gap.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Create rollback journal hash chain mismatch.");
            if (!IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid create rollback record hash.");
            var calculated = HashPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Create rollback journal record hash mismatch.");

            var full = NormalizeSource(line.OriginalPath);
            if (!rebuilt.TryAdd(full, line.ToBaseline() with { OriginalPath = full }))
                throw new InvalidDataException("Duplicate create rollback baseline.");

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            _baselines.Clear();
            foreach (var pair in rebuilt) _baselines[pair.Key] = pair.Value;
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(CreateJournalLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private static void EnsureMissing(string full)
    {
        try
        {
            _ = File.GetAttributes(full);
            throw new InvalidOperationException("Cannot record an originally-absent baseline because the target exists: " + full);
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }

    private static void RejectReparseAncestors(string full)
    {
        var parent = Directory.GetParent(full);
        while (parent is not null)
        {
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Create rollback path must not traverse a reparse-point directory: " + parent.FullName);
            parent = parent.Parent;
        }
    }

    private static string NormalizeSource(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Source path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full))
            throw new ArgumentException("Source path must be absolute.", nameof(path));
        return full;
    }

    private string HashPayload(CreateJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Create rollback store must not be a reparse point: " + path);
    }
}

public sealed record CreateRollbackBaseline(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record CreateJournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string PreviousRecordSha256);

internal sealed record CreateJournalLine(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateJournalPayload Payload => new(Sequence, CapturedUtc, OriginalPath, PreviousRecordSha256);

    public CreateRollbackBaseline ToBaseline() =>
        new(Sequence, CapturedUtc, OriginalPath, PreviousRecordSha256, RecordSha256);
}
