using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Repository-level acknowledgement that a specific validated recovery plan may be released.
/// Stored outside Sessions so acknowledgement never mutates rollback/recovery evidence itself.
/// </summary>
public sealed class RollbackRetentionReleaseStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<RollbackRetentionReleaseRecord> _records = new();
    private long _nextSequence;
    private string _lastRecordSha256 = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RollbackRetentionReleaseRecord> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public RollbackRetentionReleaseStore(string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        _root = Path.Combine(repositoryFull, "Retention");
        _journal = Path.Combine(_root, "retention-release-journal.jsonl");

        Directory.CreateDirectory(_root);
        RejectReparse(repositoryFull);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<RollbackRetentionReleaseRecord> RecordReleaseAsync(
        string sessionId,
        string recoveryPlanId,
        CancellationToken cancellationToken = default)
    {
        ValidateSessionId(sessionId);
        ValidatePlanId(recoveryPlanId);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records
                    .Where(x => x.SessionId.Equals(sessionId, StringComparison.Ordinal))
                    .OrderByDescending(x => x.Sequence)
                    .FirstOrDefault();

                if (existing is not null &&
                    existing.RecoveryPlanId.Equals(recoveryPlanId, StringComparison.OrdinalIgnoreCase))
                    return existing;
            }

            var sequence = checked(++_nextSequence);
            var payload = new RollbackRetentionReleasePayload(
                sequence,
                DateTime.UtcNow,
                sessionId,
                recoveryPlanId.ToUpperInvariant(),
                _lastRecordSha256);
            var recordHash = HashPayload(payload);
            var line = new RollbackRetentionReleaseLine(
                payload.Sequence,
                payload.ReleasedUtc,
                payload.SessionId,
                payload.RecoveryPlanId,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(line);
            _lastRecordSha256 = recordHash;
            var record = line.ToRecord();
            lock (_records) _records.Add(record);
            return record;
        }
        finally
        {
            _gate.Release();
        }
    }

    public bool TryGetLatestRelease(
        string sessionId,
        out RollbackRetentionReleaseRecord? release)
    {
        ValidateSessionId(sessionId);
        lock (_records)
        {
            release = _records
                .Where(x => x.SessionId.Equals(sessionId, StringComparison.Ordinal))
                .OrderByDescending(x => x.Sequence)
                .FirstOrDefault();
            return release is not null;
        }
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
                _lastRecordSha256 = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<RollbackRetentionReleaseRecord>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rollback retention release record.");

            RollbackRetentionReleaseLine line;
            try
            {
                line = JsonSerializer.Deserialize<RollbackRetentionReleaseLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rollback retention release record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rollback retention release JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid rollback retention release fields.");

            ValidateSessionId(line.SessionId);
            ValidatePlanId(line.RecoveryPlanId);

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention release hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention release record hash mismatch.");

            rebuilt.Add(line.ToRecord() with { RecoveryPlanId = line.RecoveryPlanId.ToUpperInvariant() });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            lock (_records)
            {
                _records.Clear();
                _records.AddRange(rebuilt);
            }
            _nextSequence = expectedSequence - 1;
            _lastRecordSha256 = expectedPrevious;
        }
    }

    private void AppendLine(RollbackRetentionReleaseLine line)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using var fs = new FileStream(
            _journal,
            FileMode.Append,
            FileAccess.Write,
            FileShare.Read,
            64 * 1024,
            FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(RollbackRetentionReleasePayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateSessionId(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Length > 80)
            throw new ArgumentException("Invalid rollback session id.", nameof(sessionId));
        foreach (var c in sessionId)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new ArgumentException("Rollback session id contains an unsafe character.", nameof(sessionId));
    }

    private static void ValidatePlanId(string planId)
    {
        if (!IsSha256(planId))
            throw new ArgumentException("Recovery plan id must be a SHA-256 value.", nameof(planId));
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback retention release store refuses reparse-point paths: " + path);
    }
}

public sealed record RollbackRetentionReleaseRecord(
    long Sequence,
    DateTime ReleasedUtc,
    string SessionId,
    string RecoveryPlanId,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record RollbackRetentionReleasePayload(
    long Sequence,
    DateTime ReleasedUtc,
    string SessionId,
    string RecoveryPlanId,
    string PreviousRecordSha256);

internal sealed record RollbackRetentionReleaseLine(
    long Sequence,
    DateTime ReleasedUtc,
    string SessionId,
    string RecoveryPlanId,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public RollbackRetentionReleasePayload Payload => new(
        Sequence, ReleasedUtc, SessionId, RecoveryPlanId, PreviousRecordSha256);

    public RollbackRetentionReleaseRecord ToRecord() => new(
        Sequence, ReleasedUtc, SessionId, RecoveryPlanId, PreviousRecordSha256, RecordSha256);
}
