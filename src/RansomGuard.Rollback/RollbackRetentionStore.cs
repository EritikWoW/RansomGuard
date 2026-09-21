using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

public sealed class RollbackRetentionStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<RollbackRetentionRecord> _records = new();
    private long _nextSequence;
    private string _lastHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RollbackRetentionRecord> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public RollbackRetentionStore(string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        _root = Path.Combine(repositoryFull, "retention-state");
        _journal = Path.Combine(_root, "retention-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public Task<RollbackRetentionRecord> RecordAsync(
        RollbackRetentionEventType eventType,
        string planId,
        string sessionId,
        string sessionEvidenceSha256,
        long sessionBytes,
        string reason,
        CancellationToken cancellationToken = default) =>
        AppendAsync(
            eventType, planId, sessionId, sessionEvidenceSha256,
            sessionBytes, reason, cancellationToken);

    public RollbackRetentionRecord? LatestForSession(string sessionId)
    {
        lock (_records)
            return _records.LastOrDefault(x =>
                x.SessionId.Equals(sessionId, StringComparison.Ordinal));
    }

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private async Task<RollbackRetentionRecord> AppendAsync(
        RollbackRetentionEventType eventType,
        string planId,
        string sessionId,
        string sessionEvidenceSha256,
        long sessionBytes,
        string reason,
        CancellationToken cancellationToken)
    {
        ValidateSessionId(sessionId);
        if (!IsSha256(planId))
            throw new ArgumentException("Retention plan id must be SHA-256 hex.", nameof(planId));
        if (!IsSha256(sessionEvidenceSha256))
            throw new ArgumentException("Session evidence digest must be SHA-256 hex.", nameof(sessionEvidenceSha256));
        if (sessionBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(sessionBytes));
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Retention reason is required.", nameof(reason));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateTransition(eventType, sessionId, planId, sessionEvidenceSha256);

            var sequence = checked(++_nextSequence);
            var payload = new RollbackRetentionPayload(
                sequence,
                DateTime.UtcNow,
                eventType,
                planId,
                sessionId,
                sessionEvidenceSha256,
                sessionBytes,
                reason.Trim(),
                _lastHash);
            var recordHash = HashPayload(payload);
            var line = new RollbackRetentionLine(
                payload.Sequence,
                payload.OccurredUtc,
                payload.EventType,
                payload.PlanId,
                payload.SessionId,
                payload.SessionEvidenceSha256,
                payload.SessionBytes,
                payload.Reason,
                payload.PreviousRecordSha256,
                recordHash);

            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
            using (var fs = new FileStream(
                       _journal, FileMode.Append, FileAccess.Write, FileShare.Read,
                       64 * 1024, FileOptions.WriteThrough))
            {
                fs.Write(bytes);
                fs.Flush(true);
            }

            _lastHash = recordHash;
            var record = line.ToRecord();
            lock (_records) _records.Add(record);
            return record;
        }
        finally
        {
            _gate.Release();
        }
    }

    private void ValidateTransition(
        RollbackRetentionEventType eventType,
        string sessionId,
        string planId,
        string evidenceSha)
    {
        lock (_records)
        {
            var previous = _records.LastOrDefault(x =>
                x.SessionId.Equals(sessionId, StringComparison.Ordinal));

            if (previous is null)
            {
                if (eventType != RollbackRetentionEventType.PurgeStarted)
                    throw new InvalidOperationException("Retention lifecycle must start with PurgeStarted.");
                return;
            }

            if (previous.EventType == RollbackRetentionEventType.PurgeCompleted)
                throw new InvalidOperationException("Retention purge is already completed for this session.");

            if (!previous.PlanId.Equals(planId, StringComparison.OrdinalIgnoreCase) ||
                !previous.SessionEvidenceSha256.Equals(evidenceSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "Incomplete retention purge can only continue with the original plan/evidence identity.");

            var expected = previous.EventType switch
            {
                RollbackRetentionEventType.PurgeStarted => RollbackRetentionEventType.Quarantined,
                RollbackRetentionEventType.Quarantined => RollbackRetentionEventType.PurgeCompleted,
                _ => throw new InvalidOperationException("Invalid retention event transition.")
            };
            if (eventType != expected)
                throw new InvalidOperationException(
                    $"Retention event {eventType} cannot follow {previous.EventType}; expected {expected}.");
        }
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                lock (_records) _records.Clear();
                _nextSequence = 0;
                _lastHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<RollbackRetentionRecord>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rollback retention journal record.");

            RollbackRetentionLine line;
            try
            {
                line = JsonSerializer.Deserialize<RollbackRetentionLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rollback retention journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rollback retention journal JSON.", ex);
            }

            ValidateSessionId(line.SessionId);
            if (line.Sequence != expectedSequence ||
                line.SessionBytes < 0 ||
                !IsSha256(line.PlanId) ||
                !IsSha256(line.SessionEvidenceSha256) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256) ||
                string.IsNullOrWhiteSpace(line.Reason))
                throw new InvalidDataException("Invalid rollback retention journal fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention journal record hash mismatch.");

            rebuilt.Add(line.ToRecord());
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        ValidateRebuiltTransitions(rebuilt);

        if (rebuildState)
        {
            lock (_records)
            {
                _records.Clear();
                _records.AddRange(rebuilt);
            }
            _nextSequence = expectedSequence - 1;
            _lastHash = expectedPrevious;
        }
    }

    private static void ValidateRebuiltTransitions(IReadOnlyList<RollbackRetentionRecord> records)
    {
        foreach (var group in records.GroupBy(x => x.SessionId, StringComparer.Ordinal))
        {
            var ordered = group.OrderBy(x => x.Sequence).ToArray();
            if (ordered[0].EventType != RollbackRetentionEventType.PurgeStarted)
                throw new InvalidDataException("Retention session sequence must start with PurgeStarted.");

            var planId = ordered[0].PlanId;
            var evidence = ordered[0].SessionEvidenceSha256;
            var expected = RollbackRetentionEventType.PurgeStarted;

            foreach (var record in ordered)
            {
                if (record.EventType != expected)
                    throw new InvalidDataException("Invalid rollback retention event transition.");
                if (!record.PlanId.Equals(planId, StringComparison.OrdinalIgnoreCase) ||
                    !record.SessionEvidenceSha256.Equals(evidence, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Rollback retention plan/evidence identity changed mid-purge.");

                expected = record.EventType switch
                {
                    RollbackRetentionEventType.PurgeStarted => RollbackRetentionEventType.Quarantined,
                    RollbackRetentionEventType.Quarantined => RollbackRetentionEventType.PurgeCompleted,
                    RollbackRetentionEventType.PurgeCompleted => 0,
                    _ => throw new InvalidDataException("Unknown rollback retention event.")
                };

                if (expected == 0 && record != ordered[^1])
                    throw new InvalidDataException("Rollback retention records exist after PurgeCompleted.");
            }
        }
    }

    private string HashPayload(RollbackRetentionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateSessionId(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Length > 80)
            throw new ArgumentException("Invalid rollback session id.", nameof(sessionId));
        foreach (var c in sessionId)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new ArgumentException("Rollback session id contains an unsafe character.", nameof(sessionId));
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback retention state must not be a reparse point: " + path);
    }
}

public enum RollbackRetentionEventType
{
    PurgeStarted = 1,
    Quarantined = 2,
    PurgeCompleted = 3
}

public sealed record RollbackRetentionRecord(
    long Sequence,
    DateTime OccurredUtc,
    RollbackRetentionEventType EventType,
    string PlanId,
    string SessionId,
    string SessionEvidenceSha256,
    long SessionBytes,
    string Reason,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record RollbackRetentionPayload(
    long Sequence,
    DateTime OccurredUtc,
    RollbackRetentionEventType EventType,
    string PlanId,
    string SessionId,
    string SessionEvidenceSha256,
    long SessionBytes,
    string Reason,
    string PreviousRecordSha256);

internal sealed record RollbackRetentionLine(
    long Sequence,
    DateTime OccurredUtc,
    RollbackRetentionEventType EventType,
    string PlanId,
    string SessionId,
    string SessionEvidenceSha256,
    long SessionBytes,
    string Reason,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RollbackRetentionPayload Payload => new(
        Sequence, OccurredUtc, EventType, PlanId, SessionId,
        SessionEvidenceSha256, SessionBytes, Reason, PreviousRecordSha256);

    public RollbackRetentionRecord ToRecord() => new(
        Sequence, OccurredUtc, EventType, PlanId, SessionId,
        SessionEvidenceSha256, SessionBytes, Reason,
        PreviousRecordSha256, RecordSha256);
}
