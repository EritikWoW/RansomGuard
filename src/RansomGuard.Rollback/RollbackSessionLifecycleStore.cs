using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

public sealed class RollbackSessionLifecycleStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<RollbackSessionLifecycleRecord> _records = new();
    private long _nextSequence;
    private string _lastHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RollbackSessionLifecycleRecord> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public RollbackSessionLifecycleSnapshot Snapshot
    {
        get
        {
            lock (_records)
            {
                if (_records.Count == 0)
                    return new RollbackSessionLifecycleSnapshot(
                        RollbackSessionLifecycleState.LegacyUnmanaged,
                        false, null, null, null, string.Empty);

                var created = _records.First(x => x.EventType == RollbackSessionLifecycleEventType.Created);
                var completed = _records.LastOrDefault(x => x.EventType == RollbackSessionLifecycleEventType.Completed);
                var faulted = _records.LastOrDefault(x => x.EventType == RollbackSessionLifecycleEventType.Faulted);
                var held = false;
                foreach (var record in _records)
                {
                    if (record.EventType == RollbackSessionLifecycleEventType.HoldSet) held = true;
                    if (record.EventType == RollbackSessionLifecycleEventType.HoldReleased) held = false;
                }

                var state = completed is not null
                    ? RollbackSessionLifecycleState.Completed
                    : faulted is not null
                        ? RollbackSessionLifecycleState.Faulted
                        : RollbackSessionLifecycleState.Active;

                return new RollbackSessionLifecycleSnapshot(
                    state,
                    held,
                    created.OccurredUtc,
                    completed?.OccurredUtc,
                    faulted?.OccurredUtc,
                    _records[^1].RecordSha256);
            }
        }
    }

    public RollbackSessionLifecycleStore(string sessionRoot)
    {
        if (string.IsNullOrWhiteSpace(sessionRoot))
            throw new ArgumentException("Rollback session root is required.", nameof(sessionRoot));

        var sessionFull = Path.GetFullPath(sessionRoot);
        _root = Path.Combine(sessionFull, "lifecycle-state");
        _journal = Path.Combine(_root, "session-lifecycle.jsonl");

        if (Directory.Exists(_root))
        {
            RejectReparse(_root);
            LoadAndValidateJournal();
        }
    }

    public void InitializeCreated(DateTime? occurredUtc = null)
    {
        Directory.CreateDirectory(_root);
        RejectReparse(_root);

        if (File.Exists(_journal))
        {
            LoadAndValidateJournal();
            if (_records.Count != 0)
                throw new InvalidOperationException("Rollback session lifecycle is already initialized.");
        }

        AppendSync(RollbackSessionLifecycleEventType.Created, "session-created", occurredUtc ?? DateTime.UtcNow);
    }

    public Task<RollbackSessionLifecycleRecord> MarkCompletedAsync(
        string reason,
        CancellationToken cancellationToken = default) =>
        AppendAsync(RollbackSessionLifecycleEventType.Completed, reason, cancellationToken);

    public Task<RollbackSessionLifecycleRecord> MarkFaultedAsync(
        string reason,
        CancellationToken cancellationToken = default) =>
        AppendAsync(RollbackSessionLifecycleEventType.Faulted, reason, cancellationToken);

    public Task<RollbackSessionLifecycleRecord> SetHoldAsync(
        string reason,
        CancellationToken cancellationToken = default) =>
        AppendAsync(RollbackSessionLifecycleEventType.HoldSet, reason, cancellationToken);

    public Task<RollbackSessionLifecycleRecord> ReleaseHoldAsync(
        string reason,
        CancellationToken cancellationToken = default) =>
        AppendAsync(RollbackSessionLifecycleEventType.HoldReleased, reason, cancellationToken);

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private async Task<RollbackSessionLifecycleRecord> AppendAsync(
        RollbackSessionLifecycleEventType eventType,
        string reason,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Lifecycle reason is required.", nameof(reason));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return AppendCore(eventType, reason, DateTime.UtcNow);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void AppendSync(
        RollbackSessionLifecycleEventType eventType,
        string reason,
        DateTime occurredUtc)
    {
        _gate.Wait();
        try
        {
            _ = AppendCore(eventType, reason, occurredUtc);
        }
        finally
        {
            _gate.Release();
        }
    }

    private RollbackSessionLifecycleRecord AppendCore(
        RollbackSessionLifecycleEventType eventType,
        string reason,
        DateTime occurredUtc)
    {
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        ValidateTransition(eventType);

        var sequence = checked(++_nextSequence);
        var payload = new RollbackSessionLifecyclePayload(
            sequence,
            occurredUtc.ToUniversalTime(),
            eventType,
            reason.Trim(),
            _lastHash);
        var recordHash = HashPayload(payload);
        var line = new RollbackSessionLifecycleLine(
            payload.Sequence,
            payload.OccurredUtc,
            payload.EventType,
            payload.Reason,
            payload.PreviousRecordSha256,
            recordHash);

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using (var fs = new FileStream(
                   _journal,
                   FileMode.Append,
                   FileAccess.Write,
                   FileShare.Read,
                   64 * 1024,
                   FileOptions.WriteThrough))
        {
            fs.Write(bytes);
            fs.Flush(true);
        }

        _lastHash = recordHash;
        var record = line.ToRecord();
        lock (_records) _records.Add(record);
        return record;
    }

    private void ValidateTransition(RollbackSessionLifecycleEventType eventType)
    {
        lock (_records)
        {
            if (_records.Count == 0)
            {
                if (eventType != RollbackSessionLifecycleEventType.Created)
                    throw new InvalidOperationException("Rollback session lifecycle must start with Created.");
                return;
            }

            if (eventType == RollbackSessionLifecycleEventType.Created)
                throw new InvalidOperationException("Rollback session lifecycle cannot contain multiple Created events.");

            var terminal = _records.Any(x =>
                x.EventType is RollbackSessionLifecycleEventType.Completed
                    or RollbackSessionLifecycleEventType.Faulted);

            if (eventType is RollbackSessionLifecycleEventType.Completed or RollbackSessionLifecycleEventType.Faulted)
            {
                if (terminal)
                    throw new InvalidOperationException("Rollback session lifecycle already has a terminal event.");
                return;
            }

            var held = false;
            foreach (var record in _records)
            {
                if (record.EventType == RollbackSessionLifecycleEventType.HoldSet) held = true;
                if (record.EventType == RollbackSessionLifecycleEventType.HoldReleased) held = false;
            }

            if (eventType == RollbackSessionLifecycleEventType.HoldSet && held)
                throw new InvalidOperationException("Rollback session is already on hold.");
            if (eventType == RollbackSessionLifecycleEventType.HoldReleased && !held)
                throw new InvalidOperationException("Rollback session is not on hold.");
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
        var rebuilt = new List<RollbackSessionLifecycleRecord>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rollback session lifecycle record.");

            RollbackSessionLifecycleLine line;
            try
            {
                line = JsonSerializer.Deserialize<RollbackSessionLifecycleLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rollback session lifecycle record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rollback session lifecycle JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256) ||
                string.IsNullOrWhiteSpace(line.Reason))
                throw new InvalidDataException("Invalid rollback session lifecycle fields.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback session lifecycle hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback session lifecycle record hash mismatch.");

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

    private static void ValidateRebuiltTransitions(IReadOnlyList<RollbackSessionLifecycleRecord> records)
    {
        if (records.Count == 0)
            throw new InvalidDataException("Rollback session lifecycle journal is empty.");
        if (records[0].EventType != RollbackSessionLifecycleEventType.Created)
            throw new InvalidDataException("Rollback session lifecycle must start with Created.");

        var createdCount = 0;
        var terminalCount = 0;
        var held = false;
        foreach (var record in records)
        {
            if (record.EventType == RollbackSessionLifecycleEventType.Created)
            {
                createdCount++;
                if (record.Sequence != 1)
                    throw new InvalidDataException("Created lifecycle event must be first.");
            }

            if (record.EventType is RollbackSessionLifecycleEventType.Completed
                or RollbackSessionLifecycleEventType.Faulted)
                terminalCount++;

            if (terminalCount > 1)
                throw new InvalidDataException("Rollback session lifecycle has multiple terminal events.");

            if (record.EventType == RollbackSessionLifecycleEventType.HoldSet)
            {
                if (held) throw new InvalidDataException("Rollback session lifecycle contains duplicate HoldSet.");
                held = true;
            }
            else if (record.EventType == RollbackSessionLifecycleEventType.HoldReleased)
            {
                if (!held) throw new InvalidDataException("Rollback session lifecycle contains unmatched HoldReleased.");
                held = false;
            }
        }

        if (createdCount != 1)
            throw new InvalidDataException("Rollback session lifecycle must contain exactly one Created event.");
    }

    private string HashPayload(RollbackSessionLifecyclePayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback session lifecycle must not be a reparse point: " + path);
    }
}

public enum RollbackSessionLifecycleEventType
{
    Created = 1,
    Completed = 2,
    Faulted = 3,
    HoldSet = 4,
    HoldReleased = 5
}

public enum RollbackSessionLifecycleState
{
    LegacyUnmanaged = 0,
    Active = 1,
    Completed = 2,
    Faulted = 3
}

public sealed record RollbackSessionLifecycleSnapshot(
    RollbackSessionLifecycleState State,
    bool IsHeld,
    DateTime? CreatedUtc,
    DateTime? CompletedUtc,
    DateTime? FaultedUtc,
    string LastRecordSha256)
{
    public bool IsRetentionEligible =>
        State == RollbackSessionLifecycleState.Completed && !IsHeld;
}

public sealed record RollbackSessionLifecycleRecord(
    long Sequence,
    DateTime OccurredUtc,
    RollbackSessionLifecycleEventType EventType,
    string Reason,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record RollbackSessionLifecyclePayload(
    long Sequence,
    DateTime OccurredUtc,
    RollbackSessionLifecycleEventType EventType,
    string Reason,
    string PreviousRecordSha256);

internal sealed record RollbackSessionLifecycleLine(
    long Sequence,
    DateTime OccurredUtc,
    RollbackSessionLifecycleEventType EventType,
    string Reason,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RollbackSessionLifecyclePayload Payload =>
        new(Sequence, OccurredUtc, EventType, Reason, PreviousRecordSha256);

    public RollbackSessionLifecycleRecord ToRecord() =>
        new(Sequence, OccurredUtc, EventType, Reason, PreviousRecordSha256, RecordSha256);
}
