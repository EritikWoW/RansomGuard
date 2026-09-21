using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable session lifecycle marker used by retention policy.
/// Missing/unfinished lifecycle evidence always keeps a session non-purgeable.
/// </summary>
public sealed class RollbackSessionLifecycleStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<RollbackSessionLifecycleRecord> _records = new();
    private string _lastRecordSha256 = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RollbackSessionLifecycleRecord> Records
    {
        get { lock (_records) return _records.ToArray(); }
    }

    public bool IsOpened
    {
        get { lock (_records) return _records.Any(x => x.State == RollbackSessionLifecycleState.Opened); }
    }

    public bool IsClosedCleanly
    {
        get { lock (_records) return _records.Count == 2 &&
            _records[0].State == RollbackSessionLifecycleState.Opened &&
            _records[1].State == RollbackSessionLifecycleState.ClosedCleanly; }
    }

    public DateTime? OpenedUtc
    {
        get { lock (_records) return _records.FirstOrDefault(x => x.State == RollbackSessionLifecycleState.Opened)?.ObservedUtc; }
    }

    public DateTime? ClosedUtc
    {
        get { lock (_records) return _records.FirstOrDefault(x => x.State == RollbackSessionLifecycleState.ClosedCleanly)?.ObservedUtc; }
    }

    public RollbackSessionLifecycleStore(string sessionRoot)
    {
        if (string.IsNullOrWhiteSpace(sessionRoot))
            throw new ArgumentException("Rollback session root is required.", nameof(sessionRoot));

        _root = Path.GetFullPath(sessionRoot);
        _journal = Path.Combine(_root, "session-lifecycle.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public async Task<RollbackSessionLifecycleRecord> RecordOpenedAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                if (_records.Count != 0)
                {
                    if (_records.Count >= 1 && _records[0].State == RollbackSessionLifecycleState.Opened)
                        return _records[0];
                    throw new InvalidDataException("Rollback session lifecycle cannot be opened from its current state.");
                }
            }

            return Append(RollbackSessionLifecycleState.Opened);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RollbackSessionLifecycleRecord> RecordClosedCleanlyAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                if (_records.Count == 0 ||
                    _records[0].State != RollbackSessionLifecycleState.Opened)
                    throw new InvalidDataException("Rollback session cannot close cleanly without a committed Opened record.");

                if (_records.Count == 2)
                {
                    if (_records[1].State == RollbackSessionLifecycleState.ClosedCleanly)
                        return _records[1];
                    throw new InvalidDataException("Rollback session lifecycle contains an invalid terminal record.");
                }

                if (_records.Count != 1)
                    throw new InvalidDataException("Rollback session lifecycle has unexpected extra records.");
            }

            return Append(RollbackSessionLifecycleState.ClosedCleanly);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private RollbackSessionLifecycleRecord Append(RollbackSessionLifecycleState state)
    {
        var sequence = checked(_records.Count + 1L);
        var payload = new RollbackSessionLifecyclePayload(
            sequence,
            DateTime.UtcNow,
            state,
            _lastRecordSha256);
        var hash = HashPayload(payload);
        var line = new RollbackSessionLifecycleLine(
            payload.Sequence,
            payload.ObservedUtc,
            payload.State,
            payload.PreviousRecordSha256,
            hash);

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

        _lastRecordSha256 = hash;
        var record = line.ToRecord();
        lock (_records) _records.Add(record);
        return record;
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                lock (_records) _records.Clear();
                _lastRecordSha256 = new string('0', 64);
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
                !Enum.IsDefined(line.State) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid rollback session lifecycle fields.");

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback session lifecycle hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback session lifecycle record hash mismatch.");

            rebuilt.Add(line.ToRecord());
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuilt.Count is < 1 or > 2 ||
            rebuilt[0].State != RollbackSessionLifecycleState.Opened ||
            (rebuilt.Count == 2 && rebuilt[1].State != RollbackSessionLifecycleState.ClosedCleanly))
            throw new InvalidDataException("Rollback session lifecycle state sequence is invalid.");

        if (rebuilt.Count == 2 && rebuilt[1].ObservedUtc < rebuilt[0].ObservedUtc)
            throw new InvalidDataException("Rollback session lifecycle close time predates open time.");

        if (rebuildState)
        {
            lock (_records)
            {
                _records.Clear();
                _records.AddRange(rebuilt);
            }
            _lastRecordSha256 = expectedPrevious;
        }
    }

    private string HashPayload(RollbackSessionLifecyclePayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback session lifecycle refuses reparse-point paths: " + path);
    }
}

public enum RollbackSessionLifecycleState
{
    Opened = 1,
    ClosedCleanly = 2
}

public sealed record RollbackSessionLifecycleRecord(
    long Sequence,
    DateTime ObservedUtc,
    RollbackSessionLifecycleState State,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record RollbackSessionLifecyclePayload(
    long Sequence,
    DateTime ObservedUtc,
    RollbackSessionLifecycleState State,
    string PreviousRecordSha256);

internal sealed record RollbackSessionLifecycleLine(
    long Sequence,
    DateTime ObservedUtc,
    RollbackSessionLifecycleState State,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public RollbackSessionLifecyclePayload Payload => new(
        Sequence, ObservedUtc, State, PreviousRecordSha256);

    public RollbackSessionLifecycleRecord ToRecord() => new(
        Sequence, ObservedUtc, State, PreviousRecordSha256, RecordSha256);
}
