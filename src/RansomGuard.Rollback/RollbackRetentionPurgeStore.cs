using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable audit trail for explicit retention purge operations.
/// Intent is committed before the session is moved; quarantine is committed before recursive delete.
/// </summary>
public sealed class RollbackRetentionPurgeStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<RollbackRetentionPurgeRecord> _records = new();
    private long _nextSequence;
    private string _lastRecordSha256 = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<RollbackRetentionPurgeRecord> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public RollbackRetentionPurgeStore(string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));

        var repositoryFull = Path.GetFullPath(repositoryRoot);
        _root = Path.Combine(repositoryFull, "Retention");
        _journal = Path.Combine(_root, "retention-purge-journal.jsonl");

        RejectReparse(repositoryFull);
        if (Directory.Exists(_root))
            RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public Task<RollbackRetentionPurgeRecord> RecordIntentAsync(
        string operationId,
        string sessionId,
        string retentionPlanId,
        string recoveryPlanId,
        string releaseRecordSha256,
        long sizeBytes,
        string quarantineRelativePath,
        CancellationToken cancellationToken = default) =>
        RecordAsync(
            RollbackRetentionPurgeState.Intent,
            operationId,
            sessionId,
            retentionPlanId,
            recoveryPlanId,
            releaseRecordSha256,
            sizeBytes,
            quarantineRelativePath,
            cancellationToken);

    public Task<RollbackRetentionPurgeRecord> RecordQuarantinedAsync(
        RollbackRetentionPurgeRecord intent,
        CancellationToken cancellationToken = default) =>
        RecordAsync(
            RollbackRetentionPurgeState.Quarantined,
            intent.OperationId,
            intent.SessionId,
            intent.RetentionPlanId,
            intent.RecoveryPlanId,
            intent.ReleaseRecordSha256,
            intent.SizeBytes,
            intent.QuarantineRelativePath,
            cancellationToken);

    public Task<RollbackRetentionPurgeRecord> RecordCompletedAsync(
        RollbackRetentionPurgeRecord intent,
        CancellationToken cancellationToken = default) =>
        RecordAsync(
            RollbackRetentionPurgeState.Completed,
            intent.OperationId,
            intent.SessionId,
            intent.RetentionPlanId,
            intent.RecoveryPlanId,
            intent.ReleaseRecordSha256,
            intent.SizeBytes,
            intent.QuarantineRelativePath,
            cancellationToken);

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private async Task<RollbackRetentionPurgeRecord> RecordAsync(
        RollbackRetentionPurgeState state,
        string operationId,
        string sessionId,
        string retentionPlanId,
        string recoveryPlanId,
        string releaseRecordSha256,
        long sizeBytes,
        string quarantineRelativePath,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId);
        ValidateSessionId(sessionId);
        ValidateSha(retentionPlanId, nameof(retentionPlanId));
        ValidateSha(recoveryPlanId, nameof(recoveryPlanId));
        ValidateSha(releaseRecordSha256, nameof(releaseRecordSha256));
        if (sizeBytes < 0) throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        ValidateRelativeQuarantinePath(quarantineRelativePath);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var operation = _records
                    .Where(x => x.OperationId.Equals(operationId, StringComparison.Ordinal))
                    .OrderBy(x => x.Sequence)
                    .ToArray();

                var existing = operation.FirstOrDefault(x => x.State == state);
                if (existing is not null)
                    return existing;

                var expectedState = operation.Length switch
                {
                    0 => RollbackRetentionPurgeState.Intent,
                    1 when operation[0].State == RollbackRetentionPurgeState.Intent =>
                        RollbackRetentionPurgeState.Quarantined,
                    2 when operation[0].State == RollbackRetentionPurgeState.Intent &&
                           operation[1].State == RollbackRetentionPurgeState.Quarantined =>
                        RollbackRetentionPurgeState.Completed,
                    _ => throw new InvalidDataException("Retention purge operation has an invalid durable state sequence.")
                };

                if (state != expectedState)
                    throw new InvalidDataException(
                        $"Retention purge state '{state}' is invalid; expected '{expectedState}'.");

                if (operation.Length != 0 &&
                    operation.Any(x =>
                        !x.SessionId.Equals(sessionId, StringComparison.Ordinal) ||
                        !x.RetentionPlanId.Equals(retentionPlanId, StringComparison.OrdinalIgnoreCase) ||
                        !x.RecoveryPlanId.Equals(recoveryPlanId, StringComparison.OrdinalIgnoreCase) ||
                        !x.ReleaseRecordSha256.Equals(releaseRecordSha256, StringComparison.OrdinalIgnoreCase) ||
                        x.SizeBytes != sizeBytes ||
                        !x.QuarantineRelativePath.Equals(quarantineRelativePath, StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("Retention purge operation metadata changed between durable states.");
            }

            var sequence = checked(++_nextSequence);
            var payload = new RollbackRetentionPurgePayload(
                sequence,
                DateTime.UtcNow,
                state,
                operationId,
                sessionId,
                retentionPlanId.ToUpperInvariant(),
                recoveryPlanId.ToUpperInvariant(),
                releaseRecordSha256.ToUpperInvariant(),
                sizeBytes,
                quarantineRelativePath.Replace('\\', '/'),
                _lastRecordSha256);
            var hash = HashPayload(payload);
            var line = new RollbackRetentionPurgeLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.State,
                payload.OperationId,
                payload.SessionId,
                payload.RetentionPlanId,
                payload.RecoveryPlanId,
                payload.ReleaseRecordSha256,
                payload.SizeBytes,
                payload.QuarantineRelativePath,
                payload.PreviousRecordSha256,
                hash);

            AppendLine(line);
            _lastRecordSha256 = hash;
            var record = line.ToRecord();
            lock (_records) _records.Add(record);
            return record;
        }
        finally
        {
            _gate.Release();
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
                _lastRecordSha256 = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<RollbackRetentionPurgeRecord>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank rollback retention purge record.");

            RollbackRetentionPurgeLine line;
            try
            {
                line = JsonSerializer.Deserialize<RollbackRetentionPurgeLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid rollback retention purge record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rollback retention purge JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                !Enum.IsDefined(line.State) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid rollback retention purge fields.");

            ValidateOperationId(line.OperationId);
            ValidateSessionId(line.SessionId);
            ValidateSha(line.RetentionPlanId, nameof(line.RetentionPlanId));
            ValidateSha(line.RecoveryPlanId, nameof(line.RecoveryPlanId));
            ValidateSha(line.ReleaseRecordSha256, nameof(line.ReleaseRecordSha256));
            if (line.SizeBytes < 0)
                throw new InvalidDataException("Retention purge size cannot be negative.");
            ValidateRelativeQuarantinePath(line.QuarantineRelativePath);

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention purge hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback retention purge record hash mismatch.");

            rebuilt.Add(line.ToRecord());
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        foreach (var group in rebuilt.GroupBy(x => x.OperationId, StringComparer.Ordinal))
        {
            var states = group.OrderBy(x => x.Sequence).Select(x => x.State).ToArray();
            if (states.Length > 3 ||
                states[0] != RollbackRetentionPurgeState.Intent ||
                (states.Length >= 2 && states[1] != RollbackRetentionPurgeState.Quarantined) ||
                (states.Length == 3 && states[2] != RollbackRetentionPurgeState.Completed))
                throw new InvalidDataException("Rollback retention purge operation state sequence is invalid.");

            var first = group.OrderBy(x => x.Sequence).First();
            if (group.Any(x =>
                    !x.SessionId.Equals(first.SessionId, StringComparison.Ordinal) ||
                    !x.RetentionPlanId.Equals(first.RetentionPlanId, StringComparison.OrdinalIgnoreCase) ||
                    !x.RecoveryPlanId.Equals(first.RecoveryPlanId, StringComparison.OrdinalIgnoreCase) ||
                    !x.ReleaseRecordSha256.Equals(first.ReleaseRecordSha256, StringComparison.OrdinalIgnoreCase) ||
                    x.SizeBytes != first.SizeBytes ||
                    !x.QuarantineRelativePath.Equals(first.QuarantineRelativePath, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Rollback retention purge operation metadata drift detected.");
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

    private void AppendLine(RollbackRetentionPurgeLine line)
    {
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
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

    private string HashPayload(RollbackRetentionPurgePayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static void ValidateOperationId(string value)
    {
        if (value.Length != 32 || !value.All(char.IsAsciiHexDigit))
            throw new ArgumentException("Retention purge operation id must be 32 hex characters.", nameof(value));
    }

    private static void ValidateSessionId(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Length > 80)
            throw new ArgumentException("Invalid rollback session id.", nameof(sessionId));
        foreach (var c in sessionId)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new ArgumentException("Rollback session id contains an unsafe character.", nameof(sessionId));
    }

    private static void ValidateSha(string value, string parameterName)
    {
        if (!IsSha256(value))
            throw new ArgumentException("Expected SHA-256 value.", parameterName);
    }

    private static void ValidateRelativeQuarantinePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            Path.IsPathRooted(value) ||
            value.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(x => x is "." or ".."))
            throw new ArgumentException("Invalid retention quarantine relative path.", nameof(value));
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback retention purge store refuses reparse-point paths: " + path);
    }
}

public enum RollbackRetentionPurgeState
{
    Intent = 1,
    Quarantined = 2,
    Completed = 3
}

public sealed record RollbackRetentionPurgeRecord(
    long Sequence,
    DateTime ObservedUtc,
    RollbackRetentionPurgeState State,
    string OperationId,
    string SessionId,
    string RetentionPlanId,
    string RecoveryPlanId,
    string ReleaseRecordSha256,
    long SizeBytes,
    string QuarantineRelativePath,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record RollbackRetentionPurgePayload(
    long Sequence,
    DateTime ObservedUtc,
    RollbackRetentionPurgeState State,
    string OperationId,
    string SessionId,
    string RetentionPlanId,
    string RecoveryPlanId,
    string ReleaseRecordSha256,
    long SizeBytes,
    string QuarantineRelativePath,
    string PreviousRecordSha256);

internal sealed record RollbackRetentionPurgeLine(
    long Sequence,
    DateTime ObservedUtc,
    RollbackRetentionPurgeState State,
    string OperationId,
    string SessionId,
    string RetentionPlanId,
    string RecoveryPlanId,
    string ReleaseRecordSha256,
    long SizeBytes,
    string QuarantineRelativePath,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public RollbackRetentionPurgePayload Payload => new(
        Sequence, ObservedUtc, State, OperationId, SessionId, RetentionPlanId,
        RecoveryPlanId, ReleaseRecordSha256, SizeBytes, QuarantineRelativePath,
        PreviousRecordSha256);

    public RollbackRetentionPurgeRecord ToRecord() => new(
        Sequence, ObservedUtc, State, OperationId, SessionId, RetentionPlanId,
        RecoveryPlanId, ReleaseRecordSha256, SizeBytes, QuarantineRelativePath,
        PreviousRecordSha256, RecordSha256);
}
