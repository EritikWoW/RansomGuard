using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

public enum ContainmentEvidencePhase
{
    Requested = 1,
    KernelActive = 2
}

public sealed record ContainmentEvidence(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentEvidencePhase Phase,
    ulong KernelSequence,
    ulong ProcessId,
    long ProcessCreationFileTimeUtc,
    uint EventType,
    string Path,
    uint PreservationDecision,
    int EvidenceCount,
    int DistinctPathCount,
    uint KernelStatus,
    bool ContainmentActive,
    ulong ContainedProcessId,
    string PreviousRecordSha256,
    string RecordSha256);

public sealed class ContainmentEvidenceStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<ContainmentEvidence> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyList<ContainmentEvidence> Records
    {
        get { lock (_records) return _records.OrderBy(x => x.Sequence).ToArray(); }
    }

    public ContainmentEvidenceStore(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Containment evidence root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "containment-journal.jsonl");
        if (createIfMissing)
        {
            Directory.CreateDirectory(_root);
        }
        else if (!Directory.Exists(_root))
        {
            if (File.Exists(_root)) throw new IOException("Containment evidence root is not a directory: " + _root);
            throw new DirectoryNotFoundException("Containment evidence root does not exist: " + _root);
        }
        RejectReparse(_root);
        LoadAndValidateJournal();
    }

    public Task<ContainmentEvidence> RecordRequestAsync(
        ulong kernelSequence,
        ulong processId,
        long processCreationFileTimeUtc,
        uint eventType,
        string path,
        uint preservationDecision,
        int evidenceCount,
        int distinctPathCount,
        CancellationToken cancellationToken = default) =>
        RecordAsync(
            ContainmentEvidencePhase.Requested,
            kernelSequence,
            processId,
            processCreationFileTimeUtc,
            eventType,
            path,
            preservationDecision,
            evidenceCount,
            distinctPathCount,
            0,
            false,
            0,
            cancellationToken);

    public Task<ContainmentEvidence> RecordKernelActiveAsync(
        ulong kernelSequence,
        ulong processId,
        long processCreationFileTimeUtc,
        uint eventType,
        string path,
        uint preservationDecision,
        int evidenceCount,
        int distinctPathCount,
        uint kernelStatus,
        ulong containedProcessId,
        CancellationToken cancellationToken = default)
    {
        if (containedProcessId != processId)
            throw new InvalidDataException("Containment acknowledgement PID does not match the requested process.");

        return RecordAsync(
            ContainmentEvidencePhase.KernelActive,
            kernelSequence,
            processId,
            processCreationFileTimeUtc,
            eventType,
            path,
            preservationDecision,
            evidenceCount,
            distinctPathCount,
            kernelStatus,
            true,
            containedProcessId,
            cancellationToken);
    }

    public void VerifyAll() => LoadAndValidateJournal(rebuildState: false);

    private async Task<ContainmentEvidence> RecordAsync(
        ContainmentEvidencePhase phase,
        ulong kernelSequence,
        ulong processId,
        long processCreationFileTimeUtc,
        uint eventType,
        string path,
        uint preservationDecision,
        int evidenceCount,
        int distinctPathCount,
        uint kernelStatus,
        bool containmentActive,
        ulong containedProcessId,
        CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(phase)) throw new InvalidDataException("Invalid containment evidence phase.");
        if (kernelSequence == 0) throw new ArgumentOutOfRangeException(nameof(kernelSequence));
        if (processId <= 4) throw new ArgumentOutOfRangeException(nameof(processId));
        if (processCreationFileTimeUtc <= 0) throw new ArgumentOutOfRangeException(nameof(processCreationFileTimeUtc));
        if (eventType == 0) throw new ArgumentOutOfRangeException(nameof(eventType));
        if (preservationDecision == 0) throw new ArgumentOutOfRangeException(nameof(preservationDecision));
        if (evidenceCount < 1 || distinctPathCount < 1 || distinctPathCount > evidenceCount)
            throw new InvalidDataException("Invalid containment trigger counters.");
        if (phase == ContainmentEvidencePhase.Requested &&
            (kernelStatus != 0 || containmentActive || containedProcessId != 0))
            throw new InvalidDataException("Containment request evidence cannot claim kernel activation.");
        if (phase == ContainmentEvidencePhase.KernelActive &&
            (kernelStatus != 0 || !containmentActive || containedProcessId != processId))
            throw new InvalidDataException("Kernel-active containment evidence must report STATUS_SUCCESS and bind the requested PID.");

        var full = NormalizePath(path);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_records)
            {
                var existing = _records.SingleOrDefault(x =>
                    x.KernelSequence == kernelSequence &&
                    x.Phase == phase);
                if (existing is not null)
                {
                    if (existing.ProcessId == processId &&
                        existing.ProcessCreationFileTimeUtc == processCreationFileTimeUtc &&
                        existing.EventType == eventType &&
                        existing.Path.Equals(full, StringComparison.OrdinalIgnoreCase) &&
                        existing.PreservationDecision == preservationDecision &&
                        existing.EvidenceCount == evidenceCount &&
                        existing.DistinctPathCount == distinctPathCount &&
                        existing.KernelStatus == kernelStatus &&
                        existing.ContainmentActive == containmentActive &&
                        existing.ContainedProcessId == containedProcessId)
                        return existing;

                    throw new InvalidDataException("Conflicting duplicate containment evidence.");
                }

                if (phase == ContainmentEvidencePhase.KernelActive)
                {
                    var request = _records.SingleOrDefault(x =>
                        x.KernelSequence == kernelSequence &&
                        x.Phase == ContainmentEvidencePhase.Requested);
                    if (request is null ||
                        request.ProcessId != processId ||
                        request.ProcessCreationFileTimeUtc != processCreationFileTimeUtc ||
                        request.EventType != eventType ||
                        !request.Path.Equals(full, StringComparison.OrdinalIgnoreCase) ||
                        request.PreservationDecision != preservationDecision ||
                        request.EvidenceCount != evidenceCount ||
                        request.DistinctPathCount != distinctPathCount)
                        throw new InvalidDataException("Containment kernel-active evidence is not linked to the exact durable request.");
                }
            }

            var sequence = checked(++_nextSequence);
            var payload = new ContainmentPayload(
                sequence,
                DateTime.UtcNow,
                phase,
                kernelSequence,
                processId,
                processCreationFileTimeUtc,
                eventType,
                full,
                preservationDecision,
                evidenceCount,
                distinctPathCount,
                kernelStatus,
                containmentActive,
                containedProcessId,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new ContainmentLine(
                payload.Sequence,
                payload.ObservedUtc,
                payload.Phase,
                payload.KernelSequence,
                payload.ProcessId,
                payload.ProcessCreationFileTimeUtc,
                payload.EventType,
                payload.Path,
                payload.PreservationDecision,
                payload.EvidenceCount,
                payload.DistinctPathCount,
                payload.KernelStatus,
                payload.ContainmentActive,
                payload.ContainedProcessId,
                payload.PreviousRecordSha256,
                recordHash);

            AppendLine(line);
            _lastRecordHash = recordHash;
            var record = line.ToEvidence();
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
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var rebuilt = new List<ContainmentEvidence>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var requested = new Dictionary<ulong, ContainmentEvidence>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank containment evidence journal record.");

            ContainmentLine line;
            try
            {
                line = JsonSerializer.Deserialize<ContainmentLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid containment evidence journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid containment evidence journal JSON.", ex);
            }

            var key = $"{(int)line.Phase}:{line.KernelSequence}";
            if (line.Sequence != expectedSequence ||
                line.KernelSequence == 0 ||
                line.ProcessId <= 4 ||
                line.ProcessCreationFileTimeUtc <= 0 ||
                line.EventType == 0 ||
                line.PreservationDecision == 0 ||
                line.EvidenceCount < 1 ||
                line.DistinctPathCount < 1 ||
                line.DistinctPathCount > line.EvidenceCount ||
                !Enum.IsDefined(line.Phase) ||
                !keys.Add(key) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid containment evidence journal fields.");

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment evidence journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment evidence journal record hash mismatch.");

            var full = NormalizePath(line.Path);
            var evidence = line.ToEvidence() with { Path = full };
            if (line.Phase == ContainmentEvidencePhase.Requested)
            {
                if (line.KernelStatus != 0 || line.ContainmentActive || line.ContainedProcessId != 0)
                    throw new InvalidDataException("Containment request record claims kernel activation.");
                requested.Add(line.KernelSequence, evidence);
            }
            else
            {
                if (!requested.TryGetValue(line.KernelSequence, out var request) ||
                    line.KernelStatus != 0 ||
                    !line.ContainmentActive ||
                    line.ContainedProcessId != line.ProcessId ||
                    request.ProcessId != line.ProcessId ||
                    request.ProcessCreationFileTimeUtc != line.ProcessCreationFileTimeUtc ||
                    request.EventType != line.EventType ||
                    !request.Path.Equals(full, StringComparison.OrdinalIgnoreCase) ||
                    request.PreservationDecision != line.PreservationDecision ||
                    request.EvidenceCount != line.EvidenceCount ||
                    request.DistinctPathCount != line.DistinctPathCount)
                    throw new InvalidDataException("Containment kernel-active record is not linked to the exact durable request.");
            }

            rebuilt.Add(evidence);
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
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendLine(ContainmentLine line)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, _json) + "\n");
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(ContainmentPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Containment evidence path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Containment evidence store must not be a reparse point: " + path);
    }
}

internal sealed record ContainmentPayload(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentEvidencePhase Phase,
    ulong KernelSequence,
    ulong ProcessId,
    long ProcessCreationFileTimeUtc,
    uint EventType,
    string Path,
    uint PreservationDecision,
    int EvidenceCount,
    int DistinctPathCount,
    uint KernelStatus,
    bool ContainmentActive,
    ulong ContainedProcessId,
    string PreviousRecordSha256);

internal sealed record ContainmentLine(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentEvidencePhase Phase,
    ulong KernelSequence,
    ulong ProcessId,
    long ProcessCreationFileTimeUtc,
    uint EventType,
    string Path,
    uint PreservationDecision,
    int EvidenceCount,
    int DistinctPathCount,
    uint KernelStatus,
    bool ContainmentActive,
    ulong ContainedProcessId,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public ContainmentPayload Payload => new(
        Sequence,
        ObservedUtc,
        Phase,
        KernelSequence,
        ProcessId,
        ProcessCreationFileTimeUtc,
        EventType,
        Path,
        PreservationDecision,
        EvidenceCount,
        DistinctPathCount,
        KernelStatus,
        ContainmentActive,
        ContainedProcessId,
        PreviousRecordSha256);

    public ContainmentEvidence ToEvidence() => new(
        Sequence,
        ObservedUtc,
        Phase,
        KernelSequence,
        ProcessId,
        ProcessCreationFileTimeUtc,
        EventType,
        Path,
        PreservationDecision,
        EvidenceCount,
        DistinctPathCount,
        KernelStatus,
        ContainmentActive,
        ContainedProcessId,
        PreviousRecordSha256,
        RecordSha256);
}
