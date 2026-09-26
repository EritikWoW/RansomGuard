using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Core;

public enum ContainmentActuationLedgerPhase
{
    Prepared = 1,
    SuspendOwned = 2,
    SuspendCompleted = 3,
    ResumeOwned = 4,
    ResumeCompleted = 5,
    Failed = 6
}

public enum ContainmentActuationResultState
{
    Prepared = 1,
    InProgress = 2,
    Suspended = 3,
    Resumed = 4,
    Failed = 5,
    FailedRecovered = 6
}

public sealed record ContainmentActuationRequest(
    string RequestId,
    ContainmentActuationBinding Binding,
    DateTime RequestedUtc);

public sealed record ContainmentActuationResult(
    string RequestId,
    string AuthorizationId,
    string State,
    DateTime ObservedUtc,
    int OwnedSuspendCount,
    string[] ReasonCodes);

public sealed record ContainmentActuationLedgerEntry(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentActuationLedgerPhase Phase,
    string RequestId,
    string AuthorizationId,
    string CaseId,
    DateTime AuthorizationEvaluatedUtc,
    DateTime AuthorizationExpiresUtc,
    int ProcessId,
    long ProcessCreationFileTimeUtc,
    string ImagePath,
    string ImageSha256,
    DateTime ProtectionObservedUtc,
    uint ThreadId,
    string ReasonCode,
    string PreviousRecordSha256,
    string RecordSha256);

public sealed class ContainmentActuationLedger
{
    private const string JournalName = "containment-actuation-journal.jsonl";
    private const string PreparedReason = "ValidationReady";
    private const string SuspendOwnedReason = "SuspendIncrementOwned";
    private const string SuspendCompletedReason = "SuspendCompleted";
    private const string ResumeOwnedReason = "OwnedSuspendIncrementResumed";
    private const string ResumeCompletedReason = "ResumeCompleted";

    private readonly string _root;
    private readonly string _journal;
    private readonly object _gate = new();
    private readonly List<ContainmentActuationLedgerEntry> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;

    public IReadOnlyList<ContainmentActuationLedgerEntry> Records
    {
        get
        {
            lock (_gate)
                return _records.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public ContainmentActuationLedger(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Containment actuation ledger root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, JournalName);

        RejectReparseChain(_root);
        if (createIfMissing)
            Directory.CreateDirectory(_root);
        else if (!Directory.Exists(_root))
        {
            if (File.Exists(_root))
                throw new IOException("Containment actuation ledger root is not a directory: " + _root);
            throw new DirectoryNotFoundException("Containment actuation ledger root does not exist: " + _root);
        }

        RejectReparseChain(_root);
        RejectReparseChain(_journal);
        LoadAndValidateJournal();
    }

    public bool IsAuthorizationConsumed(string authorizationId)
    {
        if (!IsGuidN(authorizationId))
            return true;

        lock (_gate)
            return _records.Any(x =>
                x.Phase == ContainmentActuationLedgerPhase.Prepared &&
                string.Equals(x.AuthorizationId, authorizationId, StringComparison.OrdinalIgnoreCase));
    }

    public ContainmentActuationLedgerEntry Prepare(
        ContainmentActuationRequest request,
        ContainmentActuationValidationDecision validation)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(validation);

        if (!validation.Ready ||
            !string.Equals(validation.State, ContainmentActuationValidationState.Ready.ToString(), StringComparison.Ordinal) ||
            validation.Reasons is null ||
            validation.Reasons.Length != 0)
            throw new InvalidOperationException("Actuation preparation requires a current Ready validation decision.");

        var normalized = NormalizeRequest(request);

        lock (_gate)
        {
            var byRequest = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.Prepared &&
                string.Equals(x.RequestId, normalized.RequestId, StringComparison.OrdinalIgnoreCase));
            if (byRequest is not null)
            {
                if (SameBinding(byRequest, normalized.Binding))
                    return byRequest;
                throw new InvalidDataException("Conflicting duplicate containment actuation request id.");
            }

            var consumed = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.Prepared &&
                string.Equals(x.AuthorizationId, normalized.Binding.AuthorizationId, StringComparison.OrdinalIgnoreCase));
            if (consumed is not null)
                throw new InvalidOperationException("AuthorizationAlreadyConsumed");

            return Append(
                ContainmentActuationLedgerPhase.Prepared,
                normalized.RequestId,
                normalized.Binding,
                0,
                PreparedReason,
                normalized.RequestedUtc);
        }
    }

    public ContainmentActuationLedgerEntry RecordSuspendOwned(string requestId, uint threadId)
    {
        if (threadId == 0)
            throw new ArgumentOutOfRangeException(nameof(threadId));

        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.ResumeCompleted, "RequestAlreadyResumed");
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.Failed, "RequestAlreadyFailed");
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.SuspendCompleted, "SuspendAlreadyCompleted");

            var existing = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendOwned &&
                RequestEquals(x, requestId) &&
                x.ThreadId == threadId);
            if (existing is not null)
                return existing;

            if (_records.Any(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeOwned &&
                RequestEquals(x, requestId) &&
                x.ThreadId == threadId))
                throw new InvalidOperationException("ThreadOwnershipAlreadyReleased");

            return Append(
                ContainmentActuationLedgerPhase.SuspendOwned,
                prepared.RequestId,
                BindingFrom(prepared),
                threadId,
                SuspendOwnedReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentActuationLedgerEntry RecordSuspendCompleted(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.ResumeCompleted, "RequestAlreadyResumed");
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.Failed, "RequestAlreadyFailed");

            var existing = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendCompleted &&
                RequestEquals(x, requestId));
            if (existing is not null)
                return existing;

            if (!_records.Any(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendOwned &&
                RequestEquals(x, requestId)))
                throw new InvalidOperationException("NoOwnedSuspendIncrement");
            if (_records.Any(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeOwned &&
                RequestEquals(x, requestId)))
                throw new InvalidOperationException("ResumeAlreadyStarted");

            return Append(
                ContainmentActuationLedgerPhase.SuspendCompleted,
                prepared.RequestId,
                BindingFrom(prepared),
                0,
                SuspendCompletedReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentActuationLedgerEntry RecordResumeOwned(string requestId, uint threadId)
    {
        if (threadId == 0)
            throw new ArgumentOutOfRangeException(nameof(threadId));

        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.ResumeCompleted, "RequestAlreadyResumed");

            var mayResume =
                _records.Any(x => x.Phase == ContainmentActuationLedgerPhase.SuspendCompleted && RequestEquals(x, requestId)) ||
                _records.Any(x => x.Phase == ContainmentActuationLedgerPhase.Failed && RequestEquals(x, requestId));
            if (!mayResume)
                throw new InvalidOperationException("ResumeNotAuthorizedBySuspendCompletionOrFailure");

            var owned = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendOwned &&
                RequestEquals(x, requestId) &&
                x.ThreadId == threadId)
                ?? throw new InvalidOperationException("SuspendIncrementNotOwned");

            var existing = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeOwned &&
                RequestEquals(x, requestId) &&
                x.ThreadId == threadId);
            if (existing is not null)
                return existing;

            return Append(
                ContainmentActuationLedgerPhase.ResumeOwned,
                prepared.RequestId,
                BindingFrom(owned),
                threadId,
                ResumeOwnedReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentActuationLedgerEntry RecordResumeCompleted(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var existing = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeCompleted &&
                RequestEquals(x, requestId));
            if (existing is not null)
                return existing;

            var owned = _records.Where(x =>
                x.Phase == ContainmentActuationLedgerPhase.SuspendOwned &&
                RequestEquals(x, requestId)).Select(x => x.ThreadId).Distinct().ToArray();
            if (owned.Length == 0)
                throw new InvalidOperationException("NoOwnedSuspendIncrement");
            var mayCompleteResume =
                _records.Any(x => x.Phase == ContainmentActuationLedgerPhase.SuspendCompleted && RequestEquals(x, requestId)) ||
                _records.Any(x => x.Phase == ContainmentActuationLedgerPhase.Failed && RequestEquals(x, requestId));
            if (!mayCompleteResume)
                throw new InvalidOperationException("ResumeNotAuthorizedBySuspendCompletionOrFailure");

            var resumed = _records.Where(x =>
                x.Phase == ContainmentActuationLedgerPhase.ResumeOwned &&
                RequestEquals(x, requestId)).Select(x => x.ThreadId).Distinct().ToHashSet();
            if (owned.Any(x => !resumed.Contains(x)))
                throw new InvalidOperationException("OwnedSuspendIncrementStillOutstanding");

            return Append(
                ContainmentActuationLedgerPhase.ResumeCompleted,
                prepared.RequestId,
                BindingFrom(prepared),
                0,
                ResumeCompletedReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentActuationLedgerEntry RecordFailed(string requestId, string reasonCode)
    {
        ValidateReasonCode(reasonCode);

        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            EnsureNoPhase(requestId, ContainmentActuationLedgerPhase.ResumeCompleted, "RequestAlreadyResumed");

            var existing = _records.FirstOrDefault(x =>
                x.Phase == ContainmentActuationLedgerPhase.Failed &&
                RequestEquals(x, requestId));
            if (existing is not null)
            {
                if (string.Equals(existing.ReasonCode, reasonCode, StringComparison.Ordinal))
                    return existing;
                throw new InvalidDataException("Conflicting containment actuation failure reason.");
            }

            return Append(
                ContainmentActuationLedgerPhase.Failed,
                prepared.RequestId,
                BindingFrom(prepared),
                0,
                reasonCode,
                DateTime.UtcNow);
        }
    }

    public ContainmentActuationResult ResultFor(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var requestRecords = _records.Where(x => RequestEquals(x, prepared.RequestId)).OrderBy(x => x.Sequence).ToArray();
            var owned = requestRecords.Where(x => x.Phase == ContainmentActuationLedgerPhase.SuspendOwned)
                .Select(x => x.ThreadId).Distinct().ToHashSet();
            var resumed = requestRecords.Where(x => x.Phase == ContainmentActuationLedgerPhase.ResumeOwned)
                .Select(x => x.ThreadId).Distinct().ToHashSet();
            var outstanding = owned.Count(x => !resumed.Contains(x));
            var failed = requestRecords.Where(x => x.Phase == ContainmentActuationLedgerPhase.Failed).ToArray();
            var resumeCompleted = requestRecords.Any(x => x.Phase == ContainmentActuationLedgerPhase.ResumeCompleted);
            var suspendCompleted = requestRecords.Any(x => x.Phase == ContainmentActuationLedgerPhase.SuspendCompleted);

            var state = failed.Length > 0
                ? resumeCompleted
                    ? ContainmentActuationResultState.FailedRecovered
                    : ContainmentActuationResultState.Failed
                : resumeCompleted
                    ? ContainmentActuationResultState.Resumed
                    : suspendCompleted
                        ? ContainmentActuationResultState.Suspended
                        : owned.Count > 0
                            ? ContainmentActuationResultState.InProgress
                            : ContainmentActuationResultState.Prepared;

            return new(
                prepared.RequestId,
                prepared.AuthorizationId,
                state.ToString(),
                requestRecords[^1].ObservedUtc,
                outstanding,
                failed.Select(x => x.ReasonCode).Distinct(StringComparer.Ordinal).ToArray());
        }
    }

    public void VerifyAll()
    {
        lock (_gate)
            LoadAndValidateJournal(rebuildState: false);
    }

    private ContainmentActuationLedgerEntry RequirePrepared(string requestId)
    {
        if (!IsGuidN(requestId))
            throw new ArgumentException("Request id must be a 32-character GUID in N format.", nameof(requestId));

        return _records.FirstOrDefault(x =>
            x.Phase == ContainmentActuationLedgerPhase.Prepared &&
            RequestEquals(x, requestId))
            ?? throw new InvalidOperationException("ActuationRequestNotPrepared");
    }

    private void EnsureNoPhase(string requestId, ContainmentActuationLedgerPhase phase, string reason)
    {
        if (_records.Any(x => x.Phase == phase && RequestEquals(x, requestId)))
            throw new InvalidOperationException(reason);
    }

    private ContainmentActuationLedgerEntry Append(
        ContainmentActuationLedgerPhase phase,
        string requestId,
        ContainmentActuationBinding binding,
        uint threadId,
        string reasonCode,
        DateTime observedUtc)
    {
        ValidateReasonCode(reasonCode);
        if (observedUtc.Kind != DateTimeKind.Utc)
            throw new InvalidDataException("Actuation ledger timestamps must be UTC.");

        var normalizedPath = WinPaths.Normalize(binding.ImagePath)
            ?? throw new InvalidDataException("Actuation ledger image path is invalid.");

        var sequence = checked(++_nextSequence);
        var payload = new ContainmentActuationLedgerPayload(
            sequence,
            observedUtc,
            phase,
            requestId.ToLowerInvariant(),
            binding.AuthorizationId.ToLowerInvariant(),
            binding.CaseId,
            binding.EvaluatedUtc,
            binding.ExpiresUtc,
            binding.Process.Pid,
            binding.Process.CreationFileTimeUtc,
            normalizedPath,
            binding.ImageSha256.ToUpperInvariant(),
            binding.ProtectionObservedUtc,
            threadId,
            reasonCode,
            _lastRecordHash);
        var recordHash = HashPayload(payload);
        var line = new ContainmentActuationLedgerLine(
            payload.Sequence,
            payload.ObservedUtc,
            payload.Phase,
            payload.RequestId,
            payload.AuthorizationId,
            payload.CaseId,
            payload.AuthorizationEvaluatedUtc,
            payload.AuthorizationExpiresUtc,
            payload.ProcessId,
            payload.ProcessCreationFileTimeUtc,
            payload.ImagePath,
            payload.ImageSha256,
            payload.ProtectionObservedUtc,
            payload.ThreadId,
            payload.ReasonCode,
            payload.PreviousRecordSha256,
            recordHash);

        AppendLine(line);
        _lastRecordHash = recordHash;
        var record = line.ToEntry();
        _records.Add(record);
        return record;
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                _records.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparseChain(_journal);
        var rebuilt = new List<ContainmentActuationLedgerEntry>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank containment actuation ledger record.");

            ContainmentActuationLedgerLine line;
            try
            {
                line = JsonSerializer.Deserialize<ContainmentActuationLedgerLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid containment actuation ledger record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid containment actuation ledger JSON.", ex);
            }

            if (line.Sequence != expectedSequence ||
                !Enum.IsDefined(line.Phase) ||
                line.ObservedUtc.Kind != DateTimeKind.Utc ||
                !IsGuidN(line.RequestId) ||
                !IsGuidN(line.AuthorizationId) ||
                string.IsNullOrWhiteSpace(line.CaseId) ||
                line.AuthorizationEvaluatedUtc.Kind != DateTimeKind.Utc ||
                line.AuthorizationExpiresUtc.Kind != DateTimeKind.Utc ||
                line.AuthorizationExpiresUtc <= line.AuthorizationEvaluatedUtc ||
                line.AuthorizationExpiresUtc - line.AuthorizationEvaluatedUtc > ContainmentActuationPolicy.MaxAuthorizationLifetime ||
                line.ProcessId <= 4 ||
                line.ProcessCreationFileTimeUtc <= 0 ||
                WinPaths.Normalize(line.ImagePath) is null ||
                !DecisionPolicy.HashEqual(line.ImageSha256, line.ImageSha256) ||
                line.ProtectionObservedUtc.Kind != DateTimeKind.Utc ||
                !ValidThreadField(line.Phase, line.ThreadId) ||
                !IsReasonCode(line.ReasonCode) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid containment actuation ledger fields.");

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment actuation ledger hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment actuation ledger record hash mismatch.");

            rebuilt.Add(line.ToEntry() with
            {
                ImagePath = WinPaths.Normalize(line.ImagePath)!,
                ImageSha256 = line.ImageSha256.ToUpperInvariant()
            });
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        ValidateReplay(rebuilt);

        if (rebuildState)
        {
            _records.Clear();
            _records.AddRange(rebuilt);
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void ValidateReplay(IReadOnlyList<ContainmentActuationLedgerEntry> entries)
    {
        var authorizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var group in entries.GroupBy(x => x.RequestId, StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group.OrderBy(x => x.Sequence).ToArray();
            if (ordered.Length == 0 || ordered[0].Phase != ContainmentActuationLedgerPhase.Prepared)
                throw new InvalidDataException("Actuation ledger request does not begin with Prepared.");

            var first = ordered[0];
            if (!authorizations.TryAdd(first.AuthorizationId, first.RequestId))
                throw new InvalidDataException("Actuation authorization was consumed by more than one request.");

            if (first.ThreadId != 0 || !string.Equals(first.ReasonCode, PreparedReason, StringComparison.Ordinal))
                throw new InvalidDataException("Invalid Prepared actuation ledger record.");

            var owned = new HashSet<uint>();
            var resumed = new HashSet<uint>();
            var suspendCompleted = false;
            var resumeCompleted = false;
            var failed = false;

            foreach (var record in ordered.Skip(1))
            {
                if (!SameIdentity(first, record))
                    throw new InvalidDataException("Actuation ledger identity changed inside one request.");
                if (resumeCompleted)
                    throw new InvalidDataException("Actuation ledger contains records after ResumeCompleted.");

                switch (record.Phase)
                {
                    case ContainmentActuationLedgerPhase.Prepared:
                        throw new InvalidDataException("Duplicate Prepared actuation ledger record.");
                    case ContainmentActuationLedgerPhase.SuspendOwned:
                        if (failed || suspendCompleted || !owned.Add(record.ThreadId) ||
                            !string.Equals(record.ReasonCode, SuspendOwnedReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid SuspendOwned transition.");
                        break;
                    case ContainmentActuationLedgerPhase.SuspendCompleted:
                        if (failed || suspendCompleted || owned.Count == 0 || record.ThreadId != 0 ||
                            !string.Equals(record.ReasonCode, SuspendCompletedReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid SuspendCompleted transition.");
                        suspendCompleted = true;
                        break;
                    case ContainmentActuationLedgerPhase.ResumeOwned:
                        if ((!suspendCompleted && !failed) ||
                            !owned.Contains(record.ThreadId) ||
                            !resumed.Add(record.ThreadId) ||
                            !string.Equals(record.ReasonCode, ResumeOwnedReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid ResumeOwned transition.");
                        break;
                    case ContainmentActuationLedgerPhase.ResumeCompleted:
                        if ((!suspendCompleted && !failed) ||
                            owned.Count == 0 ||
                            owned.Any(x => !resumed.Contains(x)) ||
                            record.ThreadId != 0 ||
                            !string.Equals(record.ReasonCode, ResumeCompletedReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid ResumeCompleted transition.");
                        resumeCompleted = true;
                        break;
                    case ContainmentActuationLedgerPhase.Failed:
                        if (failed || record.ThreadId != 0)
                            throw new InvalidDataException("Invalid Failed transition.");
                        failed = true;
                        break;
                    default:
                        throw new InvalidDataException("Unknown actuation ledger transition.");
                }
            }
        }
    }

    private void AppendLine(ContainmentActuationLedgerLine line)
    {
        RejectReparseChain(_root);
        RejectReparseChain(_journal);
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
        RejectReparseChain(_journal);
    }

    private ContainmentActuationRequest NormalizeRequest(ContainmentActuationRequest request)
    {
        if (!IsGuidN(request.RequestId))
            throw new ArgumentException("Request id must be a 32-character GUID in N format.", nameof(request));
        if (request.RequestedUtc.Kind != DateTimeKind.Utc)
            throw new InvalidDataException("RequestedUtc must be UTC.");

        var binding = request.Binding ?? throw new InvalidDataException("Actuation binding is required.");
        if (!IsGuidN(binding.AuthorizationId))
            throw new InvalidDataException("Authorization id must be a 32-character GUID in N format.");
        if (string.IsNullOrWhiteSpace(binding.CaseId))
            throw new InvalidDataException("Case id is required.");
        if (binding.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            binding.ExpiresUtc.Kind != DateTimeKind.Utc ||
            binding.ExpiresUtc <= binding.EvaluatedUtc ||
            binding.ExpiresUtc - binding.EvaluatedUtc > ContainmentActuationPolicy.MaxAuthorizationLifetime)
            throw new InvalidDataException("Authorization lifetime is invalid.");
        if (request.RequestedUtc < binding.EvaluatedUtc || request.RequestedUtc > binding.ExpiresUtc)
            throw new InvalidDataException("Actuation request is outside the authorization lifetime.");
        if (binding.Process.Pid <= 4 || binding.Process.CreationFileTimeUtc <= 0)
            throw new InvalidDataException("Bound process identity is invalid.");
        var imagePath = WinPaths.Normalize(binding.ImagePath)
            ?? throw new InvalidDataException("Bound image path is invalid.");
        if (!DecisionPolicy.HashEqual(binding.ImageSha256, binding.ImageSha256))
            throw new InvalidDataException("Bound image SHA-256 is invalid.");
        if (binding.ProtectionObservedUtc.Kind != DateTimeKind.Utc)
            throw new InvalidDataException("ProtectionObservedUtc must be UTC.");
        if (binding.Authorization is null ||
            !binding.Authorization.Eligible ||
            !string.Equals(binding.Authorization.State, ContainmentAuthorizationState.Eligible.ToString(), StringComparison.Ordinal) ||
            binding.Authorization.Reasons is null ||
            binding.Authorization.Reasons.Length != 0)
            throw new InvalidDataException("Bound authorization is not Eligible.");

        return request with
        {
            RequestId = request.RequestId.ToLowerInvariant(),
            Binding = binding with
            {
                AuthorizationId = binding.AuthorizationId.ToLowerInvariant(),
                ImagePath = imagePath,
                ImageSha256 = binding.ImageSha256.ToUpperInvariant()
            }
        };
    }

    private static ContainmentActuationBinding BindingFrom(ContainmentActuationLedgerEntry entry) =>
        new(
            entry.AuthorizationId,
            entry.CaseId,
            entry.AuthorizationEvaluatedUtc,
            entry.AuthorizationExpiresUtc,
            new ProcessKey(entry.ProcessId, entry.ProcessCreationFileTimeUtc),
            entry.ImagePath,
            entry.ImageSha256,
            entry.ProtectionObservedUtc,
            new(ContainmentAuthorizationState.Eligible.ToString(), true, Array.Empty<string>()));

    private static bool SameBinding(ContainmentActuationLedgerEntry entry, ContainmentActuationBinding binding) =>
        string.Equals(entry.AuthorizationId, binding.AuthorizationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(entry.CaseId, binding.CaseId, StringComparison.Ordinal) &&
        entry.AuthorizationEvaluatedUtc == binding.EvaluatedUtc &&
        entry.AuthorizationExpiresUtc == binding.ExpiresUtc &&
        entry.ProcessId == binding.Process.Pid &&
        entry.ProcessCreationFileTimeUtc == binding.Process.CreationFileTimeUtc &&
        WinPaths.Equal(entry.ImagePath, binding.ImagePath) &&
        DecisionPolicy.HashEqual(entry.ImageSha256, binding.ImageSha256) &&
        entry.ProtectionObservedUtc == binding.ProtectionObservedUtc;

    private static bool SameIdentity(ContainmentActuationLedgerEntry left, ContainmentActuationLedgerEntry right) =>
        string.Equals(left.RequestId, right.RequestId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.AuthorizationId, right.AuthorizationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        left.AuthorizationEvaluatedUtc == right.AuthorizationEvaluatedUtc &&
        left.AuthorizationExpiresUtc == right.AuthorizationExpiresUtc &&
        left.ProcessId == right.ProcessId &&
        left.ProcessCreationFileTimeUtc == right.ProcessCreationFileTimeUtc &&
        WinPaths.Equal(left.ImagePath, right.ImagePath) &&
        DecisionPolicy.HashEqual(left.ImageSha256, right.ImageSha256) &&
        left.ProtectionObservedUtc == right.ProtectionObservedUtc;

    private static bool RequestEquals(ContainmentActuationLedgerEntry entry, string requestId) =>
        string.Equals(entry.RequestId, requestId, StringComparison.OrdinalIgnoreCase);

    private string HashPayload(ContainmentActuationLedgerPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool ValidThreadField(ContainmentActuationLedgerPhase phase, uint threadId) =>
        phase is ContainmentActuationLedgerPhase.SuspendOwned or ContainmentActuationLedgerPhase.ResumeOwned
            ? threadId != 0
            : threadId == 0;

    private static void ValidateReasonCode(string value)
    {
        if (!IsReasonCode(value))
            throw new ArgumentException("Reason code must be 1-64 ASCII letters, digits, '.', '_' or '-'.", nameof(value));
    }

    private static bool IsReasonCode(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 64 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    private static bool IsGuidN(string? value) =>
        value is not null && Guid.TryParseExact(value, "N", out _);

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static void RejectReparseChain(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full)
            ?? throw new IOException("Path has no filesystem root: " + full);
        var cursor = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var relative = full[root.Length..];

        foreach (var segment in relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries))
        {
            cursor = Path.Combine(cursor, segment);
            if (!File.Exists(cursor) && !Directory.Exists(cursor))
                break;
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Containment actuation ledger must not traverse a reparse point: " + cursor);
        }
    }
}

internal sealed record ContainmentActuationLedgerPayload(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentActuationLedgerPhase Phase,
    string RequestId,
    string AuthorizationId,
    string CaseId,
    DateTime AuthorizationEvaluatedUtc,
    DateTime AuthorizationExpiresUtc,
    int ProcessId,
    long ProcessCreationFileTimeUtc,
    string ImagePath,
    string ImageSha256,
    DateTime ProtectionObservedUtc,
    uint ThreadId,
    string ReasonCode,
    string PreviousRecordSha256);

internal sealed record ContainmentActuationLedgerLine(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentActuationLedgerPhase Phase,
    string RequestId,
    string AuthorizationId,
    string CaseId,
    DateTime AuthorizationEvaluatedUtc,
    DateTime AuthorizationExpiresUtc,
    int ProcessId,
    long ProcessCreationFileTimeUtc,
    string ImagePath,
    string ImageSha256,
    DateTime ProtectionObservedUtc,
    uint ThreadId,
    string ReasonCode,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public ContainmentActuationLedgerPayload Payload => new(
        Sequence,
        ObservedUtc,
        Phase,
        RequestId,
        AuthorizationId,
        CaseId,
        AuthorizationEvaluatedUtc,
        AuthorizationExpiresUtc,
        ProcessId,
        ProcessCreationFileTimeUtc,
        ImagePath,
        ImageSha256,
        ProtectionObservedUtc,
        ThreadId,
        ReasonCode,
        PreviousRecordSha256);

    public ContainmentActuationLedgerEntry ToEntry() => new(
        Sequence,
        ObservedUtc,
        Phase,
        RequestId,
        AuthorizationId,
        CaseId,
        AuthorizationEvaluatedUtc,
        AuthorizationExpiresUtc,
        ProcessId,
        ProcessCreationFileTimeUtc,
        ImagePath,
        ImageSha256,
        ProtectionObservedUtc,
        ThreadId,
        ReasonCode,
        PreviousRecordSha256,
        RecordSha256);
}
