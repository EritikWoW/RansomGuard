using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Core;

public enum ContainmentStateChangeJournalPhase
{
    Prepared = 1,
    SuspendApplied = 2,
    ExplicitResumeApplied = 3,
    Completed = 4,
    Abnormal = 5
}

public sealed record ContainmentStateChangeJournalEntry(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentStateChangeJournalPhase Phase,
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
    string BindingFingerprint,
    string ReasonCode,
    string PreviousRecordSha256,
    string RecordSha256);

public sealed class ContainmentStateChangeJournal
{
    private const string JournalName = "containment-state-change-journal.jsonl";
    private const string PreparedReason = "ValidationReady";
    private const string SuspendReason = "StateChangeSuspendApplied";
    private const string ResumeReason = "StateChangeExplicitResumeApplied";
    private const string CompletedReason = "StateChangeSessionCompleted";

    private readonly string _root;
    private readonly string _journal;
    private readonly object _gate = new();
    private readonly List<ContainmentStateChangeJournalEntry> _records = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;

    public IReadOnlyList<ContainmentStateChangeJournalEntry> Records
    {
        get
        {
            lock (_gate)
                return _records.OrderBy(x => x.Sequence).ToArray();
        }
    }

    public ContainmentStateChangeJournal(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Containment state-change journal root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, JournalName);
        RejectReparseChain(_root);

        if (createIfMissing)
            Directory.CreateDirectory(_root);
        else if (!Directory.Exists(_root))
            throw new DirectoryNotFoundException("Containment state-change journal root does not exist: " + _root);

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
                x.Phase == ContainmentStateChangeJournalPhase.Prepared &&
                string.Equals(x.AuthorizationId, authorizationId, StringComparison.OrdinalIgnoreCase));
    }

    public ContainmentStateChangeJournalEntry Prepare(
        ContainmentActuationRequest request,
        ContainmentActuationValidationDecision validation)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(validation);

        if (!validation.Ready ||
            !string.Equals(validation.State, ContainmentActuationValidationState.Ready.ToString(), StringComparison.Ordinal) ||
            validation.Reasons is null ||
            validation.Reasons.Length != 0)
            throw new InvalidOperationException("State-change preparation requires a current Ready validation decision.");

        var normalized = NormalizeRequest(request);
        var fingerprint = ContainmentActuationPolicy.ComputeBindingFingerprint(normalized.Binding);
        if (!DecisionPolicy.HashEqual(validation.BindingFingerprint, fingerprint))
            throw new InvalidOperationException("ActuationValidationBindingMismatch");

        lock (_gate)
        {
            var byRequest = _records.FirstOrDefault(x =>
                x.Phase == ContainmentStateChangeJournalPhase.Prepared &&
                RequestEquals(x, normalized.RequestId));
            if (byRequest is not null)
            {
                if (SameBinding(byRequest, normalized.Binding) &&
                    DecisionPolicy.HashEqual(byRequest.BindingFingerprint, fingerprint))
                    return byRequest;
                throw new InvalidDataException("Conflicting duplicate state-change request id.");
            }

            if (_records.Any(x =>
                x.Phase == ContainmentStateChangeJournalPhase.Prepared &&
                string.Equals(x.AuthorizationId, normalized.Binding.AuthorizationId, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("AuthorizationAlreadyConsumed");

            return Append(
                ContainmentStateChangeJournalPhase.Prepared,
                normalized.RequestId,
                normalized.Binding,
                fingerprint,
                PreparedReason,
                normalized.RequestedUtc);
        }
    }

    public ContainmentStateChangeJournalEntry RecordSuspendApplied(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var existing = FindPhase(requestId, ContainmentStateChangeJournalPhase.SuspendApplied);
            if (existing is not null)
                return existing;

            EnsureNoTerminal(requestId);
            return Append(
                ContainmentStateChangeJournalPhase.SuspendApplied,
                prepared.RequestId,
                BindingFrom(prepared),
                prepared.BindingFingerprint,
                SuspendReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentStateChangeJournalEntry RecordExplicitResumeApplied(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var existing = FindPhase(requestId, ContainmentStateChangeJournalPhase.ExplicitResumeApplied);
            if (existing is not null)
                return existing;

            EnsureNoTerminal(requestId);
            if (FindPhase(requestId, ContainmentStateChangeJournalPhase.SuspendApplied) is null)
                throw new InvalidOperationException("StateChangeSuspendNotRecorded");

            return Append(
                ContainmentStateChangeJournalPhase.ExplicitResumeApplied,
                prepared.RequestId,
                BindingFrom(prepared),
                prepared.BindingFingerprint,
                ResumeReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentStateChangeJournalEntry RecordCompleted(string requestId)
    {
        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var existing = FindPhase(requestId, ContainmentStateChangeJournalPhase.Completed);
            if (existing is not null)
                return existing;

            if (FindPhase(requestId, ContainmentStateChangeJournalPhase.Abnormal) is not null)
                throw new InvalidOperationException("StateChangeSessionAlreadyAbnormal");
            if (FindPhase(requestId, ContainmentStateChangeJournalPhase.ExplicitResumeApplied) is null)
                throw new InvalidOperationException("ExplicitResumeNotRecorded");

            return Append(
                ContainmentStateChangeJournalPhase.Completed,
                prepared.RequestId,
                BindingFrom(prepared),
                prepared.BindingFingerprint,
                CompletedReason,
                DateTime.UtcNow);
        }
    }

    public ContainmentStateChangeJournalEntry RecordAbnormal(string requestId, string reasonCode)
    {
        ValidateReasonCode(reasonCode);

        lock (_gate)
        {
            var prepared = RequirePrepared(requestId);
            var existing = FindPhase(requestId, ContainmentStateChangeJournalPhase.Abnormal);
            if (existing is not null)
            {
                if (string.Equals(existing.ReasonCode, reasonCode, StringComparison.Ordinal))
                    return existing;
                throw new InvalidDataException("Conflicting state-change abnormal reason.");
            }

            if (FindPhase(requestId, ContainmentStateChangeJournalPhase.Completed) is not null)
                throw new InvalidOperationException("StateChangeSessionAlreadyCompleted");

            return Append(
                ContainmentStateChangeJournalPhase.Abnormal,
                prepared.RequestId,
                BindingFrom(prepared),
                prepared.BindingFingerprint,
                reasonCode,
                DateTime.UtcNow);
        }
    }

    public ContainmentStateChangeJournalEntry[] IncompleteRequests()
    {
        lock (_gate)
        {
            return _records
                .Where(x => x.Phase == ContainmentStateChangeJournalPhase.Prepared)
                .Where(x =>
                    FindPhase(x.RequestId, ContainmentStateChangeJournalPhase.Completed) is null &&
                    FindPhase(x.RequestId, ContainmentStateChangeJournalPhase.Abnormal) is null)
                .OrderBy(x => x.Sequence)
                .ToArray();
        }
    }

    public void VerifyAll()
    {
        lock (_gate)
            LoadAndValidateJournal(rebuildState: false);
    }

    private ContainmentStateChangeJournalEntry RequirePrepared(string requestId)
    {
        if (!IsGuidN(requestId))
            throw new ArgumentException("Request id must be a 32-character GUID in N format.", nameof(requestId));

        return _records.FirstOrDefault(x =>
            x.Phase == ContainmentStateChangeJournalPhase.Prepared &&
            RequestEquals(x, requestId))
            ?? throw new InvalidOperationException("StateChangeRequestNotPrepared");
    }

    private ContainmentStateChangeJournalEntry? FindPhase(string requestId, ContainmentStateChangeJournalPhase phase) =>
        _records.FirstOrDefault(x => x.Phase == phase && RequestEquals(x, requestId));

    private void EnsureNoTerminal(string requestId)
    {
        if (FindPhase(requestId, ContainmentStateChangeJournalPhase.Completed) is not null)
            throw new InvalidOperationException("StateChangeSessionAlreadyCompleted");
        if (FindPhase(requestId, ContainmentStateChangeJournalPhase.Abnormal) is not null)
            throw new InvalidOperationException("StateChangeSessionAlreadyAbnormal");
    }

    private ContainmentStateChangeJournalEntry Append(
        ContainmentStateChangeJournalPhase phase,
        string requestId,
        ContainmentActuationBinding binding,
        string bindingFingerprint,
        string reasonCode,
        DateTime observedUtc)
    {
        ValidateReasonCode(reasonCode);
        if (observedUtc.Kind != DateTimeKind.Utc)
            throw new InvalidDataException("State-change journal timestamps must be UTC.");
        if (!IsSha256(bindingFingerprint))
            throw new InvalidDataException("State-change binding fingerprint is invalid.");

        var normalizedPath = WinPaths.Normalize(binding.ImagePath)
            ?? throw new InvalidDataException("State-change journal image path is invalid.");

        var sequence = checked(++_nextSequence);
        var payload = new ContainmentStateChangeJournalPayload(
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
            bindingFingerprint.ToUpperInvariant(),
            reasonCode,
            _lastRecordHash);
        var recordHash = HashPayload(payload);
        var line = new ContainmentStateChangeJournalLine(
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
            payload.BindingFingerprint,
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
        var rebuilt = new List<ContainmentStateChangeJournalEntry>();
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank containment state-change journal record.");

            ContainmentStateChangeJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<ContainmentStateChangeJournalLine>(raw, _json)
                    ?? throw new InvalidDataException("Invalid containment state-change journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid containment state-change journal JSON.", ex);
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
                !IsSha256(line.BindingFingerprint) ||
                !IsReasonCode(line.ReasonCode) ||
                !IsSha256(line.PreviousRecordSha256) ||
                !IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid containment state-change journal fields.");

            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment state-change journal hash chain mismatch.");
            if (!HashPayload(line.Payload).Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment state-change journal record hash mismatch.");

            rebuilt.Add(line.ToEntry() with
            {
                ImagePath = WinPaths.Normalize(line.ImagePath)!,
                ImageSha256 = line.ImageSha256.ToUpperInvariant(),
                BindingFingerprint = line.BindingFingerprint.ToUpperInvariant()
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

    private void ValidateReplay(IReadOnlyList<ContainmentStateChangeJournalEntry> entries)
    {
        var authorizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var group in entries.GroupBy(x => x.RequestId, StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group.OrderBy(x => x.Sequence).ToArray();
            if (ordered.Length == 0 || ordered[0].Phase != ContainmentStateChangeJournalPhase.Prepared)
                throw new InvalidDataException("State-change request does not begin with Prepared.");

            var first = ordered[0];
            var reconstructedFingerprint = ContainmentActuationPolicy.ComputeBindingFingerprint(BindingFrom(first));
            if (!DecisionPolicy.HashEqual(first.BindingFingerprint, reconstructedFingerprint))
                throw new InvalidDataException("State-change journal binding fingerprint mismatch.");
            if (!authorizations.TryAdd(first.AuthorizationId, first.RequestId))
                throw new InvalidDataException("State-change authorization was consumed by more than one request.");
            if (!string.Equals(first.ReasonCode, PreparedReason, StringComparison.Ordinal))
                throw new InvalidDataException("Invalid state-change Prepared record.");

            var suspended = false;
            var resumed = false;
            var terminal = false;

            foreach (var record in ordered.Skip(1))
            {
                if (!SameIdentity(first, record))
                    throw new InvalidDataException("State-change journal identity changed inside one request.");
                if (terminal)
                    throw new InvalidDataException("State-change journal contains records after a terminal outcome.");

                switch (record.Phase)
                {
                    case ContainmentStateChangeJournalPhase.Prepared:
                        throw new InvalidDataException("Duplicate state-change Prepared record.");
                    case ContainmentStateChangeJournalPhase.SuspendApplied:
                        if (suspended || resumed || !string.Equals(record.ReasonCode, SuspendReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid state-change SuspendApplied transition.");
                        suspended = true;
                        break;
                    case ContainmentStateChangeJournalPhase.ExplicitResumeApplied:
                        if (!suspended || resumed || !string.Equals(record.ReasonCode, ResumeReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid state-change ExplicitResumeApplied transition.");
                        resumed = true;
                        break;
                    case ContainmentStateChangeJournalPhase.Completed:
                        if (!suspended || !resumed || !string.Equals(record.ReasonCode, CompletedReason, StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid state-change Completed transition.");
                        terminal = true;
                        break;
                    case ContainmentStateChangeJournalPhase.Abnormal:
                        terminal = true;
                        break;
                    default:
                        throw new InvalidDataException("Unknown state-change journal transition.");
                }
            }
        }
    }

    private void AppendLine(ContainmentStateChangeJournalLine line)
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

    private static ContainmentActuationRequest NormalizeRequest(ContainmentActuationRequest request)
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
            throw new InvalidDataException("State-change request is outside the authorization lifetime.");
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

    private static ContainmentActuationBinding BindingFrom(ContainmentStateChangeJournalEntry entry) =>
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

    private static bool SameBinding(ContainmentStateChangeJournalEntry entry, ContainmentActuationBinding binding) =>
        string.Equals(entry.AuthorizationId, binding.AuthorizationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(entry.CaseId, binding.CaseId, StringComparison.Ordinal) &&
        entry.AuthorizationEvaluatedUtc == binding.EvaluatedUtc &&
        entry.AuthorizationExpiresUtc == binding.ExpiresUtc &&
        entry.ProcessId == binding.Process.Pid &&
        entry.ProcessCreationFileTimeUtc == binding.Process.CreationFileTimeUtc &&
        WinPaths.Equal(entry.ImagePath, binding.ImagePath) &&
        DecisionPolicy.HashEqual(entry.ImageSha256, binding.ImageSha256) &&
        entry.ProtectionObservedUtc == binding.ProtectionObservedUtc;

    private static bool SameIdentity(ContainmentStateChangeJournalEntry left, ContainmentStateChangeJournalEntry right) =>
        string.Equals(left.RequestId, right.RequestId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.AuthorizationId, right.AuthorizationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        left.AuthorizationEvaluatedUtc == right.AuthorizationEvaluatedUtc &&
        left.AuthorizationExpiresUtc == right.AuthorizationExpiresUtc &&
        left.ProcessId == right.ProcessId &&
        left.ProcessCreationFileTimeUtc == right.ProcessCreationFileTimeUtc &&
        WinPaths.Equal(left.ImagePath, right.ImagePath) &&
        DecisionPolicy.HashEqual(left.ImageSha256, right.ImageSha256) &&
        left.ProtectionObservedUtc == right.ProtectionObservedUtc &&
        DecisionPolicy.HashEqual(left.BindingFingerprint, right.BindingFingerprint);

    private static bool RequestEquals(ContainmentStateChangeJournalEntry entry, string requestId) =>
        string.Equals(entry.RequestId, requestId, StringComparison.OrdinalIgnoreCase);

    private string HashPayload(ContainmentStateChangeJournalPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

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
        var cursor = root;
        var relative = full[root.Length..];

        foreach (var segment in relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries))
        {
            cursor = Path.Combine(cursor, segment);
            if (!File.Exists(cursor) && !Directory.Exists(cursor))
                break;
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Containment state-change journal must not traverse a reparse point: " + cursor);
        }
    }
}

internal sealed record ContainmentStateChangeJournalPayload(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentStateChangeJournalPhase Phase,
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
    string BindingFingerprint,
    string ReasonCode,
    string PreviousRecordSha256);

internal sealed record ContainmentStateChangeJournalLine(
    long Sequence,
    DateTime ObservedUtc,
    ContainmentStateChangeJournalPhase Phase,
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
    string BindingFingerprint,
    string ReasonCode,
    string PreviousRecordSha256,
    string RecordSha256)
{
    public ContainmentStateChangeJournalPayload Payload => new(
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
        BindingFingerprint,
        ReasonCode,
        PreviousRecordSha256);

    public ContainmentStateChangeJournalEntry ToEntry() => new(
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
        BindingFingerprint,
        ReasonCode,
        PreviousRecordSha256,
        RecordSha256);
}
