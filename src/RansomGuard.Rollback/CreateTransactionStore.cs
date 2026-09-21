using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Durable two-phase evidence for mutation-capable IRP_MJ_CREATE operations.
/// A Pending record is committed before the kernel CREATE is allowed to continue.
/// An Outcome record is committed from the post-create callback and carries the
/// actual create action plus kernel FILE_ID_INFORMATION when the CREATE succeeded.
/// </summary>
public sealed class CreateTransactionStore
{
    private readonly string _root;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<ulong, CreateTransactionState> _transactions = new();
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public IReadOnlyCollection<CreateTransactionState> Transactions =>
        _transactions.Values.OrderBy(x => x.Pending.JournalSequence).ToArray();

    public CreateTransactionStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Create transaction root is required.", nameof(root));

        _root = Path.GetFullPath(root);
        _journal = Path.Combine(_root, "create-transaction-journal.jsonl");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        LoadAndValidateJournal(requireComplete: true);
    }

    public async Task<CreateTransactionPending> RegisterPendingAsync(
        ulong preCreateSequence,
        string path,
        uint createFlags,
        uint preservationDecision,
        DurableFileIdentity? preIdentity,
        CancellationToken cancellationToken = default)
    {
        if (preCreateSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(preCreateSequence));

        var full = NormalizeSource(path);
        var preVolume = preIdentity?.VolumeSerialHex ?? string.Empty;
        var preFileId = preIdentity?.FileIdHex ?? string.Empty;
        ValidateOptionalIdentity(preVolume, preFileId);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_transactions.ContainsKey(preCreateSequence))
                throw new InvalidOperationException("CREATE transaction sequence is already registered.");

            var journalSequence = checked(++_nextSequence);
            var payload = new CreateTransactionPayload(
                journalSequence,
                DateTime.UtcNow,
                CreateTransactionRecordKind.Pending,
                preCreateSequence,
                0,
                full,
                createFlags,
                preservationDecision,
                0,
                0,
                0,
                preVolume,
                preFileId,
                string.Empty,
                string.Empty,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = CreateTransactionLine.FromPayload(payload, recordHash);
            AppendJournalLine(line);
            _lastRecordHash = recordHash;

            var pending = line.ToPending();
            if (!_transactions.TryAdd(preCreateSequence, new CreateTransactionState(pending, null)))
                throw new InvalidOperationException("Concurrent CREATE transaction registration collision.");
            return pending;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public bool TryGetPending(ulong preCreateSequence, out CreateTransactionPending? pending)
    {
        if (_transactions.TryGetValue(preCreateSequence, out var state))
        {
            pending = state.Pending;
            return true;
        }

        pending = null;
        return false;
    }

    public async Task<CreateTransactionOutcome> CompleteAsync(
        ulong preCreateSequence,
        ulong postCreateSequence,
        string path,
        uint createFlags,
        uint completionStatus,
        uint createAction,
        uint identityStatus,
        DurableFileIdentity? postIdentity,
        CancellationToken cancellationToken = default)
    {
        if (preCreateSequence == 0 || postCreateSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(preCreateSequence));

        var full = NormalizeSource(path);
        var postVolume = postIdentity?.VolumeSerialHex ?? string.Empty;
        var postFileId = postIdentity?.FileIdHex ?? string.Empty;
        ValidateOptionalIdentity(postVolume, postFileId);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_transactions.TryGetValue(preCreateSequence, out var state))
                throw new InvalidDataException("CREATE outcome has no durable pending transaction.");
            if (state.Outcome is not null)
                throw new InvalidDataException("Duplicate CREATE transaction outcome.");
            if (!state.Pending.OriginalPath.Equals(full, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE outcome path does not match its pending transaction.");
            if (state.Pending.CreateFlags != createFlags)
                throw new InvalidDataException("CREATE outcome flags do not match its pending transaction.");

            var succeeded = IsNtSuccess(completionStatus);
            if (succeeded)
            {
                if (createAction > 3)
                    throw new InvalidDataException("Successful CREATE has an unknown create action.");
                if (IsNtSuccess(identityStatus) != (postIdentity is not null))
                    throw new InvalidDataException("CREATE identity status and post identity disagree.");
            }
            else if (postIdentity is not null)
            {
                throw new InvalidDataException("Failed CREATE must not claim a post-create file identity.");
            }

            var journalSequence = checked(++_nextSequence);
            var payload = new CreateTransactionPayload(
                journalSequence,
                DateTime.UtcNow,
                CreateTransactionRecordKind.Outcome,
                preCreateSequence,
                postCreateSequence,
                full,
                createFlags,
                state.Pending.PreservationDecision,
                completionStatus,
                createAction,
                identityStatus,
                state.Pending.PreVolumeSerialHex,
                state.Pending.PreFileIdHex,
                postVolume,
                postFileId,
                _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = CreateTransactionLine.FromPayload(payload, recordHash);
            AppendJournalLine(line);
            _lastRecordHash = recordHash;

            var outcome = line.ToOutcome();
            _transactions[preCreateSequence] = state with { Outcome = outcome };
            return outcome;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    public void VerifyAll() => LoadAndValidateJournal(requireComplete: true, rebuildState: false);

    private void LoadAndValidateJournal(bool requireComplete, bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                _transactions.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedJournalSequence = 1;
        var rebuilt = new Dictionary<ulong, CreateTransactionState>();

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new InvalidDataException("Blank CREATE transaction journal record.");

            CreateTransactionLine line;
            try
            {
                line = JsonSerializer.Deserialize<CreateTransactionLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid CREATE transaction journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid CREATE transaction journal JSON.", ex);
            }

            if (line.JournalSequence != expectedJournalSequence)
                throw new InvalidDataException("CREATE transaction journal sequence gap.");
            if (!IsSha256(line.PreviousRecordSha256) ||
                !line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE transaction journal hash chain mismatch.");
            if (!IsSha256(line.RecordSha256))
                throw new InvalidDataException("Invalid CREATE transaction record hash.");
            if (line.PreCreateSequence == 0 || string.IsNullOrWhiteSpace(line.OriginalPath))
                throw new InvalidDataException("Invalid CREATE transaction record fields.");

            ValidateOptionalIdentity(line.PreVolumeSerialHex, line.PreFileIdHex);
            ValidateOptionalIdentity(line.PostVolumeSerialHex, line.PostFileIdHex);

            var calculated = HashPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("CREATE transaction journal record hash mismatch.");

            var full = NormalizeSource(line.OriginalPath);
            if (line.Kind == CreateTransactionRecordKind.Pending)
            {
                if (line.PostCreateSequence != 0 || line.CompletionStatus != 0 || line.CreateAction != 0 ||
                    line.IdentityStatus != 0 || line.PostVolumeSerialHex.Length != 0 || line.PostFileIdHex.Length != 0)
                    throw new InvalidDataException("Invalid pending CREATE transaction record.");

                var normalized = line with { OriginalPath = full };
                if (!rebuilt.TryAdd(line.PreCreateSequence,
                        new CreateTransactionState(normalized.ToPending(), null)))
                    throw new InvalidDataException("Duplicate pending CREATE transaction.");
            }
            else if (line.Kind == CreateTransactionRecordKind.Outcome)
            {
                if (!rebuilt.TryGetValue(line.PreCreateSequence, out var state))
                    throw new InvalidDataException("CREATE transaction outcome appears before pending record.");
                if (state.Outcome is not null || line.PostCreateSequence == 0 ||
                    state.Pending.CreateFlags != line.CreateFlags ||
                    !state.Pending.OriginalPath.Equals(full, StringComparison.OrdinalIgnoreCase) ||
                    state.Pending.PreservationDecision != line.PreservationDecision ||
                    !state.Pending.PreVolumeSerialHex.Equals(line.PreVolumeSerialHex, StringComparison.OrdinalIgnoreCase) ||
                    !state.Pending.PreFileIdHex.Equals(line.PreFileIdHex, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("CREATE transaction outcome does not match pending state.");

                var succeeded = IsNtSuccess(line.CompletionStatus);
                if (succeeded)
                {
                    if (line.CreateAction > 3)
                        throw new InvalidDataException("Successful CREATE transaction has an unknown create action.");
                    var hasPostIdentity = line.PostVolumeSerialHex.Length != 0 && line.PostFileIdHex.Length != 0;
                    if (IsNtSuccess(line.IdentityStatus) != hasPostIdentity)
                        throw new InvalidDataException("CREATE transaction identity status and stored identity disagree.");
                }
                else if (line.PostVolumeSerialHex.Length != 0 || line.PostFileIdHex.Length != 0)
                {
                    throw new InvalidDataException("Failed CREATE transaction must not contain post identity.");
                }

                rebuilt[line.PreCreateSequence] = state with { Outcome = (line with { OriginalPath = full }).ToOutcome() };
            }
            else
            {
                throw new InvalidDataException("Unknown CREATE transaction journal record kind.");
            }

            expectedPrevious = line.RecordSha256;
            expectedJournalSequence++;
        }

        if (requireComplete && rebuilt.Values.Any(x => x.Outcome is null || !x.Outcome.IsReconciled))
            throw new InvalidDataException("Incomplete CREATE transaction found: post-create reconciliation is missing or unverifiable.");

        if (rebuildState)
        {
            _transactions.Clear();
            foreach (var pair in rebuilt) _transactions[pair.Key] = pair.Value;
            _nextSequence = expectedJournalSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(CreateTransactionLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string HashPayload(CreateTransactionPayload payload) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static bool IsNtSuccess(uint status) => unchecked((int)status) >= 0;

    private static void ValidateOptionalIdentity(string? volumeSerialHex, string? fileIdHex)
    {
        if (volumeSerialHex is null || fileIdHex is null)
            throw new InvalidDataException("CREATE transaction identity fields must not be null.");

        if (volumeSerialHex.Length == 0 && fileIdHex.Length == 0) return;
        if (!IsFixedHex(volumeSerialHex, 16) || !IsFixedHex(fileIdHex, 32))
            throw new InvalidDataException("Invalid CREATE transaction file identity.");
    }

    private static bool IsFixedHex(string value, int length) =>
        value.Length == length && value.All(char.IsAsciiHexDigit);

    private static bool IsSha256(string? value) =>
        value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static string NormalizeSource(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Source path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full))
            throw new ArgumentException("Source path must be absolute.", nameof(path));
        return full;
    }

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("CREATE transaction store must not be a reparse point: " + path);
    }
}

public enum CreateTransactionRecordKind
{
    Pending = 1,
    Outcome = 2
}

public sealed record CreateTransactionPending(
    long JournalSequence,
    DateTime CapturedUtc,
    ulong PreCreateSequence,
    string OriginalPath,
    uint CreateFlags,
    uint PreservationDecision,
    string PreVolumeSerialHex,
    string PreFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? PreIdentity =>
        PreVolumeSerialHex.Length == 0 ? null : new DurableFileIdentity(PreVolumeSerialHex, PreFileIdHex);
}

public sealed record CreateTransactionOutcome(
    long JournalSequence,
    DateTime CapturedUtc,
    ulong PreCreateSequence,
    ulong PostCreateSequence,
    string OriginalPath,
    uint CreateFlags,
    uint PreservationDecision,
    uint CompletionStatus,
    uint CreateAction,
    uint IdentityStatus,
    string PreVolumeSerialHex,
    string PreFileIdHex,
    string PostVolumeSerialHex,
    string PostFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public DurableFileIdentity? PreIdentity =>
        PreVolumeSerialHex.Length == 0 ? null : new DurableFileIdentity(PreVolumeSerialHex, PreFileIdHex);

    [JsonIgnore]
    public DurableFileIdentity? PostIdentity =>
        PostVolumeSerialHex.Length == 0 ? null : new DurableFileIdentity(PostVolumeSerialHex, PostFileIdHex);

    [JsonIgnore]
    public bool IsReconciled
    {
        get
        {
            if (unchecked((int)CompletionStatus) < 0) return true;
            if (unchecked((int)IdentityStatus) < 0 || PostIdentity is null) return false;

            return CreateAction switch
            {
                0 => PreIdentity is not null && !PreIdentity.Equals(PostIdentity), // FILE_SUPERSEDED
                1 => PreIdentity is not null && PreIdentity.Equals(PostIdentity),  // FILE_OPENED
                2 => PreIdentity is null,                                           // FILE_CREATED
                3 => PreIdentity is not null && PreIdentity.Equals(PostIdentity),   // FILE_OVERWRITTEN
                _ => false
            };
        }
    }
}

public sealed record CreateTransactionState(
    CreateTransactionPending Pending,
    CreateTransactionOutcome? Outcome);

internal sealed record CreateTransactionPayload(
    long JournalSequence,
    DateTime CapturedUtc,
    CreateTransactionRecordKind Kind,
    ulong PreCreateSequence,
    ulong PostCreateSequence,
    string OriginalPath,
    uint CreateFlags,
    uint PreservationDecision,
    uint CompletionStatus,
    uint CreateAction,
    uint IdentityStatus,
    string PreVolumeSerialHex,
    string PreFileIdHex,
    string PostVolumeSerialHex,
    string PostFileIdHex,
    string PreviousRecordSha256);

internal sealed record CreateTransactionLine(
    long JournalSequence,
    DateTime CapturedUtc,
    CreateTransactionRecordKind Kind,
    ulong PreCreateSequence,
    ulong PostCreateSequence,
    string OriginalPath,
    uint CreateFlags,
    uint PreservationDecision,
    uint CompletionStatus,
    uint CreateAction,
    uint IdentityStatus,
    string PreVolumeSerialHex,
    string PreFileIdHex,
    string PostVolumeSerialHex,
    string PostFileIdHex,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public CreateTransactionPayload Payload => new(
        JournalSequence, CapturedUtc, Kind, PreCreateSequence, PostCreateSequence,
        OriginalPath, CreateFlags, PreservationDecision, CompletionStatus, CreateAction,
        IdentityStatus, PreVolumeSerialHex, PreFileIdHex, PostVolumeSerialHex, PostFileIdHex,
        PreviousRecordSha256);

    public static CreateTransactionLine FromPayload(CreateTransactionPayload payload, string recordHash) => new(
        payload.JournalSequence, payload.CapturedUtc, payload.Kind, payload.PreCreateSequence,
        payload.PostCreateSequence, payload.OriginalPath, payload.CreateFlags, payload.PreservationDecision,
        payload.CompletionStatus, payload.CreateAction, payload.IdentityStatus,
        payload.PreVolumeSerialHex, payload.PreFileIdHex, payload.PostVolumeSerialHex,
        payload.PostFileIdHex, payload.PreviousRecordSha256, recordHash);

    public CreateTransactionPending ToPending() => new(
        JournalSequence, CapturedUtc, PreCreateSequence, OriginalPath, CreateFlags,
        PreservationDecision, PreVolumeSerialHex, PreFileIdHex, PreviousRecordSha256, RecordSha256);

    public CreateTransactionOutcome ToOutcome() => new(
        JournalSequence, CapturedUtc, PreCreateSequence, PostCreateSequence, OriginalPath,
        CreateFlags, PreservationDecision, CompletionStatus, CreateAction, IdentityStatus,
        PreVolumeSerialHex, PreFileIdHex, PostVolumeSerialHex, PostFileIdHex,
        PreviousRecordSha256, RecordSha256);
}
