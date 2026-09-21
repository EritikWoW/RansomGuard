using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Rollback;

/// <summary>
/// Append-only pre-image store. It never overwrites the protected source file and restores only to a new copy.
/// This library is the durable rollback primitive; the minifilter integration must capture a pre-image BEFORE
/// allowing the destructive mutation to continue.
/// </summary>
public sealed class RollbackStore
{
    private readonly string _root;
    private readonly string _objects;
    private readonly string _journal;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<string, RollbackCapture> _firstCapture =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;

    public RollbackStore(string root)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Rollback root is required.", nameof(root));
        _root = Path.GetFullPath(root);
        _objects = Path.Combine(_root, "objects");
        _journal = Path.Combine(_root, "journal.jsonl");
        Directory.CreateDirectory(_objects);
        RejectReparse(_root);
        RejectReparse(_objects);
        LoadAndValidateJournal();
    }

    public IReadOnlyCollection<RollbackCapture> Captures => _firstCapture.Values.OrderBy(x => x.Sequence).ToArray();

    public Task<RollbackCapture> CapturePreimageAsync(string path, RollbackMutationKind mutation,
        CancellationToken cancellationToken = default) =>
        CapturePreimageCoreAsync(path, mutation, null, cancellationToken);

    public Task<RollbackCapture> CapturePreimageAsync(string path, RollbackMutationKind mutation,
        DurableFileIdentity expectedIdentity, CancellationToken cancellationToken = default) =>
        CapturePreimageCoreAsync(path, mutation, expectedIdentity, cancellationToken);

    private async Task<RollbackCapture> CapturePreimageCoreAsync(string path, RollbackMutationKind mutation,
        DurableFileIdentity? expectedIdentity, CancellationToken cancellationToken)
    {
        var full = NormalizeSource(path);
        if (_firstCapture.TryGetValue(full, out var existing)) return existing;

        var source = new FileInfo(full);
        if (!source.Exists) throw new FileNotFoundException("Source file no longer exists before pre-image capture.", full);
        RejectReparse(full);

        var pathId = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(full.ToUpperInvariant())));
        var objectName = pathId + ".preimage";
        var objectPath = Path.Combine(_objects, objectName);
        var relative = Path.GetRelativePath(_root, objectPath);
        var temp = objectPath + "." + Guid.NewGuid().ToString("N") + ".tmp";

        string sha;
        long length;
        try
        {
            using var input = new FileStream(full, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Write | FileShare.Delete, 1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (expectedIdentity is not null)
            {
                var actualIdentity = FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle);
                if (actualIdentity != expectedIdentity)
                    throw new InvalidDataException("Full pre-image source handle identity does not match the expected incident identity.");
            }
            using var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            length = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                hasher.AppendData(buffer, 0, read);
                length = checked(length + read);
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(true);
            sha = Hex(hasher.GetHashAndReset());
        }
        catch
        {
            TryDelete(temp);
            throw;
        }

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_firstCapture.TryGetValue(full, out existing))
            {
                TryDelete(temp);
                return existing;
            }

            if (File.Exists(objectPath))
            {
                // A previous committed capture exists only if it is also present in the validated journal.
                throw new IOException("Rollback object exists without a matching committed journal entry: " + objectPath);
            }
            File.Move(temp, objectPath);
            FlushParentBestEffort(objectPath);

            var sequence = checked(++_nextSequence);
            var payload = new JournalPayload(sequence, DateTime.UtcNow, mutation, full, relative,
                length, sha, _lastRecordHash);
            var recordHash = HashPayload(payload);
            var line = new JournalLine(payload.Sequence, payload.CapturedUtc, payload.Mutation, payload.OriginalPath,
                payload.SnapshotRelativePath, payload.OriginalLength, payload.OriginalSha256,
                payload.PreviousRecordSha256, recordHash);
            AppendJournalLine(line);
            _lastRecordHash = recordHash;
            var capture = line.ToCapture();
            if (!_firstCapture.TryAdd(full, capture))
                throw new InvalidOperationException("Concurrent rollback capture commit collision.");
            return capture;
        }
        catch
        {
            // Once the object has been atomically moved into place we deliberately do not delete it on journal failure.
            // An orphan is safer than losing a pre-image. Startup validation refuses such ambiguity for auto-recovery.
            TryDelete(temp);
            throw;
        }
        finally { _appendGate.Release(); }
    }

    public async Task<string> RestoreToNewCopyAsync(RollbackCapture capture, string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        if (capture is null) throw new ArgumentNullException(nameof(capture));
        var snapshot = SafeSnapshotPath(capture.SnapshotRelativePath);
        if (!File.Exists(snapshot)) throw new FileNotFoundException("Rollback pre-image is missing.", snapshot);
        var actual = await HashFileAsync(snapshot, cancellationToken).ConfigureAwait(false);
        if (!actual.Equals(capture.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rollback pre-image hash mismatch. Refusing recovery.");

        var destinationRoot = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(destinationRoot);
        RejectReparse(destinationRoot);
        var name = Path.GetFileName(capture.OriginalPath);
        if (string.IsNullOrWhiteSpace(name)) name = "recovered.bin";
        var destination = Path.Combine(destinationRoot, name + ".ransomguard-recovered");
        if (File.Exists(destination)) throw new IOException("Recovery output already exists: " + destination);

        var temp = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var input = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
                       FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024,
                       FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                await input.CopyToAsync(output, 1024 * 1024, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(true);
            }
            var restoredHash = await HashFileAsync(temp, cancellationToken).ConfigureAwait(false);
            if (!restoredHash.Equals(capture.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Recovered copy failed SHA-256 verification.");
            File.Move(temp, destination);
            return destination;
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    public void VerifyAll()
    {
        LoadAndValidateJournal(rebuildState: false);
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var capture in _firstCapture.Values)
        {
            var snapshot = SafeSnapshotPath(capture.SnapshotRelativePath);
            if (!File.Exists(snapshot)) throw new InvalidDataException("Committed rollback object is missing: " + snapshot);
            var info = new FileInfo(snapshot);
            if (info.Length != capture.OriginalLength)
                throw new InvalidDataException("Rollback object length mismatch: " + snapshot);
            var actualSha = HashFile(snapshot);
            if (!actualSha.Equals(capture.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Committed rollback object SHA-256 mismatch: " + snapshot);
            referenced.Add(Path.GetFullPath(snapshot));
        }

        foreach (var file in Directory.EnumerateFiles(_objects, "*.preimage", SearchOption.TopDirectoryOnly))
            if (!referenced.Contains(Path.GetFullPath(file)))
                throw new InvalidDataException("Unjournaled rollback object found: " + file);

        foreach (var file in Directory.EnumerateFiles(_objects, "*.tmp", SearchOption.TopDirectoryOnly))
            throw new InvalidDataException("Incomplete rollback temp artifact found: " + file);
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal)) return;
        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var rebuilt = new Dictionary<string, RollbackCapture>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw)) throw new InvalidDataException("Blank rollback journal record.");
            JournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<JournalLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid rollback journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid rollback journal JSON.", ex);
            }
            if (line.Sequence != expectedSequence) throw new InvalidDataException("Rollback journal sequence gap.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback journal hash chain mismatch.");
            var calculated = HashPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Rollback journal record hash mismatch.");
            if (!Enum.IsDefined(line.Mutation) || line.OriginalLength < 0 ||
                string.IsNullOrWhiteSpace(line.SnapshotRelativePath) || !IsSha256(line.OriginalSha256))
                throw new InvalidDataException("Invalid rollback journal record fields.");
            var snapshot = SafeSnapshotPath(line.SnapshotRelativePath);
            if (!File.Exists(snapshot)) throw new InvalidDataException("Rollback journal references a missing object.");
            if (new FileInfo(snapshot).Length != line.OriginalLength)
                throw new InvalidDataException("Rollback journal object length mismatch.");
            if (!rebuilt.TryAdd(Path.GetFullPath(line.OriginalPath), line.ToCapture()))
                throw new InvalidDataException("Duplicate rollback capture for original path.");
            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }
        if (rebuildState)
        {
            _firstCapture.Clear();
            foreach (var pair in rebuilt) _firstCapture[pair.Key] = pair.Value;
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(JournalLine line)
    {
        var json = JsonSerializer.Serialize(line, _json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var fs = new FileStream(_journal, FileMode.Append, FileAccess.Write, FileShare.Read,
            64 * 1024, FileOptions.WriteThrough);
        fs.Write(bytes);
        fs.Flush(true);
    }

    private string SafeSnapshotPath(string relative)
    {
        if (Path.IsPathRooted(relative)) throw new InvalidDataException("Rollback object path must be relative.");
        var full = Path.GetFullPath(Path.Combine(_root, relative));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rollback object escapes the store root.");
        RejectReparse(full);
        return full;
    }

    private static string NormalizeSource(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Source path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full)) throw new ArgumentException("Source path must be absolute.", nameof(path));
        return full;
    }

    private static string HashPayload(JournalPayload payload) =>
        Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload)));

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(fs, cancellationToken).ConfigureAwait(false);
        return Hex(hash);
    }

    private static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(fs));
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static string Hex(byte[] data) => Convert.ToHexString(data);

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback store/source must not be a reparse point: " + path);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void FlushParentBestEffort(string path)
    {
        // .NET has no portable directory fsync API. File payload and journal are Flush(true); the Windows
        // integration layer may additionally flush the parent directory handle where supported.
        _ = path;
    }
}
