using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

/// <summary>
/// Range-aware copy-on-write store for pre-write protection experiments.
/// It captures each original block at most once per incident and never modifies
/// the protected source. Recovery is written to a new file only.
/// </summary>
public sealed class RangeRollbackStore
{
    public const int DefaultBlockSize = 1024 * 1024;

    private readonly string _root;
    private readonly string _objects;
    private readonly string _journal;
    private readonly int _blockSize;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private readonly ConcurrentDictionary<string, RangeRollbackBaseline> _baselines =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, RangeRollbackBlock> _blocks =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private long _nextSequence;
    private string _lastRecordHash = new('0', 64);

    public string Root => _root;
    public string JournalPath => _journal;
    public int BlockSize => _blockSize;
    public int BaselineCount => _baselines.Count;
    public int BlockCount => _blocks.Count;
    public IReadOnlyCollection<RangeRollbackBaseline> Baselines =>
        _baselines.Values.OrderBy(x => x.Sequence).ToArray();
    public IReadOnlyCollection<RangeRollbackBlock> Blocks =>
        _blocks.Values.OrderBy(x => x.Sequence).ToArray();

    public RangeRollbackStore(string root, int blockSize = DefaultBlockSize, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Range rollback root is required.", nameof(root));
        if (blockSize < 64 * 1024 || blockSize > 16 * 1024 * 1024 || (blockSize & (blockSize - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be a power of two between 64 KiB and 16 MiB.");

        _root = Path.GetFullPath(root);
        _objects = Path.Combine(_root, "objects");
        _journal = Path.Combine(_root, "range-journal.jsonl");
        _blockSize = blockSize;
        if (createIfMissing)
        {
            Directory.CreateDirectory(_objects);
        }
        else
        {
            if (!Directory.Exists(_root))
            {
                if (File.Exists(_root)) throw new IOException("Range rollback root is not a directory: " + _root);
                throw new DirectoryNotFoundException("Range rollback root does not exist: " + _root);
            }
            if (!Directory.Exists(_objects))
            {
                if (File.Exists(_objects)) throw new IOException("Range rollback objects path is not a directory: " + _objects);
                throw new DirectoryNotFoundException("Range rollback objects directory does not exist: " + _objects);
            }
        }
        RejectReparse(_root);
        RejectReparse(_objects);
        LoadAndValidateJournal();
    }

    /// <summary>
    /// Durably captures the original blocks intersecting a pending write.
    /// The caller may allow the write only after this task completes successfully.
    /// </summary>
    public Task CaptureWritePreimageAsync(string path, long byteOffset, uint length,
        CancellationToken cancellationToken = default) =>
        CaptureWritePreimageCoreAsync(path, byteOffset, length, null, cancellationToken);

    public Task CaptureWritePreimageAsync(string path, long byteOffset, uint length,
        DurableFileIdentity expectedIdentity, CancellationToken cancellationToken = default) =>
        CaptureWritePreimageCoreAsync(path, byteOffset, length, expectedIdentity, cancellationToken);

    private async Task CaptureWritePreimageCoreAsync(string path, long byteOffset, uint length,
        DurableFileIdentity? expectedIdentity, CancellationToken cancellationToken)
    {
        if (length == 0) return;
        if (byteOffset < 0) throw new ArgumentOutOfRangeException(nameof(byteOffset), "Special/negative write offsets are not safe for range COW.");
        _ = checked(byteOffset + (long)length);

        var full = NormalizeSource(path);
        if (!File.Exists(full)) throw new FileNotFoundException("Source file no longer exists before range pre-image capture.", full);
        RejectReparse(full);

        await _appendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var input = new FileStream(full, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Write | FileShare.Delete, _blockSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (expectedIdentity is not null)
            {
                var actualIdentity = FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle);
                if (actualIdentity != expectedIdentity)
                    throw new InvalidDataException("Range pre-image source handle identity does not match the expected incident identity.");
            }

            var baseline = EnsureBaselineCommitted(full, input.Length);
            var writeEnd = checked(byteOffset + (long)length);
            var originalEnd = Math.Min(writeEnd, baseline.OriginalLength);
            if (byteOffset >= originalEnd)
            {
                // Append beyond the original EOF: baseline length is sufficient to undo the append by truncation.
                return;
            }

            var firstBlock = (byteOffset / _blockSize) * _blockSize;
            for (var blockOffset = firstBlock; blockOffset < originalEnd; blockOffset = checked(blockOffset + _blockSize))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var key = BlockKey(full, blockOffset);
                if (_blocks.ContainsKey(key)) continue;

                var blockLength = checked((int)Math.Min(_blockSize, baseline.OriginalLength - blockOffset));
                if (blockLength <= 0) break;
                if (input.Length < checked(blockOffset + blockLength))
                    throw new IOException("Source became shorter before an uncaptured original block could be preserved.");

                var pathHash = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(full.ToUpperInvariant())));
                var objectName = $"{pathHash}-{blockOffset:X16}.block";
                var objectPath = Path.Combine(_objects, objectName);
                if (File.Exists(objectPath))
                    throw new IOException("Range rollback object exists without a matching committed journal entry: " + objectPath);

                var temp = objectPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                string snapshotSha;
                try
                {
                    input.Position = blockOffset;
                    var buffer = new byte[blockLength];
                    await ReadExactlyAsync(input, buffer, cancellationToken).ConfigureAwait(false);
                    snapshotSha = Hex(SHA256.HashData(buffer));

                    using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                               blockLength, FileOptions.Asynchronous | FileOptions.WriteThrough))
                    {
                        await output.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                        output.Flush(true);
                    }

                    File.Move(temp, objectPath);
                }
                catch
                {
                    TryDelete(temp);
                    throw;
                }

                var relative = Path.GetRelativePath(_root, objectPath);
                var line = AppendRecord(RangeJournalKind.Block, full, baseline.OriginalLength, blockOffset,
                    blockLength, relative, snapshotSha);
                var capture = new RangeRollbackBlock(line.Sequence, line.CapturedUtc, full, blockOffset, blockLength,
                    relative, snapshotSha, line.PreviousRecordSha256, line.RecordSha256);
                if (!_blocks.TryAdd(key, capture))
                    throw new InvalidOperationException("Concurrent range rollback block commit collision.");
            }
        }
        finally
        {
            _appendGate.Release();
        }
    }

    /// <summary>
    /// Computes the exact byte length and SHA-256 that a range-COW recovery copy must have.
    /// The digest is derived before output creation from the current live base plus every
    /// verified committed original block, and therefore detects source drift during copy-out.
    /// </summary>
    public async Task<RangeRollbackRecoveryExpectation> ComputeExpectedRecoveryAsync(
        string damagedPath,
        CancellationToken cancellationToken = default)
    {
        var full = NormalizeSource(damagedPath);
        if (!_baselines.TryGetValue(full, out var baseline))
            throw new InvalidOperationException("No range rollback baseline exists for this path.");
        if (!File.Exists(full))
            throw new FileNotFoundException("Damaged source is missing; range reconstruction cannot use it as the base.", full);
        RejectReparse(full);

        using var input = new FileStream(
            full, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Write | FileShare.Delete,
            _blockSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length < baseline.OriginalLength)
            throw new InvalidDataException(
                "Damaged source is shorter than the recorded original length. Use a full pre-image/transaction recovery path.");

        var blocks = _blocks.Values
            .Where(x => x.OriginalPath.Equals(full, StringComparison.OrdinalIgnoreCase))
            .ToDictionary(x => x.BlockOffset);

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (long offset = 0; offset < baseline.OriginalLength; offset = checked(offset + _blockSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var length = checked((int)Math.Min(_blockSize, baseline.OriginalLength - offset));

            if (blocks.TryGetValue(offset, out var block))
            {
                if (block.BlockLength != length)
                    throw new InvalidDataException("Range rollback block length does not match the original file segment.");
                var snapshot = SafeSnapshotPath(block.SnapshotRelativePath);
                if (!File.Exists(snapshot))
                    throw new FileNotFoundException("Range rollback block is missing.", snapshot);
                var bytes = await File.ReadAllBytesAsync(snapshot, cancellationToken).ConfigureAwait(false);
                if (bytes.Length != block.BlockLength)
                    throw new InvalidDataException("Range rollback block length mismatch.");
                var blockSha = Hex(SHA256.HashData(bytes));
                if (!blockSha.Equals(block.SnapshotSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Range rollback block SHA-256 mismatch.");
                hash.AppendData(bytes);
                continue;
            }

            input.Position = offset;
            var currentBytes = new byte[length];
            await ReadExactlyAsync(input, currentBytes, cancellationToken).ConfigureAwait(false);
            hash.AppendData(currentBytes);
        }

        return new RangeRollbackRecoveryExpectation(
            baseline.OriginalLength,
            Hex(hash.GetHashAndReset()));
    }

    /// <summary>
    /// Reconstructs a write-damaged file into a new copy by overlaying captured original blocks
    /// and restoring the original file length. This method never overwrites the damaged source.
    /// </summary>
    public async Task<string> RestoreToNewCopyAsync(string damagedPath, string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        var full = NormalizeSource(damagedPath);
        if (!_baselines.TryGetValue(full, out var baseline))
            throw new InvalidOperationException("No range rollback baseline exists for this path.");
        if (!File.Exists(full)) throw new FileNotFoundException("Damaged source is missing; range reconstruction cannot use it as the base.", full);
        RejectReparse(full);

        var damagedLength = new FileInfo(full).Length;
        if (damagedLength < baseline.OriginalLength)
            throw new InvalidDataException("Damaged source is shorter than the recorded original length. Use a full pre-image/transaction recovery path.");

        var destinationRoot = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(destinationRoot);
        RejectReparse(destinationRoot);
        var name = Path.GetFileName(full);
        if (string.IsNullOrWhiteSpace(name)) name = "recovered.bin";
        var destination = Path.Combine(destinationRoot, name + ".ransomguard-cow-recovered");
        if (File.Exists(destination)) throw new IOException("Recovery output already exists: " + destination);
        var temp = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            using (var input = new FileStream(full, FileMode.Open, FileAccess.Read,
                       FileShare.Read | FileShare.Write | FileShare.Delete, _blockSize,
                       FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                       _blockSize, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await input.CopyToAsync(output, _blockSize, cancellationToken).ConfigureAwait(false);

                var blocks = _blocks.Values
                    .Where(x => x.OriginalPath.Equals(full, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(x => x.BlockOffset)
                    .ToArray();

                foreach (var block in blocks)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var snapshot = SafeSnapshotPath(block.SnapshotRelativePath);
                    if (!File.Exists(snapshot)) throw new FileNotFoundException("Range rollback block is missing.", snapshot);
                    var bytes = await File.ReadAllBytesAsync(snapshot, cancellationToken).ConfigureAwait(false);
                    if (bytes.Length != block.BlockLength)
                        throw new InvalidDataException("Range rollback block length mismatch.");
                    var sha = Hex(SHA256.HashData(bytes));
                    if (!sha.Equals(block.SnapshotSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Range rollback block SHA-256 mismatch.");

                    output.Position = block.BlockOffset;
                    await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                }

                output.SetLength(baseline.OriginalLength);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(true);
            }

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
        foreach (var block in _blocks.Values)
        {
            var snapshot = SafeSnapshotPath(block.SnapshotRelativePath);
            if (!File.Exists(snapshot)) throw new InvalidDataException("Committed range rollback block is missing: " + snapshot);
            var bytes = File.ReadAllBytes(snapshot);
            if (bytes.Length != block.BlockLength)
                throw new InvalidDataException("Committed range rollback block length mismatch: " + snapshot);
            var sha = Hex(SHA256.HashData(bytes));
            if (!sha.Equals(block.SnapshotSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Committed range rollback block hash mismatch: " + snapshot);
            referenced.Add(Path.GetFullPath(snapshot));
        }

        foreach (var file in Directory.EnumerateFiles(_objects, "*.block", SearchOption.TopDirectoryOnly))
            if (!referenced.Contains(Path.GetFullPath(file)))
                throw new InvalidDataException("Unjournaled range rollback object found: " + file);

        foreach (var file in Directory.EnumerateFiles(_objects, "*.tmp", SearchOption.TopDirectoryOnly))
            throw new InvalidDataException("Incomplete range rollback temp artifact found: " + file);
    }

    private RangeRollbackBaseline EnsureBaselineCommitted(string full, long currentLength)
    {
        if (_baselines.TryGetValue(full, out var existing)) return existing;
        var line = AppendRecord(RangeJournalKind.Baseline, full, currentLength, 0, 0, string.Empty, string.Empty);
        var baseline = new RangeRollbackBaseline(line.Sequence, line.CapturedUtc, full, currentLength,
            line.PreviousRecordSha256, line.RecordSha256);
        if (!_baselines.TryAdd(full, baseline))
            throw new InvalidOperationException("Concurrent range rollback baseline commit collision.");
        return baseline;
    }

    private RangeJournalLine AppendRecord(RangeJournalKind kind, string full, long originalLength,
        long blockOffset, int blockLength, string relative, string snapshotSha)
    {
        var sequence = checked(++_nextSequence);
        var payload = new RangeJournalPayload(sequence, DateTime.UtcNow, kind, full, originalLength,
            blockOffset, blockLength, relative, snapshotSha, _lastRecordHash);
        var recordHash = HashPayload(payload);
        var line = new RangeJournalLine(payload.Sequence, payload.CapturedUtc, payload.Kind, payload.OriginalPath,
            payload.OriginalLength, payload.BlockOffset, payload.BlockLength, payload.SnapshotRelativePath,
            payload.SnapshotSha256, payload.PreviousRecordSha256, recordHash);
        AppendJournalLine(line);
        _lastRecordHash = recordHash;
        return line;
    }

    private void LoadAndValidateJournal(bool rebuildState = true)
    {
        if (!File.Exists(_journal))
        {
            if (rebuildState)
            {
                _baselines.Clear();
                _blocks.Clear();
                _nextSequence = 0;
                _lastRecordHash = new string('0', 64);
            }
            return;
        }

        RejectReparse(_journal);
        var expectedPrevious = new string('0', 64);
        long expectedSequence = 1;
        var baselines = new Dictionary<string, RangeRollbackBaseline>(StringComparer.OrdinalIgnoreCase);
        var blocks = new Dictionary<string, RangeRollbackBlock>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in File.ReadLines(_journal, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(raw)) throw new InvalidDataException("Blank range rollback journal record.");
            RangeJournalLine line;
            try
            {
                line = JsonSerializer.Deserialize<RangeJournalLine>(raw, _json)
                       ?? throw new InvalidDataException("Invalid range rollback journal record.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid range rollback journal JSON.", ex);
            }
            if (line.Sequence != expectedSequence) throw new InvalidDataException("Range rollback journal sequence gap.");
            if (!line.PreviousRecordSha256.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Range rollback journal hash chain mismatch.");
            var calculated = HashPayload(line.Payload);
            if (!calculated.Equals(line.RecordSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Range rollback journal record hash mismatch.");

            var full = NormalizeSource(line.OriginalPath);
            if (line.Kind == RangeJournalKind.Baseline)
            {
                if (line.OriginalLength < 0 || line.BlockOffset != 0 || line.BlockLength != 0 ||
                    line.SnapshotRelativePath.Length != 0 || line.SnapshotSha256.Length != 0)
                    throw new InvalidDataException("Invalid range rollback baseline record.");
                if (!baselines.TryAdd(full, new RangeRollbackBaseline(line.Sequence, line.CapturedUtc, full,
                        line.OriginalLength, line.PreviousRecordSha256, line.RecordSha256)))
                    throw new InvalidDataException("Duplicate range rollback baseline.");
            }
            else if (line.Kind == RangeJournalKind.Block)
            {
                if (!baselines.TryGetValue(full, out var baseline))
                    throw new InvalidDataException("Range rollback block appears before its file baseline.");
                if (line.OriginalLength != baseline.OriginalLength || line.BlockOffset < 0 ||
                    line.BlockLength <= 0 || line.BlockLength > _blockSize ||
                    string.IsNullOrWhiteSpace(line.SnapshotRelativePath) || !IsSha256(line.SnapshotSha256))
                    throw new InvalidDataException("Invalid range rollback block record.");
                if ((line.BlockOffset % _blockSize) != 0)
                    throw new InvalidDataException("Range rollback block offset is not aligned.");
                if (line.BlockOffset >= baseline.OriginalLength ||
                    line.BlockLength != Math.Min(_blockSize, baseline.OriginalLength - line.BlockOffset))
                    throw new InvalidDataException("Range rollback block does not match the original file geometry.");
                var snapshot = SafeSnapshotPath(line.SnapshotRelativePath);
                if (!File.Exists(snapshot) || new FileInfo(snapshot).Length != line.BlockLength)
                    throw new InvalidDataException("Range rollback journal references a missing/truncated block.");
                var key = BlockKey(full, line.BlockOffset);
                if (!blocks.TryAdd(key, new RangeRollbackBlock(line.Sequence, line.CapturedUtc, full,
                        line.BlockOffset, line.BlockLength, line.SnapshotRelativePath, line.SnapshotSha256,
                        line.PreviousRecordSha256, line.RecordSha256)))
                    throw new InvalidDataException("Duplicate range rollback block record.");
            }
            else
            {
                throw new InvalidDataException("Unknown range rollback journal record kind.");
            }

            expectedPrevious = line.RecordSha256;
            expectedSequence++;
        }

        if (rebuildState)
        {
            _baselines.Clear();
            _blocks.Clear();
            foreach (var pair in baselines) _baselines[pair.Key] = pair.Value;
            foreach (var pair in blocks) _blocks[pair.Key] = pair.Value;
            _nextSequence = expectedSequence - 1;
            _lastRecordHash = expectedPrevious;
        }
    }

    private void AppendJournalLine(RangeJournalLine line)
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
        if (Path.IsPathRooted(relative)) throw new InvalidDataException("Range rollback object path must be relative.");
        var full = Path.GetFullPath(Path.Combine(_root, relative));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Range rollback object escapes the store root.");
        RejectReparse(full);
        return full;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Source ended before an original rollback block was captured.");
            offset += read;
        }
    }

    private static string NormalizeSource(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Source path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Path.IsPathRooted(full)) throw new ArgumentException("Source path must be absolute.", nameof(path));
        return full;
    }

    private static string BlockKey(string full, long blockOffset) => full + "|" + blockOffset.ToString("X16");

    private string HashPayload(RangeJournalPayload payload) =>
        Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, _json)));

    private static string Hex(byte[] data) => Convert.ToHexString(data);

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(c => char.IsAsciiHexDigit(c));

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Range rollback store/source must not be a reparse point: " + path);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

public sealed record RangeRollbackRecoveryExpectation(long ExpectedLength, string ExpectedSha256);

public sealed record RangeRollbackBaseline(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    long OriginalLength,
    string PreviousRecordSha256,
    string RecordSha256);

public sealed record RangeRollbackBlock(
    long Sequence,
    DateTime CapturedUtc,
    string OriginalPath,
    long BlockOffset,
    int BlockLength,
    string SnapshotRelativePath,
    string SnapshotSha256,
    string PreviousRecordSha256,
    string RecordSha256);

internal enum RangeJournalKind
{
    Baseline = 1,
    Block = 2
}

internal sealed record RangeJournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    RangeJournalKind Kind,
    string OriginalPath,
    long OriginalLength,
    long BlockOffset,
    int BlockLength,
    string SnapshotRelativePath,
    string SnapshotSha256,
    string PreviousRecordSha256);

internal sealed record RangeJournalLine(
    long Sequence,
    DateTime CapturedUtc,
    RangeJournalKind Kind,
    string OriginalPath,
    long OriginalLength,
    long BlockOffset,
    int BlockLength,
    string SnapshotRelativePath,
    string SnapshotSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public RangeJournalPayload Payload => new(Sequence, CapturedUtc, Kind, OriginalPath, OriginalLength,
        BlockOffset, BlockLength, SnapshotRelativePath, SnapshotSha256, PreviousRecordSha256);
}
