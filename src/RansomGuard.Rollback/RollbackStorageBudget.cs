namespace RansomGuard.Rollback;

/// <summary>
/// Session-scoped fail-closed storage admission for preservation work.
/// Capacity is based on actual committed session bytes plus all in-flight reservations.
/// </summary>
public sealed class RollbackStorageBudget
{
    public const long MiB = 1024L * 1024L;
    public const long GiB = 1024L * MiB;
    public const long MetadataReservationBytes = 128L * 1024L;
    public const long FullCaptureOverheadBytes = 128L * 1024L;
    public const long RangeJournalBaseBytes = 64L * 1024L;
    public const long RangeJournalPerBlockBytes = 16L * 1024L;

    private readonly string _sessionRoot;
    private readonly long _maxSessionBytes;
    private readonly long _minFreeBytes;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _reservedBytes;

    public string SessionRoot => _sessionRoot;
    public long MaxSessionBytes => _maxSessionBytes;
    public long MinFreeBytes => _minFreeBytes;

    public RollbackStorageBudget(string sessionRoot, long maxSessionBytes, long minFreeBytes)
    {
        if (string.IsNullOrWhiteSpace(sessionRoot))
            throw new ArgumentException("Rollback session root is required.", nameof(sessionRoot));
        if (maxSessionBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxSessionBytes));
        if (minFreeBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(minFreeBytes));

        _sessionRoot = Path.GetFullPath(sessionRoot);
        _maxSessionBytes = maxSessionBytes;
        _minFreeBytes = minFreeBytes;

        if (!Directory.Exists(_sessionRoot))
            throw new DirectoryNotFoundException("Rollback session root does not exist: " + _sessionRoot);
        RejectReparse(_sessionRoot);
    }

    public async ValueTask<RollbackStorageReservation> ReserveAsync(
        long estimatedBytes,
        string purpose,
        CancellationToken cancellationToken = default)
    {
        if (estimatedBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(estimatedBytes));
        if (string.IsNullOrWhiteSpace(purpose))
            throw new ArgumentException("Storage reservation purpose is required.", nameof(purpose));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var actual = MeasureDirectoryBytes(_sessionRoot);
            var free = QueryAvailableFreeSpace(_sessionRoot);

            if (actual > _maxSessionBytes)
                throw new RollbackStorageBudgetExceededException(
                    purpose, estimatedBytes, actual, _reservedBytes, free,
                    _maxSessionBytes, _minFreeBytes,
                    "Rollback session already exceeds its configured storage limit.");

            if (estimatedBytes > _maxSessionBytes - actual - _reservedBytes)
                throw new RollbackStorageBudgetExceededException(
                    purpose, estimatedBytes, actual, _reservedBytes, free,
                    _maxSessionBytes, _minFreeBytes,
                    "Rollback session quota would be exceeded.");

            if (free < _minFreeBytes ||
                estimatedBytes > free - _minFreeBytes ||
                _reservedBytes > free - _minFreeBytes - estimatedBytes)
                throw new RollbackStorageBudgetExceededException(
                    purpose, estimatedBytes, actual, _reservedBytes, free,
                    _maxSessionBytes, _minFreeBytes,
                    "Filesystem free-space reserve would be violated.");

            _reservedBytes = checked(_reservedBytes + estimatedBytes);
            return new RollbackStorageReservation(this, estimatedBytes, purpose);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<RollbackStorageBudgetStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return new RollbackStorageBudgetStatus(
                MeasureDirectoryBytes(_sessionRoot),
                _reservedBytes,
                QueryAvailableFreeSpace(_sessionRoot),
                _maxSessionBytes,
                _minFreeBytes);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async ValueTask ReleaseAsync(long reservedBytes)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (reservedBytes < 0 || reservedBytes > _reservedBytes)
                throw new InvalidOperationException("Rollback storage reservation accounting underflow.");
            _reservedBytes -= reservedBytes;
        }
        finally
        {
            _gate.Release();
        }
    }

    public static long EstimateFullPreimageBytes(RollbackStore store, string path)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.TryGetCapture(path, out _))
            return 0;

        var info = new FileInfo(Path.GetFullPath(path));
        if (!info.Exists)
            throw new FileNotFoundException("Cannot estimate full pre-image for a missing file.", info.FullName);
        return checked(info.Length + FullCaptureOverheadBytes);
    }

    public static long EstimateOriginallyAbsentBytes(CreateRollbackStore store, string path)
    {
        ArgumentNullException.ThrowIfNull(store);
        return store.WasOriginallyAbsent(path) ? 0 : MetadataReservationBytes;
    }

    public static long EstimateRangeCaptureBytes(
        RangeRollbackStore store,
        string path,
        long byteOffset,
        uint length)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (length == 0) return 0;
        if (byteOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(byteOffset));

        var full = Path.GetFullPath(path);
        var baseline = store.Baselines.SingleOrDefault(x =>
            Path.GetFullPath(x.OriginalPath).Equals(full, StringComparison.OrdinalIgnoreCase));
        var originalLength = baseline?.OriginalLength ?? new FileInfo(full).Length;
        var writeEnd = checked(byteOffset + (long)length);
        var originalEnd = Math.Min(writeEnd, originalLength);

        var estimate = baseline is null ? RangeJournalBaseBytes : 0L;
        if (byteOffset >= originalEnd)
            return estimate;

        var existingOffsets = store.Blocks
            .Where(x => Path.GetFullPath(x.OriginalPath).Equals(full, StringComparison.OrdinalIgnoreCase))
            .Select(x => x.BlockOffset)
            .ToHashSet();

        var firstBlock = (byteOffset / store.BlockSize) * store.BlockSize;
        for (var blockOffset = firstBlock; blockOffset < originalEnd;
             blockOffset = checked(blockOffset + store.BlockSize))
        {
            if (existingOffsets.Contains(blockOffset))
                continue;

            var blockLength = Math.Min((long)store.BlockSize, originalLength - blockOffset);
            if (blockLength <= 0) break;
            estimate = checked(estimate + blockLength + RangeJournalPerBlockBytes);
        }

        return estimate;
    }

    private static long MeasureDirectoryBytes(string root)
    {
        long total = 0;
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            RejectReparse(directory);

            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(file);
                total = checked(total + new FileInfo(file).Length);
            }

            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(child);
                pending.Push(child);
            }
        }

        return total;
    }

    private static long QueryAvailableFreeSpace(string path)
    {
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrWhiteSpace(root))
            throw new IOException("Cannot resolve filesystem root for rollback storage.");
        var drive = new DriveInfo(root);
        if (!drive.IsReady)
            throw new IOException("Rollback storage drive is not ready: " + root);
        return drive.AvailableFreeSpace;
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback storage budget refuses reparse-point paths: " + path);
    }
}

public sealed class RollbackStorageReservation : IAsyncDisposable
{
    private RollbackStorageBudget? _owner;

    internal RollbackStorageReservation(RollbackStorageBudget owner, long bytes, string purpose)
    {
        _owner = owner;
        Bytes = bytes;
        Purpose = purpose;
    }

    public long Bytes { get; }
    public string Purpose { get; }

    public async ValueTask DisposeAsync()
    {
        var owner = Interlocked.Exchange(ref _owner, null);
        if (owner is not null)
            await owner.ReleaseAsync(Bytes).ConfigureAwait(false);
    }
}

public sealed record RollbackStorageBudgetStatus(
    long ActualSessionBytes,
    long ReservedBytes,
    long AvailableFreeBytes,
    long MaxSessionBytes,
    long MinFreeBytes);

public sealed class RollbackStorageBudgetExceededException : IOException
{
    public RollbackStorageBudgetExceededException(
        string purpose,
        long requestedBytes,
        long actualSessionBytes,
        long reservedBytes,
        long availableFreeBytes,
        long maxSessionBytes,
        long minFreeBytes,
        string message)
        : base(message)
    {
        Purpose = purpose;
        RequestedBytes = requestedBytes;
        ActualSessionBytes = actualSessionBytes;
        ReservedBytes = reservedBytes;
        AvailableFreeBytes = availableFreeBytes;
        MaxSessionBytes = maxSessionBytes;
        MinFreeBytes = minFreeBytes;
    }

    public string Purpose { get; }
    public long RequestedBytes { get; }
    public long ActualSessionBytes { get; }
    public long ReservedBytes { get; }
    public long AvailableFreeBytes { get; }
    public long MaxSessionBytes { get; }
    public long MinFreeBytes { get; }
}
