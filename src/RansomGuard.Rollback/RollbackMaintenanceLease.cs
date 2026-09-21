using System.Text;

namespace RansomGuard.Rollback;

/// <summary>
/// Cross-process exclusive lease for destructive retention execution and lifecycle hold changes.
/// The lock file is repository metadata; FileShare.None provides the actual exclusion.
/// </summary>
public sealed class RollbackMaintenanceLease : IDisposable
{
    private readonly FileStream _stream;

    private RollbackMaintenanceLease(FileStream stream)
    {
        _stream = stream;
    }

    public static RollbackMaintenanceLease Acquire(string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(repositoryRoot))
            throw new ArgumentException("Rollback repository root is required.", nameof(repositoryRoot));

        var root = Path.GetFullPath(repositoryRoot);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("Rollback repository root does not exist: " + root);
        RejectReparse(root);

        var stateRoot = Path.Combine(root, "retention-state");
        Directory.CreateDirectory(stateRoot);
        RejectReparse(stateRoot);

        var lockPath = Path.Combine(stateRoot, "maintenance.lock");
        FileStream stream;
        try
        {
            stream = new FileStream(
                lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
        }
        catch (IOException ex)
        {
            throw new IOException(
                "Another rollback maintenance operation currently owns the repository lease.",
                ex);
        }

        try
        {
            if ((File.GetAttributes(lockPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Rollback maintenance lock must not be a reparse point.");

            stream.SetLength(0);
            var bytes = Encoding.UTF8.GetBytes(
                $"pid={Environment.ProcessId};utc={DateTime.UtcNow:O}{Environment.NewLine}");
            stream.Write(bytes);
            stream.Flush(true);
            stream.Position = 0;
            return new RollbackMaintenanceLease(stream);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void Dispose() => _stream.Dispose();

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback maintenance state must not be a reparse point: " + path);
    }
}
