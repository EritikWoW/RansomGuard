namespace RansomGuard.Rollback;

/// <summary>Owns independent rollback sessions. A first pre-image is scoped to one session, never to all time.</summary>
public sealed class RollbackRepository
{
    private readonly string _root;
    private readonly string _sessions;
    private readonly bool _createIfMissing;

    public string Root => _root;

    public RollbackRepository(string root, bool createIfMissing = true)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Rollback repository root is required.", nameof(root));
        _root = Path.GetFullPath(root);
        _sessions = Path.Combine(_root, "Sessions");
        _createIfMissing = createIfMissing;
        if (createIfMissing)
        {
            Directory.CreateDirectory(_sessions);
        }
        else
        {
            if (!Directory.Exists(_root))
            {
                if (File.Exists(_root)) throw new IOException("Rollback repository root is not a directory: " + _root);
                throw new DirectoryNotFoundException("Rollback repository root does not exist: " + _root);
            }
            if (!Directory.Exists(_sessions))
            {
                if (File.Exists(_sessions)) throw new IOException("Rollback Sessions path is not a directory: " + _sessions);
                throw new DirectoryNotFoundException("Rollback Sessions directory does not exist: " + _sessions);
            }
        }
        RejectReparse(_root);
        RejectReparse(_sessions);
    }

    public RollbackStore CreateSession(string sessionId, DateTime? createdUtc = null)
    {
        if (!_createIfMissing) throw new InvalidOperationException("Read-only rollback repository cannot create sessions.");
        ValidateSessionId(sessionId);
        var path = Path.Combine(_sessions, sessionId);
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Rollback session already exists: " + sessionId);
        Directory.CreateDirectory(path);
        var store = new RollbackStore(path);
        new RollbackSessionLifecycleStore(path).InitializeCreated(createdUtc);
        return store;
    }

    public RollbackStore OpenSession(string sessionId)
    {
        ValidateSessionId(sessionId);
        var path = Path.Combine(_sessions, sessionId);
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException("Rollback session not found: " + sessionId);
        return new RollbackStore(path, _createIfMissing);
    }

    public string[] SessionIds() => Directory.EnumerateDirectories(_sessions)
        .Select(Path.GetFileName).Where(x => !string.IsNullOrWhiteSpace(x)).Cast<string>()
        .Order(StringComparer.Ordinal).ToArray();

    public void VerifyAll()
    {
        foreach (var id in SessionIds())
        {
            var store = OpenSession(id);
            store.VerifyAll();

            var lifecycleRoot = Path.Combine(store.Root, "lifecycle-state");
            if (Directory.Exists(lifecycleRoot))
                new RollbackSessionLifecycleStore(store.Root).VerifyAll();

            var rangeRoot = Path.Combine(store.Root, "write-cow");
            if (Directory.Exists(rangeRoot))
                new RangeRollbackStore(rangeRoot, createIfMissing: _createIfMissing).VerifyAll();

            var createRoot = Path.Combine(store.Root, "create-state");
            if (Directory.Exists(createRoot))
            {
                new CreateRollbackStore(createRoot, createIfMissing: _createIfMissing).VerifyAll();
                new CreateOperationStore(createRoot, createIfMissing: _createIfMissing).VerifyAll();
            }

            var identityRoot = Path.Combine(store.Root, "identity-state");
            if (Directory.Exists(identityRoot))
                new FileIdentityStore(identityRoot, createIfMissing: _createIfMissing).VerifyAll();

            var renameRoot = Path.Combine(store.Root, "rename-state");
            if (Directory.Exists(renameRoot))
                new RenameRollbackStore(renameRoot, createIfMissing: _createIfMissing).VerifyAll();

            var truncateRoot = Path.Combine(store.Root, "truncate-state");
            if (Directory.Exists(truncateRoot))
                new TruncateOperationStore(truncateRoot, createIfMissing: _createIfMissing).VerifyAll();

            var deleteRoot = Path.Combine(store.Root, "delete-state");
            if (Directory.Exists(deleteRoot))
                new DeleteOperationStore(deleteRoot, createIfMissing: _createIfMissing).VerifyAll();

            var restartRoot = Path.Combine(store.Root, "restart-state");
            if (Directory.Exists(restartRoot))
                new RestartReconciliationStore(restartRoot, createIfMissing: _createIfMissing).VerifyAll();

            var pagingRoot = Path.Combine(store.Root, "paging-state");
            if (Directory.Exists(pagingRoot))
                new PagingWriteEvidenceStore(pagingRoot, createIfMissing: _createIfMissing).VerifyAll();

            var sectionRoot = Path.Combine(store.Root, "section-state");
            if (Directory.Exists(sectionRoot))
                new WritableSectionEvidenceStore(sectionRoot, createIfMissing: _createIfMissing).VerifyAll();

            var activationRoot = Path.Combine(store.Root, "activation-state");
            if (Directory.Exists(activationRoot))
                new ActivationPreflightStore(activationRoot, createIfMissing: _createIfMissing).VerifyAll();

            var topologyRoot = Path.Combine(store.Root, "activation-topology-state");
            if (Directory.Exists(topologyRoot))
                new ActivationTopologyStore(topologyRoot, createIfMissing: _createIfMissing).VerifyAll();

            var containmentRoot = Path.Combine(store.Root, "containment-state");
            if (Directory.Exists(containmentRoot))
                new ContainmentEvidenceStore(containmentRoot, createIfMissing: _createIfMissing).VerifyAll();
        }

        var retentionRoot = Path.Combine(_root, "retention-state");
        if (Directory.Exists(retentionRoot))
            new RollbackRetentionStore(_root, createIfMissing: false).VerifyAll();
    }

    private static void ValidateSessionId(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Length > 80)
            throw new ArgumentException("Invalid rollback session id.", nameof(sessionId));
        foreach (var c in sessionId)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new ArgumentException("Rollback session id contains an unsafe character.", nameof(sessionId));
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Rollback repository must not be a reparse point: " + path);
    }
}
