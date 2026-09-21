namespace RansomGuard.Rollback;

/// <summary>Owns independent rollback sessions. A first pre-image is scoped to one session, never to all time.</summary>
public sealed class RollbackRepository
{
    private readonly string _root;
    private readonly string _sessions;

    public string Root => _root;

    public RollbackRepository(string root)
    {
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Rollback repository root is required.", nameof(root));
        _root = Path.GetFullPath(root);
        _sessions = Path.Combine(_root, "Sessions");
        Directory.CreateDirectory(_sessions);
        RejectReparse(_root);
        RejectReparse(_sessions);
    }

    public RollbackStore CreateSession(string sessionId)
    {
        ValidateSessionId(sessionId);
        var path = Path.Combine(_sessions, sessionId);
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Rollback session already exists: " + sessionId);
        Directory.CreateDirectory(path);
        return new RollbackStore(path);
    }

    public RollbackStore OpenSession(string sessionId)
    {
        ValidateSessionId(sessionId);
        var path = Path.Combine(_sessions, sessionId);
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException("Rollback session not found: " + sessionId);
        return new RollbackStore(path);
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
            var rangeRoot = Path.Combine(store.Root, "write-cow");
            if (Directory.Exists(rangeRoot))
                new RangeRollbackStore(rangeRoot).VerifyAll();

            var createRoot = Path.Combine(store.Root, "create-state");
            if (Directory.Exists(createRoot))
            {
                new CreateRollbackStore(createRoot).VerifyAll();
                new CreateOperationStore(createRoot).VerifyAll();
            }

            var identityRoot = Path.Combine(store.Root, "identity-state");
            if (Directory.Exists(identityRoot))
                new FileIdentityStore(identityRoot).VerifyAll();

            var renameRoot = Path.Combine(store.Root, "rename-state");
            if (Directory.Exists(renameRoot))
                new RenameRollbackStore(renameRoot).VerifyAll();

            var restartRoot = Path.Combine(store.Root, "restart-state");
            if (Directory.Exists(restartRoot))
                new RestartReconciliationStore(restartRoot).VerifyAll();

            var pagingRoot = Path.Combine(store.Root, "paging-state");
            if (Directory.Exists(pagingRoot))
                new PagingWriteEvidenceStore(pagingRoot).VerifyAll();

            var sectionRoot = Path.Combine(store.Root, "section-state");
            if (Directory.Exists(sectionRoot))
                new WritableSectionEvidenceStore(sectionRoot).VerifyAll();

            var activationRoot = Path.Combine(store.Root, "activation-state");
            if (Directory.Exists(activationRoot))
                new ActivationPreflightStore(activationRoot).VerifyAll();

            var topologyRoot = Path.Combine(store.Root, "activation-topology-state");
            if (Directory.Exists(topologyRoot))
                new ActivationTopologyStore(topologyRoot).VerifyAll();
        }
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
