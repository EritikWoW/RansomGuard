using System.Text;
using System.Text.Json;
using RansomGuard.Rollback;

var json = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true,
    WriteIndented = true
};

if (args.Length == 0)
{
    Usage();
    return 0;
}

try
{
    var command = args[0].ToLowerInvariant();
    var options = Parse(args.Skip(1).ToArray());

    switch (command)
    {
        case "status":
        {
            var repositoryRoot = Require(options, "--repository");
            var repository = new RollbackRepository(repositoryRoot);
            repository.VerifyAll();

            foreach (var sessionId in repository.SessionIds())
            {
                var store = repository.OpenSession(sessionId);
                var lifecycleRoot = Path.Combine(store.Root, "lifecycle-state");
                if (!Directory.Exists(lifecycleRoot))
                {
                    Console.WriteLine($"{sessionId}	LegacyUnmanaged	held=false");
                    continue;
                }

                var lifecycle = new RollbackSessionLifecycleStore(store.Root);
                lifecycle.VerifyAll();
                var snapshot = lifecycle.Snapshot;
                Console.WriteLine(
                    $"{sessionId}	{snapshot.State}	held={snapshot.IsHeld}	completed={snapshot.CompletedUtc:O}");
            }
            return 0;
        }

        case "retention-plan":
        {
            var repositoryRoot = Require(options, "--repository");
            var output = Require(options, "--output");
            var policy = ParsePolicy(options);

            var plan = RollbackRetentionPlanner.Build(repositoryRoot, policy);
            WriteNewJson(output, plan, json);

            Console.WriteLine($"RETENTION PLAN OK: {Path.GetFullPath(output)}");
            Console.WriteLine($"PlanId={plan.PlanId}");
            Console.WriteLine($"Actions={plan.Actions.Count}; reclaim={plan.PlannedReclaimBytes}; unresolvedExcess={plan.UnresolvedExcessBytes}");
            Console.WriteLine($"Protected={plan.ProtectedSessions}; held={plan.HeldSessions}; legacy={plan.LegacySessions}; issues={plan.Issues.Count}");
            return 0;
        }

        case "retention-execute":
        {
            var repositoryRoot = Require(options, "--repository");
            var planPath = Require(options, "--plan");
            var reportPath = Require(options, "--report");

            if (!File.Exists(planPath))
                throw new FileNotFoundException("Retention plan file does not exist.", planPath);

            var plan = JsonSerializer.Deserialize<RollbackRetentionPlan>(
                File.ReadAllText(planPath, Encoding.UTF8), json)
                ?? throw new InvalidDataException("Retention plan JSON is invalid.");

            using var reportStream = OpenNewOutput(reportPath);
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var report = await RollbackRetentionExecutor.ExecuteAsync(
                repositoryRoot, plan, cts.Token).ConfigureAwait(false);
            WriteJson(reportStream, report, json);

            Console.WriteLine($"RETENTION {(report.Succeeded ? "PASSED" : "FAILED")}: reclaimed={report.ReclaimedBytes}");
            Console.WriteLine($"PlanId={report.PlanId}; succeeded={report.SucceededActions}/{report.RequestedActions}; failed={report.FailedActions}");
            return report.Succeeded ? 0 : 4;
        }

        case "hold":
        {
            var repositoryRoot = Require(options, "--repository");
            var sessionId = Require(options, "--session");
            var reason = Require(options, "--reason");

            using var maintenanceLease = RollbackMaintenanceLease.Acquire(repositoryRoot);
            var repository = new RollbackRepository(repositoryRoot);
            repository.VerifyAll();
            var store = repository.OpenSession(sessionId);
            var lifecycle = new RollbackSessionLifecycleStore(store.Root);
            if (lifecycle.Snapshot.State == RollbackSessionLifecycleState.LegacyUnmanaged)
                throw new InvalidDataException("Legacy session has no managed lifecycle and cannot be modified automatically.");

            _ = await lifecycle.SetHoldAsync(reason).ConfigureAwait(false);
            Console.WriteLine($"HOLD SET: {sessionId}");
            return 0;
        }

        case "release-hold":
        {
            var repositoryRoot = Require(options, "--repository");
            var sessionId = Require(options, "--session");
            var reason = Require(options, "--reason");

            using var maintenanceLease = RollbackMaintenanceLease.Acquire(repositoryRoot);
            var repository = new RollbackRepository(repositoryRoot);
            repository.VerifyAll();
            var store = repository.OpenSession(sessionId);
            var lifecycle = new RollbackSessionLifecycleStore(store.Root);
            if (lifecycle.Snapshot.State == RollbackSessionLifecycleState.LegacyUnmanaged)
                throw new InvalidDataException("Legacy session has no managed lifecycle and cannot be modified automatically.");

            _ = await lifecycle.ReleaseHoldAsync(reason).ConfigureAwait(false);
            Console.WriteLine($"HOLD RELEASED: {sessionId}");
            return 0;
        }

        default:
            throw new ArgumentException($"Unknown command '{args[0]}'.");
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Rollback maintenance cancelled.");
    return 5;
}
catch (Exception ex) when (
    ex is IOException or InvalidDataException or UnauthorizedAccessException
        or ArgumentException or InvalidOperationException)
{
    Console.Error.WriteLine("Rollback maintenance refused/failed: " + ex.Message);
    return 3;
}

static RollbackRetentionPolicy ParsePolicy(Dictionary<string, string> options)
{
    var maxAgeDays = ParseDouble(options, "--max-age-days", 30, min: 1, max: 3650);
    var maxCompletedMiB = ParseLong(options, "--max-completed-mib", 32768, min: 1, max: 10485760);
    var minPressureHours = ParseDouble(options, "--min-pressure-hours", 24, min: 0, max: maxAgeDays * 24);

    return new RollbackRetentionPolicy(
        TimeSpan.FromDays(maxAgeDays),
        checked(maxCompletedMiB * 1024L * 1024L),
        TimeSpan.FromHours(minPressureHours));
}

static Dictionary<string, string> Parse(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            throw new ArgumentException($"Unknown or incomplete argument: {args[i]}");
        if (!result.TryAdd(args[i], args[++i]))
            throw new ArgumentException($"Duplicate argument: {args[i - 1]}");
    }
    return result;
}

static string Require(Dictionary<string, string> options, string name)
{
    if (!options.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
        throw new ArgumentException($"Missing {name}.");
    return value;
}

static long ParseLong(
    Dictionary<string, string> options,
    string name,
    long defaultValue,
    long min,
    long max)
{
    if (!options.TryGetValue(name, out var raw))
        return defaultValue;
    if (!long.TryParse(raw, out var value) || value < min || value > max)
        throw new ArgumentOutOfRangeException(name, $"{name} must be between {min} and {max}.");
    return value;
}

static double ParseDouble(
    Dictionary<string, string> options,
    string name,
    double defaultValue,
    double min,
    double max)
{
    if (!options.TryGetValue(name, out var raw))
        return defaultValue;
    if (!double.TryParse(raw, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var value) ||
        value < min || value > max)
        throw new ArgumentOutOfRangeException(name, $"{name} must be between {min} and {max}.");
    return value;
}

static void WriteNewJson<T>(string path, T value, JsonSerializerOptions options)
{
    using var stream = OpenNewOutput(path);
    WriteJson(stream, value, options);
}

static FileStream OpenNewOutput(string path)
{
    var full = Path.GetFullPath(path);
    var parent = Path.GetDirectoryName(full)
        ?? throw new ArgumentException("Output path must have a parent directory.", nameof(path));

    RejectExistingReparseAncestors(parent);
    Directory.CreateDirectory(parent);
    if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
        throw new IOException("Output parent must not be a reparse point: " + parent);

    return new FileStream(
        full, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
        64 * 1024, FileOptions.WriteThrough);
}

static void WriteJson<T>(FileStream stream, T value, JsonSerializerOptions options)
{
    var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, options));
    stream.Write(bytes);
    stream.Flush(true);
}

static void RejectExistingReparseAncestors(string path)
{
    var current = new DirectoryInfo(Path.GetFullPath(path));
    if (!current.Exists) current = current.Parent;
    while (current is not null)
    {
        if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Output path must not traverse a reparse point: " + current.FullName);
        current = current.Parent;
    }
}

static void Usage()
{
    Console.WriteLine("RansomGuard rollback maintenance (Engineering LAB only)");
    Console.WriteLine("Status:           RansomGuard.RollbackMaintenance.exe status --repository <ROLLBACK_ROOT>");
    Console.WriteLine("Plan retention:   RansomGuard.RollbackMaintenance.exe retention-plan --repository <ROLLBACK_ROOT> --output <NEW_PLAN_JSON> [--max-age-days 30] [--max-completed-mib 32768] [--min-pressure-hours 24]");
    Console.WriteLine("Execute retention:RansomGuard.RollbackMaintenance.exe retention-execute --repository <ROLLBACK_ROOT> --plan <PLAN_JSON> --report <NEW_REPORT_JSON>");
    Console.WriteLine("Hold:             RansomGuard.RollbackMaintenance.exe hold --repository <ROLLBACK_ROOT> --session <SESSION_ID> --reason <TEXT>");
    Console.WriteLine("Release hold:     RansomGuard.RollbackMaintenance.exe release-hold --repository <ROLLBACK_ROOT> --session <SESSION_ID> --reason <TEXT>");
    Console.WriteLine("Retention is explicit/manual. Active, Faulted, Held, legacy and pending-transaction sessions are never selected.");
}
