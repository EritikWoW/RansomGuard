using System.Text;
using System.Text.Json;
using RansomGuard.Rollback;

const int DefaultMinimumAgeHours = 168;
const int MinimumPurgeAgeHours = 24;
const int MaximumAgeHours = 24 * 3650;

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
        case "plan":
        {
            var repository = Require(options, "--repository");
            var output = Require(options, "--output");
            var minimumAgeHours = ParseAge(options);

            var plan = RollbackRetentionPlanner.Build(
                repository,
                minimumAgeHours);
            WriteNewJson(output, plan, json);

            Console.WriteLine($"RETENTION PLAN OK: {Path.GetFullPath(output)}");
            Console.WriteLine($"PlanId={plan.PlanId}");
            Console.WriteLine($"Sessions={plan.Sessions.Count}; Eligible={plan.Sessions.Count(x => x.Decision == RollbackRetentionDecision.Eligible)}; EligibleBytes={plan.EligibleBytes}");
            return 0;
        }

        case "release":
        {
            var repository = Path.GetFullPath(Require(options, "--repository"));
            var session = Require(options, "--session");
            var recoveryPlanPath = Require(options, "--recovery-plan");
            RequireConfirmation(options, $"RELEASE:{session}");

            var recoveryPlan = ReadJson<RollbackRecoveryPlan>(
                recoveryPlanPath, json, "Recovery plan");
            if (!Path.GetFullPath(recoveryPlan.RepositoryRoot)
                    .Equals(repository, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Recovery plan belongs to a different rollback repository.");
            if (!recoveryPlan.SessionId.Equals(session, StringComparison.Ordinal))
                throw new InvalidDataException("Recovery plan belongs to a different rollback session.");

            var release = await RollbackRetentionPlanner.ReleaseAsync(
                repository,
                session,
                recoveryPlan.PlanId).ConfigureAwait(false);

            Console.WriteLine($"RETENTION RELEASE OK: session={release.SessionId}");
            Console.WriteLine($"RecoveryPlanId={release.RecoveryPlanId}");
            Console.WriteLine($"ReleaseRecordSha256={release.RecordSha256}");
            return 0;
        }

        case "purge":
        {
            var repository = Path.GetFullPath(Require(options, "--repository"));
            var session = Require(options, "--session");
            var retentionPlanPath = Require(options, "--retention-plan");
            RequireConfirmation(options, $"PURGE:{session}");

            var retentionPlan = ReadJson<RollbackRetentionPlan>(
                retentionPlanPath, json, "Retention plan");
            if (retentionPlan.MinimumAgeHours < MinimumPurgeAgeHours)
                throw new InvalidDataException(
                    $"Retention purge requires minimumAgeHours >= {MinimumPurgeAgeHours}. Generate a new plan with --min-age-hours {MinimumPurgeAgeHours} or greater.");

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var report = await RollbackRetentionPurgeExecutor.PurgeSessionAsync(
                repository,
                retentionPlan,
                session,
                cts.Token).ConfigureAwait(false);

            Console.WriteLine($"RETENTION PURGE COMPLETED: session={report.SessionId}");
            Console.WriteLine($"OperationId={report.OperationId}");
            Console.WriteLine($"PurgedBytes={report.PurgedBytes}");
            Console.WriteLine($"CompletedRecordSha256={report.CompletedRecordSha256}");
            return 0;
        }

        default:
            throw new ArgumentException($"Unknown command '{args[0]}'.");
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine(
        "Retention purge cancelled. If quarantine had already started, rollback evidence remains under Retention\\PurgeQuarantine and the purge journal records the last durable state.");
    return 5;
}
catch (Exception ex) when (
    ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
{
    Console.Error.WriteLine("Retention refused/failed: " + ex.Message);
    return 3;
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

static int ParseAge(Dictionary<string, string> options)
{
    if (!options.TryGetValue("--min-age-hours", out var raw))
        return DefaultMinimumAgeHours;

    if (!int.TryParse(raw, out var hours) ||
        hours < MinimumPurgeAgeHours ||
        hours > MaximumAgeHours)
        throw new ArgumentOutOfRangeException(
            nameof(options),
            $"--min-age-hours must be between {MinimumPurgeAgeHours} and {MaximumAgeHours}.");

    return hours;
}

static void RequireConfirmation(
    Dictionary<string, string> options,
    string expected)
{
    var actual = Require(options, "--confirm");
    if (!actual.Equals(expected, StringComparison.Ordinal))
        throw new InvalidDataException(
            $"Typed confirmation mismatch. Required exact token: {expected}");
}

static T ReadJson<T>(
    string path,
    JsonSerializerOptions options,
    string description)
{
    var full = Path.GetFullPath(path);
    if (!File.Exists(full))
        throw new FileNotFoundException(description + " file does not exist.", full);
    if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        throw new IOException(description + " file must not be a reparse point.");

    return JsonSerializer.Deserialize<T>(
               File.ReadAllText(full, Encoding.UTF8), options)
           ?? throw new InvalidDataException(description + " JSON is invalid.");
}

static void WriteNewJson<T>(
    string path,
    T value,
    JsonSerializerOptions options)
{
    var full = Path.GetFullPath(path);
    var parent = Path.GetDirectoryName(full)
        ?? throw new ArgumentException("Retention plan output must have a parent directory.", nameof(path));

    RejectExistingReparseAncestors(parent);
    Directory.CreateDirectory(parent);
    if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
        throw new IOException("Retention plan output parent must not be a reparse point.");

    var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, options));
    using var stream = new FileStream(
        full,
        FileMode.CreateNew,
        FileAccess.Write,
        FileShare.Read,
        64 * 1024,
        FileOptions.WriteThrough);
    stream.Write(bytes);
    stream.Flush(true);
}

static void RejectExistingReparseAncestors(string path)
{
    var current = new DirectoryInfo(Path.GetFullPath(path));
    if (!current.Exists) current = current.Parent;
    while (current is not null)
    {
        if (current.Exists &&
            (current.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException(
                "Retention plan output must not traverse a reparse point: " + current.FullName);
        current = current.Parent;
    }
}

static void Usage()
{
    Console.WriteLine("RansomGuard safe rollback retention (Engineering LAB only)");
    Console.WriteLine($"Plan:    RansomGuard.RollbackRetention.exe plan --repository <ROLLBACK_ROOT> --output <NEW_PLAN_JSON> [--min-age-hours {DefaultMinimumAgeHours}]");
    Console.WriteLine("Release: RansomGuard.RollbackRetention.exe release --repository <ROLLBACK_ROOT> --session <SESSION_ID> --recovery-plan <RECOVERY_PLAN_JSON> --confirm RELEASE:<SESSION_ID>");
    Console.WriteLine("Purge:   RansomGuard.RollbackRetention.exe purge --repository <ROLLBACK_ROOT> --session <SESSION_ID> --retention-plan <RETENTION_PLAN_JSON> --confirm PURGE:<SESSION_ID>");
    Console.WriteLine($"Purge plans must use a minimum age of at least {MinimumPurgeAgeHours} hours. There is no wildcard/all-sessions purge.");
}
