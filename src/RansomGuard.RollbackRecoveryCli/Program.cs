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
        case "plan":
        {
            var repository = Require(options, "--repository");
            var session = Require(options, "--session");
            var output = Require(options, "--output");

            var plan = RollbackRecoveryPlanner.Build(repository, session);
            WriteNewJson(output, plan, json);

            Console.WriteLine($"PLAN OK: {Path.GetFullPath(output)}");
            Console.WriteLine($"PlanId={plan.PlanId}");
            Console.WriteLine($"Ready={plan.ReadyCount}; Review={plan.ReviewCount}; Blocked={plan.BlockedCount}");
            return 0;
        }

        case "execute":
        {
            var repository = Require(options, "--repository");
            var planPath = Require(options, "--plan");
            var output = Require(options, "--output");

            if (!File.Exists(planPath))
                throw new FileNotFoundException("Recovery plan file does not exist.", planPath);

            var plan = JsonSerializer.Deserialize<RollbackRecoveryPlan>(
                File.ReadAllText(planPath, Encoding.UTF8), json)
                ?? throw new InvalidDataException("Recovery plan JSON is invalid.");

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var report = await RollbackRecoveryExecutor.ExecuteReadyAsync(
                repository, plan, output, cts.Token).ConfigureAwait(false);

            Console.WriteLine($"EXECUTION {(report.Succeeded ? "PASSED" : "FAILED")}: {report.OutputRoot}");
            Console.WriteLine($"PlanId={report.PlanId}");
            Console.WriteLine($"Succeeded={report.SucceededActions}/{report.RequestedReadyActions}; ReviewNotExecuted={report.ReviewActionsNotExecuted}; BlockedNotExecuted={report.BlockedActionsNotExecuted}");
            return report.Succeeded ? 0 : 4;
        }

        default:
            throw new ArgumentException($"Unknown command '{args[0]}'.");
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Recovery execution cancelled. Existing verified copy-out files are left untouched; live evidence is unchanged.");
    return 5;
}
catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
{
    Console.Error.WriteLine("Recovery refused/failed: " + ex.Message);
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

static void WriteNewJson<T>(string path, T value, JsonSerializerOptions options)
{
    var full = Path.GetFullPath(path);
    var parent = Path.GetDirectoryName(full)
        ?? throw new ArgumentException("Plan output must have a parent directory.", nameof(path));
    Directory.CreateDirectory(parent);
    if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
        throw new IOException("Plan output parent must not be a reparse point: " + parent);

    var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, options));
    using var stream = new FileStream(
        full, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
        64 * 1024, FileOptions.WriteThrough);
    stream.Write(bytes);
    stream.Flush(true);
}

static void Usage()
{
    Console.WriteLine("RansomGuard verified rollback recovery (Engineering LAB only)");
    Console.WriteLine("Plan:    RansomGuard.RollbackRecovery.exe plan --repository <ROLLBACK_ROOT> --session <SESSION_ID> --output <NEW_PLAN_JSON>");
    Console.WriteLine("Execute: RansomGuard.RollbackRecovery.exe execute --repository <ROLLBACK_ROOT> --plan <PLAN_JSON> --output <NEW_OUTPUT_DIRECTORY>");
    Console.WriteLine("Only validated Ready copy-out actions are executed. Live source/evidence files are never overwritten, renamed or deleted.");
}
