using System.Security.Cryptography;
using System.Text.Json;
using RansomGuard.Management;

static string ServicePath(string packageRoot) =>
    Path.Combine(Path.GetFullPath(packageRoot), "RansomGuard.Service.exe");

static string HashService(string packageRoot)
{
    var path = ServicePath(packageRoot);
    using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    return Convert.ToHexString(SHA256.HashData(file));
}

static void Print(object value) =>
    Console.WriteLine(JsonSerializer.Serialize(value));

try
{
    if (args.Length < 1) throw new ArgumentException("Command required.");
    var command = args[0];

    switch (command)
    {
        case "install":
        {
            if (args.Length != 3) throw new ArgumentException("install <packageRoot> <protectedRoot>");
            var hash = HashService(args[1]);
            var image = ServiceAdministration.Install(args[1], hash, new[] { Path.GetFullPath(args[2]) }, false, "INSTALL");
            Print(new { command, image, hash });
            return 0;
        }
        case "review-update":
        {
            if (args.Length != 2) throw new ArgumentException("review-update <packageRoot>");
            var hash = HashService(args[1]);
            var version = ServiceAdministration.ReviewUpdateInput(args[1], hash);
            Print(new { command, version, hash });
            return 0;
        }
        case "update":
        {
            if (args.Length != 2) throw new ArgumentException("update <packageRoot>");
            var hash = HashService(args[1]);
            var result = ServiceAdministration.Update(args[1], hash, "UPDATE");
            Print(result);
            return 0;
        }
        case "expect-update-failure":
        {
            if (args.Length != 3) throw new ArgumentException("expect-update-failure <packageRoot> <messageFragment>");
            var hash = HashService(args[1]);
            try
            {
                _ = ServiceAdministration.Update(args[1], hash, "UPDATE");
                throw new InvalidOperationException("Update unexpectedly succeeded.");
            }
            catch (IOException ex)
            {
                if (!ex.Message.Contains(args[2], StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Update failed for an unexpected reason: " + ex.Message, ex);
                Print(new { command, expectedFailure = true, message = ex.Message, hash });
                return 0;
            }
        }
        case "expect-review-failure":
        {
            if (args.Length != 4) throw new ArgumentException("expect-review-failure <packageRoot> <expectedHash> <messageFragment>");
            try
            {
                _ = ServiceAdministration.ReviewUpdateInput(args[1], args[2]);
                throw new InvalidOperationException("Update review unexpectedly succeeded.");
            }
            catch (IOException ex)
            {
                if (!ex.Message.Contains(args[3], StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Update review failed for an unexpected reason: " + ex.Message, ex);
                Print(new { command, expectedFailure = true, message = ex.Message });
                return 0;
            }
        }
        case "query":
        {
            if (args.Length != 1) throw new ArgumentException("query");
            Print(ServiceAdministration.Query());
            return 0;
        }
        case "uninstall":
        {
            if (args.Length != 1) throw new ArgumentException("uninstall");
            var status = ServiceAdministration.Query();
            if (!status.QuerySucceeded) throw new IOException(status.Error);
            if (!status.Installed)
            {
                Print(new { command, alreadyAbsent = true });
                return 0;
            }
            if (!string.Equals(status.State, "Stopped", StringComparison.Ordinal))
                ServiceAdministration.Execute("stop", "STOP");
            ServiceAdministration.Execute("uninstall", "UNINSTALL");
            var after = ServiceAdministration.Query();
            if (!after.QuerySucceeded || after.Installed)
                throw new IOException("Service registration remained after qualification uninstall.");
            Print(new { command, removed = true });
            return 0;
        }
        default:
            throw new ArgumentException("Unknown command: " + command);
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}
