using System.IO;
using System.Reflection;
using RansomGuard.Core;
namespace RansomGuard.Ui.Administration;

internal static class PackageIdentity
{
    internal static string ServiceSha256()
    {
        var values = typeof(PackageIdentity).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(a => a.Key == "RansomGuard.ServiceSha256").Select(a => a.Value).ToArray();
        if (values.Length != 1 || !DecisionPolicy.HashEqual(values[0], values[0]))
            throw new IOException("Service image identity is not embedded. Use a complete release built by build_windows.cmd.");
        return values[0]!;
    }
}
