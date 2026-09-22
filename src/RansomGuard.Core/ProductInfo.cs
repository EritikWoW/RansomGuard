using System.Reflection;

namespace RansomGuard.Core;

public static class ProductInfo
{
    public static string Version { get; } = ResolveVersion();

    private static string ResolveVersion()
    {
        var assembly = Assembly.GetEntryAssembly() ?? typeof(ProductInfo).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var metadataSeparator = informational.IndexOf('+');
            return metadataSeparator >= 0
                ? informational[..metadataSeparator]
                : informational;
        }

        return assembly.GetName().Version?.ToString() ?? "unknown";
    }
}
