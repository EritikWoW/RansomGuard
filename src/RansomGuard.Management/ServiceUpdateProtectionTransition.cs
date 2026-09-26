using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

internal sealed record UpdateProtectionPackage(
    string Root,
    ProtectionPackageDescriptor Descriptor,
    string DescriptorPath,
    string GateClientPath,
    string DriverSysPath,
    string DriverInfPath,
    string DriverCatPath);

internal sealed record RegisteredProtectionIdentity(
    string DriverSysSha256,
    string Altitude);

public static partial class ServiceAdministration
{
    private const string UpdateProtectionDirectoryName = "Protection";
    private const string UpdateProtectionDescriptorName = "protection-package.json";
    private const string ProductionFilterServiceKey = @"SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter";
    private const long UpdateProtectionDescriptorMaxBytes = 64 * 1024;
    private const long UpdateGateClientMaxBytes = 256L * 1024 * 1024;
    private const long UpdateDriverMaxBytes = 64L * 1024 * 1024;
    private const long UpdateInfMaxBytes = 512 * 1024;
    private const long UpdateCatalogMaxBytes = 64L * 1024 * 1024;

    private static readonly JsonSerializerOptions UpdateProtectionJson = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false
    };

    private static GuardSettings ReadUpdateSettings(string path)
    {
        FileSafety.NoReparse(path);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 or > 65536)
            throw new IOException("Installed configuration exceeds the update migration bound.");
        if (!WinPaths.Equal(Path.GetFullPath(path), Native.FinalFilePath(input.SafeFileHandle)))
            throw new IOException("Installed configuration path was redirected.");

        var settings = JsonSerializer.Deserialize<GuardSettings>(input)
            ?? throw new IOException("Installed configuration is missing.");
        settings.Validate();
        if (settings.ProtectedRoots.Length == 0)
            throw new IOException("Installed configuration lost explicit protected roots.");
        return settings;
    }

    private static UpdateProtectionPackage? InspectUpdateProtectionPackage(
        string packageRoot,
        string expectedVersion)
    {
        var root = Path.Combine(Path.GetFullPath(packageRoot), UpdateProtectionDirectoryName);
        if (!Directory.Exists(root))
            return null;

        FileSafety.NoReparse(root);
        ValidateUpdateProtectionLayout(root);

        var descriptorPath = Path.Combine(root, UpdateProtectionDescriptorName);
        var gatePath = Path.Combine(root, "GateClient", "RansomGuard.GateClient.exe");
        var driverRoot = Path.Combine(root, "Driver");
        var sysPath = Path.Combine(driverRoot, "RansomGuardMinifilter.sys");
        var infPath = Path.Combine(driverRoot, "RansomGuardMinifilter.inf");
        var catPath = Path.Combine(driverRoot, "RansomGuardMinifilter.cat");

        ProtectionPackageDescriptor descriptor;
        using (var descriptorFile = OpenExactUpdateProtectionFile(
                   descriptorPath, 2, UpdateProtectionDescriptorMaxBytes))
        {
            descriptor = JsonSerializer.Deserialize<ProtectionPackageDescriptor>(
                             descriptorFile, UpdateProtectionJson)
                         ?? throw new InvalidDataException("Protection package descriptor is empty.");
        }

        ProtectionPackagePolicy.ValidateDescriptor(descriptor, expectedVersion);

        using var gate = OpenExactUpdateProtectionFile(gatePath, 4096, UpdateGateClientMaxBytes);
        using var sys = OpenExactUpdateProtectionFile(sysPath, 4096, UpdateDriverMaxBytes);
        using var inf = OpenExactUpdateProtectionFile(infPath, 64, UpdateInfMaxBytes);
        using var cat = OpenExactUpdateProtectionFile(catPath, 256, UpdateCatalogMaxBytes);

        if (!DecisionPolicy.HashEqual(HashUpdateProtectionFile(gate), descriptor.GateClientSha256) ||
            !DecisionPolicy.HashEqual(HashUpdateProtectionFile(sys), descriptor.DriverSysSha256) ||
            !DecisionPolicy.HashEqual(HashUpdateProtectionFile(inf), descriptor.DriverInfSha256) ||
            !DecisionPolicy.HashEqual(HashUpdateProtectionFile(cat), descriptor.DriverCatSha256))
            throw new InvalidDataException(
                "Protection package bytes do not match the transition descriptor SHA-256 values.");

        if (!string.Equals(
                FileVersionInfo.GetVersionInfo(gatePath).FileVersion,
                expectedVersion,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Protection GateClient FileVersion does not match the target service version.");

        ValidateUpdateProtectionInf(ReadUpdateProtectionText(inf), descriptor);

        return new(
            root,
            descriptor,
            descriptorPath,
            gatePath,
            sysPath,
            infPath,
            catPath);
    }

    private static void ValidateUpdateProtectionTransition(
        GuardSettings settings,
        string previousFolder,
        string previousVersion,
        UpdateProtectionPackage? target)
    {
        var previous = InspectUpdateProtectionPackage(previousFolder, previousVersion);
        var registered = ReadRegisteredProtectionIdentity();

        if (string.Equals(settings.Mode, "Enforce", StringComparison.Ordinal) && previous is null)
            throw new IOException(
                "The current Enforce installation has no version-bound Protection package; update is refused.");

        if (registered is not null && previous is null)
            throw new IOException(
                "A production protection registration exists without the previous immutable Protection package; update is refused.");

        if (previous is not null && target is null)
            throw new IOException(
                "The installed version has a Protection package, so the target update must carry its own compatible version-bound Protection package.");

        if (previous is not null && target is not null &&
            !ProtectionPackagePolicy.IsInPlaceTransitionCompatible(previous.Descriptor, target.Descriptor))
            throw new IOException(
                "The target protection package changes the registered filter identity or binary. " +
                "That requires a separate explicit maintenance transition; the service updater will not replace it silently.");

        if (registered is not null && target is not null)
        {
            if (!DecisionPolicy.HashEqual(
                    registered.DriverSysSha256,
                    target.Descriptor.DriverSysSha256) ||
                !string.Equals(
                    registered.Altitude,
                    target.Descriptor.Altitude,
                    StringComparison.Ordinal))
                throw new IOException(
                    "The target protection package is incompatible with the currently registered production filter.");
        }
    }

    private static void StageUpdateProtectionPackage(
        UpdateProtectionPackage? source,
        string targetFolder)
    {
        if (source is null)
            return;

        var root = Path.Combine(targetFolder, UpdateProtectionDirectoryName);
        var gateRoot = Path.Combine(root, "GateClient");
        var driverRoot = Path.Combine(root, "Driver");
        EnsureInstallDirectory(root);
        EnsureInstallDirectory(gateRoot);
        EnsureInstallDirectory(driverRoot);

        CopyUpdateProtectionFile(
            source.DescriptorPath,
            Path.Combine(root, UpdateProtectionDescriptorName),
            2,
            UpdateProtectionDescriptorMaxBytes);
        CopyUpdateProtectionFile(
            source.GateClientPath,
            Path.Combine(gateRoot, "RansomGuard.GateClient.exe"),
            4096,
            UpdateGateClientMaxBytes);
        CopyUpdateProtectionFile(
            source.DriverSysPath,
            Path.Combine(driverRoot, "RansomGuardMinifilter.sys"),
            4096,
            UpdateDriverMaxBytes);
        CopyUpdateProtectionFile(
            source.DriverInfPath,
            Path.Combine(driverRoot, "RansomGuardMinifilter.inf"),
            64,
            UpdateInfMaxBytes);
        CopyUpdateProtectionFile(
            source.DriverCatPath,
            Path.Combine(driverRoot, "RansomGuardMinifilter.cat"),
            256,
            UpdateCatalogMaxBytes);

        var staged = InspectUpdateProtectionPackage(targetFolder, source.Descriptor.Version)
            ?? throw new InvalidDataException("Staged Protection package disappeared.");
        if (staged.Descriptor != source.Descriptor)
            throw new InvalidDataException(
                "Staged Protection descriptor changed during the update transition.");

        var registered = ReadRegisteredProtectionIdentity();
        if (registered is not null &&
            (!DecisionPolicy.HashEqual(
                 registered.DriverSysSha256,
                 staged.Descriptor.DriverSysSha256) ||
             !string.Equals(
                 registered.Altitude,
                 staged.Descriptor.Altitude,
                 StringComparison.Ordinal)))
            throw new IOException(
                "Staged Protection package no longer matches the registered production filter.");
    }

    private static void CleanupStagedProtectionPackage(string targetFolder)
    {
        var root = Path.Combine(targetFolder, UpdateProtectionDirectoryName);
        if (!Directory.Exists(root))
            return;

        var gateRoot = Path.Combine(root, "GateClient");
        var driverRoot = Path.Combine(root, "Driver");
        foreach (var path in new[]
                 {
                     Path.Combine(root, UpdateProtectionDescriptorName),
                     Path.Combine(gateRoot, "RansomGuard.GateClient.exe"),
                     Path.Combine(driverRoot, "RansomGuardMinifilter.sys"),
                     Path.Combine(driverRoot, "RansomGuardMinifilter.inf"),
                     Path.Combine(driverRoot, "RansomGuardMinifilter.cat")
                 })
        {
            try
            {
                if (!File.Exists(path)) continue;
                FileSafety.NoReparse(path);
                File.Delete(path);
            }
            catch (IOException)
            {
            }
        }

        foreach (var directory in new[] { driverRoot, gateRoot, root })
        {
            try
            {
                if (!Directory.Exists(directory)) continue;
                FileSafety.NoReparse(directory);
                Directory.Delete(directory, false);
            }
            catch (IOException)
            {
            }
        }
    }

    private static RegisteredProtectionIdentity? ReadRegisteredProtectionIdentity()
    {
        using var service = Registry.LocalMachine.OpenSubKey(ProductionFilterServiceKey, writable: false);
        if (service is null)
            return null;

        if (Convert.ToInt32(service.GetValue("Start", -1), System.Globalization.CultureInfo.InvariantCulture) != 3 ||
            Convert.ToInt32(service.GetValue("Type", -1), System.Globalization.CultureInfo.InvariantCulture) != 2)
            throw new IOException("Registered production filter contract is not compatible with an in-place update.");

        using var instances = service.OpenSubKey(@"Parameters\Instances", writable: false)
            ?? throw new IOException("Registered production filter instance configuration is missing.");
        var defaultInstance = instances.GetValue("DefaultInstance") as string;
        if (string.IsNullOrWhiteSpace(defaultInstance))
            throw new IOException("Registered production filter default instance is missing.");

        using var instance = instances.OpenSubKey(defaultInstance, writable: false)
            ?? throw new IOException("Registered production filter default instance key is missing.");
        var altitude = instance.GetValue("Altitude") as string;
        var flags = Convert.ToInt32(
            instance.GetValue("Flags", -1),
            System.Globalization.CultureInfo.InvariantCulture);
        ProtectionPackagePolicy.ValidateAltitude(altitude);
        if (flags != 1)
            throw new IOException("Registered production filter attachment flags are incompatible.");

        var rawImage = service.GetValue("ImagePath") as string;
        if (string.IsNullOrWhiteSpace(rawImage))
            throw new IOException("Registered production filter image path is missing.");
        var image = ResolveUpdateServiceImagePath(rawImage);
        using var file = OpenExactUpdateProtectionFile(image, 4096, UpdateDriverMaxBytes);
        var hash = HashUpdateProtectionFile(file);
        return new(hash, altitude!);
    }

    private static string ResolveUpdateServiceImagePath(string value)
    {
        var path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                path[@"\SystemRoot\".Length..]);
        else if (!Path.IsPathRooted(path))
            path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                path);
        return Path.GetFullPath(path);
    }

    private static void ValidateUpdateProtectionLayout(string root)
    {
        static string[] Names(string directory) =>
            Directory.EnumerateFileSystemEntries(directory)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

        var expectedRoot = new[]
        {
            "Driver",
            "GateClient",
            UpdateProtectionDescriptorName
        }.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
        if (!Names(root).SequenceEqual(expectedRoot, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Protection package root contains missing or unexpected entries.");

        var gateRoot = Path.Combine(root, "GateClient");
        var driverRoot = Path.Combine(root, "Driver");
        FileSafety.NoReparse(gateRoot);
        FileSafety.NoReparse(driverRoot);
        if (!Names(gateRoot).SequenceEqual(
                new[] { "RansomGuard.GateClient.exe" },
                StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Protection/GateClient contains missing or unexpected entries.");

        var expectedDriver = new[]
        {
            "RansomGuardMinifilter.cat",
            "RansomGuardMinifilter.inf",
            "RansomGuardMinifilter.sys"
        };
        if (!Names(driverRoot).SequenceEqual(expectedDriver, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Protection/Driver contains missing or unexpected entries.");
    }

    private static FileStream OpenExactUpdateProtectionFile(
        string path,
        long minBytes,
        long maxBytes)
    {
        FileSafety.NoReparse(path);
        var full = Path.GetFullPath(path);
        var file = new FileStream(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        try
        {
            if (file.Length < minBytes || file.Length > maxBytes)
                throw new InvalidDataException(
                    "Protection transition file size rejected: " + Path.GetFileName(full));
            if (!WinPaths.Equal(full, Native.FinalFilePath(file.SafeFileHandle)))
                throw new IOException(
                    "Protection transition source path was redirected: " + Path.GetFileName(full));
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    private static string HashUpdateProtectionFile(FileStream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        return hash;
    }

    private static string ReadUpdateProtectionText(FileStream stream)
    {
        stream.Position = 0;
        using var reader = new StreamReader(
            stream,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 1024,
            leaveOpen: true);
        var text = reader.ReadToEnd();
        stream.Position = 0;
        return text;
    }

    private static void ValidateUpdateProtectionInf(
        string inf,
        ProtectionPackageDescriptor descriptor)
    {
        if (inf.Contains("UNASSIGNED LAB PLACEHOLDER", StringComparison.OrdinalIgnoreCase) ||
            inf.Contains("RansomGuard Lab", StringComparison.OrdinalIgnoreCase) ||
            inf.Contains(ProtectionPackagePolicy.LabPlaceholderAltitude, StringComparison.Ordinal))
            throw new InvalidDataException(
                "LAB identity/placeholder altitude is forbidden in a production update package.");

        var altitude = Regex.Match(
            inf,
            @"(?im)^\s*Instance1\.Altitude\s*=\s*""(?<value>[^""]+)""\s*$");
        if (!altitude.Success ||
            !string.Equals(
                altitude.Groups["value"].Value,
                descriptor.Altitude,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Update INF altitude does not match the protection descriptor.");

        var provider = Regex.Match(
            inf,
            @"(?im)^\s*ProviderString\s*=\s*""(?<value>[^""]+)""\s*$");
        if (!provider.Success ||
            !string.Equals(
                provider.Groups["value"].Value,
                descriptor.Provider,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Update INF provider does not match the protection descriptor.");

        var version = Regex.Match(
            inf,
            @"(?im)^\s*DriverVer\s*=\s*[^,]+,(?<value>\d+\.\d+\.\d+\.\d+)\s*$");
        if (!version.Success ||
            !string.Equals(
                version.Groups["value"].Value,
                descriptor.Version,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Update INF DriverVer does not match the target service version.");
    }

    private static void CopyUpdateProtectionFile(
        string sourcePath,
        string destinationPath,
        long minBytes,
        long maxBytes)
    {
        using var source = OpenExactUpdateProtectionFile(sourcePath, minBytes, maxBytes);
        CopyNewAndFlush(source, destinationPath);
        SetInstallFileAcl(destinationPath);
    }
}
