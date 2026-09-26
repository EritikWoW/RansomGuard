using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal static class ProtectionPackageVerifier
{
    private const string DirectoryName = "Protection";
    private const string DescriptorName = "protection-package.json";
    private const long MaxDescriptorBytes = 64 * 1024;
    private const long MaxGateClientBytes = 256L * 1024 * 1024;
    private const long MaxDriverBytes = 64L * 1024 * 1024;
    private const long MaxInfBytes = 512 * 1024;
    private const long MaxCatalogBytes = 64L * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false
    };

    public static ProtectionPackageAdmission Inspect(string applicationBaseDirectory, string expectedVersion)
    {
        var observed = DateTime.UtcNow;
        var root = Path.Combine(Path.GetFullPath(applicationBaseDirectory), DirectoryName);
        if (!Directory.Exists(root))
            return Rejected("Missing", false, "Production protection package is not installed beside the service.", observed);

        try
        {
            FileSafety.NoReparse(root);

            var descriptorPath = Path.Combine(root, DescriptorName);
            var servicePath = Path.Combine(Path.GetFullPath(applicationBaseDirectory), "RansomGuard.Service.exe");
            var gatePath = Path.Combine(root, "GateClient", "RansomGuard.GateClient.exe");
            var driverDirectory = Path.Combine(root, "Driver");
            var sysPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.sys");
            var infPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.inf");
            var catPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.cat");
            foreach (var path in new[] { servicePath, descriptorPath, gatePath, sysPath, infPath, catPath })
                FileSafety.NoReparse(path);

            var runningImage = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(runningImage) || !WinPaths.Equal(runningImage, servicePath))
                return Rejected("ServiceIdentityMismatch", true,
                    "The running process image is not the fixed RansomGuard.Service.exe beside the protection package.", observed);
            if (!File.Exists(servicePath))
                return Rejected("ServiceIdentityMissing", true, "Running package does not contain the expected RansomGuard.Service.exe identity.", observed);
            if (!File.Exists(descriptorPath) || !File.Exists(gatePath) ||
                !File.Exists(sysPath) || !File.Exists(infPath) || !File.Exists(catPath))
                return Rejected("Incomplete", true, "Production protection package layout is incomplete.", observed);

            ValidateExactLayout(root);

            ProtectionPackageDescriptor descriptor;
            using (var descriptorFile = OpenExactFile(descriptorPath, 2, MaxDescriptorBytes))
            {
                descriptor = JsonSerializer.Deserialize<ProtectionPackageDescriptor>(descriptorFile, Json)
                    ?? throw new InvalidDataException("Protection package descriptor is empty.");
            }
            ProtectionPackagePolicy.ValidateDescriptor(descriptor, expectedVersion);

            using var service = OpenExactFile(servicePath, 4096, MaxGateClientBytes);
            using var gate = OpenExactFile(gatePath, 4096, MaxGateClientBytes);
            using var sys = OpenExactFile(sysPath, 4096, MaxDriverBytes);
            using var inf = OpenExactFile(infPath, 64, MaxInfBytes);
            using var cat = OpenExactFile(catPath, 256, MaxCatalogBytes);

            var gateHash = Hash(gate);
            var sysHash = Hash(sys);
            var infHash = Hash(inf);
            var catHash = Hash(cat);
            if (!DecisionPolicy.HashEqual(gateHash, descriptor.GateClientSha256) ||
                !DecisionPolicy.HashEqual(sysHash, descriptor.DriverSysSha256) ||
                !DecisionPolicy.HashEqual(infHash, descriptor.DriverInfSha256) ||
                !DecisionPolicy.HashEqual(catHash, descriptor.DriverCatSha256))
                return Rejected("HashMismatch", true, "Protection package bytes do not match the descriptor SHA-256 values.", observed, descriptor.Altitude, true, true);

            var serviceVersion = FileVersionInfo.GetVersionInfo(servicePath).FileVersion;
            var gateVersion = FileVersionInfo.GetVersionInfo(gatePath).FileVersion;
            if (!string.Equals(serviceVersion, expectedVersion, StringComparison.Ordinal) ||
                !string.Equals(gateVersion, expectedVersion, StringComparison.Ordinal))
                return Rejected("VersionMismatch", true, "Service/GateClient FileVersion does not match the package version.", observed, descriptor.Altitude, true, true, true);

            service.Position = 0;
            var serviceSignature = Authenticode.Check(service, servicePath);
            if (!string.Equals(serviceSignature.Status, "ValidCached", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(serviceSignature.CertificateThumbprint))
                return Rejected("ServiceSignatureRejected", true,
                    $"Service Authenticode verification is '{serviceSignature.Status}' or has no signer identity.",
                    observed, descriptor.Altitude, true, true, true);

            var infText = ReadTextFromStart(inf, MaxInfBytes);
            ValidateInf(infText, descriptor);

            gate.Position = 0;
            var gateSignature = Authenticode.Check(gate, gatePath);
            if (!string.Equals(gateSignature.Status, "ValidCached", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(gateSignature.CertificateThumbprint))
                return Rejected("GateClientSignatureRejected", true,
                    $"GateClient Authenticode verification is '{gateSignature.Status}' or has no signer identity.",
                    observed, descriptor.Altitude, true, true, true);
            if (!string.Equals(
                    gateSignature.CertificateThumbprint,
                    serviceSignature.CertificateThumbprint,
                    StringComparison.OrdinalIgnoreCase))
                return Rejected("GateClientSignerMismatch", true,
                    "GateClient signer certificate does not match the running service signer.",
                    observed, descriptor.Altitude, true, true, true);

            cat.Position = 0;
            var catSignature = Authenticode.Check(cat, catPath);
            if (!string.Equals(catSignature.Status, "ValidCached", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(catSignature.CertificateThumbprint))
                return Rejected("CatalogSignatureRejected", true,
                    $"Driver catalog signature verification is '{catSignature.Status}' or has no signer identity.",
                    observed, descriptor.Altitude, true, true, true, true);
            if (!string.Equals(
                    catSignature.CertificateThumbprint,
                    serviceSignature.CertificateThumbprint,
                    StringComparison.OrdinalIgnoreCase))
                return Rejected("CatalogSignerMismatch", true,
                    "Driver catalog signer certificate does not match the running service signer.",
                    observed, descriptor.Altitude, true, true, true, true);

            sys.Position = 0;
            var sysMembership = DriverCatalogTrust.VerifyMember(sys, sysPath, catPath);
            if (!string.Equals(sysMembership.Status, "ValidCatalogMember", StringComparison.Ordinal))
                return Rejected("DriverCatalogMembershipRejected", true,
                    $"Driver SYS is not a trusted member of the supplied catalog: {sysMembership.Status}.",
                    observed, descriptor.Altitude, true, true, true, true, true);

            inf.Position = 0;
            var infMembership = DriverCatalogTrust.VerifyMember(inf, infPath, catPath);
            if (!string.Equals(infMembership.Status, "ValidCatalogMember", StringComparison.Ordinal))
                return Rejected("InfCatalogMembershipRejected", true,
                    $"Driver INF is not a trusted member of the supplied catalog: {infMembership.Status}.",
                    observed, descriptor.Altitude, true, true, true, true, true);

            return new(
                "Admitted",
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                "Protection package identity, signatures and SYS/INF catalog membership passed; package is admitted for the production lifecycle.",
                descriptor.Altitude,
                observed,
                serviceSignature.CertificateThumbprint);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or
                                   InvalidOperationException or JsonException or CryptographicException)
        {
            return Rejected("Rejected", true, ex.GetType().Name + ": " + ex.Message, observed);
        }
    }

    private static void ValidateExactLayout(string root)
    {
        static string[] Names(string directory) =>
            Directory.EnumerateFileSystemEntries(directory)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

        var rootNames = Names(root);
        var expectedRoot = new[] { "Driver", "GateClient", DescriptorName }
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
        if (!rootNames.SequenceEqual(expectedRoot, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("Protection package root contains missing or unexpected entries.");

        var gateDirectory = Path.Combine(root, "GateClient");
        var gateNames = Names(gateDirectory);
        if (!gateNames.SequenceEqual(new[] { "RansomGuard.GateClient.exe" }, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("Protection/GateClient contains missing or unexpected entries.");

        var driverDirectory = Path.Combine(root, "Driver");
        var driverNames = Names(driverDirectory);
        var expectedDriver = new[]
        {
            "RansomGuardMinifilter.cat",
            "RansomGuardMinifilter.inf",
            "RansomGuardMinifilter.sys"
        };
        if (!driverNames.SequenceEqual(expectedDriver, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("Protection/Driver contains missing or unexpected entries.");
    }

    private static FileStream OpenExactFile(string path, long minBytes, long maxBytes)
    {
        var full = Path.GetFullPath(path);
        var file = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (file.Length < minBytes || file.Length > maxBytes)
                throw new InvalidDataException($"Protection package file size rejected: {Path.GetFileName(full)}.");
            var final = Native.FinalFilePath(file.SafeFileHandle);
            if (!WinPaths.Equal(full, final))
                throw new IOException("Protection package file path was redirected: " + Path.GetFileName(full));
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    private static string Hash(FileStream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        return hash;
    }

    private static string ReadTextFromStart(FileStream stream, long maxBytes)
    {
        if (stream.Length > maxBytes) throw new InvalidDataException("INF exceeds size limit.");
        stream.Position = 0;
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
        var text = reader.ReadToEnd();
        stream.Position = 0;
        return text;
    }

    private static void ValidateInf(string inf, ProtectionPackageDescriptor descriptor)
    {
        if (inf.Contains("UNASSIGNED LAB PLACEHOLDER", StringComparison.OrdinalIgnoreCase) ||
            inf.Contains("RansomGuard Lab", StringComparison.OrdinalIgnoreCase) ||
            inf.Contains(ProtectionPackagePolicy.LabPlaceholderAltitude, StringComparison.Ordinal))
            throw new InvalidDataException("LAB identity/placeholder altitude is forbidden in a production protection package.");

        var altitude = Regex.Match(
            inf,
            @"(?im)^\s*Instance1\.Altitude\s*=\s*""(?<value>[^""]+)""\s*$");
        if (!altitude.Success ||
            !string.Equals(altitude.Groups["value"].Value, descriptor.Altitude, StringComparison.Ordinal))
            throw new InvalidDataException("INF altitude does not match the production package descriptor.");

        var provider = Regex.Match(
            inf,
            @"(?im)^\s*ProviderString\s*=\s*""(?<value>[^""]+)""\s*$");
        if (!provider.Success ||
            !string.Equals(provider.Groups["value"].Value, descriptor.Provider, StringComparison.Ordinal))
            throw new InvalidDataException("INF provider does not match the production package descriptor.");

        var driverVersion = Regex.Match(
            inf,
            @"(?im)^\s*DriverVer\s*=\s*[^,]+,(?<value>\d+\.\d+\.\d+\.\d+)\s*$");
        if (!driverVersion.Success ||
            !string.Equals(driverVersion.Groups["value"].Value, descriptor.Version, StringComparison.Ordinal))
            throw new InvalidDataException("INF DriverVer does not match the production package descriptor.");
    }

    // Flags describe stages that completed successfully before rejection; ReadyForLifecycle is always false here.
    private static ProtectionPackageAdmission Rejected(
        string state,
        bool present,
        string reason,
        DateTime observed,
        string? altitude = null,
        bool layout = false,
        bool descriptor = false,
        bool hashes = false,
        bool gateSignature = false,
        bool catalogSignature = false,
        bool catalogMembership = false) =>
        new(
            state,
            present,
            layout,
            descriptor,
            hashes,
            gateSignature,
            catalogSignature,
            catalogMembership,
            false,
            reason,
            altitude,
            observed);
}
