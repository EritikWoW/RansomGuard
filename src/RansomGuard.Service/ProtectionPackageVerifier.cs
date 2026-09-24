using System.Diagnostics;
using System.Security.Cryptography;
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
            var gatePath = Path.Combine(root, "GateClient", "RansomGuard.GateClient.exe");
            var driverDirectory = Path.Combine(root, "Driver");
            var sysPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.sys");
            var infPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.inf");
            var catPath = Path.Combine(driverDirectory, "RansomGuardMinifilter.cat");
            foreach (var path in new[] { descriptorPath, gatePath, sysPath, infPath, catPath })
                FileSafety.NoReparse(path);

            if (!File.Exists(descriptorPath) || !File.Exists(gatePath) ||
                !File.Exists(sysPath) || !File.Exists(infPath) || !File.Exists(catPath))
                return Rejected("Incomplete", true, "Production protection package layout is incomplete.", observed);

            ProtectionPackageDescriptor descriptor;
            using (var descriptorFile = OpenExactFile(descriptorPath, 2, MaxDescriptorBytes))
            {
                descriptor = JsonSerializer.Deserialize<ProtectionPackageDescriptor>(descriptorFile, Json)
                    ?? throw new InvalidDataException("Protection package descriptor is empty.");
            }
            ProtectionPackagePolicy.ValidateDescriptor(descriptor, expectedVersion);

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
                return Rejected("HashMismatch", true, "Protection package bytes do not match the descriptor SHA-256 values.", observed, descriptor.Altitude, true);

            var gateVersion = FileVersionInfo.GetVersionInfo(gatePath).FileVersion;
            if (!string.Equals(gateVersion, expectedVersion, StringComparison.Ordinal))
                return Rejected("VersionMismatch", true, "GateClient FileVersion does not match the service.", observed, descriptor.Altitude, true, true);

            var infText = ReadTextFromStart(inf, MaxInfBytes);
            ValidateInf(infText, descriptor);

            gate.Position = 0;
            var gateSignature = Authenticode.Check(gate, gatePath);
            if (!string.Equals(gateSignature.Status, "ValidCached", StringComparison.Ordinal))
                return Rejected("GateClientSignatureRejected", true,
                    $"GateClient Authenticode verification is '{gateSignature.Status}', not ValidCached.",
                    observed, descriptor.Altitude, true, true, true);

            cat.Position = 0;
            var catSignature = Authenticode.Check(cat, catPath);
            if (!string.Equals(catSignature.Status, "ValidCached", StringComparison.Ordinal))
                return Rejected("CatalogSignatureRejected", true,
                    $"Driver catalog signature verification is '{catSignature.Status}', not ValidCached.",
                    observed, descriptor.Altitude, true, true, true, true);

            // Deliberate fail-closed boundary. A valid signed .cat file plus matching local hashes does
            // not prove that this SYS hash is actually a member of that catalog. The next milestone
            // must verify SYS -> CAT membership with the Windows catalog APIs before driver load.
            return new(
                "CatalogMembershipPending",
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                "Package identity/signatures passed, but SYS-to-CAT membership is not yet cryptographically verified; driver load is refused.",
                descriptor.Altitude,
                observed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or
                                   InvalidOperationException or JsonException or CryptographicException)
        {
            return Rejected("Rejected", true, ex.GetType().Name + ": " + ex.Message, observed);
        }
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
        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
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

        var protocolVersion = Regex.Match(
            inf,
            @"(?im)^\s*DriverVer\s*=\s*[^,]+,(?<value>\d+\.\d+\.\d+\.\d+)\s*$");
        if (!protocolVersion.Success)
            throw new InvalidDataException("INF DriverVer is missing or malformed.");
    }

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
        bool catalogSignature = false) =>
        new(
            state,
            present,
            layout,
            descriptor,
            hashes,
            gateSignature,
            catalogSignature,
            false,
            false,
            reason,
            altitude,
            observed);
}
