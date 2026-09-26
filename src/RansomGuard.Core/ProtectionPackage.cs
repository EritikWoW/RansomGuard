using System.Text.RegularExpressions;

namespace RansomGuard.Core;

public sealed record ProtectionPackageDescriptor(
    int Schema,
    string Profile,
    string Version,
    int Protocol,
    string Provider,
    string Altitude,
    string GateClientSha256,
    string DriverSysSha256,
    string DriverInfSha256,
    string DriverCatSha256);

public sealed record ProtectionPackageAdmission(
    string State,
    bool PackagePresent,
    bool LayoutVerified,
    bool DescriptorVerified,
    bool HashesVerified,
    bool GateClientSignatureVerified,
    bool CatalogSignatureVerified,
    bool CatalogMembershipVerified,
    bool ReadyForLifecycle,
    string Reason,
    string? Altitude,
    DateTime ObservedUtc,
    string? SignerCertificateSha256 = null);

public static class ProtectionPackagePolicy
{
    public const int DescriptorSchema = 1;
    public const int ProtocolVersion = 18;
    public const string ProductionProfile = "ProductionProtection";
    public const string ProductionProvider = "RansomGuard";
    public const string LabPlaceholderAltitude = "370099.4242";

    public static void ValidateDescriptor(ProtectionPackageDescriptor descriptor, string expectedVersion)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (descriptor.Schema != DescriptorSchema)
            throw new InvalidOperationException("Unsupported protection package descriptor schema.");
        if (!string.Equals(descriptor.Profile, ProductionProfile, StringComparison.Ordinal))
            throw new InvalidOperationException("Protection package profile is not ProductionProtection.");
        if (!string.Equals(descriptor.Version, expectedVersion, StringComparison.Ordinal))
            throw new InvalidOperationException("Protection package version does not match the service.");
        if (descriptor.Protocol != ProtocolVersion)
            throw new InvalidOperationException("Protection package protocol does not match the service.");
        if (!string.Equals(descriptor.Provider, ProductionProvider, StringComparison.Ordinal))
            throw new InvalidOperationException("Protection package provider is not the production provider.");

        ValidateAltitude(descriptor.Altitude);
        foreach (var hash in new[]
        {
            descriptor.GateClientSha256,
            descriptor.DriverSysSha256,
            descriptor.DriverInfSha256,
            descriptor.DriverCatSha256
        })
        {
            if (!IsSha256(hash))
                throw new InvalidOperationException("Protection package contains an invalid SHA-256 digest.");
        }
    }

    public static bool IsInPlaceTransitionCompatible(
        ProtectionPackageDescriptor current,
        ProtectionPackageDescriptor target)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(target);

        return current.Protocol == target.Protocol &&
               string.Equals(current.Provider, target.Provider, StringComparison.Ordinal) &&
               string.Equals(current.Altitude, target.Altitude, StringComparison.Ordinal) &&
               string.Equals(current.DriverSysSha256, target.DriverSysSha256, StringComparison.OrdinalIgnoreCase);
    }

    public static void ValidateAltitude(string? altitude)
    {
        if (string.IsNullOrWhiteSpace(altitude) ||
            string.Equals(altitude, LabPlaceholderAltitude, StringComparison.Ordinal))
            throw new InvalidOperationException("LAB/unassigned placeholder altitude is forbidden for production admission.");
        if (!Regex.IsMatch(altitude, @"^[0-9]{4,6}(?:\.[0-9]{1,8})?$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Protection package altitude format is invalid.");
    }

    public static bool IsSha256(string? value)
    {
        if (value is null || value.Length != 64) return false;
        foreach (var ch in value)
            if (!Uri.IsHexDigit(ch)) return false;
        return true;
    }
}
