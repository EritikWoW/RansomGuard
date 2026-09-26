namespace RansomGuard.Core;
public readonly record struct ProcessKey(int Pid, long CreationFileTimeUtc);
public enum FileKind { Open, Write, Delete, Rename }
public sealed record FileSignal(DateTime EventUtc, DateTime ReceivedUtc, ProcessKey Process,
    string ProcessName, string? ImagePath, string Path, FileKind Kind, bool CanaryCandidate = false)
{
    public string? DestinationPath { get; init; } // Unknown for existing ETW rename events; never guessed.
}
public sealed record RiskSignal(ProcessKey Process, string Name, string? ImagePath, DateTime DetectedUtc,
    DateTime LastEventUtc, double DeliveryLagMs, int Score, int Writes, int Renames, int Deletes,
    int DistinctFiles, bool CanaryCandidate, bool TruncatedWindow, string[] Reasons,
    FileSignal[] Evidence)
{
    public DateTime? FirstEvidenceEventUtc => Evidence.Length == 0 ? null : Evidence.Min(e => e.EventUtc);
    public DateTime? FirstEvidenceReceivedUtc => Evidence.Length == 0 ? null : Evidence.Min(e => e.ReceivedUtc);
    public double FirstEvidenceToDecisionMs => FirstEvidenceEventUtc is DateTime first
        ? Math.Max(0, (DetectedUtc - first).TotalMilliseconds) : 0;
    public double FirstReceiveToDecisionMs => FirstEvidenceReceivedUtc is DateTime first
        ? Math.Max(0, (DetectedUtc - first).TotalMilliseconds) : 0;
    public double MaxEvidenceDeliveryLagMs => Evidence.Length == 0 ? DeliveryLagMs
        : Evidence.Max(e => Math.Max(0, (e.ReceivedUtc - e.EventUtc).TotalMilliseconds));
    public double P95EvidenceDeliveryLagMs
    {
        get
        {
            if (Evidence.Length == 0) return DeliveryLagMs;
            var values = Evidence.Select(e => Math.Max(0, (e.ReceivedUtc - e.EventUtc).TotalMilliseconds)).Order().ToArray();
            return values[Math.Clamp((int)Math.Ceiling(values.Length * 0.95) - 1, 0, values.Length - 1)];
        }
    }
}
public sealed record SignatureEvidence(string Status, string? NativeStatus, string? Publisher,
    string? CertificateThumbprint, string RevocationPolicy = "OfflineCacheOnly",
    string Coverage = "EmbeddedSignatureOnly");
public readonly record struct FileIdentityEvidence(
    uint VolumeSerialNumber,
    ulong FileIndex,
    long Size,
    long LastWriteFileTimeUtc);

public static class FileIdentityPolicy
{
    public static bool SameFile(FileIdentityEvidence? expected, FileIdentityEvidence? actual)
        => expected is FileIdentityEvidence left &&
           actual is FileIdentityEvidence right &&
           left.VolumeSerialNumber == right.VolumeSerialNumber &&
           left.FileIndex == right.FileIndex;
}

public sealed record ImageEvidence(string? Path, string? Sha256, long? Size, string Status,
    SignatureEvidence Signature, string LocalDisposition, DateTime ObservedUtc, string? Error)
{
    public FileIdentityEvidence? FileIdentity { get; init; }
}
public sealed record LabIdentity(ProcessKey Process, string ImagePath, string Sha256, DateTime ExpiresUtc);
public sealed record ActionDecision(bool AllowLabSuspend, string Reason);
public sealed record ContentSample(string Path, string Sha256, double Entropy, string Header,
    int SampleBytes, long FileBytes, DateTime SampledUtc);
public sealed record ContentChange(string Path, string Status, ContentSample Before,
    ContentSample? After, bool? SampleChanged, double? EntropyDelta, string? Error)
{
    public string? ObservedPath { get; init; }
}
