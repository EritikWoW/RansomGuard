using System.Text.Json.Serialization;

namespace RansomGuard.Rollback;

public enum RollbackMutationKind
{
    Write = 1,
    Rename = 2,
    Delete = 3
}

public sealed record RollbackCapture(
    long Sequence,
    DateTime CapturedUtc,
    RollbackMutationKind Mutation,
    string OriginalPath,
    string SnapshotRelativePath,
    long OriginalLength,
    string OriginalSha256,
    string PreviousRecordSha256,
    string RecordSha256);

internal sealed record JournalPayload(
    long Sequence,
    DateTime CapturedUtc,
    RollbackMutationKind Mutation,
    string OriginalPath,
    string SnapshotRelativePath,
    long OriginalLength,
    string OriginalSha256,
    string PreviousRecordSha256);

internal sealed record JournalLine(
    long Sequence,
    DateTime CapturedUtc,
    RollbackMutationKind Mutation,
    string OriginalPath,
    string SnapshotRelativePath,
    long OriginalLength,
    string OriginalSha256,
    string PreviousRecordSha256,
    string RecordSha256)
{
    [JsonIgnore]
    public JournalPayload Payload => new(Sequence, CapturedUtc, Mutation, OriginalPath, SnapshotRelativePath,
        OriginalLength, OriginalSha256, PreviousRecordSha256);

    public RollbackCapture ToCapture() => new(Sequence, CapturedUtc, Mutation, OriginalPath,
        SnapshotRelativePath, OriginalLength, OriginalSha256, PreviousRecordSha256, RecordSha256);
}
