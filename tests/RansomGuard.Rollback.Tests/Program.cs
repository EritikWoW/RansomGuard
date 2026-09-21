using System.Security.Cryptography;
using System.Text;
using RansomGuard.Rollback;

var passed = 0;
void Check(bool condition, string name)
{
    if (!condition) throw new Exception("FAIL: " + name);
    Console.WriteLine("PASS: " + name); passed++;
}

var root = Path.Combine(Path.GetTempPath(), "RansomGuardRollbackTests", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var sourceDir = Path.Combine(root, "source"); Directory.CreateDirectory(sourceDir);
    var repoDir = Path.Combine(root, "repo");
    var source = Path.Combine(sourceDir, "document.bin");
    var original = Encoding.UTF8.GetBytes("ORIGINAL:" + new string('A', 4096));
    await File.WriteAllBytesAsync(source, original);

    var repo = new RollbackRepository(repoDir);
    var store = repo.CreateSession("incident_a");
    var first = await store.CapturePreimageAsync(source, RollbackMutationKind.Write);
    Check(first.Sequence == 1, "first capture has sequence 1");
    Check(first.OriginalLength == original.Length, "pre-image length captured");
    Check(first.OriginalSha256 == Convert.ToHexString(SHA256.HashData(original)), "pre-image SHA-256 captured");

    await File.WriteAllTextAsync(source, "ENCRYPTED/CHANGED");
    var second = await store.CapturePreimageAsync(source, RollbackMutationKind.Write);
    Check(second.RecordSha256 == first.RecordSha256, "first pre-image wins inside one incident session");

    var output = Path.Combine(root, "recovered");
    var recovered = await store.RestoreToNewCopyAsync(first, output);
    Check(File.Exists(recovered), "recovery writes a new copy");
    Check(File.ReadAllBytes(recovered).SequenceEqual(original), "recovered bytes equal original pre-image");
    Check(File.ReadAllText(source) == "ENCRYPTED/CHANGED", "recovery never overwrites changed source");

    var reopened = repo.OpenSession("incident_a");
    Check(reopened.Captures.Count == 1, "journal rebuilds committed first-capture index");
    reopened.VerifyAll(); Check(true, "validated journal and object lengths");
    repo.VerifyAll(); Check(true, "repository validates all sessions");

    var duplicateOutputBlocked = false;
    try { await reopened.RestoreToNewCopyAsync(first, output); }
    catch (IOException) { duplicateOutputBlocked = true; }
    Check(duplicateOutputBlocked, "existing recovery output is never overwritten");

    // A later incident gets a fresh pre-image for the then-current version of the file.
    var later = repo.CreateSession("incident_b");
    var laterCapture = await later.CapturePreimageAsync(source, RollbackMutationKind.Write);
    Check(laterCapture.OriginalSha256 == Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(source))),
        "new incident captures the current file, not an ancient global pre-image");

    // Range-aware COW captures only original blocks touched by writes and restores to a new copy.
    var cowSource = Path.Combine(sourceDir, "cow.bin");
    var cowOriginal = Enumerable.Range(0, 3 * 1024 * 1024 + 12345)
        .Select(i => (byte)(i % 251)).ToArray();
    await File.WriteAllBytesAsync(cowSource, cowOriginal);
    var cow = new RangeRollbackStore(Path.Combine(root, "cow-session"));
    await cow.CaptureWritePreimageAsync(cowSource, 512 * 1024, 4096);
    Check(cow.BaselineCount == 1, "range COW records one file baseline");
    Check(cow.BlockCount == 1, "range COW captures first touched block only");

    await using (var rw = new FileStream(cowSource, FileMode.Open, FileAccess.Write, FileShare.Read))
    {
        rw.Position = 512 * 1024;
        await rw.WriteAsync(new byte[4096]);
        rw.Position = 2 * 1024 * 1024 + 2000;
        await cow.CaptureWritePreimageAsync(cowSource, rw.Position, 8192);
        await rw.WriteAsync(Enumerable.Repeat((byte)0xCC, 8192).ToArray());
    }
    Check(cow.BlockCount == 2, "range COW captures a newly touched block later in the incident");

    var cowRecoveryDir = Path.Combine(root, "cow-recovered");
    var cowRecovered = await cow.RestoreToNewCopyAsync(cowSource, cowRecoveryDir);
    Check(File.ReadAllBytes(cowRecovered).SequenceEqual(cowOriginal),
        "range COW reconstructs original bytes from damaged file plus captured blocks");
    Check(!File.ReadAllBytes(cowSource).SequenceEqual(cowOriginal),
        "range COW recovery never overwrites damaged source");

    var appendSource = Path.Combine(sourceDir, "append.bin");
    var appendOriginal = Encoding.UTF8.GetBytes("APPEND-BASELINE");
    await File.WriteAllBytesAsync(appendSource, appendOriginal);
    var appendCow = new RangeRollbackStore(Path.Combine(root, "append-session"));
    await appendCow.CaptureWritePreimageAsync(appendSource, appendOriginal.Length, 2048);
    await using (var append = new FileStream(appendSource, FileMode.Append, FileAccess.Write, FileShare.Read))
        await append.WriteAsync(new byte[2048]);
    Check(appendCow.BlockCount == 0, "append beyond original EOF needs baseline but no original data block");
    var appendRecovered = await appendCow.RestoreToNewCopyAsync(appendSource, Path.Combine(root, "append-recovered"));
    Check(File.ReadAllBytes(appendRecovered).SequenceEqual(appendOriginal),
        "range COW recovery truncates appended bytes to original length");

    cow.VerifyAll(); Check(true, "range COW journal and block hashes verify");
    appendCow.VerifyAll(); Check(true, "append-only range COW baseline verifies");

    var journal = reopened.JournalPath;
    var journalBytes = await File.ReadAllBytesAsync(journal);
    journalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(journal, journalBytes);
    var corruptionRejected = false;
    try { _ = repo.OpenSession("incident_a"); }
    catch (InvalidDataException) { corruptionRejected = true; }
    Check(corruptionRejected, "journal corruption is rejected");

    var cancelStore = repo.CreateSession("incident_cancel");
    var cancelSource = Path.Combine(sourceDir, "cancel.bin");
    await File.WriteAllBytesAsync(cancelSource, new byte[4 * 1024 * 1024]);
    using var cts = new CancellationTokenSource(); cts.Cancel();
    var cancelled = false;
    try { await cancelStore.CapturePreimageAsync(cancelSource, RollbackMutationKind.Write, cts.Token); }
    catch (OperationCanceledException) { cancelled = true; }
    Check(cancelled, "cancelled pre-image capture fails closed");
    Check(cancelStore.Captures.Count == 0, "cancelled capture commits no journal record");

    var unsafeIdRejected = false;
    try { repo.CreateSession("../escape"); }
    catch (ArgumentException) { unsafeIdRejected = true; }
    Check(unsafeIdRejected, "unsafe session id is rejected");

    Console.WriteLine($"All {passed} rollback tests passed. These are file-store tests, not minifilter integration tests.");
    return 0;
}
finally
{
    try { Directory.Delete(root, true); } catch { }
}
