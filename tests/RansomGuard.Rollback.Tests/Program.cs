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

    // Crash ambiguity is rejected: durable objects without a journal commit must not be silently trusted.
    var orphanRoot = Path.Combine(root, "orphan-full");
    var orphanStore = new RollbackStore(orphanRoot);
    var orphanObjects = Path.Combine(orphanRoot, "objects");
    await File.WriteAllBytesAsync(Path.Combine(orphanObjects, "orphan.preimage"), new byte[] { 1, 2, 3 });
    var orphanRejected = false;
    try { orphanStore.VerifyAll(); }
    catch (InvalidDataException) { orphanRejected = true; }
    Check(orphanRejected, "unjournaled full pre-image object is rejected");

    var tempRoot = Path.Combine(root, "temp-full");
    var tempStore = new RollbackStore(tempRoot);
    await File.WriteAllBytesAsync(Path.Combine(tempRoot, "objects", "capture.tmp"), new byte[] { 9 });
    var tempRejected = false;
    try { tempStore.VerifyAll(); }
    catch (InvalidDataException) { tempRejected = true; }
    Check(tempRejected, "incomplete full pre-image temp artifact is rejected");

    // Same-length corruption must be caught by SHA-256, not only by object length.
    var hashSource = Path.Combine(sourceDir, "hash.bin");
    await File.WriteAllBytesAsync(hashSource, Encoding.UTF8.GetBytes("HASH-ORIGINAL-CONTENT"));
    var hashStore = new RollbackStore(Path.Combine(root, "hash-session"));
    var hashCapture = await hashStore.CapturePreimageAsync(hashSource, RollbackMutationKind.Write);
    var hashObject = Path.Combine(hashStore.Root, hashCapture.SnapshotRelativePath);
    var hashBytes = await File.ReadAllBytesAsync(hashObject);
    hashBytes[0] ^= 0x5A;
    await File.WriteAllBytesAsync(hashObject, hashBytes);
    var hashRejected = false;
    try { hashStore.VerifyAll(); }
    catch (InvalidDataException) { hashRejected = true; }
    Check(hashRejected, "same-length full pre-image corruption is rejected by SHA-256");

    var rangeOrphanRoot = Path.Combine(root, "orphan-range");
    var rangeOrphan = new RangeRollbackStore(rangeOrphanRoot);
    await File.WriteAllBytesAsync(Path.Combine(rangeOrphanRoot, "objects", "orphan.block"), new byte[] { 1 });
    var rangeOrphanRejected = false;
    try { rangeOrphan.VerifyAll(); }
    catch (InvalidDataException) { rangeOrphanRejected = true; }
    Check(rangeOrphanRejected, "unjournaled range block is rejected");

    var rangeTempRoot = Path.Combine(root, "temp-range");
    var rangeTemp = new RangeRollbackStore(rangeTempRoot);
    await File.WriteAllBytesAsync(Path.Combine(rangeTempRoot, "objects", "block.tmp"), new byte[] { 1 });
    var rangeTempRejected = false;
    try { rangeTemp.VerifyAll(); }
    catch (InvalidDataException) { rangeTempRejected = true; }
    Check(rangeTempRejected, "incomplete range temp artifact is rejected");

    // Create semantics record durable absence rather than inventing a zero-byte pre-image.
    var createRoot = Path.Combine(root, "create-state");
    var createStore = new CreateRollbackStore(createRoot);
    var newPath = Path.Combine(sourceDir, "new-during-incident.bin");
    var absent = await createStore.CaptureAbsentAsync(newPath);
    Check(absent.Sequence == 1, "create baseline records first absent path");
    Check(createStore.WasOriginallyAbsent(newPath), "create baseline marks path originally absent");
    var absentAgain = await createStore.CaptureAbsentAsync(newPath);
    Check(absentAgain.RecordSha256 == absent.RecordSha256, "create absence baseline is first-wins");
    await File.WriteAllTextAsync(newPath, "created later");
    createStore.VerifyAll();
    Check(true, "create baseline remains valid after the path is created");
    var reopenedCreate = new CreateRollbackStore(createRoot);
    Check(reopenedCreate.WasOriginallyAbsent(newPath), "create baseline rebuilds after reopen");

    var existingCreatePath = Path.Combine(sourceDir, "already-exists.bin");
    await File.WriteAllTextAsync(existingCreatePath, "original");
    var existingCreateRejected = false;
    try { await createStore.CaptureAbsentAsync(existingCreatePath); }
    catch (InvalidOperationException) { existingCreateRejected = true; }
    Check(existingCreateRejected, "create absence baseline rejects an existing target");

    var createJournalBytes = await File.ReadAllBytesAsync(createStore.JournalPath);
    createJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(createStore.JournalPath, createJournalBytes);
    var createJournalRejected = false;
    try { _ = new CreateRollbackStore(createRoot); }
    catch (InvalidDataException) { createJournalRejected = true; }
    Check(createJournalRejected, "create baseline journal corruption is rejected");

    Check(CreateGatePolicy.Decide(CreateDisposition.Supersede, CreateTargetState.File) ==
        CreatePreservationAction.CaptureExistingPreimage, "FILE_SUPERSEDE existing file requires pre-image");
    Check(CreateGatePolicy.Decide(CreateDisposition.Overwrite, CreateTargetState.File) ==
        CreatePreservationAction.CaptureExistingPreimage, "FILE_OVERWRITE existing file requires pre-image");
    Check(CreateGatePolicy.Decide(CreateDisposition.OverwriteIf, CreateTargetState.File) ==
        CreatePreservationAction.CaptureExistingPreimage, "FILE_OVERWRITE_IF existing file requires pre-image");
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.File) ==
        CreatePreservationAction.NoPreservationRequired, "FILE_OPEN existing file is non-destructive at CREATE time");
    Check(CreateGatePolicy.Decide(CreateDisposition.OpenIf, CreateTargetState.File) ==
        CreatePreservationAction.NoPreservationRequired, "FILE_OPEN_IF existing file is non-destructive at CREATE time");
    Check(CreateGatePolicy.Decide(CreateDisposition.Create, CreateTargetState.File) ==
        CreatePreservationAction.NoPreservationRequired, "FILE_CREATE existing file needs no snapshot because create fails");

    foreach (var disposition in new[]
    {
        CreateDisposition.Supersede, CreateDisposition.Create,
        CreateDisposition.OpenIf, CreateDisposition.OverwriteIf
    })
        Check(CreateGatePolicy.Decide(disposition, CreateTargetState.Missing) ==
            CreatePreservationAction.RecordOriginallyAbsent,
            $"{disposition} missing path records originally-absent baseline");

    foreach (var disposition in new[] { CreateDisposition.Open, CreateDisposition.Overwrite })
        Check(CreateGatePolicy.Decide(disposition, CreateTargetState.Missing) ==
            CreatePreservationAction.NoPreservationRequired,
            $"{disposition} missing path needs no baseline because create fails");

    Check(!CreateGatePolicy.TryParseDisposition(6, out _), "unknown create disposition is rejected");
    Check(CreateGatePolicy.Decide(CreateDisposition.Create, CreateTargetState.Directory) ==
        CreatePreservationAction.NoPreservationRequired, "directory CREATE does not claim file-content preservation");

    // Repository-wide verification must include nested write-cow and create-state stores.
    var nestedRepo = new RollbackRepository(Path.Combine(root, "nested-repo"));
    var nestedSession = nestedRepo.CreateSession("nested");
    var nestedSource = Path.Combine(sourceDir, "nested.bin");
    await File.WriteAllBytesAsync(nestedSource, new byte[2 * 1024 * 1024]);
    var nestedCow = new RangeRollbackStore(Path.Combine(nestedSession.Root, "write-cow"));
    await nestedCow.CaptureWritePreimageAsync(nestedSource, 0, 4096);
    var nestedBlock = Directory.EnumerateFiles(Path.Combine(nestedCow.Root, "objects"), "*.block").Single();
    var nestedBytes = await File.ReadAllBytesAsync(nestedBlock);
    nestedBytes[0] ^= 0x7F;
    await File.WriteAllBytesAsync(nestedBlock, nestedBytes);
    var nestedRejected = false;
    try { nestedRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedRejected = true; }
    Check(nestedRejected, "repository verification includes nested range COW hashes");

    var nestedCreateRepo = new RollbackRepository(Path.Combine(root, "nested-create-repo"));
    var nestedCreateSession = nestedCreateRepo.CreateSession("nested_create");
    var nestedCreateState = new CreateRollbackStore(Path.Combine(nestedCreateSession.Root, "create-state"));
    var nestedMissing = Path.Combine(sourceDir, "nested-created.bin");
    await nestedCreateState.CaptureAbsentAsync(nestedMissing);
    var nestedCreateJournal = await File.ReadAllBytesAsync(nestedCreateState.JournalPath);
    nestedCreateJournal[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedCreateState.JournalPath, nestedCreateJournal);
    var nestedCreateRejected = false;
    try { nestedCreateRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedCreateRejected = true; }
    Check(nestedCreateRejected, "repository verification includes nested create-state journal");

    Console.WriteLine($"All {passed} rollback tests passed. These are file-store tests, not minifilter integration tests.");
    return 0;
}
finally
{
    try { Directory.Delete(root, true); } catch { }
}
