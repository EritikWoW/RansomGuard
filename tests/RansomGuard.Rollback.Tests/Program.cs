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
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.File, 0,
            CreateGatePolicy.FileWriteData) == CreatePreservationAction.CaptureExistingPreimage,
        "FILE_OPEN with FILE_WRITE_DATA pre-preserves existing file before writable handle returns");
    Check(CreateGatePolicy.Decide(CreateDisposition.OpenIf, CreateTargetState.File, 0,
            CreateGatePolicy.FileAppendData) == CreatePreservationAction.CaptureExistingPreimage,
        "FILE_OPEN_IF with FILE_APPEND_DATA pre-preserves existing file before append-capable handle returns");
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.File, 0,
            CreateGatePolicy.GenericWrite) == CreatePreservationAction.CaptureExistingPreimage,
        "FILE_OPEN with GENERIC_WRITE pre-preserves existing file for later writable mapping");
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.File, 0,
            0x80000000u) == CreatePreservationAction.NoPreservationRequired,
        "GENERIC_READ-only existing file still avoids eager full pre-image");
    Check(CreateGatePolicy.HasContentWriteAccess(CreateGatePolicy.FileWriteData) &&
          CreateGatePolicy.HasContentWriteAccess(CreateGatePolicy.FileAppendData) &&
          CreateGatePolicy.HasContentWriteAccess(CreateGatePolicy.GenericWrite) &&
          !CreateGatePolicy.HasContentWriteAccess(0x80000000u),
        "content-write access classifier is conservative and excludes read-only opens");
    Check(CreateGatePolicy.Decide(CreateDisposition.Create, CreateTargetState.File) ==
        CreatePreservationAction.NoPreservationRequired, "FILE_CREATE existing file needs no snapshot because create fails");
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.File,
            CreateGatePolicy.FileDeleteOnClose) == CreatePreservationAction.CaptureExistingPreimage,
        "FILE_DELETE_ON_CLOSE existing file requires pre-image even for FILE_OPEN");
    Check(CreateGatePolicy.Decide(CreateDisposition.Open, CreateTargetState.Directory,
            CreateGatePolicy.FileDeleteOnClose) == CreatePreservationAction.DenyUnsupported,
        "FILE_DELETE_ON_CLOSE existing directory is denied until topology rollback exists");
    Check(CreateGatePolicy.Decide(CreateDisposition.Create, CreateTargetState.Missing,
            CreateGatePolicy.FileDeleteOnClose) == CreatePreservationAction.RecordOriginallyAbsent,
        "FILE_DELETE_ON_CLOSE newly created path still records originally-absent baseline");

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

    // CREATE operations are two-phase: pre-operation preservation intent plus correlated post-operation outcome.
    var createOpsRoot = Path.Combine(root, "create-operation-state");
    var createOps = new CreateOperationStore(createOpsRoot);
    var createOriginalIdentity = new DurableFileIdentity(
        "0011223344556677", "0123456789ABCDEFFEDCBA9876543210");
    var createFinalIdentity = new DurableFileIdentity(
        "0011223344556677", "11112222333344445555666677778888");
    var createOperationPath = Path.Combine(sourceDir, "create-operation.bin");

    var createIntent = await createOps.RecordIntentAsync(
        301,
        createOperationPath,
        CreateDisposition.Overwrite,
        0,
        0x40000000,
        CreateTargetState.File,
        CreatePreservationAction.CaptureExistingPreimage,
        new string('A', 64),
        createOriginalIdentity);
    Check(createIntent.RequestSequence == 301 && createOps.PendingIntents.Count == 1,
        "CREATE intent remains pending until post-operation reconciliation");
    Check(createIntent.OriginalIdentity == createOriginalIdentity,
        "CREATE intent records original identity for preserved existing file");

    var createSucceeded = await createOps.RecordCompletionAsync(
        301,
        CreateCompletionState.Succeeded,
        0,
        1,
        createOperationPath,
        createFinalIdentity);
    Check(createSucceeded.FinalIdentity == createFinalIdentity &&
          createSucceeded.FinalPath.Equals(createOperationPath, StringComparison.OrdinalIgnoreCase),
        "CREATE authoritative success records final path and kernel identity");
    Check(createOps.PendingIntents.Count == 0,
        "CREATE authoritative completion clears pending intent");

    var createAbsentPath = Path.Combine(sourceDir, "create-absent-operation.bin");
    _ = await createOps.RecordIntentAsync(
        302,
        createAbsentPath,
        CreateDisposition.Create,
        0,
        0x40000000,
        CreateTargetState.Missing,
        CreatePreservationAction.RecordOriginallyAbsent,
        new string('B', 64),
        null);
    var createIdentityUnresolved = await createOps.RecordCompletionAsync(
        302,
        CreateCompletionState.SucceededIdentityUnresolved,
        0,
        2,
        createAbsentPath,
        null);
    Check(createIdentityUnresolved.State == CreateCompletionState.SucceededIdentityUnresolved,
        "CREATE success can retain final name while marking kernel identity unresolved");

    var createNameUnresolvedPath = Path.Combine(sourceDir, "create-name-unresolved.bin");
    _ = await createOps.RecordIntentAsync(
        303,
        createNameUnresolvedPath,
        CreateDisposition.Open,
        0,
        0x80000000,
        CreateTargetState.File,
        CreatePreservationAction.NoPreservationRequired,
        string.Empty,
        null);
    var createNameUnresolved = await createOps.RecordCompletionAsync(
        303,
        CreateCompletionState.SucceededNameUnresolved,
        0,
        1,
        null,
        createOriginalIdentity);
    Check(createNameUnresolved.State == CreateCompletionState.SucceededNameUnresolved &&
          createNameUnresolved.FinalIdentity == createOriginalIdentity,
        "CREATE success can retain kernel identity while marking tunneled name unresolved");

    var writableOpenPath = Path.Combine(sourceDir, "create-writable-open.bin");
    _ = await createOps.RecordIntentAsync(
        308,
        writableOpenPath,
        CreateDisposition.Open,
        0,
        CreateGatePolicy.GenericWrite,
        CreateTargetState.File,
        CreatePreservationAction.CaptureExistingPreimage,
        new string('F', 64),
        createOriginalIdentity);
    var writableOpenCompletion = await createOps.RecordCompletionAsync(
        308,
        CreateCompletionState.Succeeded,
        0,
        1,
        writableOpenPath,
        createOriginalIdentity);
    Check(writableOpenCompletion.FinalIdentity == createOriginalIdentity,
        "write-capable FILE_OPEN keeps the committed pre-image contract through completion");

    var writableOpenWithoutSnapshotRejected = false;
    try
    {
        _ = await createOps.RecordIntentAsync(
            309,
            Path.Combine(sourceDir, "create-writable-open-invalid.bin"),
            CreateDisposition.Open,
            0,
            CreateGatePolicy.FileWriteData,
            CreateTargetState.File,
            CreatePreservationAction.NoPreservationRequired,
            string.Empty,
            null);
    }
    catch (InvalidDataException) { writableOpenWithoutSnapshotRejected = true; }
    Check(writableOpenWithoutSnapshotRejected,
        "CREATE journal rejects write-capable existing-file open without committed pre-image");

    var createFullyUnresolvedPath = Path.Combine(sourceDir, "create-fully-unresolved.bin");
    _ = await createOps.RecordIntentAsync(
        304,
        createFullyUnresolvedPath,
        CreateDisposition.OpenIf,
        0,
        0x80000000,
        CreateTargetState.Missing,
        CreatePreservationAction.RecordOriginallyAbsent,
        new string('E', 64),
        null);
    var createFullyUnresolved = await createOps.RecordCompletionAsync(
        304,
        CreateCompletionState.SucceededNameAndIdentityUnresolved,
        0,
        1,
        null,
        null);
    Check(createFullyUnresolved.State == CreateCompletionState.SucceededNameAndIdentityUnresolved,
        "CREATE success explicitly represents unresolved name and identity");

    var inconsistentCreateIntentRejected = false;
    try
    {
        _ = await createOps.RecordIntentAsync(
            307,
            Path.Combine(sourceDir, "create-inconsistent.bin"),
            CreateDisposition.OpenIf,
            0,
            0x80000000,
            CreateTargetState.Missing,
            CreatePreservationAction.NoPreservationRequired,
            string.Empty,
            null);
    }
    catch (InvalidDataException) { inconsistentCreateIntentRejected = true; }
    Check(inconsistentCreateIntentRejected,
        "CREATE intent rejects preservation action inconsistent with disposition/target policy");

    var createFailedPath = Path.Combine(sourceDir, "create-failed.bin");
    _ = await createOps.RecordIntentAsync(
        305,
        createFailedPath,
        CreateDisposition.Open,
        0,
        0x80000000,
        CreateTargetState.Missing,
        CreatePreservationAction.NoPreservationRequired,
        string.Empty,
        null);
    var createFailed = await createOps.RecordCompletionAsync(
        305,
        CreateCompletionState.Failed,
        0xC0000034u,
        0,
        null,
        null);
    Check(createFailed.State == CreateCompletionState.Failed,
        "CREATE failed filesystem operation is recorded separately from intent");

    var createPendingPath = Path.Combine(sourceDir, "create-pending.bin");
    _ = await createOps.RecordIntentAsync(
        306,
        createPendingPath,
        CreateDisposition.Create,
        0,
        0x40000000,
        CreateTargetState.Missing,
        CreatePreservationAction.RecordOriginallyAbsent,
        new string('C', 64),
        null);
    Check(createOps.PendingIntents.Single().RequestSequence == 306,
        "missing CREATE result leaves intent pending rather than inferring success");

    var reopenedCreateOps = new CreateOperationStore(createOpsRoot);
    Check(reopenedCreateOps.Completions.Count == 6 &&
          reopenedCreateOps.PendingIntents.Single().RequestSequence == 306,
        "CREATE intent/completion correlation rebuilds after reopen");

    var exactCreateCompletion = await createOps.RecordCompletionAsync(
        301,
        CreateCompletionState.Succeeded,
        0,
        1,
        createOperationPath,
        createFinalIdentity);
    Check(exactCreateCompletion.RecordSha256 == createSucceeded.RecordSha256,
        "exact duplicate CREATE completion is idempotent");

    var conflictingCreateCompletionRejected = false;
    try
    {
        _ = await createOps.RecordCompletionAsync(
            301,
            CreateCompletionState.Failed,
            0xC0000001u,
            0,
            null,
            null);
    }
    catch (InvalidDataException) { conflictingCreateCompletionRejected = true; }
    Check(conflictingCreateCompletionRejected,
        "conflicting duplicate CREATE completion is rejected");

    var missingCreateIntentRejected = false;
    try
    {
        _ = await createOps.RecordCompletionAsync(
            999,
            CreateCompletionState.Failed,
            0xC0000001u,
            0,
            null,
            null);
    }
    catch (InvalidDataException) { missingCreateIntentRejected = true; }
    Check(missingCreateIntentRejected,
        "CREATE completion without committed intent is rejected");

    var createCompletionCorruptionRoot = Path.Combine(root, "create-completion-corruption");
    var createCompletionCorruption = new CreateOperationStore(createCompletionCorruptionRoot);
    _ = await createCompletionCorruption.RecordIntentAsync(
        401,
        createAbsentPath,
        CreateDisposition.Create,
        0,
        0x40000000,
        CreateTargetState.Missing,
        CreatePreservationAction.RecordOriginallyAbsent,
        new string('D', 64),
        null);
    _ = await createCompletionCorruption.RecordCompletionAsync(
        401,
        CreateCompletionState.Succeeded,
        0,
        1,
        createAbsentPath,
        createFinalIdentity);
    var createCompletionBytes = await File.ReadAllBytesAsync(createCompletionCorruption.CompletionJournalPath);
    createCompletionBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(createCompletionCorruption.CompletionJournalPath, createCompletionBytes);
    var createCompletionCorruptionRejected = false;
    try { _ = new CreateOperationStore(createCompletionCorruptionRoot); }
    catch (InvalidDataException) { createCompletionCorruptionRejected = true; }
    Check(createCompletionCorruptionRejected,
        "CREATE completion journal corruption is rejected");

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

    // Durable Windows identity distinguishes path aliases from path replacement.
    var identityRoot = Path.Combine(root, "identity-state");
    var identityStore = new FileIdentityStore(identityRoot);
    var identityPath = Path.Combine(sourceDir, "identity-original.bin");
    var identityMoved = Path.Combine(sourceDir, "identity-moved.bin");
    await File.WriteAllTextAsync(identityPath, "identity-original");
    var identityFirst = await identityStore.CaptureOrVerifyAsync(identityPath);
    Check(identityFirst.Identity.FileIdHex.Length == 32, "file identity captures 128-bit file id");
    Check(identityFirst.Identity.VolumeSerialHex.Length == 16, "file identity captures volume serial");
    var identityAgain = await identityStore.CaptureOrVerifyAsync(identityPath);
    Check(identityAgain.RecordSha256 == identityFirst.RecordSha256,
        "same path and same file identity reuses the committed baseline");

    File.Move(identityPath, identityMoved);
    var identityAlias = await identityStore.CaptureOrVerifyAsync(identityMoved);
    Check(identityAlias.Identity == identityFirst.Identity,
        "rename keeps the same durable file identity");
    Check(identityStore.PathsFor(identityFirst.Identity).Length == 2,
        "identity journal can associate multiple observed paths with one file");

    await File.WriteAllTextAsync(identityPath, "replacement-at-old-path");
    var identityReplacementRejected = false;
    try { _ = await identityStore.CaptureOrVerifyAsync(identityPath); }
    catch (InvalidDataException) { identityReplacementRejected = true; }
    Check(identityReplacementRejected,
        "same path changing to a different file identity is rejected");

    var handleBoundFull = new RollbackStore(Path.Combine(root, "identity-full-preimage"));
    var fullHandleMismatchRejected = false;
    try
    {
        _ = await handleBoundFull.CapturePreimageAsync(identityPath, RollbackMutationKind.Write,
            identityFirst.Identity);
    }
    catch (InvalidDataException) { fullHandleMismatchRejected = true; }
    Check(fullHandleMismatchRejected,
        "full pre-image verifies expected identity on the exact source handle");

    var handleBoundRange = new RangeRollbackStore(Path.Combine(root, "identity-range-preimage"));
    var rangeHandleMismatchRejected = false;
    try
    {
        await handleBoundRange.CaptureWritePreimageAsync(identityPath, 0, 1, identityFirst.Identity);
    }
    catch (InvalidDataException) { rangeHandleMismatchRejected = true; }
    Check(rangeHandleMismatchRejected,
        "range COW verifies expected identity on the exact source handle");

    identityStore.VerifyAll();
    Check(true, "file identity hash-chain journal verifies");

    var malformedIdentityRoot = Path.Combine(root, "malformed-identity-state");
    Directory.CreateDirectory(malformedIdentityRoot);
    await File.WriteAllTextAsync(Path.Combine(malformedIdentityRoot, "identity-journal.jsonl"),
        "{\"sequence\":1,\"capturedUtc\":\"2026-09-21T00:00:00Z\",\"originalPath\":null,\"volumeSerialHex\":null,\"fileIdHex\":null,\"previousRecordSha256\":null,\"recordSha256\":null}\n");
    var malformedIdentityRejected = false;
    try { _ = new FileIdentityStore(malformedIdentityRoot); }
    catch (InvalidDataException) { malformedIdentityRejected = true; }
    Check(malformedIdentityRejected, "malformed/null file identity journal fields are rejected deterministically");

    var nestedIdentityRepo = new RollbackRepository(Path.Combine(root, "nested-identity-repo"));
    var nestedIdentitySession = nestedIdentityRepo.CreateSession("nested_identity");
    var nestedIdentityState = new FileIdentityStore(Path.Combine(nestedIdentitySession.Root, "identity-state"));
    var nestedIdentityPath = Path.Combine(sourceDir, "nested-identity.bin");
    await File.WriteAllTextAsync(nestedIdentityPath, "nested identity");
    await nestedIdentityState.CaptureOrVerifyAsync(nestedIdentityPath);
    var nestedIdentityJournal = await File.ReadAllBytesAsync(nestedIdentityState.JournalPath);
    nestedIdentityJournal[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedIdentityState.JournalPath, nestedIdentityJournal);
    var nestedIdentityRejected = false;
    try { nestedIdentityRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedIdentityRejected = true; }
    Check(nestedIdentityRejected, "repository verification includes nested identity-state journal");

    // Rename intent captures exact source/destination topology only after preservation state is available.
    var renameRoot = Path.Combine(root, "rename-state");
    var renameStore = new RenameRollbackStore(renameRoot);
    var sourceIdentity = new DurableFileIdentity("0011223344556677", "00112233445566778899AABBCCDDEEFF");
    var destinationIdentity = new DurableFileIdentity("0011223344556677", "FFEEDDCCBBAA99887766554433221100");
    var renameSource = Path.Combine(sourceDir, "rename-source.bin");
    var renameDestination = Path.Combine(sourceDir, "rename-destination.bin");

    var renameAbsent = await renameStore.CaptureIntentAsync(
        101, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    Check(renameAbsent.Sequence == 1, "rename intent records first transaction sequence");
    Check(renameAbsent.DestinationState == RenameDestinationState.OriginallyAbsent,
        "rename intent records originally-absent destination");
    Check(!renameAbsent.SourceOriginallyAbsent,
        "rename intent distinguishes pre-incident source from incident-created source");

    var renameExisting = await renameStore.CaptureIntentAsync(
        102, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.ExistingFile, destinationIdentity, 1, 65);
    Check(renameExisting.DestinationIdentity == destinationIdentity,
        "rename intent records existing destination identity");
    Check(renameExisting.RenameFlags == 1 && renameExisting.FileInformationClass == 65,
        "rename intent records rename flags and information class");

    var renameSame = await renameStore.CaptureIntentAsync(
        103, renameSource, renameSource, sourceIdentity, false,
        RenameDestinationState.SameAsSource, sourceIdentity, 0, 10);
    Check(renameSame.DestinationState == RenameDestinationState.SameAsSource,
        "rename intent supports same-path/case-only topology");

    renameStore.VerifyAll();
    Check(new RenameRollbackStore(renameRoot).Intents.Count == 3,
        "rename intent journal rebuilds after reopen");
    Check(renameStore.PendingIntents.Count == 3,
        "rename intents remain pending until post-operation completion is recorded");

    var renameSucceeded = await renameStore.RecordCompletionAsync(
        101, RenameCompletionState.Succeeded, 0, 0, renameDestination, sourceIdentity);
    Check(renameSucceeded.State == RenameCompletionState.Succeeded &&
          renameSucceeded.FinalDestinationPath.Equals(renameDestination, StringComparison.OrdinalIgnoreCase) &&
          renameSucceeded.FinalIdentity == sourceIdentity,
        "successful rename completion records final destination and source file identity");

    var renameFailed = await renameStore.RecordCompletionAsync(
        102, RenameCompletionState.Failed, 0xC0000035u, 0, null, null);
    Check(renameFailed.State == RenameCompletionState.Failed,
        "failed rename completion is recorded separately from intent");

    var renameUnresolved = await renameStore.RecordCompletionAsync(
        103, RenameCompletionState.SucceededNameUnresolved, 0, 0, null, sourceIdentity);
    Check(renameUnresolved.State == RenameCompletionState.SucceededNameUnresolved &&
          renameUnresolved.FinalIdentity == sourceIdentity,
        "successful rename can retain kernel identity while tunneled name is unresolved");
    Check(renameStore.PendingIntents.Count == 0,
        "completed rename intents leave no pending reconciliation");

    _ = await renameStore.CaptureIntentAsync(
        106, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    var identityUnresolvedCompletion = await renameStore.RecordCompletionAsync(
        106, RenameCompletionState.SucceededIdentityUnresolved, 0, 0, renameDestination, null);
    Check(identityUnresolvedCompletion.State == RenameCompletionState.SucceededIdentityUnresolved &&
          identityUnresolvedCompletion.FinalIdentity is null,
        "rename success can explicitly retain final name while kernel identity is unresolved");

    _ = await renameStore.CaptureIntentAsync(
        107, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    var fullyUnresolvedCompletion = await renameStore.RecordCompletionAsync(
        107, RenameCompletionState.SucceededNameAndIdentityUnresolved, 0, 0, null, null);
    Check(fullyUnresolvedCompletion.State == RenameCompletionState.SucceededNameAndIdentityUnresolved,
        "rename success explicitly represents unresolved final name and identity");

    var mismatchStore = new RenameRollbackStore(Path.Combine(root, "rename-identity-mismatch"));
    _ = await mismatchStore.CaptureIntentAsync(
        108, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    var wrongFinalIdentityRejected = false;
    try
    {
        _ = await mismatchStore.RecordCompletionAsync(
            108, RenameCompletionState.Succeeded, 0, 0, renameDestination, destinationIdentity);
    }
    catch (InvalidDataException) { wrongFinalIdentityRejected = true; }
    Check(wrongFinalIdentityRejected,
        "rename completion rejects a final kernel identity different from the committed source identity");
    Check(mismatchStore.PendingIntents.Single().RequestSequence == 108,
        "identity-mismatched rename remains pending instead of being promoted to completed");

    var reopenedRename = new RenameRollbackStore(renameRoot);
    Check(reopenedRename.Completions.Count == 5,
        "rename completion journal rebuilds all authoritative and unresolved states after reopen");
    Check(reopenedRename.PendingIntents.Count == 0,
        "reopened rename state preserves completion correlation");

    var conflictingRenameCompletionRejected = false;
    try
    {
        _ = await renameStore.RecordCompletionAsync(
            101, RenameCompletionState.Failed, 0xC0000001u, 0, null, null);
    }
    catch (InvalidDataException) { conflictingRenameCompletionRejected = true; }
    Check(conflictingRenameCompletionRejected,
        "conflicting duplicate rename completion is rejected");

    var invalidRenameStateRejected = false;
    try
    {
        _ = await renameStore.CaptureIntentAsync(
            104, renameSource, renameDestination, sourceIdentity, false,
            RenameDestinationState.ExistingFile, null, 0, 10);
    }
    catch (InvalidDataException) { invalidRenameStateRejected = true; }
    Check(invalidRenameStateRejected, "existing rename destination without identity is rejected");

    var renameJournalBytes = await File.ReadAllBytesAsync(renameStore.JournalPath);
    renameJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(renameStore.JournalPath, renameJournalBytes);
    var renameJournalRejected = false;
    try { _ = new RenameRollbackStore(renameRoot); }
    catch (InvalidDataException) { renameJournalRejected = true; }
    Check(renameJournalRejected, "rename intent journal corruption is rejected");

    var completionCorruptionRoot = Path.Combine(root, "rename-completion-corruption");
    var completionCorruptionStore = new RenameRollbackStore(completionCorruptionRoot);
    _ = await completionCorruptionStore.CaptureIntentAsync(
        150, renameSource, renameDestination, sourceIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    _ = await completionCorruptionStore.RecordCompletionAsync(
        150, RenameCompletionState.Succeeded, 0, 0, renameDestination, sourceIdentity);
    var completionJournalBytes = await File.ReadAllBytesAsync(completionCorruptionStore.CompletionJournalPath);
    completionJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(completionCorruptionStore.CompletionJournalPath, completionJournalBytes);
    var completionJournalRejected = false;
    try { _ = new RenameRollbackStore(completionCorruptionRoot); }
    catch (InvalidDataException) { completionJournalRejected = true; }
    Check(completionJournalRejected, "rename completion journal corruption is rejected");

    var nestedRenameRepo = new RollbackRepository(Path.Combine(root, "nested-rename-repo"));
    var nestedRenameSession = nestedRenameRepo.CreateSession("nested_rename");
    var nestedRenameState = new RenameRollbackStore(Path.Combine(nestedRenameSession.Root, "rename-state"));
    await nestedRenameState.CaptureIntentAsync(
        201, renameSource, renameDestination, sourceIdentity, true,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    Check(nestedRenameState.Intents.Single().SourceOriginallyAbsent,
        "rename intent records incident-created source without manufacturing source pre-image");
    var nestedRenameJournal = await File.ReadAllBytesAsync(nestedRenameState.JournalPath);
    nestedRenameJournal[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedRenameState.JournalPath, nestedRenameJournal);
    var nestedRenameRejected = false;
    try { nestedRenameRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedRenameRejected = true; }
    Check(nestedRenameRejected, "repository verification includes nested rename-state journal");

    // Restart reconciliation records evidence for pending intents without converting evidence into completion.
    var restartCreateRoot = Path.Combine(root, "restart-create-state");
    var restartCreateOperations = new CreateOperationStore(restartCreateRoot);
    var restartCreatePath = Path.Combine(sourceDir, "restart-create.bin");
    var restartCreateIntent = await restartCreateOperations.RecordIntentAsync(
        301,
        restartCreatePath,
        CreateDisposition.Create,
        0,
        0,
        CreateTargetState.Missing,
        CreatePreservationAction.RecordOriginallyAbsent,
        new string('A', 64),
        null);
    var createMissingEvidence = RestartReconciliationClassifier.ClassifyCreate(
        restartCreateIntent,
        new RestartPathObservation(RestartPathState.Missing, null));
    Check(createMissingEvidence == RestartEvidenceState.SupportsNotCompleted,
        "restart CREATE evidence recognizes an originally-missing path that is still missing");
    var createPresentEvidence = RestartReconciliationClassifier.ClassifyCreate(
        restartCreateIntent,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    Check(createPresentEvidence == RestartEvidenceState.SupportsCompleted,
        "restart CREATE evidence recognizes a newly-present file without promoting completion");

    var restartRenameStore = new RenameRollbackStore(Path.Combine(root, "restart-rename-state"));
    var restartRenameIntent = await restartRenameStore.CaptureIntentAsync(
        302,
        renameSource,
        renameDestination,
        sourceIdentity,
        false,
        RenameDestinationState.OriginallyAbsent,
        null,
        0,
        10);
    var renameCompletedEvidence = RestartReconciliationClassifier.ClassifyRename(
        restartRenameIntent,
        new RestartPathObservation(RestartPathState.Missing, null),
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    Check(renameCompletedEvidence == RestartEvidenceState.SupportsCompleted,
        "restart RENAME evidence recognizes source identity at destination");
    var renameNotCompletedEvidence = RestartReconciliationClassifier.ClassifyRename(
        restartRenameIntent,
        new RestartPathObservation(RestartPathState.File, sourceIdentity),
        new RestartPathObservation(RestartPathState.Missing, null));
    Check(renameNotCompletedEvidence == RestartEvidenceState.SupportsNotCompleted,
        "restart RENAME evidence recognizes unchanged source and absent destination");

    var restartStateRoot = Path.Combine(root, "restart-evidence");
    var restartState = new RestartReconciliationStore(restartStateRoot);
    var createObservation = await restartState.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        createPresentEvidence,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    Check(createObservation.Sequence == 1,
        "restart reconciliation commits first evidence record");
    var duplicateObservation = await restartState.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        createPresentEvidence,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    Check(duplicateObservation.Sequence == createObservation.Sequence &&
          restartState.Observations.Count == 1,
        "identical restart evidence is idempotent across repeated startup scans");

    var renameObservation = await restartState.RecordObservationAsync(
        RestartOperationKind.Rename,
        restartRenameIntent.RequestSequence,
        restartRenameIntent.RecordSha256,
        renameCompletedEvidence,
        restartRenameIntent.SourcePath,
        new RestartPathObservation(RestartPathState.Missing, null),
        restartRenameIntent.DestinationPath,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    Check(renameObservation.Sequence == 2 &&
          restartState.Observations.Count == 2,
        "restart reconciliation durably links RENAME evidence to its exact intent hash");
    restartState.VerifyAll();
    Check(new RestartReconciliationStore(restartStateRoot).Observations.Count == 2,
        "restart reconciliation journal rebuilds after reopen");
    Check(restartCreateOperations.PendingIntents.Single().RequestSequence == 301 &&
          restartRenameStore.PendingIntents.Single().RequestSequence == 302,
        "restart evidence never manufactures authoritative CREATE/RENAME completion");

    var restartAssessmentRoot = Path.Combine(root, "restart-assessment");
    var restartAssessmentStore = new RestartReconciliationStore(restartAssessmentRoot);
    var assessmentCompleted = await restartAssessmentStore.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsCompleted,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    var decisiveAssessment = restartAssessmentStore.Assess(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256);
    Check(decisiveAssessment.State == RestartEvidenceAssessmentState.ConsistentSupportsCompleted &&
          decisiveAssessment.ObservationCount == 1 &&
          decisiveAssessment.LatestRecordSha256 == assessmentCompleted.RecordSha256,
        "restart assessment accepts only exact consistent decisive evidence");

    var restartIdentityDriftStore = new RestartReconciliationStore(
        Path.Combine(root, "restart-assessment-identity-drift"));
    _ = await restartIdentityDriftStore.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsCompleted,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.File, sourceIdentity));
    _ = await restartIdentityDriftStore.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsCompleted,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.File, createOriginalIdentity));
    var identityDriftAssessment = restartIdentityDriftStore.Assess(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256);
    Check(identityDriftAssessment.State == RestartEvidenceAssessmentState.Unresolved &&
          identityDriftAssessment.ObservationCount == 2,
        "restart assessment rejects same-decision evidence with identity drift");

    _ = await restartAssessmentStore.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsNotCompleted,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.Missing, null));
    var conflictingAssessment = restartAssessmentStore.Assess(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256);
    Check(conflictingAssessment.State == RestartEvidenceAssessmentState.Unresolved &&
          conflictingAssessment.ObservationCount == 2,
        "restart assessment keeps conflicting observations unresolved");

    var absentAssessment = restartAssessmentStore.Assess(
        RestartOperationKind.Create,
        9999,
        new string('B', 64));
    Check(absentAssessment.State == RestartEvidenceAssessmentState.NoEvidence &&
          absentAssessment.ObservationCount == 0,
        "restart assessment does not borrow evidence from another request or intent");

    var nestedRestartRepo = new RollbackRepository(Path.Combine(root, "nested-restart-repo"));
    var nestedRestartSession = nestedRestartRepo.CreateSession("nested_restart");
    var nestedRestartState = new RestartReconciliationStore(Path.Combine(nestedRestartSession.Root, "restart-state"));
    _ = await nestedRestartState.RecordObservationAsync(
        RestartOperationKind.Create,
        restartCreateIntent.RequestSequence,
        restartCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsNotCompleted,
        restartCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.Missing, null));
    var restartJournalBytes = await File.ReadAllBytesAsync(nestedRestartState.JournalPath);
    restartJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedRestartState.JournalPath, restartJournalBytes);
    var nestedRestartRejected = false;
    try { nestedRestartRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedRestartRejected = true; }
    Check(nestedRestartRejected,
        "repository verification includes nested restart reconciliation journal");

    // Paging-write visibility is durable evidence only; it does not claim preservation.
    var pagingRoot = Path.Combine(root, "paging-evidence");
    var paging = new PagingWriteEvidenceStore(pagingRoot);
    var pagingPath = Path.Combine(sourceDir, "mapped.bin");
    var pagingFirst = await paging.RecordAsync(
        401, pagingPath, 4096, 8192, sourceIdentity, 1);
    Check(pagingFirst.Sequence == 1 && pagingFirst.Identity == sourceIdentity,
        "paging-write evidence records tracked path, range and durable identity");
    var pagingDuplicate = await paging.RecordAsync(
        401, pagingPath, 4096, 8192, sourceIdentity, 1);
    Check(pagingDuplicate.Sequence == pagingFirst.Sequence && paging.Records.Count == 1,
        "paging-write evidence is idempotent for the same kernel sequence");
    var conflictingPagingRejected = false;
    try { _ = await paging.RecordAsync(401, pagingPath, 8192, 4096, sourceIdentity, 1); }
    catch (InvalidDataException) { conflictingPagingRejected = true; }
    Check(conflictingPagingRejected,
        "conflicting duplicate paging-write kernel sequence is rejected");
    paging.VerifyAll();
    Check(new PagingWriteEvidenceStore(pagingRoot).Records.Count == 1,
        "paging-write evidence journal rebuilds after reopen");

    var nestedPagingRepo = new RollbackRepository(Path.Combine(root, "nested-paging-repo"));
    var nestedPagingSession = nestedPagingRepo.CreateSession("nested_paging");
    var nestedPaging = new PagingWriteEvidenceStore(Path.Combine(nestedPagingSession.Root, "paging-state"));
    _ = await nestedPaging.RecordAsync(
        402, pagingPath, 0, 4096, sourceIdentity, 1);
    var pagingJournalBytes = await File.ReadAllBytesAsync(nestedPaging.JournalPath);
    pagingJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedPaging.JournalPath, pagingJournalBytes);
    var nestedPagingRejected = false;
    try { nestedPagingRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedPagingRejected = true; }
    Check(nestedPagingRejected,
        "repository verification includes nested paging-write evidence journal");

    // Writable-section attestation proves that a mapping is backed by a committed CREATE baseline.
    var writableIntent = createOps.Intents.Single(x => x.RequestSequence == 308);
    createOps.TryGetCompletion(308, out var writableCompletion);
    var verifiedSectionState = WritableSectionAttestation.Evaluate(
        writableIntent,
        writableCompletion,
        writableOpenPath,
        WritableSectionAttestation.SnapshotCommitted);
    Check(verifiedSectionState == WritableSectionAttestationState.BaselineVerified,
        "writable section attests full pre-image committed before write-capable CREATE returned");

    var readOnlyIntent = createOps.Intents.Single(x => x.RequestSequence == 303);
    createOps.TryGetCompletion(303, out var readOnlyCompletion);
    var unprotectedSectionState = WritableSectionAttestation.Evaluate(
        readOnlyIntent,
        readOnlyCompletion,
        createNameUnresolvedPath,
        WritableSectionAttestation.NoPreservationRequired);
    Check(unprotectedSectionState == WritableSectionAttestationState.Unprotected,
        "section attestation explicitly exposes a CREATE that had no preservation baseline");

    Check(WritableSectionAttestation.Evaluate(
            null, null, writableOpenPath, WritableSectionAttestation.SnapshotCommitted) ==
          WritableSectionAttestationState.MissingCreateIntent,
        "section attestation rejects missing CREATE intent");
    Check(WritableSectionAttestation.Evaluate(
            writableIntent, writableCompletion, writableOpenPath,
            WritableSectionAttestation.NoPreservationRequired) ==
          WritableSectionAttestationState.DecisionMismatch,
        "section attestation detects gate decision mismatch");
    Check(WritableSectionAttestation.Evaluate(
            writableIntent, writableCompletion, Path.Combine(sourceDir, "wrong-section-path.bin"),
            WritableSectionAttestation.SnapshotCommitted) ==
          WritableSectionAttestationState.PathMismatch,
        "section attestation detects tracked path mismatch");

    var sectionRoot = Path.Combine(root, "section-evidence");
    var sectionStore = new WritableSectionEvidenceStore(sectionRoot);
    var sectionEvidence = await sectionStore.RecordAsync(
        501,
        writableIntent.RequestSequence,
        writableOpenPath,
        0x04,
        WritableSectionAttestation.SnapshotCommitted,
        verifiedSectionState,
        createOriginalIdentity);
    Check(sectionEvidence.Sequence == 1 &&
          sectionEvidence.State == WritableSectionAttestationState.BaselineVerified,
        "writable-section evidence commits verified baseline state");
    var duplicateSection = await sectionStore.RecordAsync(
        501,
        writableIntent.RequestSequence,
        writableOpenPath,
        0x04,
        WritableSectionAttestation.SnapshotCommitted,
        verifiedSectionState,
        createOriginalIdentity);
    Check(duplicateSection.Sequence == sectionEvidence.Sequence &&
          sectionStore.Records.Count == 1,
        "writable-section evidence is idempotent for identical kernel sequence");
    var conflictingSectionRejected = false;
    try
    {
        _ = await sectionStore.RecordAsync(
            501,
            writableIntent.RequestSequence,
            writableOpenPath,
            0x40,
            WritableSectionAttestation.SnapshotCommitted,
            verifiedSectionState,
            createOriginalIdentity);
    }
    catch (InvalidDataException) { conflictingSectionRejected = true; }
    Check(conflictingSectionRejected,
        "conflicting duplicate writable-section kernel sequence is rejected");
    sectionStore.VerifyAll();
    Check(new WritableSectionEvidenceStore(sectionRoot).Records.Count == 1,
        "writable-section evidence journal rebuilds after reopen");

    var nestedSectionRepo = new RollbackRepository(Path.Combine(root, "nested-section-repo"));
    var nestedSectionSession = nestedSectionRepo.CreateSession("nested_section");
    var nestedSection = new WritableSectionEvidenceStore(Path.Combine(nestedSectionSession.Root, "section-state"));
    _ = await nestedSection.RecordAsync(
        502,
        writableIntent.RequestSequence,
        writableOpenPath,
        0x04,
        WritableSectionAttestation.SnapshotCommitted,
        WritableSectionAttestationState.BaselineVerified,
        createOriginalIdentity);
    var sectionJournalBytes = await File.ReadAllBytesAsync(nestedSection.JournalPath);
    sectionJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedSection.JournalPath, sectionJournalBytes);
    var nestedSectionRejected = false;
    try { nestedSectionRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedSectionRejected = true; }
    Check(nestedSectionRejected,
        "repository verification includes nested writable-section evidence journal");

    // Activation preflight persists kernel evidence before the LAB gate can become active.
    var activationRoot = Path.Combine(root, "activation-evidence");
    var activation = new ActivationPreflightStore(activationRoot);
    var activationPath = Path.Combine(sourceDir, "activation.bin");
    var activationSafe = await activation.RecordAsync(
        601, activationPath, 0, false, createOriginalIdentity);
    Check(activationSafe.Sequence == 1 &&
          !activationSafe.WritableViewPresent &&
          activationSafe.Identity == createOriginalIdentity,
        "activation preflight records a clean identity-bound file probe");
    var activationDuplicate = await activation.RecordAsync(
        601, activationPath, 0, false, createOriginalIdentity);
    Check(activationDuplicate.Sequence == activationSafe.Sequence &&
          activation.Records.Count == 1,
        "activation preflight evidence is idempotent for identical kernel sequence");
    var activationConflictRejected = false;
    try
    {
        _ = await activation.RecordAsync(
            601, activationPath, 0, true, createOriginalIdentity);
    }
    catch (InvalidDataException) { activationConflictRejected = true; }
    Check(activationConflictRejected,
        "activation preflight rejects conflicting duplicate kernel sequence");
    _ = await activation.RecordAsync(
        602, activationPath, 0, true, createOriginalIdentity);
    Check(activation.Records.Single(x => x.KernelSequence == 602).WritableViewPresent,
        "activation preflight persists pre-existing writable-view evidence");
    activation.VerifyAll();
    Check(new ActivationPreflightStore(activationRoot).Records.Count == 2,
        "activation preflight journal rebuilds after reopen");

    var nestedActivationRepo = new RollbackRepository(Path.Combine(root, "nested-activation-repo"));
    var nestedActivationSession = nestedActivationRepo.CreateSession("nested_activation");
    var nestedActivation = new ActivationPreflightStore(
        Path.Combine(nestedActivationSession.Root, "activation-state"));
    _ = await nestedActivation.RecordAsync(
        603, activationPath, 0, false, createOriginalIdentity);
    var activationJournalBytes = await File.ReadAllBytesAsync(nestedActivation.JournalPath);
    activationJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedActivation.JournalPath, activationJournalBytes);
    var nestedActivationRejected = false;
    try { nestedActivationRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedActivationRejected = true; }
    Check(nestedActivationRejected,
        "repository verification includes nested activation-preflight journal");

    // Activation topology evidence binds the held root/directories through the activation boundary.
    var topologyRoot = Path.Combine(root, "activation-topology-evidence");
    var topology = new ActivationTopologyStore(topologyRoot);
    var protectedRootPath = Path.Combine(sourceDir, "topology-root");
    var protectedChildPath = Path.Combine(protectedRootPath, "child");
    var topologyRootEvidence = await topology.RecordAsync(
        protectedRootPath, createOriginalIdentity, isRoot: true);
    Check(topologyRootEvidence.Sequence == 1 &&
          topologyRootEvidence.IsRoot &&
          topologyRootEvidence.Identity == createOriginalIdentity,
        "activation topology records identity-bound protected root");
    var topologyDuplicate = await topology.RecordAsync(
        protectedRootPath, createOriginalIdentity, isRoot: true);
    Check(topologyDuplicate.Sequence == topologyRootEvidence.Sequence &&
          topology.Records.Count == 1,
        "activation topology evidence is idempotent for the same directory identity");
    var topologyChild = await topology.RecordAsync(
        protectedChildPath, sourceIdentity, isRoot: false);
    Check(topologyChild.Sequence == 2 && !topologyChild.IsRoot,
        "activation topology records nested held directory");
    var topologyConflictRejected = false;
    try
    {
        _ = await topology.RecordAsync(
            protectedChildPath, createOriginalIdentity, isRoot: false);
    }
    catch (InvalidDataException) { topologyConflictRejected = true; }
    Check(topologyConflictRejected,
        "activation topology rejects directory identity drift");
    topology.VerifyAll();
    Check(new ActivationTopologyStore(topologyRoot).Records.Count == 2,
        "activation topology journal rebuilds after reopen");

    var nestedTopologyRepo = new RollbackRepository(Path.Combine(root, "nested-topology-repo"));
    var nestedTopologySession = nestedTopologyRepo.CreateSession("nested_topology");
    var nestedTopology = new ActivationTopologyStore(
        Path.Combine(nestedTopologySession.Root, "activation-topology-state"));
    _ = await nestedTopology.RecordAsync(
        protectedRootPath, createOriginalIdentity, isRoot: true);
    var topologyJournalBytes = await File.ReadAllBytesAsync(nestedTopology.JournalPath);
    topologyJournalBytes[^2] ^= 1;
    await File.WriteAllBytesAsync(nestedTopology.JournalPath, topologyJournalBytes);
    var nestedTopologyRejected = false;
    try { nestedTopologyRepo.VerifyAll(); }
    catch (InvalidDataException) { nestedTopologyRejected = true; }
    Check(nestedTopologyRejected,
        "repository verification includes nested activation-topology journal");

    // Verified recovery planning must expose safe copy-out actions while never guessing topology repair.
    var planRepoRoot = Path.Combine(root, "recovery-plan-repo");
    var planRepo = new RollbackRepository(planRepoRoot);
    var planSession = planRepo.CreateSession("plan_case");
    var planSource = Path.Combine(root, "recovery-plan-source");
    Directory.CreateDirectory(planSource);

    var fullPlanPath = Path.Combine(planSource, "full.bin");
    var fullOriginalBytes = Enumerable.Range(0, 8192).Select(x => (byte)(x % 251)).ToArray();
    await File.WriteAllBytesAsync(fullPlanPath, fullOriginalBytes);
    var fullCapture = await planSession.CapturePreimageAsync(fullPlanPath, RollbackMutationKind.Delete);

    var planRange = new RangeRollbackStore(Path.Combine(planSession.Root, "write-cow"));
    await planRange.CaptureWritePreimageAsync(fullPlanPath, 0, 64);
    using (var mutateFull = new FileStream(fullPlanPath, FileMode.Open, FileAccess.Write, FileShare.Read))
    {
        mutateFull.Position = 128;
        await mutateFull.WriteAsync(Enumerable.Repeat((byte)0xA5, 64).ToArray());
        await mutateFull.FlushAsync();
        mutateFull.Flush(true);
    }

    var rangeOnlyPath = Path.Combine(planSource, "range-only.bin");
    var rangeOriginalBytes = Enumerable.Range(0, 128 * 1024).Select(x => (byte)((x * 7) % 251)).ToArray();
    await File.WriteAllBytesAsync(rangeOnlyPath, rangeOriginalBytes);
    await planRange.CaptureWritePreimageAsync(rangeOnlyPath, 4096, 128);
    using (var mutate = new FileStream(rangeOnlyPath, FileMode.Open, FileAccess.Write, FileShare.Read))
    {
        mutate.Position = 4096;
        await mutate.WriteAsync(Enumerable.Repeat((byte)0xCC, 128).ToArray());
        await mutate.FlushAsync();
        mutate.Flush(true);
    }

    var planCreateRoot = Path.Combine(planSession.Root, "create-state");
    var planCreateBaselines = new CreateRollbackStore(planCreateRoot);
    var planCreateOps = new CreateOperationStore(planCreateRoot);
    var originallyAbsent = Path.Combine(planSource, "incident-created.bin");
    var absentBaseline = await planCreateBaselines.CaptureAbsentAsync(originallyAbsent);
    var planIdentity = new DurableFileIdentity(
        "0102030405060708", "00112233445566778899AABBCCDDEEFF");
    _ = await planCreateOps.RecordIntentAsync(
        9001, originallyAbsent, CreateDisposition.Create, 0, CreateGatePolicy.GenericWrite,
        CreateTargetState.Missing, CreatePreservationAction.RecordOriginallyAbsent,
        absentBaseline.RecordSha256, null);
    _ = await planCreateOps.RecordCompletionAsync(
        9001, CreateCompletionState.Succeeded, 0, 0, originallyAbsent, planIdentity);

    var pendingCreatePath = Path.Combine(planSource, "pending-open.bin");
    var pendingCreateIntent = await planCreateOps.RecordIntentAsync(
        9002, pendingCreatePath, CreateDisposition.Open, 0, 0,
        CreateTargetState.Missing, CreatePreservationAction.NoPreservationRequired,
        string.Empty, null);

    var planRenameRoot = Path.Combine(planSession.Root, "rename-state");
    var planRenames = new RenameRollbackStore(planRenameRoot);
    var renameSourceA = Path.Combine(planSource, "rename-source-a.bin");
    var renameDestinationA = Path.Combine(planSource, "rename-destination-a.bin");
    _ = await planRenames.CaptureIntentAsync(
        9101, renameSourceA, renameDestinationA, planIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);
    _ = await planRenames.RecordCompletionAsync(
        9101, RenameCompletionState.Succeeded, 0, 0, renameDestinationA, planIdentity);

    var renameSourceB = Path.Combine(planSource, "rename-source-b.bin");
    var renameDestinationB = Path.Combine(planSource, "rename-destination-b.bin");
    var pendingRenameIntent = await planRenames.CaptureIntentAsync(
        9102, renameSourceB, renameDestinationB, planIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);

    var renameSourceC = Path.Combine(planSource, "rename-source-c.bin");
    var renameDestinationC = Path.Combine(planSource, "rename-destination-c.bin");
    var ambiguousRenameIntent = await planRenames.CaptureIntentAsync(
        9103, renameSourceC, renameDestinationC, planIdentity, false,
        RenameDestinationState.OriginallyAbsent, null, 0, 10);

    var planRestart = new RestartReconciliationStore(
        Path.Combine(planSession.Root, "restart-state"));
    var createCrashEvidence = await planRestart.RecordObservationAsync(
        RestartOperationKind.Create,
        pendingCreateIntent.RequestSequence,
        pendingCreateIntent.RecordSha256,
        RestartEvidenceState.SupportsNotCompleted,
        pendingCreateIntent.OriginalPath,
        new RestartPathObservation(RestartPathState.Missing, null));
    var renameCrashEvidence = await planRestart.RecordObservationAsync(
        RestartOperationKind.Rename,
        pendingRenameIntent.RequestSequence,
        pendingRenameIntent.RecordSha256,
        RestartEvidenceState.SupportsNotCompleted,
        pendingRenameIntent.SourcePath,
        new RestartPathObservation(RestartPathState.File, planIdentity),
        pendingRenameIntent.DestinationPath,
        new RestartPathObservation(RestartPathState.Missing, null));
    _ = await planRestart.RecordObservationAsync(
        RestartOperationKind.Rename,
        ambiguousRenameIntent.RequestSequence,
        ambiguousRenameIntent.RecordSha256,
        RestartEvidenceState.Ambiguous,
        ambiguousRenameIntent.SourcePath,
        new RestartPathObservation(RestartPathState.QueryFailed, null),
        ambiguousRenameIntent.DestinationPath,
        new RestartPathObservation(RestartPathState.Missing, null));

    var recoveryPlan = RollbackRecoveryPlanner.Build(planRepoRoot, "plan_case");
    Check(recoveryPlan.ReadyCount == 2 &&
          recoveryPlan.ReviewCount == 5 &&
          recoveryPlan.BlockedCount == 1 &&
          !recoveryPlan.AutomaticTopologyMutationAllowed,
        "recovery planner separates copy-out readiness from review/blocked topology");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.RestoreFullPreimageCopy &&
            x.State == RecoveryActionState.Ready &&
            x.PrimaryPath.Equals(fullPlanPath, StringComparison.OrdinalIgnoreCase) &&
            x.EvidenceRecordSha256 == fullCapture.RecordSha256),
        "recovery planner exposes verified full pre-image as ready copy-out");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.RestoreRangeCowCopy &&
            x.State == RecoveryActionState.Informational &&
            x.PrimaryPath.Equals(fullPlanPath, StringComparison.OrdinalIgnoreCase)),
        "full pre-image supersedes range-COW for the same path");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.RestoreRangeCowCopy &&
            x.State == RecoveryActionState.Ready &&
            x.PrimaryPath.Equals(rangeOnlyPath, StringComparison.OrdinalIgnoreCase) &&
            x.RequiresLiveSource),
        "range-only evidence remains ready but explicitly requires the live damaged source");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.ReviewOriginallyAbsentPath &&
            x.State == RecoveryActionState.Review &&
            x.PrimaryPath.Equals(originallyAbsent, StringComparison.OrdinalIgnoreCase)),
        "originally-absent path is review-only and never an automatic delete");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.ReviewCreateTransaction &&
            x.State == RecoveryActionState.Review &&
            x.EvidenceSequence == 9002 &&
            x.EvidenceRecordSha256 == createCrashEvidence.RecordSha256),
        "consistent restart CREATE evidence becomes review-only crash recovery");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.ReviewRenameTopology &&
            x.State == RecoveryActionState.Review &&
            x.EvidenceSequence == 9101),
        "authoritative successful RENAME is topology review, not automatic rename");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.ReviewRenameTopology &&
            x.State == RecoveryActionState.Review &&
            x.EvidenceSequence == 9102 &&
            x.EvidenceRecordSha256 == renameCrashEvidence.RecordSha256),
        "consistent restart RENAME evidence becomes review-only crash recovery");
    Check(recoveryPlan.Actions.Any(x =>
            x.Kind == RecoveryActionKind.ReviewRenameTopology &&
            x.State == RecoveryActionState.Blocked &&
            x.EvidenceSequence == 9103),
        "ambiguous restart RENAME evidence remains blocked");
    Check(recoveryPlan.PlanId.Length == 64 &&
          recoveryPlan.JournalEvidenceSha256.Length == 64,
        "recovery plan binds deterministic SHA-256 plan/evidence digests");

    var repeatedRecoveryPlan = RollbackRecoveryPlanner.Build(planRepoRoot, "plan_case");
    Check(repeatedRecoveryPlan.PlanId == recoveryPlan.PlanId &&
          repeatedRecoveryPlan.JournalEvidenceSha256 == recoveryPlan.JournalEvidenceSha256,
        "recovery plan identity is stable for unchanged validated evidence");

    var recoveryOutput = Path.Combine(root, "verified-recovery-output");
    var execution = await RollbackRecoveryExecutor.ExecuteReadyAsync(
        planRepoRoot, recoveryPlan, recoveryOutput);
    Check(execution.Succeeded &&
          execution.RequestedReadyActions == 2 &&
          execution.SucceededActions == 2 &&
          execution.FailedActions == 0 &&
          execution.ReviewActionsNotExecuted == 5 &&
          execution.BlockedActionsNotExecuted == 1 &&
          !execution.AutomaticTopologyMutationPerformed,
        "recovery executor performs only ready copy-out actions");

    var fullExecution = execution.Items.Single(x => x.Kind == RecoveryActionKind.RestoreFullPreimageCopy);
    var rangeExecution = execution.Items.Single(x => x.Kind == RecoveryActionKind.RestoreRangeCowCopy);
    Check(File.ReadAllBytes(fullExecution.RecoveredPath).SequenceEqual(fullOriginalBytes),
        "full pre-image executor output equals original bytes");
    Check(File.ReadAllBytes(rangeExecution.RecoveredPath).SequenceEqual(rangeOriginalBytes),
        "range-COW executor output equals original bytes");
    Check(!File.ReadAllBytes(fullPlanPath).SequenceEqual(fullOriginalBytes) &&
          !File.ReadAllBytes(rangeOnlyPath).SequenceEqual(rangeOriginalBytes),
        "copy-out executor leaves damaged live sources untouched");
    Check(File.Exists(Path.Combine(recoveryOutput, "recovery-plan.json")) &&
          File.Exists(Path.Combine(recoveryOutput, "recovery-execution.json")) &&
          fullExecution.RecoveredSha256.Length == 64 &&
          rangeExecution.RecoveredSha256.Length == 64,
        "recovery executor persists plan/report and output SHA-256 evidence");

    _ = await planCreateOps.RecordCompletionAsync(
        9002, CreateCompletionState.Failed, 0xC0000001, 0, null, null);
    var staleRejected = false;
    var staleOutput = Path.Combine(root, "stale-recovery-output");
    try
    {
        _ = await RollbackRecoveryExecutor.ExecuteReadyAsync(
            planRepoRoot, recoveryPlan, staleOutput);
    }
    catch (InvalidDataException) { staleRejected = true; }
    Check(staleRejected && !Directory.Exists(staleOutput),
        "stale recovery plan is rejected before any output is created");

    // Session-level storage admission must account for concurrent reservations and committed bytes.
    var budgetRoot = Path.Combine(root, "storage-budget-session");
    Directory.CreateDirectory(budgetRoot);
    var budget = new RollbackStorageBudget(
        budgetRoot,
        1024 * 1024,
        0);

    var firstReservation = await budget.ReserveAsync(
        700 * 1024, "first-concurrent-reservation");
    var concurrentBudgetRejected = false;
    try
    {
        _ = await budget.ReserveAsync(
            400 * 1024, "second-concurrent-reservation");
    }
    catch (RollbackStorageBudgetExceededException)
    {
        concurrentBudgetRejected = true;
    }
    Check(concurrentBudgetRejected,
        "storage budget includes in-flight reservations in session quota");

    var reservedStatus = await budget.GetStatusAsync();
    Check(reservedStatus.ReservedBytes == 700 * 1024 &&
          reservedStatus.MaxSessionBytes == 1024 * 1024,
        "storage budget status exposes bounded in-flight reservation");

    await firstReservation.DisposeAsync();
    var afterRelease = await budget.ReserveAsync(
        400 * 1024, "reservation-after-release");
    await afterRelease.DisposeAsync();
    Check((await budget.GetStatusAsync()).ReservedBytes == 0,
        "storage reservations release capacity after preservation finishes");

    var committedBudgetFile = Path.Combine(budgetRoot, "committed.bin");
    await File.WriteAllBytesAsync(committedBudgetFile, new byte[900 * 1024]);
    var committedBudgetRejected = false;
    try
    {
        _ = await budget.ReserveAsync(
            200 * 1024, "quota-after-committed-bytes");
    }
    catch (RollbackStorageBudgetExceededException)
    {
        committedBudgetRejected = true;
    }
    Check(committedBudgetRejected,
        "storage budget re-measures committed session bytes before admission");

    var estimateRepo = new RollbackRepository(Path.Combine(root, "storage-estimator-repo"));
    var estimateSession = estimateRepo.CreateSession("estimate_case");
    var estimateSource = Path.Combine(root, "storage-estimator-source");
    Directory.CreateDirectory(estimateSource);

    var estimateFullPath = Path.Combine(estimateSource, "full.bin");
    await File.WriteAllBytesAsync(estimateFullPath, new byte[4096]);
    var firstFullEstimate = RollbackStorageBudget.EstimateFullPreimageBytes(
        estimateSession, estimateFullPath);
    Check(firstFullEstimate > 4096,
        "full pre-image estimator includes file bytes plus commit overhead");
    _ = await estimateSession.CapturePreimageAsync(
        estimateFullPath, RollbackMutationKind.Delete);
    Check(RollbackStorageBudget.EstimateFullPreimageBytes(
              estimateSession, estimateFullPath) == 0,
        "full pre-image estimator does not reserve an already committed capture");

    var estimateRange = new RangeRollbackStore(
        Path.Combine(estimateSession.Root, "write-cow"));
    var estimateRangePath = Path.Combine(estimateSource, "range.bin");
    await File.WriteAllBytesAsync(estimateRangePath, new byte[128 * 1024]);
    var firstRangeEstimate = RollbackStorageBudget.EstimateRangeCaptureBytes(
        estimateRange, estimateRangePath, 4096, 128);
    Check(firstRangeEstimate > 128 * 1024,
        "range estimator reserves uncaptured block plus journal overhead");
    await estimateRange.CaptureWritePreimageAsync(
        estimateRangePath, 4096, 128);
    Check(RollbackStorageBudget.EstimateRangeCaptureBytes(
              estimateRange, estimateRangePath, 4096, 128) == 0,
        "range estimator does not reserve an already committed block/baseline");

    var estimateCreate = new CreateRollbackStore(
        Path.Combine(estimateSession.Root, "create-state"));
    var estimateAbsentPath = Path.Combine(estimateSource, "absent.bin");
    Check(RollbackStorageBudget.EstimateOriginallyAbsentBytes(
              estimateCreate, estimateAbsentPath) ==
          RollbackStorageBudget.MetadataReservationBytes,
        "absence estimator reserves metadata before first baseline");
    _ = await estimateCreate.CaptureAbsentAsync(estimateAbsentPath);
    Check(RollbackStorageBudget.EstimateOriginallyAbsentBytes(
              estimateCreate, estimateAbsentPath) == 0,
        "absence estimator does not reserve an existing baseline again");

    // Retention lifecycle and cleanup must never select Active/Faulted/Held/pending sessions.
    var retentionRepoRoot = Path.Combine(root, "retention-repo");
    var retentionRepo = new RollbackRepository(retentionRepoRoot);
    var maintenanceLeaseConflictRejected = false;
    using (var maintenanceLease = RollbackMaintenanceLease.Acquire(retentionRepoRoot))
    {
        try
        {
            using var secondMaintenanceLease = RollbackMaintenanceLease.Acquire(retentionRepoRoot);
        }
        catch (IOException) { maintenanceLeaseConflictRejected = true; }
    }
    using (var reacquiredMaintenanceLease = RollbackMaintenanceLease.Acquire(retentionRepoRoot))
    {
        Check(maintenanceLeaseConflictRejected,
            "rollback maintenance lease serializes retention and hold changes");
    }

    var retentionSource = Path.Combine(root, "retention-source");
    Directory.CreateDirectory(retentionSource);
    var retentionNow = DateTime.UtcNow;

    var oldSession = retentionRepo.CreateSession(
        "old_completed", retentionNow.AddDays(-41));
    var oldLifecycle = new RollbackSessionLifecycleStore(oldSession.Root);
    _ = await oldLifecycle.MarkCompletedAtAsync(
        "test-old-completed", retentionNow.AddDays(-40));

    var heldSession = retentionRepo.CreateSession(
        "held_completed", retentionNow.AddDays(-46));
    var heldLifecycle = new RollbackSessionLifecycleStore(heldSession.Root);
    _ = await heldLifecycle.MarkCompletedAtAsync(
        "test-held-completed", retentionNow.AddDays(-45));
    _ = await heldLifecycle.SetHoldAsync("legal-hold");

    var activeSession = retentionRepo.CreateSession("active_session");
    var activeLifecycle = new RollbackSessionLifecycleStore(activeSession.Root);
    Check(activeLifecycle.Snapshot.State == RollbackSessionLifecycleState.Active,
        "new rollback session lifecycle starts Active");

    var faultedSession = retentionRepo.CreateSession("faulted_session");
    var faultedLifecycle = new RollbackSessionLifecycleStore(faultedSession.Root);
    _ = await faultedLifecycle.MarkFaultedAsync("synthetic-worker-failure");

    var pendingSession = retentionRepo.CreateSession("pending_completed");
    var pendingCreateRoot = Path.Combine(pendingSession.Root, "create-state");
    var pendingCreateOps = new CreateOperationStore(pendingCreateRoot);
    _ = await pendingCreateOps.RecordIntentAsync(
        12001,
        Path.Combine(retentionSource, "pending.bin"),
        CreateDisposition.Open,
        0,
        0,
        CreateTargetState.Missing,
        CreatePreservationAction.NoPreservationRequired,
        string.Empty,
        null);
    var pendingLifecycle = new RollbackSessionLifecycleStore(pendingSession.Root);
    _ = await pendingLifecycle.MarkCompletedAsync(
        "synthetic-invalid-completed");

    var retentionPlanHeld = RollbackRetentionPlanner.Build(retentionRepoRoot);
    Check(retentionPlanHeld.Actions.Any(x =>
              x.Kind == RollbackRetentionActionKind.PurgeCompletedSession &&
              x.SessionId == "old_completed") &&
          !retentionPlanHeld.Actions.Any(x => x.SessionId == "held_completed") &&
          !retentionPlanHeld.Actions.Any(x => x.SessionId == "active_session") &&
          !retentionPlanHeld.Actions.Any(x => x.SessionId == "faulted_session") &&
          !retentionPlanHeld.Actions.Any(x => x.SessionId == "pending_completed"),
        "retention planner selects only eligible completed unheld sessions");
    Check(retentionPlanHeld.HeldSessions == 1 &&
          retentionPlanHeld.ProtectedSessions >= 3 &&
          retentionPlanHeld.Issues.Any(x =>
              x.SessionId == "pending_completed" &&
              x.Reason.Contains("pending CREATE/RENAME", StringComparison.Ordinal)),
        "retention planner reports held/protected/pending sessions");

    var staleRetentionPlan = retentionPlanHeld;
    _ = await oldLifecycle.SetHoldAsync("temporary-hold-after-plan");
    var staleRetentionRejected = false;
    try
    {
        _ = await RollbackRetentionExecutor.ExecuteAsync(
            retentionRepoRoot, staleRetentionPlan);
    }
    catch (InvalidDataException) { staleRetentionRejected = true; }
    Check(staleRetentionRejected &&
          Directory.Exists(oldSession.Root),
        "retention executor rejects stale plan after lifecycle hold change");

    _ = await oldLifecycle.ReleaseHoldAsync("release-test-hold");
    var executableRetentionPlan = RollbackRetentionPlanner.Build(retentionRepoRoot);
    var retentionExecution = await RollbackRetentionExecutor.ExecuteAsync(
        retentionRepoRoot, executableRetentionPlan);
    Check(retentionExecution.Succeeded &&
          retentionExecution.Items.Any(x =>
              x.SessionId == "old_completed" &&
              x.State == RollbackRetentionExecutionState.Succeeded) &&
          !Directory.Exists(Path.Combine(retentionRepoRoot, "Sessions", "old_completed")) &&
          !Directory.Exists(Path.Combine(retentionRepoRoot, "Retired", "old_completed")),
        "retention executor quarantines and purges eligible completed session");
    var retentionJournal = new RollbackRetentionStore(
        retentionRepoRoot, createIfMissing: false);
    var oldRetentionEvents = retentionJournal.Records
        .Where(x => x.SessionId == "old_completed")
        .Select(x => x.EventType)
        .ToArray();
    Check(oldRetentionEvents.SequenceEqual(new[]
          {
              RollbackRetentionEventType.PurgeStarted,
              RollbackRetentionEventType.Quarantined,
              RollbackRetentionEventType.PurgeCompleted
          }),
        "retention journal records started/quarantined/completed purge chain");

    // Capacity pressure may select an otherwise unexpired completed session, but never younger than MinPressureAge.
    var capacityRepoRoot = Path.Combine(root, "retention-capacity-repo");
    var capacityRepo = new RollbackRepository(capacityRepoRoot);
    for (var n = 0; n < 2; n++)
    {
        var completedAt = retentionNow.AddDays(-2 - n);
        var session = capacityRepo.CreateSession(
            $"capacity_{n}", completedAt.AddHours(-1));
        _ = await new RollbackSessionLifecycleStore(session.Root).MarkCompletedAtAsync(
            "capacity-test", completedAt);
    }
    var capacityPlan = RollbackRetentionPlanner.Build(
        capacityRepoRoot,
        new RollbackRetentionPolicy(
            TimeSpan.FromDays(30),
            MaxCompletedBytes: 1,
            MinPressureAge: TimeSpan.FromDays(1)));
    Check(capacityPlan.Actions.Any(x =>
              x.Kind == RollbackRetentionActionKind.PurgeCompletedSession &&
              x.Reason == "completed-storage-capacity-pressure") &&
          capacityPlan.PlannedReclaimBytes > 0,
        "retention planner selects oldest eligible sessions under capacity pressure");

    // Incomplete purge must resume safely from Retired after a crash between move and Quarantined receipt.
    var resumeRepoRoot = Path.Combine(root, "retention-resume-repo");
    var resumeRepo = new RollbackRepository(resumeRepoRoot);
    var resumeSession = resumeRepo.CreateSession(
        "resume_case", retentionNow.AddDays(-61));
    _ = await new RollbackSessionLifecycleStore(resumeSession.Root)
        .MarkCompletedAtAsync("resume-test", retentionNow.AddDays(-60));

    var resumeDigest = RollbackRetentionPlanner.ComputeSessionDigest(
        resumeSession.Root);
    var resumeBytes = RollbackRetentionPlanner.MeasureTreeBytes(
        resumeSession.Root);
    var interruptedPlanId = new string('A', 64);
    var resumeRetention = new RollbackRetentionStore(resumeRepoRoot);
    _ = await resumeRetention.RecordAsync(
        RollbackRetentionEventType.PurgeStarted,
        interruptedPlanId,
        "resume_case",
        resumeDigest,
        resumeBytes,
        "synthetic-crash-resume");

    var resumeRetiredRoot = Path.Combine(resumeRepoRoot, "Retired");
    Directory.CreateDirectory(resumeRetiredRoot);
    var resumeRetiredPath = Path.Combine(resumeRetiredRoot, "resume_case");
    Directory.Move(resumeSession.Root, resumeRetiredPath);

    var resumePlan = RollbackRetentionPlanner.Build(resumeRepoRoot);
    Check(resumePlan.Actions.Any(x =>
              x.Kind == RollbackRetentionActionKind.ResumePurgeFromRetired &&
              x.SessionId == "resume_case"),
        "retention planner detects moved incomplete purge after crash");
    var resumeExecution = await RollbackRetentionExecutor.ExecuteAsync(
        resumeRepoRoot, resumePlan);
    Check(resumeExecution.Succeeded &&
          !Directory.Exists(resumeRetiredPath) &&
          new RollbackRetentionStore(resumeRepoRoot, createIfMissing: false)
              .LatestForSession("resume_case")?.EventType ==
              RollbackRetentionEventType.PurgeCompleted,
        "retention executor resumes quarantined purge and commits completion receipt");

    Console.WriteLine($"All {passed} rollback tests passed. These are file-store tests, not minifilter integration tests.");
    return 0;
}
finally
{
    try { Directory.Delete(root, true); } catch { }
}
