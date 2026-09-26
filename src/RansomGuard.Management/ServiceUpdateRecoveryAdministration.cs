using System.Text.Json;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record ServiceUpdateRecoveryReview(
    string TransactionId,
    string JournalPhase,
    string RegisteredImage,
    string ServiceState,
    string PreviousImage,
    string PreviousVersion,
    string TargetImage,
    string TargetVersion,
    string RequiredAction);

public sealed record ServiceUpdateRecoveryResult(
    string TransactionId,
    string PreviousImage,
    string PreviousVersion,
    string ObservedImage,
    string Outcome);

public static partial class ServiceAdministration
{
    private static readonly string[] RecoverableUpdatePhases =
    [
        "Prepared",
        "ScmCommitted",
        "TargetStarted",
        "TargetVerifiedStopped",
        "RollbackStarting",
        "RollbackScmCommitted",
        "RollbackFailed"
    ];

    public static ServiceUpdateRecoveryReview ReviewInterruptedUpdate()
    {
        RuleAdministration.DemandAdministrator();
        var store = new SecureStore();
        var (record, _) = ReadSingleIncompleteUpdate(store);

        using var scm = Scm.OpenSCManagerW(null, null, 1);
        if (scm.IsInvalid) throw Error();
        using var service = Scm.OpenServiceW(scm, AdminContract.ServiceName, QueryConfig | QueryStatus);
        if (service.IsInvalid) throw Error();

        var registration = Configuration(service);
        ValidateRecoveryRegistration(registration, record);
        VerifyRecordedPreviousImage(record);

        var state = StateName(Status(service).CurrentState);
        var observed = Path.GetFullPath(registration.ImagePath);
        var action = WinPaths.Equal(observed, record.PreviousImage) &&
                     string.Equals(record.Phase, "Prepared", StringComparison.Ordinal)
            ? "AbortBeforeCommit"
            : "RollbackToPrevious";

        return new(
            record.TransactionId,
            record.Phase,
            observed,
            state,
            Path.GetFullPath(record.PreviousImage),
            record.PreviousVersion,
            Path.GetFullPath(record.TargetImage),
            record.TargetVersion,
            action);
    }

    public static ServiceUpdateRecoveryResult RecoverInterruptedUpdate(
        string transactionId,
        string confirmation)
    {
        if (!Guid.TryParseExact(transactionId, "N", out _))
            throw new ArgumentException("A canonical update transaction id is required.");

        var maintenance = StateMaintenanceGate.Acquire();
        var maintenanceReleased = false;
        try
        {
            RuleAdministration.DemandAdministrator();
            AdminContract.CheckConfirmation("update-recovery", confirmation);

            var store = new SecureStore();
            var (record, journalPath) = ReadSingleIncompleteUpdate(store);
            if (!string.Equals(record.TransactionId, transactionId, StringComparison.OrdinalIgnoreCase))
                throw new IOException(
                    "The requested update transaction is not the single current incomplete transaction.");

            using var scm = Scm.OpenSCManagerW(null, null, 3);
            if (scm.IsInvalid) throw Error();
            using var service = Scm.OpenServiceW(
                scm,
                AdminContract.ServiceName,
                QueryConfig | QueryStatus | StartAccess | StopAccess | ChangeConfigAccess);
            if (service.IsInvalid) throw Error();

            var registration = Configuration(service);
            ValidateRecoveryRegistration(registration, record);
            var observedImage = Path.GetFullPath(registration.ImagePath);

            StopServiceForUpdateRecovery(service);

            // Re-read after the service is stopped. A concurrent SCM change must not be
            // silently accepted as evidence for either side of the transaction.
            registration = Configuration(service);
            ValidateRecoveryRegistration(registration, record);
            if (!WinPaths.Equal(observedImage, registration.ImagePath))
                throw new IOException(
                    "SCM ImagePath changed while update recovery was acquiring a stable stopped state.");
            observedImage = Path.GetFullPath(registration.ImagePath);

            VerifyRecordedPreviousImage(record);

            if (WinPaths.Equal(observedImage, record.PreviousImage) &&
                string.Equals(record.Phase, "Prepared", StringComparison.Ordinal))
            {
                record = PersistUpdate(
                    store,
                    journalPath,
                    record,
                    "AbortedBeforeCommit",
                    "Explicit recovery observed the verified previous image still selected in SCM; no updater commit was accepted.");
                store.Audit(new
                {
                    Utc = DateTime.UtcNow,
                    Event = "ServiceUpdateRecoveryAbortedBeforeCommit",
                    Transaction = record.TransactionId,
                    PreviousImage = record.PreviousImage,
                    TargetImage = record.TargetImage,
                    ObservedImage = observedImage
                });
                return new(
                    record.TransactionId,
                    record.PreviousImage,
                    record.PreviousVersion,
                    observedImage,
                    "AbortedBeforeCommit");
            }

            var recoveryMutationStarted = false;
            try
            {
                if (WinPaths.Equal(observedImage, record.TargetImage))
                {
                    recoveryMutationStarted = true;
                    ChangeServiceImage(service, record.PreviousImage);
                    var restored = Configuration(service);
                    if (!WinPaths.Equal(restored.ImagePath, record.PreviousImage))
                        throw new IOException("SCM recovery did not retain the verified previous image path.");
                    VerifyRegistration(restored.ImagePath, restored.Account, restored.ServiceType);
                    record = PersistUpdate(
                        store,
                        journalPath,
                        record,
                        "RollbackScmCommitted",
                        "Explicit recovery restored SCM to the previous verified image.");
                }
                else if (WinPaths.Equal(observedImage, record.PreviousImage))
                {
                    // A crash may occur after SCM rollback but before the durable phase
                    // write. Treat the observed previous image as rollback evidence only
                    // after verifying its immutable install identity.
                    recoveryMutationStarted = true;
                    VerifyRegistration(
                        registration.ImagePath,
                        registration.Account,
                        registration.ServiceType);
                    record = PersistUpdate(
                        store,
                        journalPath,
                        record,
                        "RollbackScmCommitted",
                        "Explicit recovery observed SCM already restored to the previous verified image.");
                }
                else
                {
                    throw new IOException(
                        "SCM ImagePath is neither the recorded previous image nor the recorded target image. " +
                        "Recovery is refused; inspect the service registration manually.");
                }

                maintenance.Dispose();
                maintenanceReleased = true;

                if (!Scm.StartServiceW(service, 0, IntPtr.Zero)) throw Error();
                WaitFor(service, 4);
                Thread.Sleep(2000);
                if (Status(service).CurrentState != 4)
                    throw new IOException(
                        "Previous verified service image did not remain Running during interrupted-update recovery.");
                if (!Scm.ControlService(service, 1, out _)) throw Error();
                WaitFor(service, 1);

                record = PersistUpdate(
                    store,
                    journalPath,
                    record,
                    "RolledBack",
                    "Explicit interrupted-update recovery proved the previous image can start and stop cleanly.");
                store.Audit(new
                {
                    Utc = DateTime.UtcNow,
                    Event = "ServiceUpdateRecoveryCompleted",
                    Transaction = record.TransactionId,
                    PreviousImage = record.PreviousImage,
                    PreviousVersion = record.PreviousVersion,
                    TargetImage = record.TargetImage,
                    ObservedImage = observedImage,
                    Outcome = "RolledBack"
                });
                return new(
                    record.TransactionId,
                    record.PreviousImage,
                    record.PreviousVersion,
                    observedImage,
                    "RolledBack");
            }
            catch (Exception recoveryError)
            {
                if (recoveryMutationStarted)
                {
                    try
                    {
                        PersistUpdate(
                            store,
                            journalPath,
                            record,
                            "RollbackFailed",
                            "Explicit interrupted-update recovery failed: " + recoveryError.Message);
                        store.Audit(new
                        {
                            Utc = DateTime.UtcNow,
                            Event = "ServiceUpdateRecoveryFailed",
                            Transaction = record.TransactionId,
                            PreviousImage = record.PreviousImage,
                            TargetImage = record.TargetImage,
                            ObservedImage = observedImage,
                            Error = recoveryError.Message
                        });
                    }
                    catch
                    {
                        // Preserve the original recovery failure. A secondary evidence-write
                        // failure must not disguise the state that requires operator review.
                    }
                }

                throw new IOException(
                    "Interrupted update recovery could not prove a safe terminal state. " +
                    "Do not retry the updater; inspect the durable transaction and SCM registration. " +
                    recoveryError.Message,
                    recoveryError);
            }
        }
        finally
        {
            if (!maintenanceReleased) maintenance.Dispose();
        }
    }

    private static (ServiceUpdateRecord Record, string JournalPath) ReadSingleIncompleteUpdate(
        SecureStore store)
    {
        var root = Path.Combine(store.Root, ServiceUpdateDirectoryName);
        if (!Directory.Exists(root))
            throw new IOException("No interrupted service update transaction exists.");
        FileSafety.NoReparse(root);

        var incomplete = new List<(ServiceUpdateRecord Record, string JournalPath)>();
        foreach (var path in Directory.EnumerateFiles(root, "*.json", SearchOption.TopDirectoryOnly))
        {
            FileSafety.NoReparse(path);
            if (new FileInfo(path).Length is <= 0 or > 16384)
                throw new IOException("Update transaction record size invalid: " + path);

            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var record = JsonSerializer.Deserialize<ServiceUpdateRecord>(file)
                ?? throw new IOException("Update transaction record invalid: " + path);
            ValidateRecoveryRecord(record, path);

            if (record.Phase is "Completed" or "RolledBack" or "AbortedBeforeCommit")
                continue;
            if (!RecoverableUpdatePhases.Contains(record.Phase, StringComparer.Ordinal))
                throw new IOException(
                    "Unsupported incomplete update phase requires manual review: " + record.Phase);
            incomplete.Add((record, path));
        }

        return incomplete.Count switch
        {
            1 => incomplete[0],
            0 => throw new IOException("No interrupted service update transaction exists."),
            _ => throw new IOException(
                "Multiple incomplete update transactions exist. Automatic reconciliation is refused.")
        };
    }

    private static void ValidateRecoveryRecord(ServiceUpdateRecord record, string journalPath)
    {
        if (record.Schema != 1 ||
            !Guid.TryParseExact(record.TransactionId, "N", out _) ||
            !string.Equals(
                Path.GetFileNameWithoutExtension(journalPath),
                record.TransactionId,
                StringComparison.OrdinalIgnoreCase) ||
            !IsSha256Hex(record.PreviousSha256) ||
            !IsSha256Hex(record.TargetSha256) ||
            !Version.TryParse(record.PreviousVersion, out _) ||
            !Version.TryParse(record.TargetVersion, out _))
            throw new IOException("Update transaction identity is invalid: " + journalPath);

        var previous = Path.GetFullPath(record.PreviousImage);
        var target = Path.GetFullPath(record.TargetImage);
        if (!WinPaths.Under(previous, InstallRoot) ||
            !WinPaths.Under(target, InstallRoot) ||
            !string.Equals(Path.GetFileName(previous), "RansomGuard.Service.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(target), "RansomGuard.Service.exe", StringComparison.OrdinalIgnoreCase) ||
            WinPaths.Equal(previous, target))
            throw new IOException("Update transaction image paths are outside the immutable install boundary.");

        if (record.CreatedUtc == default || record.UpdatedUtc == default ||
            record.UpdatedUtc < record.CreatedUtc)
            throw new IOException("Update transaction timestamps are invalid.");
    }

    private static void ValidateRecoveryRegistration(
        ServiceConfig registration,
        ServiceUpdateRecord record)
    {
        if (registration.ServiceType != 0x10 ||
            !string.Equals(registration.Account, "LocalSystem", StringComparison.OrdinalIgnoreCase))
            throw new IOException("RansomGuard service registration identity changed; update recovery is refused.");

        if (!WinPaths.Equal(registration.ImagePath, record.PreviousImage) &&
            !WinPaths.Equal(registration.ImagePath, record.TargetImage))
            throw new IOException(
                "SCM ImagePath is neither side of the recorded update transaction; recovery is refused.");
    }

    private static void VerifyRecordedPreviousImage(ServiceUpdateRecord record)
    {
        var previous = Path.GetFullPath(record.PreviousImage);
        using var lease = VerifyInstalledImage(previous);
        var install = ReadInstallRecord(previous);
        VerifyInstalledVersion(previous, install);
        if (!string.Equals(install.Version, record.PreviousVersion, StringComparison.Ordinal) ||
            !DecisionPolicy.HashEqual(install.ImageSha256, record.PreviousSha256))
            throw new IOException(
                "Previous installed image identity does not match the interrupted update transaction.");
    }

    private static void StopServiceForUpdateRecovery(Scm.Handle service)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            var state = Status(service);
            if (state.CurrentState == 1) return;

            if (state.CurrentState == 3)
            {
                if (DateTime.UtcNow >= deadline)
                    throw new TimeoutException("Service did not stop during interrupted-update recovery.");
                Thread.Sleep(200);
                continue;
            }

            if (state.CurrentState == 2)
            {
                if (DateTime.UtcNow >= deadline)
                    throw new TimeoutException("Service did not leave StartPending during interrupted-update recovery.");
                Thread.Sleep(200);
                continue;
            }

            if (!Scm.ControlService(service, 1, out _))
                throw Error();

            while (DateTime.UtcNow < deadline)
            {
                state = Status(service);
                if (state.CurrentState == 1) return;
                Thread.Sleep(200);
            }
            throw new TimeoutException("Service did not stop during interrupted-update recovery.");
        }
    }
}
