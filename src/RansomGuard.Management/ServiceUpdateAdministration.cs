using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record ServiceUpdateResult(
    string TransactionId,
    string PreviousVersion,
    string TargetVersion,
    string PreviousImage,
    string TargetImage,
    string Outcome);

internal sealed record ServiceUpdateRecord(
    int Schema,
    string TransactionId,
    string Phase,
    string PreviousImage,
    string PreviousVersion,
    string PreviousSha256,
    string TargetImage,
    string TargetVersion,
    string TargetSha256,
    DateTime CreatedUtc,
    DateTime UpdatedUtc,
    string? Error);

public static partial class ServiceAdministration
{
    private const uint ChangeConfigAccess = 2;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const string ServiceUpdateDirectoryName = "ServiceUpdates";

    public static string ReviewUpdateInput(string packageRoot, string expectedServiceHash)
    {
        RuleAdministration.DemandAdministrator();
        var before = Query();
        if (!before.QuerySucceeded) throw new IOException(before.Error);
        if (!before.Installed) throw new IOException("RansomGuardV03 is not installed.");
        if (before.State != "Stopped") throw new IOException("Stop RansomGuardV03 cleanly before updating.");

        VerifyRegistration(before.ImagePath, before.Account, 0x10);
        using var installed = VerifyInstalledImage(before.ImagePath);
        var current = ReadInstallRecord(before.ImagePath);
        VerifyInstalledVersion(before.ImagePath, current);

        using var target = OpenVerifiedUpdateSource(packageRoot, expectedServiceHash, out var targetVersion, out _);
        RequireForwardVersion(current.Version, targetVersion);

        var currentFolder = Path.GetDirectoryName(Path.GetFullPath(before.ImagePath))
            ?? throw new IOException("Installed service folder is unavailable.");
        var currentSettings = ReadUpdateSettings(Path.Combine(currentFolder, "appsettings.json"));
        var targetProtection = InspectUpdateProtectionPackage(packageRoot, targetVersion);
        ValidateUpdateProtectionTransition(
            currentSettings,
            currentFolder,
            current.Version,
            targetProtection);

        return targetVersion;
    }

    public static ServiceUpdateResult Update(
        string packageRoot,
        string expectedServiceHash,
        string confirmation)
    {
        using var maintenance = StateMaintenanceGate.Acquire();
        RuleAdministration.DemandAdministrator();
        AdminContract.CheckConfirmation("update", confirmation);

        var store = new SecureStore();
        var before = Query();
        if (!before.QuerySucceeded) throw new IOException(before.Error);
        if (!before.Installed) throw new IOException("RansomGuardV03 is not installed.");
        if (before.State != "Stopped")
            throw new IOException("Stop RansomGuardV03 cleanly before updating. The updater never force-terminates the service.");

        using var scm = Scm.OpenSCManagerW(null, null, 3);
        if (scm.IsInvalid) throw Error();
        using var service = Scm.OpenServiceW(
            scm,
            AdminContract.ServiceName,
            QueryConfig | QueryStatus | StartAccess | StopAccess | ChangeConfigAccess);
        if (service.IsInvalid) throw Error();

        var registration = Configuration(service);
        VerifyRegistration(registration.ImagePath, registration.Account, registration.ServiceType);
        if (Status(service).CurrentState != 1)
            throw new IOException("Service state changed while preparing update; no update was applied.");

        using var installedLease = VerifyInstalledImage(registration.ImagePath);
        var previous = ReadInstallRecord(registration.ImagePath);
        VerifyInstalledVersion(registration.ImagePath, previous);

        using var targetSource = OpenVerifiedUpdateSource(
            packageRoot,
            expectedServiceHash,
            out var targetVersion,
            out var targetHash);
        RequireForwardVersion(previous.Version, targetVersion);

        var previousImage = Path.GetFullPath(registration.ImagePath);
        var previousFolder = Path.GetDirectoryName(previousImage)
            ?? throw new IOException("Installed service folder is unavailable.");
        var previousConfig = Path.Combine(previousFolder, "appsettings.json");
        VerifyInstallAcl(previousConfig, false);
        FileSafety.NoReparse(previousConfig);
        if (new FileInfo(previousConfig).Length > 65536)
            throw new IOException("Installed configuration exceeds the update migration bound.");

        var previousSettings = ReadUpdateSettings(previousConfig);
        var targetProtection = InspectUpdateProtectionPackage(packageRoot, targetVersion);
        ValidateUpdateProtectionTransition(
            previousSettings,
            previousFolder,
            previous.Version,
            targetProtection);

        EnsureNoIncompleteUpdate(store);

        EnsureInstallDirectory(InstallRoot);
        var transactionId = Guid.NewGuid().ToString("N");
        var targetFolder = Path.Combine(InstallRoot, "v" + targetVersion + "-" + transactionId);
        var targetImage = Path.Combine(targetFolder, "RansomGuard.Service.exe");
        var targetConfig = Path.Combine(targetFolder, "appsettings.json");
        var targetInstallRecord = Path.Combine(targetFolder, "install.json");
        var journalDirectory = Path.Combine(store.Root, ServiceUpdateDirectoryName);
        SecureStore.EnsureDirectory(journalDirectory);
        var journalPath = Path.Combine(journalDirectory, transactionId + ".json");

        var created = DateTime.UtcNow;
        ServiceUpdateRecord record = new(
            1,
            transactionId,
            "Staging",
            previousImage,
            previous.Version,
            previous.ImageSha256,
            targetImage,
            targetVersion,
            targetHash,
            created,
            created,
            null);

        bool targetDirectoryCreated = false;
        bool scmCommitted = false;
        try
        {
            EnsureInstallDirectory(targetFolder);
            targetDirectoryCreated = true;

            CopyNewAndFlush(targetSource, targetImage);
            SetInstallFileAcl(targetImage);
            using (var copied = new FileStream(targetImage, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (!DecisionPolicy.HashEqual(targetHash, Convert.ToHexString(SHA256.HashData(copied))))
                    throw new IOException("Staged update service hash mismatch.");
            }

            using (var sourceConfig = new FileStream(previousConfig, FileMode.Open, FileAccess.Read, FileShare.Read))
                CopyNewAndFlush(sourceConfig, targetConfig);
            SetInstallFileAcl(targetConfig);

            var stagedSettings = ReadUpdateSettings(targetConfig);
            if (!string.Equals(stagedSettings.Mode, previousSettings.Mode, StringComparison.Ordinal))
                throw new IOException("Staged configuration changed protection mode during migration.");

            StageUpdateProtectionPackage(targetProtection, targetFolder);

            WriteNew(targetInstallRecord, new InstallRecord(1, targetVersion, targetHash, DateTime.UtcNow));
            record = PersistUpdate(store, journalPath, record, "Prepared", null);
            store.Audit(new
            {
                Utc = DateTime.UtcNow,
                Event = "ServiceUpdatePrepared",
                Transaction = transactionId,
                PreviousImage = previousImage,
                PreviousVersion = previous.Version,
                TargetImage = targetImage,
                TargetVersion = targetVersion,
                TargetSha256 = targetHash,
                ProtectionTransition = targetProtection is null
                    ? "None"
                    : "VersionBoundCompatible"
            });

            ChangeServiceImage(service, targetImage);
            // A successful ChangeServiceConfigW is the irreversible external commit point
            // for this transaction. From this instruction onward every failure must take
            // the rollback path, even if the read-back or durable journal write fails.
            scmCommitted = true;
            var committedRegistration = Configuration(service);
            if (!WinPaths.Equal(committedRegistration.ImagePath, targetImage))
                throw new IOException("SCM did not retain the staged update image path.");
            record = PersistUpdate(store, journalPath, record, "ScmCommitted", null);
            store.Audit(new
            {
                Utc = DateTime.UtcNow,
                Event = "ServiceUpdateScmCommitted",
                Transaction = transactionId,
                PreviousImage = previousImage,
                TargetImage = targetImage
            });

            maintenance.Dispose();

            if (!Scm.StartServiceW(service, 0, IntPtr.Zero)) throw Error();
            WaitFor(service, 4);
            record = PersistUpdate(store, journalPath, record, "TargetStarted", null);

            Thread.Sleep(2000);
            if (Status(service).CurrentState != 4)
                throw new IOException("Updated service did not remain Running through the bounded startup verification window.");

            if (!Scm.ControlService(service, 1, out _)) throw Error();
            WaitFor(service, 1);
            record = PersistUpdate(store, journalPath, record, "TargetVerifiedStopped", null);

            using (var verified = VerifyInstalledImage(targetImage))
            {
                if (!DecisionPolicy.HashEqual(targetHash, Convert.ToHexString(SHA256.HashData(verified))))
                    throw new IOException("Updated installed image changed after startup verification.");
            }

            record = PersistUpdate(store, journalPath, record, "Completed", null);
            store.Audit(new
            {
                Utc = DateTime.UtcNow,
                Event = "ServiceUpdateCompleted",
                Transaction = transactionId,
                PreviousImage = previousImage,
                PreviousVersion = previous.Version,
                TargetImage = targetImage,
                TargetVersion = targetVersion,
                StartedAndStoppedForVerification = true
            });
            return new(
                transactionId,
                previous.Version,
                targetVersion,
                previousImage,
                targetImage,
                "Completed");
        }
        catch (Exception updateError)
        {
            if (!scmCommitted)
            {
                PersistUpdate(store, journalPath, record, "AbortedBeforeCommit", updateError.Message);
                CleanupStagedProtectionPackage(targetFolder);
                CleanupUncommittedStaging(
                    targetDirectoryCreated,
                    targetFolder,
                    targetImage,
                    targetConfig,
                    targetInstallRecord);
                throw new IOException("Update failed before the SCM commit point; the previous installation remains selected. " + updateError.Message, updateError);
            }

            try
            {
                PersistUpdate(store, journalPath, record, "RollbackStarting", updateError.Message);
                RollBackCommittedServiceUpdate(service, store, journalPath, record, previousImage);
                throw new IOException(
                    "Update failed after the SCM commit point and was rolled back to the previous verified image. " +
                    updateError.Message,
                    updateError);
            }
            catch (IOException rollbackReport) when (rollbackReport.InnerException == updateError)
            {
                throw;
            }
            catch (Exception rollbackError)
            {
                PersistUpdate(
                    store,
                    journalPath,
                    record,
                    "RollbackFailed",
                    updateError.Message + " | rollback: " + rollbackError.Message);
                store.Audit(new
                {
                    Utc = DateTime.UtcNow,
                    Event = "ServiceUpdateRollbackFailed",
                    Transaction = transactionId,
                    PreviousImage = previousImage,
                    TargetImage = targetImage,
                    UpdateError = updateError.Message,
                    RollbackError = rollbackError.Message
                });
                throw new IOException(
                    "Update failed after SCM commit and deterministic rollback could not be proved. " +
                    "Do not retry blindly; inspect the durable ServiceUpdates transaction and current SCM ImagePath. " +
                    rollbackError.Message,
                    rollbackError);
            }
        }
    }

    private static void RollBackCommittedServiceUpdate(
        Scm.Handle service,
        SecureStore store,
        string journalPath,
        ServiceUpdateRecord record,
        string previousImage)
    {
        var state = Status(service);
        if (state.CurrentState == 2)
            WaitFor(service, 4);
        state = Status(service);
        if (state.CurrentState != 1)
        {
            if (state.CurrentState != 3 && !Scm.ControlService(service, 1, out _))
                throw Error();
            WaitFor(service, 1);
        }

        using (var rollbackGate = StateMaintenanceGate.Acquire())
        {
            ChangeServiceImage(service, previousImage);
            var registration = Configuration(service);
            if (!WinPaths.Equal(registration.ImagePath, previousImage))
                throw new IOException("SCM rollback did not restore the previous image path.");
            using var previousLease = VerifyInstalledImage(previousImage);
            PersistUpdate(store, journalPath, record, "RollbackScmCommitted", null);
        }

        if (!Scm.StartServiceW(service, 0, IntPtr.Zero)) throw Error();
        WaitFor(service, 4);
        Thread.Sleep(2000);
        if (Status(service).CurrentState != 4)
            throw new IOException("Previous verified service image did not remain Running after rollback.");
        if (!Scm.ControlService(service, 1, out _)) throw Error();
        WaitFor(service, 1);

        PersistUpdate(store, journalPath, record, "RolledBack", null);
        store.Audit(new
        {
            Utc = DateTime.UtcNow,
            Event = "ServiceUpdateRolledBack",
            Transaction = record.TransactionId,
            RestoredImage = previousImage,
            RestoredVersion = record.PreviousVersion
        });
    }

    private static FileStream OpenVerifiedUpdateSource(
        string packageRoot,
        string expectedServiceHash,
        out string targetVersion,
        out string targetHash)
    {
        if (!IsSha256Hex(expectedServiceHash))
            throw new IOException("Expected service SHA-256 is invalid.");
        var root = Path.GetFullPath(packageRoot).TrimEnd(Path.DirectorySeparatorChar);
        FileSafety.NoReparse(root);
        var source = Path.Combine(root, "RansomGuard.Service.exe");
        FileSafety.NoReparse(source);
        var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (input.Length is < 4096 or > 256L * 1024 * 1024)
                throw new IOException("Update service executable size rejected.");
            if (!WinPaths.Equal(source, Native.FinalFilePath(input.SafeFileHandle)))
                throw new IOException("Update source path was redirected.");

            targetVersion = typeof(ServiceAdministration).Assembly.GetName().Version?.ToString()
                ?? throw new IOException("Target package version missing.");
            if (!string.Equals(
                    FileVersionInfo.GetVersionInfo(source).FileVersion,
                    targetVersion,
                    StringComparison.Ordinal))
                throw new IOException("Update UI/management and service versions differ. Use one complete release.");

            targetHash = Convert.ToHexString(SHA256.HashData(input));
            input.Position = 0;
            if (!DecisionPolicy.HashEqual(targetHash, expectedServiceHash))
                throw new IOException("Update service bytes do not match the SHA-256 embedded in this UI.");
            return input;
        }
        catch
        {
            input.Dispose();
            throw;
        }
    }

    private static InstallRecord ReadInstallRecord(string image)
    {
        var folder = Path.GetDirectoryName(image) ?? throw new IOException("Installed image folder missing.");
        var path = Path.Combine(folder, "install.json");
        VerifyInstallAcl(path, false);
        FileSafety.NoReparse(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is <= 0 or > 4096) throw new IOException("Install record size invalid.");
        var record = JsonSerializer.Deserialize<InstallRecord>(file)
            ?? throw new IOException("Install record unavailable.");
        if (record.Schema != 1 || !IsSha256Hex(record.ImageSha256) || string.IsNullOrWhiteSpace(record.Version))
            throw new IOException("Install record invalid.");
        return record;
    }

    private static void VerifyInstalledVersion(string image, InstallRecord record)
    {
        if (!string.Equals(
                FileVersionInfo.GetVersionInfo(image).FileVersion,
                record.Version,
                StringComparison.Ordinal))
            throw new IOException("Installed image version does not match its durable install record.");
    }

    private static void RequireForwardVersion(string currentText, string targetText)
    {
        if (!ServiceUpdatePolicy.IsForwardVersion(currentText, targetText))
            throw new IOException(
                $"Update replay/downgrade rejected. Installed={currentText}; target={targetText}. " +
                "Use recovery/rollback evidence, not the updater, to restore an older image.");
    }

    private static void EnsureNoIncompleteUpdate(SecureStore store)
    {
        var root = Path.Combine(store.Root, ServiceUpdateDirectoryName);
        if (!Directory.Exists(root)) return;
        FileSafety.NoReparse(root);
        foreach (var path in Directory.EnumerateFiles(root, "*.json", SearchOption.TopDirectoryOnly))
        {
            FileSafety.NoReparse(path);
            if (new FileInfo(path).Length is <= 0 or > 16384)
                throw new IOException("Update transaction record size invalid: " + path);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            ServiceUpdateRecord record;
            try
            {
                record = JsonSerializer.Deserialize<ServiceUpdateRecord>(file)
                    ?? throw new JsonException("Update transaction JSON deserialized to null.");
            }
            catch (JsonException ex)
            {
                throw new IOException("Update transaction record invalid: " + path, ex);
            }
            if (record.Schema != 1)
                throw new IOException("Unsupported update transaction schema: " + path);
            if (record.Phase is not ("Completed" or "RolledBack" or "AbortedBeforeCommit"))
                throw new IOException(
                    "An incomplete update transaction requires explicit recovery before another update: " +
                    record.TransactionId + " phase=" + record.Phase);
        }
    }

    private static ServiceUpdateRecord PersistUpdate(
        SecureStore store,
        string journalPath,
        ServiceUpdateRecord current,
        string phase,
        string? error)
    {
        var next = current with { Phase = phase, UpdatedUtc = DateTime.UtcNow, Error = error };
        store.WriteJson(journalPath, next);
        return next;
    }

    private static void CopyNewAndFlush(Stream source, string destination)
    {
        FileSafety.NoReparse(destination);
        source.Position = 0;
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        source.CopyTo(output);
        output.Flush(true);
    }

    private static void CleanupUncommittedStaging(
        bool targetDirectoryCreated,
        string targetFolder,
        params string[] knownFiles)
    {
        if (!targetDirectoryCreated) return;
        foreach (var file in knownFiles)
        {
            try
            {
                if (!File.Exists(file)) continue;
                FileSafety.NoReparse(file);
                File.Delete(file);
            }
            catch (IOException)
            {
            }
        }
        try
        {
            FileSafety.NoReparse(targetFolder);
            Directory.Delete(targetFolder, false);
        }
        catch (IOException)
        {
        }
    }

    private static void ChangeServiceImage(Scm.Handle service, string image)
    {
        FileSafety.NoReparse(image);
        if (!UpdateScm.ChangeServiceConfigW(
                service,
                ServiceNoChange,
                ServiceNoChange,
                ServiceNoChange,
                "\"" + image + "\"",
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null))
            throw Error();
    }

    private static class UpdateScm
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ChangeServiceConfigW(
            Scm.Handle service,
            uint serviceType,
            uint startType,
            uint errorControl,
            string? binaryPath,
            string? loadOrderGroup,
            IntPtr tagId,
            string? dependencies,
            string? serviceStartName,
            string? password,
            string? displayName);
    }
}
