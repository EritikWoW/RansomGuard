using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;
using RansomGuard.Service;

namespace RansomGuard.Management;

public sealed record StateAce(string Type, string Sid, string Rights, bool Inherited);
public sealed record StateStoreReport(string Path, bool Exists, bool PrivateAcl, string OwnerSid,
    bool InheritanceProtected, string Revision, StateAce[] Entries, bool LegacyUntrusted = false);
public sealed record StateRecoveryResult(string Root, string? Archive, bool FreshPrivateStore);

// A fixed-path administrative recovery operation. Never follows, imports or deletes archived content.
public static class StateStoreAdministration
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuardV03");
    private static readonly string[] PrivateSids = ["S-1-5-18", "S-1-5-32-544"];
    private const string TrustedMarkerName = ".ransomguard-state-v1";
    public static StateStoreReport Inspect()
    {
        RuleAdministration.DemandAdministrator();
        FileSafety.NoReparse(Root);
        if (!Directory.Exists(Root))
        {
            if (File.Exists(Root)) throw new IOException("State root is not a directory.");
            return new(Root, false, false, "", false, "Missing", []);
        }
        using var handle = OpenRoot(false);
        return Read(handle);
    }
    public static StateRecoveryResult Recover(string expectedRevision, string confirmation)
    {
        RuleAdministration.DemandAdministrator();
        AdminContract.CheckConfirmation("state-repair", confirmation);
        using var gate = StateMaintenanceGate.Acquire();
        using var instance = new Mutex(false, @"Global\RansomGuardV03-Instance");
        bool owns;
        try { owns = instance.WaitOne(0); } catch (AbandonedMutexException) { owns = true; }
        if (!owns) throw new IOException("StateBusy: another RansomGuard instance is active.");
        string? archive = null;
        bool changed = false;
        try
        {
            EnsureIdle();
            var preview = Inspect();
            if (preview.Revision != expectedRevision) throw new IOException("StateChanged: re-inspect before recovery.");
            if (preview.PrivateAcl && !preview.LegacyUntrusted) throw new InvalidOperationException("State permissions are already private; no recovery required.");
            if (preview.Exists)
            {
                // First pin the exact directory while delete sharing is denied. The old root is already
                // untrusted, so before any compatibility rename we remove non-admin access on the ROOT
                // directory only. Child ACLs/content are not imported, rewritten or deleted.
                string identity;
                using (var guard = OpenRoot(rename: true, shareDelete: false, allowDaclRepair: true))
                {
                    var current = Read(guard);
                    if (current.Revision != expectedRevision) throw new IOException("StateChanged: directory identity/ACL changed.");
                    if (!PrivateSids.Contains(current.OwnerSid, StringComparer.Ordinal))
                        throw new UnauthorizedAccessException("State root owner is not Administrators or SYSTEM. Manual review is required.");
                    identity = FileIdentity(guard);
                    HardenLegacyRootAcl(guard);
                    changed = true; // Root ACL changed even if archival later fails.
                    var hardened = Read(guard);
                    if (!hardened.PrivateAcl) throw new UnauthorizedAccessException("State root could not be restricted to Administrators/SYSTEM before archival.");
                }

                EnsureIdle();
                archive = Root + ".UNTRUSTED." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture) + "." + Guid.NewGuid().ToString("N");

                // Re-open after the ACL transition. Delete sharing is now allowed only so Windows can
                // perform a path-based compatibility move if FileRenameInfo is rejected on this host.
                // The root ACL is private at this point; the exact file identity is re-checked.
                using (var handle = OpenRoot(rename: true, shareDelete: true, allowDaclRepair: false))
                {
                    if (!string.Equals(FileIdentity(handle), identity, StringComparison.Ordinal))
                        throw new IOException("StateChanged: directory identity changed after ACL repair.");
                    var current = Read(handle);
                    if (!current.PrivateAcl) throw new UnauthorizedAccessException("State root permissions changed before archival.");
                    RenameDirectoryWithCompatibilityFallback(handle, archive);
                    if (!WinPaths.Equal(Native.FinalFilePath(handle), archive))
                        throw new IOException("StateChanged: archived directory final path was not confirmed.");
                }
                changed = true;
                // Existing child ACLs/open handles are deliberately not rewritten. The archive remains
                // untrusted evidence, but its root is no longer directly writable by the former user ACE.
            }
            if (File.Exists(Root) || Directory.Exists(Root)) throw new IOException("State root appeared concurrently. Nothing will be overwritten.");
            var store = new SecureStore(); changed = true;
            var fresh = Inspect();
            if (!fresh.PrivateAcl) throw new UnauthorizedAccessException("Fresh state root did not pass private ACL verification.");
            store.Audit(new { Utc=DateTime.UtcNow, Event="StateStoreRecovery", Archive=archive,
                ArchivedContentImported=false, ArchivedAclChanged=true, Actor=Actor() });
            return new(Root, archive, true);
        }
        catch (Exception ex) when (changed)
        {
            throw new IOException("StateRecoveryPartial: old archive=" + (archive ?? "none") +
                "; new root=" + Root + ". No files were deleted and no automatic rollback was attempted. Re-inspect. " + ex.Message, ex);
        }
        finally { instance.ReleaseMutex(); }
    }
    private static string Actor() { using var who = WindowsIdentity.GetCurrent(); return who.User?.Value ?? "Unknown"; }
    private static void EnsureIdle()
    {
        var status = ServiceAdministration.Query();
        if (!status.QuerySucceeded) throw new IOException("StateBusy: cannot confirm service state. " + status.Error);
        if (status.Installed && status.State != "Stopped") throw new IOException("StateBusy: stop the service first.");
        var processes = Process.GetProcessesByName("RansomGuard.Service");
        try { if (processes.Length != 0) throw new IOException("StateBusy: stop audit consoles first."); }
        finally { foreach (var process in processes) process.Dispose(); }
    }
    private static SafeFileHandle OpenRoot(bool rename, bool shareDelete = false, bool allowDaclRepair = false)
    {
        FileSafety.NoReparse(Root);
        uint access = 0x20080u; // READ_CONTROL | FILE_READ_ATTRIBUTES
        if (rename) access |= 0x10000u; // DELETE
        if (allowDaclRepair) access |= 0x40000u; // WRITE_DAC
        uint share = 0x1u | 0x2u | (shareDelete ? 0x4u : 0u);
        var h = StateNative.CreateFileW(Root, access, share, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (h.IsInvalid) { int error = Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(error); }
        try
        {
            if (!StateNative.GetFileInformationByHandle(h, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0) throw new IOException("State root is redirected or not a directory.");
            if (!WinPaths.Equal(Native.FinalFilePath(h), Root)) throw new IOException("State root final path differs from expected path.");
            return h;
        }
        catch { h.Dispose(); throw; }
    }
    private static StateStoreReport Read(SafeFileHandle h)
    {
        if (!StateNative.GetFileInformationByHandle(h, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        uint error = StateNative.GetSecurityInfo(h, 1, 5, out _, out _, out _, out _, out var sd);
        if (error != 0) throw new Win32Exception(unchecked((int)error));
        try
        {
            uint length = StateNative.GetSecurityDescriptorLength(sd);
            if (length is 0 or > 65536) throw new IOException("State ACL size rejected.");
            var bytes = new byte[(int)length]; Marshal.Copy(sd, bytes, 0, bytes.Length);
            var acl = new DirectorySecurity(); acl.SetSecurityDescriptorBinaryForm(bytes);
            string owner = (acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value ?? "Unknown";
            var entries = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Select(a => new StateAce(a.AccessControlType.ToString(), a.IdentityReference.Value, a.FileSystemRights.ToString(), a.IsInherited)).ToArray();
            var raw = new RawSecurityDescriptor(bytes, 0);
            bool trustedMarker = File.Exists(Path.Combine(Root, TrustedMarkerName));
            bool valid = raw.DiscretionaryAcl is not null && acl.AreAccessRulesProtected && PrivateSids.Contains(owner, StringComparer.Ordinal) &&
                entries.Length == 2 && entries.All(a => a.Type == "Allow" && PrivateSids.Contains(a.Sid, StringComparer.Ordinal) && a.Rights == "FullControl") &&
                entries.Select(a => a.Sid).Distinct(StringComparer.Ordinal).Count() == 2;
            string identity = $"{info.VolumeSerial:X8}:{info.FileIndexHigh:X8}:{info.FileIndexLow:X8}:{Convert.ToHexString(bytes)}";
            string revision = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
            return new(Root, true, valid, owner, acl.AreAccessRulesProtected, revision, entries, !trustedMarker);
        }
        finally { StateNative.LocalFree(sd); }
    }
    private static string FileIdentity(SafeFileHandle h)
    {
        if (!StateNative.GetFileInformationByHandle(h, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return $"{info.VolumeSerial:X8}:{info.FileIndexHigh:X8}:{info.FileIndexLow:X8}";
    }
    private static void HardenLegacyRootAcl(SafeFileHandle h)
    {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        acl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        byte[] sd = acl.GetSecurityDescriptorBinaryForm();
        var raw = new RawSecurityDescriptor(sd, 0);
        if (raw.DiscretionaryAcl is null) throw new IOException("Private DACL construction failed.");
        byte[] daclBytes = new byte[raw.DiscretionaryAcl.BinaryLength];
        raw.DiscretionaryAcl.GetBinaryForm(daclBytes, 0);
        IntPtr dacl = Marshal.AllocHGlobal(daclBytes.Length);
        try
        {
            Marshal.Copy(daclBytes, 0, dacl, daclBytes.Length);
            const uint DACL_SECURITY_INFORMATION = 0x00000004u;
            const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000u;
            uint error = StateNative.SetSecurityInfo(h, 1, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (error != 0) throw new Win32Exception(unchecked((int)error));
        }
        finally { Marshal.FreeHGlobal(dacl); }
    }
    private static void RenameDirectoryWithCompatibilityFallback(SafeFileHandle h, string destination)
    {
        try { RenameDirectoryByHandle(h, destination); return; }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 5)
        {
            // Some Windows/filesystem combinations reject FileRenameInfo for this directory even
            // with DELETE granted. The root has already been restricted to SYSTEM/Administrators,
            // the maintenance/instance gates are held, and this handle allows delete sharing.
            if (!StateNative.MoveFileExW(Root, destination, 0x00000008u)) // MOVEFILE_WRITE_THROUGH
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows denied both handle-based and compatible path-based archival of the old RansomGuard state directory.");
        }
    }
    private static void RenameDirectoryByHandle(SafeFileHandle h, string destination)
    {
        byte[] name = Encoding.Unicode.GetBytes(destination);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size, nameOffset = lengthOffset + 4;
        int size = checked(nameOffset + name.Length + 2);
        IntPtr memory = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(new byte[size], 0, memory, size); // ReplaceIfExists=false, RootDirectory=NULL.
            Marshal.WriteInt32(memory, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(memory, nameOffset), name.Length);
            if (!StateNative.SetFileInformationByHandle(h, 3, memory, (uint)size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
}
internal static class StateNative
{
    [StructLayout(LayoutKind.Sequential)] internal struct FileInfo
    {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    internal static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfo info);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFileInformationByHandle(SafeFileHandle h,int type,IntPtr info,uint size);
    [DllImport("advapi32.dll")]
    internal static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    internal static extern uint SetSecurityInfo(SafeFileHandle h,int type,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("advapi32.dll")] internal static extern uint GetSecurityDescriptorLength(IntPtr sd);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileExW(string existing,string destination,uint flags);
}
