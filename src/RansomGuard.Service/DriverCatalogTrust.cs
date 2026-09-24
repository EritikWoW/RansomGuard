using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal static class DriverCatalogTrust
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static SignatureEvidence VerifyMember(FileStream member, string memberPath, string catalogPath)
    {
        if (!OperatingSystem.IsWindows())
            return new("Unavailable", null, null, null, "OfflineCacheOnly", "CatalogMember");

        IntPtr catAdmin = IntPtr.Zero;
        IntPtr catalogInfoPtr = IntPtr.Zero;
        IntPtr catalogPathPtr = IntPtr.Zero;
        IntPtr memberTagPtr = IntPtr.Zero;
        IntPtr memberPathPtr = IntPtr.Zero;
        IntPtr hashPtr = IntPtr.Zero;
        WinTrustData trust = default;

        try
        {
            if (!CryptCATAdminAcquireContext2(out catAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0) || catAdmin == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminAcquireContext2 failed.");

            var hash = CalculateHash(catAdmin, member.SafeFileHandle);
            var memberTag = Convert.ToHexString(hash);

            catalogPathPtr = Marshal.StringToCoTaskMemUni(catalogPath);
            memberTagPtr = Marshal.StringToCoTaskMemUni(memberTag);
            memberPathPtr = Marshal.StringToCoTaskMemUni(memberPath);
            hashPtr = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashPtr, hash.Length);

            var catalog = new WinTrustCatalogInfo
            {
                Size = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                CatalogVersion = 0,
                CatalogFilePath = catalogPathPtr,
                MemberTag = memberTagPtr,
                MemberFilePath = memberPathPtr,
                MemberFile = member.SafeFileHandle.DangerousGetHandle(),
                CalculatedFileHash = hashPtr,
                CalculatedFileHashLength = checked((uint)hash.Length),
                CatalogContext = IntPtr.Zero,
                CatAdmin = catAdmin
            };
            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(catalog, catalogInfoPtr, false);

            trust = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UIChoice = 2,
                RevocationChecks = 1,
                UnionChoice = 2,
                Info = catalogInfoPtr,
                StateAction = 1,
                ProviderFlags = 0x1000 | 0x80 | 0x2000
            };

            var action = GenericVerifyV2;
            var result = WinVerifyTrust(new IntPtr(-1), ref action, ref trust);
            var code = unchecked((uint)result);
            return code == 0
                ? new("ValidCatalogMember", "0x00000000", null, null, "OfflineCacheOnly", "CatalogMember")
                : new("CatalogMemberRejected", $"0x{code:X8}", null, null, "OfflineCacheOnly", "CatalogMember");
        }
        catch (Exception ex) when (ex is Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            return new("Unavailable", null, null, null, "OfflineCacheOnly", "CatalogMember");
        }
        finally
        {
            if (trust.Size != 0)
            {
                trust.StateAction = 2;
                try
                {
                    var action = GenericVerifyV2;
                    _ = WinVerifyTrust(new IntPtr(-1), ref action, ref trust);
                }
                catch
                {
                    // Cleanup cannot convert a failed/unknown verification into success.
                }
            }
            if (catalogInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(catalogInfoPtr);
            if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
            if (memberPathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(memberPathPtr);
            if (memberTagPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(memberTagPtr);
            if (catalogPathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(catalogPathPtr);
            if (catAdmin != IntPtr.Zero) _ = CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static byte[] CalculateHash(IntPtr catAdmin, SafeFileHandle file)
    {
        uint bytes = 0;
        if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file.DangerousGetHandle(), ref bytes, null, 0) &&
            Marshal.GetLastWin32Error() != 122)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Catalog hash size query failed.");
        if (bytes is 0 or > 128)
            throw new InvalidDataException("Catalog member hash length is invalid.");

        var hash = new byte[bytes];
        if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file.DangerousGetHandle(), ref bytes, hash, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Catalog member hash calculation failed.");
        if (bytes != hash.Length)
            Array.Resize(ref hash, checked((int)bytes));
        return hash;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint Size;
        public uint CatalogVersion;
        public IntPtr CatalogFilePath;
        public IntPtr MemberTag;
        public IntPtr MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashLength;
        public IntPtr CatalogContext;
        public IntPtr CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr Policy;
        public IntPtr Sip;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Info;
        public uint StateAction;
        public IntPtr State;
        public IntPtr Url;
        public uint ProviderFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catAdmin,
        IntPtr subsystem,
        string hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catAdmin,
        IntPtr file,
        ref uint hashBytes,
        [Out] byte[]? hash,
        uint flags);

    [DllImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);
}
