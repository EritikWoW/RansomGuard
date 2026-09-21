using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal static class Authenticode
{
    // Cache-only revocation checking: never treat offline/unknown as a positive verification.
    // Catalog lookup is not implemented. A catalog-only binary may appear as no embedded signature.
    public static SignatureEvidence Check(FileStream file,string path)
    {
        var info=new WinTrustFileInfo{Size=(uint)Marshal.SizeOf<WinTrustFileInfo>(),FilePath=Marshal.StringToCoTaskMemUni(path),File=file.SafeFileHandle.DangerousGetHandle()};
        var ptr=Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        var data=new WinTrustData{Size=(uint)Marshal.SizeOf<WinTrustData>(),UIChoice=2,RevocationChecks=1,
            UnionChoice=1,Info=ptr,StateAction=1,ProviderFlags=0x1000|0x80|0x2000};
        var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try
        {
            Marshal.StructureToPtr(info,ptr,false);
            var result=WinVerifyTrust(new IntPtr(-1),ref action,ref data);
            var code=unchecked((uint)result);
            var status=code switch {0=>"ValidCached",0x800B0100=>"NoEmbeddedSignatureOrCatalogOnly",
                0x80092013 or 0x800B010E=>"RevocationUnavailable",0x800B010C=>"Revoked",
                0x80096010=>"BadDigest",_=>"NotVerified"};
            string? publisher=null,thumbprint=null;
            if(result==0)TryReadSigner(data.State,out publisher,out thumbprint);
            return new(status,$"0x{code:X8}",publisher,thumbprint);
        }
        catch(Exception ex) when(ex is System.Security.Cryptography.CryptographicException or DllNotFoundException or EntryPointNotFoundException)
        {return new("Unavailable",null,null,null,"OfflineCacheOnly","EmbeddedSignatureOnly");}
        finally
        {
            data.StateAction=2;
            try {WinVerifyTrust(new IntPtr(-1),ref action,ref data);} finally {Marshal.FreeHGlobal(ptr);Marshal.FreeCoTaskMem(info.FilePath);}
        }
    }
    private static void TryReadSigner(IntPtr state,out string? publisher,out string? thumbprint)
    {
        publisher=null;thumbprint=null;
        if(state==IntPtr.Zero)return;
        try
        {
            var provider=WTHelperProvDataFromStateData(state);if(provider==IntPtr.Zero)return;
            var signerPtr=WTHelperGetProvSignerFromChain(provider,0,false,0);if(signerPtr==IntPtr.Zero)return;
            var signer=Marshal.PtrToStructure<ProviderSignerPrefix>(signerPtr);
            if(signer.CertChainCount==0||signer.CertChain==IntPtr.Zero)return;
            var providerCert=Marshal.PtrToStructure<ProviderCertPrefix>(signer.CertChain);
            if(providerCert.CertContext==IntPtr.Zero)return;
            var context=Marshal.PtrToStructure<CertContext>(providerCert.CertContext);
            if(context.Encoded==IntPtr.Zero||context.EncodedLength==0||context.EncodedLength>1024*1024)return;
            var der=new byte[checked((int)context.EncodedLength)];Marshal.Copy(context.Encoded,der,0,der.Length);
            using var cert=X509CertificateLoader.LoadCertificate(der);
            publisher=cert.Subject;thumbprint=cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        }
        catch(System.Security.Cryptography.CryptographicException){ }
    }
    [StructLayout(LayoutKind.Sequential)] private struct WinTrustFileInfo {public uint Size;public IntPtr FilePath,File,KnownSubject;}
    [StructLayout(LayoutKind.Sequential)] private struct WinTrustData
    {public uint Size;public IntPtr Policy,Sip;public uint UIChoice,RevocationChecks,UnionChoice;public IntPtr Info;
     public uint StateAction;public IntPtr State,Url;public uint ProviderFlags,UIContext;public IntPtr SignatureSettings;}
    [StructLayout(LayoutKind.Sequential)] private struct ProviderSignerPrefix
    {public uint Size;public System.Runtime.InteropServices.ComTypes.FILETIME VerifyAsOf;public uint CertChainCount;public IntPtr CertChain;}
    [StructLayout(LayoutKind.Sequential)] private struct ProviderCertPrefix {public uint Size;public IntPtr CertContext;}
    [StructLayout(LayoutKind.Sequential)] private struct CertContext
    {public uint EncodingType;public IntPtr Encoded;public uint EncodedLength;public IntPtr CertInfo,Store;}
    [DllImport("wintrust.dll",ExactSpelling=true)] private static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref WinTrustData data);
    [DllImport("wintrust.dll",ExactSpelling=true)] private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);
    [DllImport("wintrust.dll",ExactSpelling=true)] private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr providerData,uint signer,[MarshalAs(UnmanagedType.Bool)] bool counterSigner,uint counterSignerIndex);
}
