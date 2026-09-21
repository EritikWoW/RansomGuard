using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace RansomGuard.Recovery;

// Offline files only. Never attach to processes, execute dump content or overwrite evidence.
public static class SafeInput
{
    public static void NoLinks(string path)
    {
        string p=Path.GetFullPath(path);
        if(OperatingSystem.IsWindows() && (p.StartsWith(@"\\",StringComparison.Ordinal)||p.AsSpan(2).Contains(':')))
            throw new IOException("Network/device/alternate-stream paths are not accepted.");
        for(string? part=p;!string.IsNullOrEmpty(part);part=Path.GetDirectoryName(part))
        {
            FileSystemInfo info=Directory.Exists(part)?new DirectoryInfo(part):new FileInfo(part);
            if(info.LinkTarget is not null || (info.Exists && (info.Attributes&FileAttributes.ReparsePoint)!=0))
                throw new IOException("Symbolic links/reparse points are not accepted.");
        }
    }
    public static FileStream OpenRead(string path,long maxBytes)
    {
        NoLinks(path);
        var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,65536,FileOptions.RandomAccess);
        try
        {
            if(stream.Length<=0 || stream.Length>maxBytes)throw new IOException("Input exceeds its size policy or is empty.");
            if(OperatingSystem.IsWindows())
            {
                if(!GetFileInformationByHandle(stream.SafeFileHandle,out var info)||info.Links!=1||(info.Attributes&0x400)!=0)
                    throw new IOException("Input is linked/reparse or its identity cannot be checked.");
                VerifyFinalPath(stream.SafeFileHandle,path);
            }
            return stream;
        }
        catch{stream.Dispose();throw;}
    }
    public static byte[] Read(string path,int maxBytes)
    { using var s=OpenRead(path,maxBytes);var bytes=new byte[(int)s.Length];s.ReadExactly(bytes);return bytes; }
    public static void WriteNew(string path,ReadOnlySpan<byte> bytes)
    {
        NoLinks(path);
        using var s=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        if(OperatingSystem.IsWindows())VerifyFinalPath(s.SafeFileHandle,path);
        s.Write(bytes);s.Flush(true);
    }
    public static IDisposable CreateOutputDirectory(string path)
    {
        NoLinks(path);
        if(Directory.Exists(path)||File.Exists(path))throw new IOException("Output directory already exists; no overwrite allowed.");
        var parent=Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new IOException("No output parent.");
        if(!Directory.Exists(parent))throw new IOException("Output parent must already exist.");
        if(OperatingSystem.IsWindows())
        {
            if(!CreateDirectoryW(path,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
            var handle=OpenDirectory(path,0x80,1,IntPtr.Zero,3,0x02000000|0x00200000,IntPtr.Zero);
            if(handle.IsInvalid){handle.Dispose();throw new IOException("Cannot pin the output directory.");}
            try
            {
                VerifyFinalPath(handle,path);
                if(!GetFileInformationByHandle(handle,out var info)||(info.Attributes&0x400)!=0)
                    throw new IOException("Output directory identity rejected.");
                return handle;
            }
            catch{handle.Dispose();throw;}
        }
        // Test-only portability; production CLI targets Windows and uses exclusive CreateDirectoryW.
        Directory.CreateDirectory(path);NoLinks(path);return new Noop();
    }
    private sealed class Noop:IDisposable{public void Dispose(){}}
    private static void VerifyFinalPath(SafeFileHandle handle,string requested)
    {
        var name=new StringBuilder(32768);uint length=GetFinalPathNameByHandleW(handle,name,(uint)name.Capacity,0);
        if(length==0||length>=name.Capacity)throw new IOException("Final path unavailable.");
        string actual=name.ToString();if(actual.StartsWith(@"\\?\",StringComparison.Ordinal))actual=actual[4..];
        if(!string.Equals(actual,Path.GetFullPath(requested),StringComparison.OrdinalIgnoreCase))
            throw new IOException("Final path differs from requested path.");
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
     public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfoNative info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder name,uint size,uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateDirectoryW(string path,IntPtr attributes);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle OpenDirectory(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
}
