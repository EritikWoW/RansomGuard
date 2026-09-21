using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
namespace RansomGuard.Service;
internal sealed class ProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public ProcessHandle():base(true) { }
    protected override bool ReleaseHandle()=>Native.CloseHandle(handle);
}
internal static class Native
{
    public const uint Query=0x1000, Synchronize=0x100000;
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern ProcessHandle OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetProcessTimes(ProcessHandle p,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern bool QueryFullProcessImageName(ProcessHandle h,int flags,StringBuilder path,ref int len);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool IsProcessCritical(ProcessHandle p,[MarshalAs(UnmanagedType.Bool)] out bool critical);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint WaitForSingleObject(ProcessHandle h,uint timeout);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern uint QueryDosDevice(string device,StringBuilder target,int max);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint len,uint flags);
    public static ProcessKey? Identity(ProcessHandle h,int pid)
        =>!h.IsInvalid && WaitForSingleObject(h,0)==258 && GetProcessTimes(h,out var t,out _,out _,out _)
            ?new ProcessKey(pid,t):null;
    public static string? ImagePath(ProcessHandle h)
    {
        var b=new StringBuilder(32768);var n=b.Capacity;
        return QueryFullProcessImageName(h,0,b,ref n)?WinPaths.Normalize(b.ToString()):null;
    }
    public static string FinalFilePath(SafeFileHandle h)
    {
        var b=new StringBuilder(32768);var n=GetFinalPathNameByHandle(h,b,(uint)b.Capacity,0);
        if(n==0 || n>=b.Capacity) throw new IOException("Cannot resolve final opened-file path.");
        return WinPaths.Normalize(b.ToString())??throw new IOException("Unsupported file namespace.");
    }
}
