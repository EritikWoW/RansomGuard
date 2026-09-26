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
internal sealed class ThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public ThreadHandle():base(true) { }
    protected override bool ReleaseHandle()=>Native.CloseHandle(handle);
}
internal sealed class SnapshotHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SnapshotHandle():base(true) { }
    protected override bool ReleaseHandle()=>Native.CloseHandle(handle);
}
[StructLayout(LayoutKind.Sequential)]
internal struct ThreadEntry32
{
    internal uint Size;
    internal uint Usage;
    internal uint ThreadId;
    internal uint OwnerProcessId;
    internal int BasePriority;
    internal int DeltaPriority;
    internal uint Flags;
}
internal static class Native
{
    public const uint Query=0x1000, Synchronize=0x100000, SuspendResume=0x0800;
    public const uint ThreadSuspendResume=0x0002, ThreadQueryLimitedInformation=0x0800, SnapThread=0x00000004;
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern ProcessHandle OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern ThreadHandle OpenThread(uint rights,bool inherit,uint threadId);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern SnapshotHandle CreateToolhelp32Snapshot(uint flags,uint processId);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool Thread32First(SnapshotHandle snapshot,ref ThreadEntry32 entry);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool Thread32Next(SnapshotHandle snapshot,ref ThreadEntry32 entry);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint GetProcessIdOfThread(ThreadHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetThreadTimes(ThreadHandle thread,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint SuspendThread(ThreadHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint ResumeThread(ThreadHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetProcessTimes(ProcessHandle p,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern bool QueryFullProcessImageName(ProcessHandle h,int flags,StringBuilder path,ref int len);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool IsProcessCritical(ProcessHandle p,[MarshalAs(UnmanagedType.Bool)] out bool critical);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint WaitForSingleObject(ProcessHandle h,uint timeout);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern uint QueryDosDevice(string device,StringBuilder target,int max);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint len,uint flags);
    [DllImport("ntdll.dll")] internal static extern int NtSuspendProcess(ProcessHandle p);
    [DllImport("ntdll.dll")] internal static extern int NtResumeProcess(ProcessHandle p);
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
internal sealed record PathResolution(string? Path,string Category);
internal sealed class DevicePaths
{
    private readonly (string Device,string Drive)[] _mapping;
    public DevicePaths()
    {
        var m=new List<(string,string)>();
        foreach(var drive in DriveInfo.GetDrives())
        {
            var b=new StringBuilder(32768);var name=drive.Name[..2];
            if(Native.QueryDosDevice(name,b,b.Capacity)!=0) m.Add((b.ToString().Split('\0')[0],name));
        }
        _mapping=m.OrderByDescending(x=>x.Item1.Length).ToArray();
    }
    public string? Resolve(string? raw)=>ResolveDetailed(raw).Path;
    public PathResolution ResolveDetailed(string? raw)
    {
        if(string.IsNullOrWhiteSpace(raw))return new(null,"unresolved-empty");
        var category=raw.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase)||raw.StartsWith(@"\\",StringComparison.Ordinal)
            ?"unresolved-network"
            :raw.StartsWith(@"\\?\",StringComparison.Ordinal)?"resolved-extended-dos"
            :raw.StartsWith(@"\??\",StringComparison.Ordinal)?"resolved-nt-dos"
            :raw.StartsWith(@"\Device\Mup\",StringComparison.OrdinalIgnoreCase)?"unresolved-device-network"
            :raw.StartsWith(@"\Device\",StringComparison.OrdinalIgnoreCase)?"device"
            :"resolved-dos";
        var normalized=WinPaths.Normalize(raw);
        if(normalized is not null)return new(normalized,category.StartsWith("resolved-",StringComparison.Ordinal)?category:"resolved-dos");
        foreach(var (device,drive) in _mapping)
            if(raw.StartsWith(device+"\\",StringComparison.OrdinalIgnoreCase))
            {
                var mapped=WinPaths.Normalize(drive+raw[device.Length..]);
                if(mapped is not null)return new(mapped,"resolved-device-mapped");
            }
        if(category=="device")category="unresolved-device-unmapped";
        else if(!category.StartsWith("unresolved-",StringComparison.Ordinal))category="unresolved-other";
        return new(null,category); // Never guess a drive, UNC location, or match a canary basename.
    }
}
internal sealed record ProcessInfo(ProcessKey Key,string Name,string? Path,DateTime CheckedUtc);
internal sealed class ProcessCatalog
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int,ProcessInfo> _cache=new();
    public void Invalidate(int pid)=>_cache.TryRemove(pid,out _);
    public ProcessInfo? Get(int pid,DateTime eventUtc)
    {
        var now=DateTime.UtcNow;
        if(_cache.TryGetValue(pid,out var old) && (now-old.CheckedUtc).TotalSeconds<2)
            return eventUtc.ToFileTimeUtc()>=old.Key.CreationFileTimeUtc?old:null;
        using var h=Native.OpenProcess(Native.Query|Native.Synchronize,false,pid);
        var key=Native.Identity(h,pid);
        if(key is null || eventUtc.ToFileTimeUtc()<key.Value.CreationFileTimeUtc) {Invalidate(pid);return null;}
        var path=Native.ImagePath(h);
        var p=new ProcessInfo(key.Value,path is null?$"pid-{pid}":Path.GetFileName(path),path,now);
        if(_cache.Count>1024) foreach(var entry in _cache.Where(x=>(now-x.Value.CheckedUtc).TotalSeconds>10).Take(512)) Invalidate(entry.Key);
        if(_cache.Count<2048) _cache[pid]=p;
        return p;
    }
}
