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
internal sealed record ProcessInfo(
    ProcessKey Key,
    string Name,
    string? Path,
    DateTime CheckedUtc,
    bool ExactIdentity,
    ulong EtwUniqueProcessKey,
    DateTime? EtwProcessStartUtc);

internal sealed class ProcessCatalog
{
    private sealed class EtwLifetime
    {
        public required int Pid { get; init; }
        public required ulong UniqueProcessKey { get; init; }
        public required string Name { get; set; }
        public required DateTime StartUtc { get; init; }
        public DateTime? StopUtc { get; set; }
        public ProcessKey? ExactKey { get; set; }
        public string? ExactPath { get; set; }
        public DateTime LastTouchedUtc { get; set; }
    }
    private sealed record EtwLifetimeSnapshot(
        int Pid,
        ulong UniqueProcessKey,
        string Name,
        DateTime StartUtc,
        DateTime? StopUtc,
        ProcessKey? ExactKey,
        string? ExactPath);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int,ProcessInfo> _cache=new();
    private readonly object _lifecycleGate=new();
    private readonly Dictionary<int,List<EtwLifetime>> _lifetimes=new();
    private long _lifecycleOperations;

    public void ObserveStart(int pid,ulong uniqueProcessKey,string? imageFileName,DateTime startUtc)
    {
        if(pid<=4)return;
        _cache.TryRemove(pid,out _);
        lock(_lifecycleGate)
        {
            var now=DateTime.UtcNow;
            if(!_lifetimes.TryGetValue(pid,out var list))_lifetimes[pid]=list=new();
            list.Add(new EtwLifetime{
                Pid=pid,
                UniqueProcessKey=uniqueProcessKey,
                Name=string.IsNullOrWhiteSpace(imageFileName)?$"pid-{pid}":Path.GetFileName(imageFileName),
                StartUtc=startUtc,
                LastTouchedUtc=now
            });
            TrimLifetimes(list,now);
            MaybeSweepLifetimes(now);
        }
    }

    public void ObserveStop(int pid,ulong uniqueProcessKey,DateTime stopUtc)
    {
        if(pid<=4)return;
        lock(_lifecycleGate)
        {
            var now=DateTime.UtcNow;
            if(!_lifetimes.TryGetValue(pid,out var list))
            {
                MaybeSweepLifetimes(now);
                return;
            }
            EtwLifetime? lifetime=null;
            if(uniqueProcessKey!=0)
                lifetime=list.LastOrDefault(x=>x.UniqueProcessKey==uniqueProcessKey && x.StopUtc is null);
            lifetime??=list.LastOrDefault(x=>x.StopUtc is null);
            if(lifetime is not null)
            {
                lifetime.StopUtc=stopUtc;
                lifetime.LastTouchedUtc=now;
            }
            TrimLifetimes(list,now);
            if(list.Count==0)_lifetimes.Remove(pid);
            MaybeSweepLifetimes(now);
        }
        // Do not discard a recently resolved exact identity here. File-I/O callbacks can
        // already be queued when ProcessStop is observed. A later ProcessStart for a reused
        // PID clears the live cache before that new process can be attributed.
    }

    public void Invalidate(int pid)=>_cache.TryRemove(pid,out _);

    public ProcessInfo? Get(int pid,DateTime eventUtc)
    {
        var now=DateTime.UtcNow;
        if(_cache.TryGetValue(pid,out var old) && (now-old.CheckedUtc).TotalSeconds<2)
        {
            if(old.Key.CreationFileTimeUtc>0 && eventUtc.ToFileTimeUtc()>=old.Key.CreationFileTimeUtc)
                return old;
        }

        try
        {
            using var h=Native.OpenProcess(Native.Query|Native.Synchronize,false,pid);
            var key=Native.Identity(h,pid);
            if(key is not null && eventUtc.ToFileTimeUtc()>=key.Value.CreationFileTimeUtc)
            {
                var path=Native.ImagePath(h);
                var lifecycle=FindLifetime(pid,eventUtc);
                var p=new ProcessInfo(
                    key.Value,
                    path is null?$"pid-{pid}":Path.GetFileName(path),
                    path,
                    now,
                    ExactIdentity:true,
                    lifecycle?.UniqueProcessKey??0,
                    lifecycle?.StartUtc);
                RememberExact(lifecycle,key.Value,path,now);
                if(_cache.Count>1024)
                    foreach(var entry in _cache.Where(x=>(now-x.Value.CheckedUtc).TotalSeconds>10).Take(512))
                        Invalidate(entry.Key);
                if(_cache.Count<2048)_cache[pid]=p;
                return p;
            }
        }
        catch(System.ComponentModel.Win32Exception)
        {
            // The process may have exited before delayed real-time ETW file I/O was consumed.
            // Fall through to the ETW lifecycle tombstone; it is evidence-only and never an
            // exact actuation identity.
        }

        var historical=FindLifetime(pid,eventUtc);
        if(historical is null)return null;
        if(historical.ExactKey is ProcessKey exact)
            return new(exact,historical.Name,historical.ExactPath,now,true,historical.UniqueProcessKey,historical.StartUtc);

        return new(
            new ProcessKey(pid,0),
            historical.Name,
            null,
            now,
            ExactIdentity:false,
            historical.UniqueProcessKey,
            historical.StartUtc);
    }

    private EtwLifetimeSnapshot? FindLifetime(int pid,DateTime eventUtc)
    {
        lock(_lifecycleGate)
        {
            if(!_lifetimes.TryGetValue(pid,out var list))return null;
            var now=DateTime.UtcNow;
            TrimLifetimes(list,now);
            var lifetime=list
                .Where(x=>x.StartUtc<=eventUtc && (x.StopUtc is null || eventUtc<=x.StopUtc.Value))
                .OrderByDescending(x=>x.StartUtc)
                .FirstOrDefault();
            if(lifetime is null)return null;
            lifetime.LastTouchedUtc=now;
            return new(
                lifetime.Pid,
                lifetime.UniqueProcessKey,
                lifetime.Name,
                lifetime.StartUtc,
                lifetime.StopUtc,
                lifetime.ExactKey,
                lifetime.ExactPath);
        }
    }

    private void RememberExact(EtwLifetimeSnapshot? snapshot,ProcessKey key,string? path,DateTime now)
    {
        if(snapshot is null)return;
        lock(_lifecycleGate)
        {
            if(!_lifetimes.TryGetValue(snapshot.Pid,out var list))return;
            var lifetime=list.LastOrDefault(x=>
                x.UniqueProcessKey==snapshot.UniqueProcessKey &&
                x.StartUtc==snapshot.StartUtc);
            if(lifetime is null)return;
            lifetime.ExactKey=key;
            lifetime.ExactPath=path;
            lifetime.LastTouchedUtc=now;
        }
    }

    private void MaybeSweepLifetimes(DateTime now)
    {
        _lifecycleOperations++;
        if((_lifecycleOperations & 0xFF)!=0)return;
        foreach(var pid in _lifetimes.Keys.ToArray())
        {
            var list=_lifetimes[pid];
            TrimLifetimes(list,now);
            if(list.Count==0)_lifetimes.Remove(pid);
        }
    }

    private static void TrimLifetimes(List<EtwLifetime> list,DateTime now)
    {
        list.RemoveAll(x=>x.StopUtc is DateTime stop && now-stop>TimeSpan.FromSeconds(30));
        if(list.Count>16)list.RemoveRange(0,list.Count-16);
    }
}
