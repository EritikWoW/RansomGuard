using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed record DumpAuthorization(LabIdentity Target,bool FullMemory);
internal sealed record DumpResult(bool Attempted,bool Succeeded,string? Path,string Status);
internal static class DumpHelper
{
    public static async Task<DumpResult> Capture(SecureStore store,string caseDir,LabIdentity identity,bool full,CancellationToken token)
    {
        store.WriteJson(Path.Combine(caseDir,"dump-authorization.json"),new DumpAuthorization(identity,full));
        var psi=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=AppContext.BaseDirectory};
        psi.ArgumentList.Add("--dump-helper");psi.ArgumentList.Add(Path.GetFileName(caseDir));
        var partial=Path.Combine(caseDir,"process.dmp.partial");
        using var p=Process.Start(psi);
        if(p is null)return new(true,false,null,"HelperFailedToStart");
        var timer=Stopwatch.StartNew();
        try
        {
            while(!p.HasExited)
            {
                if(token.IsCancellationRequested||timer.Elapsed.TotalSeconds>12||
                    (File.Exists(partial)&&new FileInfo(partial).Length>128L*1024*1024))
                {
                    p.Kill(); // Only our own freshly launched helper, never the target or a process tree.
                    await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                    return new(true,false,null,"HelperCancelledOrQuotaExceeded");
                }
                await Task.Delay(100,CancellationToken.None);
            }
            if(p.ExitCode!=0||!File.Exists(partial))return new(true,false,null,"HelperExit="+p.ExitCode);
            // Polling bounds are best-effort; postcondition rejects a large completed dump as well.
            if(new FileInfo(partial).Length==0||new FileInfo(partial).Length>128L*1024*1024)return new(true,false,null,"DumpSizeRejected");
            var dest=Path.Combine(caseDir,"process.dmp");File.Move(partial,dest,false);
            return new(true,true,dest,full?"FullMemoryLabOnly":"LimitedLabDump");
        }
        finally
        {
            try{if(!p.HasExited)p.Kill();}catch(InvalidOperationException){}
            if(File.Exists(partial))try{File.Delete(partial);}catch(IOException){}
        }
    }
    public static int Run(string caseName,SecureStore store)
    {
        if(!Regex.IsMatch(caseName,@"\A[0-9]{8}_[0-9]{6}_[0-9a-f]{32}\z"))return 2;
        var dir=Path.Combine(store.Cases,caseName);FileSafety.NoReparse(dir);
        var authorization=Path.Combine(dir,"dump-authorization.json");FileSafety.NoReparse(authorization);
        if(new FileInfo(authorization).Length>16384)return 3;
        var auth=JsonSerializer.Deserialize<DumpAuthorization>(File.ReadAllText(authorization));
        if(auth is null||DateTime.UtcNow>auth.Target.ExpiresUtc)return 4;
        var expected=Path.Combine(AppContext.BaseDirectory,"Simulator","RansomGuard.Simulator.exe");
        if(!WinPaths.Equal(expected,auth.Target.ImagePath))return 5;
        var image=new ImageInspector(store).Inspect(expected,true);
        if(image.Status!="Hashed"||!DecisionPolicy.HashEqual(image.Sha256,auth.Target.Sha256))return 6;
        using var handle=Native.OpenProcess(Native.Query|Native.Synchronize|0x0400|0x0010,false,auth.Target.Process.Pid);
        if(handle.IsInvalid||Native.Identity(handle,auth.Target.Process.Pid)!=auth.Target.Process||
            !WinPaths.Equal(Native.ImagePath(handle),expected)||!Native.IsProcessCritical(handle,out var critical)||critical)return 7;
        var file=Path.Combine(dir,"process.dmp.partial");FileSafety.NoReparse(file);
        using var f=new FileStream(file,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read);
        // Do not collect token/handle data. Full process memory requires the explicit lab-full-dump switch.
        uint flags=0x1000|0x800;if(auth.FullMemory)flags|=0x2;
        if(!MiniDumpWriteDump(handle,(uint)auth.Target.Process.Pid,f.SafeFileHandle,flags,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero))
        {
            var error=Marshal.GetLastWin32Error();
            store.WriteJson(Path.Combine(dir,"dump-helper-result.json"),new{Succeeded=false,HResult=$"0x{unchecked((uint)error):X8}"});
            return 8;
        }
        f.Flush(true);
        store.WriteJson(Path.Combine(dir,"dump-helper-result.json"),new{Succeeded=true,Bytes=f.Length,FullMemory=auth.FullMemory});
        return 0;
    }
    [DllImport("dbghelp.dll",SetLastError=true)] private static extern bool MiniDumpWriteDump(ProcessHandle process,uint pid,SafeFileHandle file,uint type,IntPtr exception,IntPtr streams,IntPtr callbacks);
}
