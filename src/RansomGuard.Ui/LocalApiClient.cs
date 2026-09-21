using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;
namespace RansomGuard.Ui;

internal sealed class LocalApiClient
{
    public async Task<T> RequestAsync<T>(string command,int limit=25,CancellationToken token=default)
    {
        if(!LocalApiContract.IsKnownCommand(command)||command==LocalApiContract.SubscribeCommand)
            throw new ArgumentOutOfRangeException(nameof(command));
        using var pipe=await Connect(token);
        await PipeFraming.WriteAsync(pipe,new ApiRequest(2,command,LocalApiContract.ClampIncidentLimit(limit)),token);
        var response=await PipeFraming.ReadAsync<ApiResponse<T>>(pipe,token);
        if(response.Protocol!=2||!response.Ok||response.Data is null)throw new IOException("Invalid API response.");
        return response.Data;
    }
    public async Task SubscribeAsync(Func<LiveFrame,Task> onFrame,CancellationToken token)
    {
        using var pipe=await Connect(token);
        await PipeFraming.WriteAsync(pipe,new ApiRequest(2,LocalApiContract.SubscribeCommand,50),token);
        long sequence=0;string? instance=null;
        while(!token.IsCancellationRequested)
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(7));
            var frame=await PipeFraming.ReadAsync<LiveFrame>(pipe,deadline.Token);
            if(frame.Protocol!=2||frame.Sequence!=sequence+1||string.IsNullOrWhiteSpace(frame.InstanceId))
                throw new IOException("Live sequence/protocol rejected; reconnect required.");
            if(instance is not null && instance!=frame.InstanceId)throw new IOException("Service instance changed.");
            if(sequence==0&&(frame.Kind!="snapshot"||frame.Diagnostics is null||frame.Incidents is null))
                throw new IOException("Complete initial snapshot required.");
            if(frame.Status is null||frame.Status.Product!="RansomGuard"||frame.Status.Minifilter is null)
                throw new IOException("Invalid live status.");
            if(frame.Kind is not ("snapshot" or "update" or "heartbeat") ||
               frame.Incidents is { Length: > 50 }||frame.Status.MonitoredRoots is { Length: > 100 })
                throw new IOException("Snapshot exceeds UI bounds.");
            if(frame.Incidents is not null && frame.Incidents.Any(x=>x is null || x.Reasons is null ||
                x.Reasons.Length>8 || x.CaseId is null || x.ProcessName is null))
                throw new IOException("Malformed incident summary.");
            if(frame.Diagnostics is { } d && (d.Telemetry is null || d.Notes is null || d.Notes.Length>32))
                throw new IOException("Malformed diagnostics snapshot.");
            sequence=frame.Sequence;instance=frame.InstanceId;
            await onFrame(frame);
        }
    }
    private static async Task<NamedPipeClientStream> Connect(CancellationToken token)
    {
        var pipe=await OpenTransport(token);
        try
        {
            // Read-only identity check; no process control and no elevation.
            if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out uint pid))throw new IOException("Cannot identify local server.");
            string pairedHash=Administration.PackageIdentity.ServiceSha256();

            // Installed service path: compare the pipe owner PID with the fixed SCM service
            // and verify its protected on-disk image. This deliberately avoids OpenProcess
            // against the LocalSystem service, which a standard desktop user may be denied.
            if(RansomGuard.Management.ServiceAdministration.MatchesInstalledPeer(pid,pairedHash)) return pipe;

            // Portable audit-console path: same-user process identity can still be checked
            // directly and must be the exact sibling image from this published package.
            using var process=OpenForImageQuery(0x1000,false,pid);
            if(process.IsInvalid)throw new IOException("The pipe exists, but its server is not the verified installed RansomGuard service and its process image cannot be queried.");
            var image=new StringBuilder(32768);uint length=(uint)image.Capacity;
            if(!QueryFullProcessImageNameW(process,0,image,ref length))throw new IOException("Server image unavailable.");
            string actual=image.ToString();
            string uiRoot=AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
            string parent=Path.GetDirectoryName(uiRoot) ?? throw new IOException("UI package layout invalid.");
            string expected=Path.GetFullPath(Path.Combine(parent,"RansomGuard.Service.exe"));
            bool siblingMatch=string.Equals(Path.GetFullPath(actual),expected,StringComparison.OrdinalIgnoreCase) &&
                RansomGuard.Management.ServiceAdministration.MatchesPackageImage(actual,pairedHash);
            if(!siblingMatch)
                throw new IOException("The pipe server is not the exact installed service or sibling audit engine paired with this UI build.");
            return pipe;
        }
        catch{pipe.Dispose();throw;}
    }
    private static async Task<NamedPipeClientStream> OpenTransport(CancellationToken token)
    {
        long deadline=Environment.TickCount64+2000;
        while(true)
        {
            token.ThrowIfCancellationRequested();
            // Explicit pipe data rights, NOT GENERIC_WRITE (which includes CreateNewInstance).
            // SECURITY_SQOS_PRESENT + SECURITY_IDENTIFICATION: server cannot impersonate the UI token.
            var handle=OpenPipe($@"\\.\pipe\{LocalApiContract.PipeName}",0x00120083,0,IntPtr.Zero,3,0x40110000,IntPtr.Zero);
            if(!handle.IsInvalid)
            {
                try{return new NamedPipeClientStream(PipeDirection.InOut,true,true,handle);}
                catch{handle.Dispose();throw;}
            }
            int error=Marshal.GetLastWin32Error();handle.Dispose();
            if(error is not(2 or 231))throw new System.ComponentModel.Win32Exception(error);
            if(Environment.TickCount64>=deadline)throw new TimeoutException("Live pipe unavailable or all connections busy.");
            await Task.Delay(80,token);
        }
    }
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafePipeHandle OpenPipe(string name,uint access,uint share,IntPtr attributes,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",EntryPoint="OpenProcess",SetLastError=true)]
    private static extern SafeProcessHandle OpenForImageQuery(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle handle,uint flags,StringBuilder name,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint serverProcessId);
}
