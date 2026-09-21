using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using RansomGuard.Core;
namespace RansomGuard.Service;

internal sealed class ReadOnlyPipeServer : BackgroundService
{
    private readonly ILogger<ReadOnlyPipeServer> _log;
    private readonly RuntimeState _state;
    private readonly GuardSettings _settings;
    public ReadOnlyPipeServer(ILogger<ReadOnlyPipeServer> log,RuntimeState state,GuardSettings settings)
    { _log=log;_state=state;_settings=settings; }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        _state.RefreshDriverStatus();
        _log.LogInformation("Read-only live pipe: {Pipe}; protocol {Version}; at most 4 clients. No mutation commands.",
            LocalApiContract.PipeName,LocalApiContract.ProtocolVersion);
        // No unbounded fire-and-forget client tasks. Each worker owns one pipe instance.
        await Task.WhenAll(Enumerable.Range(0,4).Select(_=>Serve(stoppingToken)));
    }
    private async Task Serve(CancellationToken token)
    {
        while(!token.IsCancellationRequested)
        {
            try
            {
                using var pipe=CreatePipe();
                await pipe.WaitForConnectionAsync(token);
                using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
                deadline.CancelAfter(TimeSpan.FromSeconds(2));
                var request=await PipeFraming.ReadAsync<ApiRequest>(pipe,deadline.Token,4096);
                if(request.Protocol!=LocalApiContract.ProtocolVersion||!LocalApiContract.IsKnownCommand(request.Command))
                    throw new IOException("Unsupported read-only API request.");
                if(request.Command==LocalApiContract.SubscribeCommand) await StreamSnapshots(pipe,token);
                else
                {
                    switch(request.Command)
                    {
                        case LocalApiContract.StatusCommand:
                            await Send(pipe,new ApiResponse<GuardStatusDto>(2,true,null,_state.Status(_settings)),token);break;
                        case LocalApiContract.IncidentsCommand:
                            await Send(pipe,new ApiResponse<IncidentSummaryDto[]>(2,true,null,_state.Incidents(request.Limit)),token);break;
                        case LocalApiContract.DiagnosticsCommand:
                            await Send(pipe,new ApiResponse<DiagnosticsDto>(2,true,null,_state.Diagnostics()),token);break;
                    }
                }
            }
            catch(OperationCanceledException) when(token.IsCancellationRequested){break;}
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or OperationCanceledException or System.Text.Json.JsonException)
            {
                // A failed/slow UI never stops the engine. Do not log received payloads.
                _log.LogDebug("Live UI client disconnected/rejected: {Type}",ex.GetType().Name);
                try{await Task.Delay(200,token);}catch(OperationCanceledException){break;}
            }
        }
    }
    private async Task StreamSnapshots(NamedPipeServerStream pipe,CancellationToken token)
    {
        using var changes=_state.Subscribe(); // Subscribe BEFORE capturing initial state: no lost wake-up.
        long sequence=0,telemetry=-1,incidents=-1,recovery=-1,state=-1;
        bool full=true;
        while(!token.IsCancellationRequested)
        {
            var frame=_state.Frame(_settings,++sequence,full,ref telemetry,ref incidents,ref recovery,ref state);
            await Send(pipe,frame,token);
            full=false;
            await changes.WaitAsync(TimeSpan.FromSeconds(2),token);
        }
    }
    private static async Task Send<T>(Stream pipe,T message,CancellationToken token)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        await PipeFraming.WriteAsync(pipe,message,deadline.Token);
    }
    private static NamedPipeServerStream CreatePipe()
    {
        var security=new PipeSecurity();
        security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AnonymousSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        // Explicit transport rights; no CreateNewInstance, ChangePermissions or TakeOwnership for Users.
        var userRights=PipeAccessRights.ReadData|PipeAccessRights.WriteData|PipeAccessRights.ReadAttributes|
            PipeAccessRights.WriteAttributes|PipeAccessRights.ReadExtendedAttributes|PipeAccessRights.WriteExtendedAttributes|
            PipeAccessRights.ReadPermissions|PipeAccessRights.Synchronize;
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),userRights,AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(LocalApiContract.PipeName,PipeDirection.InOut,4,
            PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.WriteThrough,4096,65536,security);
    }
}
