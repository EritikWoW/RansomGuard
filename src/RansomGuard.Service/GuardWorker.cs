using System.Threading.Channels;
using RansomGuard.Core;
using RansomGuard.Recovery;
namespace RansomGuard.Service;
internal sealed class GuardWorker:BackgroundService
{
    private readonly ILogger<GuardWorker> _log;
    private readonly IHostApplicationLifetime _life;
    private readonly GuardSettings _settings;
    private readonly SecureStore _store;
    private readonly ImageInspector _images;
    private readonly ContentSampler _samples;
    private readonly LabSession? _lab;
    private readonly RuntimeState _runtime;
    private readonly ScopedTrustCoordinator _scopedTrust;
    private readonly ProcessCatalog _catalog=new();
    private readonly RiskEngine _engine;
    private readonly Channel<RiskSignal> _incidents=Channel.CreateBounded<RiskSignal>(new BoundedChannelOptions(16){SingleReader=true,SingleWriter=true,FullMode=BoundedChannelFullMode.Wait});
    private long _incidentDrops;
    public GuardWorker(ILogger<GuardWorker> log,IHostApplicationLifetime life,GuardSettings settings,SecureStore store,
        ImageInspector images,ContentSampler samples,LabSession? lab,RuntimeState runtime,ScopedTrustCoordinator scopedTrust)
    {
        _log=log;_life=life;_settings=settings;_store=store;_images=images;_samples=samples;_lab=lab;_runtime=runtime;_scopedTrust=scopedTrust;
        _engine=new(settings,settings.ProtectedRoots,settings.CanaryFiles);
    }
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        await Task.Yield();
        using var monitor = new EtwMonitor(_catalog, _settings.QueueCapacity);
        _runtime.UpdateMonitor(new("Starting", DateTime.UtcNow, monitor.SessionName));
        try
        {
            monitor.Start();
        }
        catch (Exception ex) when (MonitoringHealth.IsOperationalFailure(ex))
        {
            PublishMonitorFailure(ex, monitor, "Startup");
            // No fake telemetry and no repeated creation of new sessions on resource exhaustion.
            // RunLab is never started when ETW initialization fails.
            await WaitForManualRestart(token);
            return;
        }

        _runtime.UpdateMonitor(new("Running", DateTime.UtcNow, monitor.SessionName));
        var protection=_runtime.Protection();
        _log.LogInformation(
            "RansomGuard v{Version}. RequestedMode={RequestedMode}; ProtectionState={ProtectionState}; KernelEnforcement={KernelEnforcement}; Lab enrolled={Lab}.",
            ProductInfo.Version,protection.RequestedMode,protection.State,protection.KernelEnforcementActive,_lab is not null);
        _log.LogInformation("Owned ETW session: {Session}. Clean Ctrl+C shutdown releases this session.", monitor.SessionName);
        foreach (var root in _settings.ProtectedRoots) _log.LogInformation("Monitored root: {Root}", root);
        _store.Audit(new { Utc=DateTime.UtcNow, Event="Startup", Version=ProductInfo.Version,
            RequestedMode=_settings.Mode, Protection=protection,
            Lab=_lab is not null, Roots=_settings.ProtectedRoots, monitor.SessionName });

        using var pipeline = CancellationTokenSource.CreateLinkedTokenSource(token);
        var pipelineToken = pipeline.Token;
        var response = Task.Run(() => RespondLoop(monitor, pipelineToken), pipelineToken);
        var metrics = Task.Run(() => Metrics(monitor, pipelineToken), pipelineToken);
        var labTask = _lab is null ? Task.CompletedTask : Task.Run(() => RunLab(pipelineToken), pipelineToken);
        var consumer = Task.Run(async () =>
        {
            await foreach (var e in monitor.Reader.ReadAllAsync(pipelineToken))
            {
                var proc = _catalog.Get(e.Pid, e.EventUtc); if (proc is null) continue;
                var labFastPath = _lab?.Identity?.Process == proc.Key;
                var decision = _engine.Evaluate(new(e.EventUtc, e.ReceivedUtc, proc.Key, proc.Name, proc.Path, e.Path, e.Kind), labFastPath);
                if (decision is not null && !_incidents.Writer.TryWrite(decision)) Interlocked.Increment(ref _incidentDrops);
                if (++_events % 1024 == 0) _engine.Expire(DateTime.UtcNow);
            }
        }, pipelineToken);
        Exception? pipelineError = null;
        try
        {
            var ended = await Task.WhenAny(consumer, monitor.Completion, response, metrics);
            await ended;
            if (!token.IsCancellationRequested)
                throw new IOException("ETW monitoring/processing pipeline exited unexpectedly. Monitoring is unavailable.");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) when (MonitoringHealth.IsOperationalFailure(ex) || ex is ChannelClosedException)
        {
            pipelineError = ex;
            PublishMonitorFailure(ex, monitor, "Runtime");
        }
        finally
        {
            pipeline.Cancel();
            _incidents.Writer.TryComplete();
            monitor.Dispose();
            try
            {
                await Task.WhenAll(consumer, response, metrics, labTask, monitor.Completion)
                    .WaitAsync(TimeSpan.FromSeconds(20));
            }
            catch (Exception ex) { _log.LogDebug(ex, "Monitoring pipeline shutdown"); }
        }
        if (pipelineError is not null && !token.IsCancellationRequested)
            await WaitForManualRestart(token);
        else
            _runtime.UpdateMonitor(new("Stopped", DateTime.UtcNow, monitor.SessionName));
    }

    private void PublishMonitorFailure(Exception error, EtwMonitor monitor, string phase)
    {
        var health = MonitoringHealth.Failed(error, monitor.SessionName, DateTime.UtcNow);
        _runtime.UpdateMonitor(health);
        _log.LogError(error, "ETW {Phase} failed: {Code}. FILE MONITORING IS UNAVAILABLE. Read-only UI/diagnostics remain available. {Hint}",
            phase, health.ErrorCode, health.RecoveryHint);
        try { _store.Audit(new { Utc=DateTime.UtcNow, Event="MonitoringUnavailable", Phase=phase, Monitor=health }); }
        catch (Exception auditError) when (auditError is IOException or UnauthorizedAccessException)
        {
            _log.LogWarning(auditError, "Unable to persist ETW failure report; see console and read-only diagnostics.");
        }
    }

    private async Task WaitForManualRestart(CancellationToken token)
    {
        if (_lab is not null)
        {
            _log.LogError("LAB aborted because ETW monitoring is unavailable. No successful test is claimed.");
            Environment.ExitCode = 6;
            _life.StopApplication();
            return;
        }
        _log.LogWarning("Diagnostics-only state. There is NO file monitoring. No ETW sessions, registry limits, security settings or other programs will be changed. Restart this audit instance after resolving the ETW resource failure.");
        try
        {
            while (!token.IsCancellationRequested)
            {
                _runtime.TouchServiceHeartbeat();
                await Task.Delay(TimeSpan.FromSeconds(5), token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
    private long _events;
    private async Task Metrics(EtwMonitor m,CancellationToken token)
    {
        var lastAudit=DateTime.UtcNow;var lastDriver=DateTime.MinValue;
        while(!token.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500),token);
            if(DateTime.UtcNow-lastDriver>TimeSpan.FromSeconds(5)){_runtime.RefreshDriverStatus();lastDriver=DateTime.UtcNow;}
            var latency=m.Latency();var paths=m.PathResolution();
            var heartbeatUtc=DateTime.UtcNow;
            var incidentDrops=Interlocked.Read(ref _incidentDrops);
            _runtime.UpdateTelemetry(new TelemetryDto(heartbeatUtc,m.EventsLost,m.Dropped,incidentDrops,_engine.WindowEvictions,_engine.TruncatedWindows,
                paths.Resolved,paths.Unresolved,latency.P50Ms,latency.P95Ms,latency.P99Ms,latency.MaxMs));
            if(heartbeatUtc-lastAudit<TimeSpan.FromSeconds(30))continue;
            lastAudit=heartbeatUtc;
            _store.Audit(new{Utc=heartbeatUtc,Event="Heartbeat",m.EventsLost,QueueDropped=m.Dropped,
                Resolution=paths,DeliveryLatency=latency,IncidentQueueDropped=incidentDrops,_engine.WindowEvictions,_engine.TruncatedWindows});
            var protection=_runtime.Protection();
            _log.LogInformation("Telemetry: ETW loss={EtwLoss}; queue loss={QueueLoss}; paths resolved={Resolved}, unresolved={Unresolved}; delivery p50={P50:F1}ms p95={P95:F1}ms p99={P99:F1}ms max={Max:F1}ms; requested={RequestedMode}; protection={ProtectionState}",
                m.EventsLost,m.Dropped,paths.Resolved,paths.Unresolved,latency.P50Ms,latency.P95Ms,latency.P99Ms,latency.MaxMs,
                protection.RequestedMode,protection.State);
            if(paths.Unresolved>0)_log.LogInformation("Unresolved path categories: {Categories}",string.Join(", ",paths.Categories.Where(x=>x.Key.StartsWith("unresolved-",StringComparison.Ordinal)).Select(x=>$"{x.Key}={x.Value}")));
        }
    }
    private async Task RunLab(CancellationToken token)
    {
        try
        {
            await Task.Delay(1200,token);_lab!.StartRun();
            _log.LogWarning("LAB ONLY: enrolled child pid={Pid}; run={RunId}; ordinary processes remain audit-only.",_lab.Identity!.Process.Pid,_lab.RunId);
            var child=_lab.Child!;
            await child.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(100),token);
            if(_lab.ResponseClaimed)await _lab.CaptureFinished.Task.WaitAsync(TimeSpan.FromSeconds(20),token);
            if(_lab.FullDump && _lab.LastDump is { Succeeded:true, Path:not null } captured && _lab.LastCaseDirectory is string caseDirectory)
            {
                if(child.ExitCode!=0)throw new IOException("Synthetic child failed; refusing a successful recovery claim.");
                var encrypted=_lab.FixturePaths().Select(p=>p+".rglocked").ToArray();
                var output=Path.Combine(caseDirectory,"RecoveredFromDump");
                _runtime.UpdateRecovery(new("ScanningDump",null,false,0,0,10,"Searching captured memory, not the saved lab key.",DateTime.UtcNow));
                var report=await Task.Run(()=>RecoveryEngine.Recover(captured.Path,encrypted,output,_lab.OriginalHashes,
                    p=>_runtime.UpdateRecovery(new(p.State,p.Algorithm,p.Authenticated>0,0,0,p.Total,
                        $"Memory bytes scanned: {p.BytesScanned:N0}; candidates: {p.Candidates}. Originals unchanged.",DateTime.UtcNow)),token),token);
                _store.WriteJson(Path.Combine(caseDirectory,"crypto-recovery.json"),report);
                _runtime.UpdateRecovery(new(report.Status,report.Algorithm,report.KeyRecovered,report.WrittenFiles,report.OriginalHashVerifiedFiles,
                    report.SelectedFiles,"Offline dump analysis complete. See crypto-recovery.json; no key file was read.",DateTime.UtcNow));
                _log.LogWarning("DUMP RECOVERY: key={Key}; algorithm={Algorithm}; recovered={Recovered}/{Total}; original hashes={Verified}; key-file-used={KeyFile}; case={Case}",
                    report.KeyRecovered,report.Algorithm??"Unknown",report.WrittenFiles,report.SelectedFiles,report.OriginalHashVerifiedFiles,report.ReferenceKeyFileUsed,caseDirectory);
                if(report.WrittenFiles!=10||report.OriginalHashVerifiedFiles!=10)Environment.ExitCode=7;
                // Briefly allow the live UI to receive the final summary before this LAB host exits.
                await Task.Delay(1500,token);
            }
            else if(_lab.FullDump)
            {
                Environment.ExitCode=7;
                _runtime.UpdateRecovery(new("NoSuccessfulDump",null,false,0,0,10,"Recovery was not run because no usable full dump was captured.",DateTime.UtcNow));
            }
            _store.Audit(new{Utc=DateTime.UtcNow,Event="LabCompleted",_lab.RunId,ChildExitCode=child.ExitCode,LockedFiles=_lab.LockedFiles(),ResponseClaimed=_lab.ResponseClaimed,
                Note="Fixture count after completion includes files processed AFTER automatic lab resume; use incident counts for freeze progress."});
            _log.LogWarning("Lab finished. Cases: {Directory}. Auto-resume was only for the owned synthetic test child.",_store.Cases);
        }
        catch(Exception ex) when(ex is not OperationCanceledException)
        {
            Environment.ExitCode=7;
            _runtime.UpdateRecovery(new("Failed",null,false,0,0,10,ex.GetType().Name+": "+ex.Message,DateTime.UtcNow));
            _log.LogError(ex,"Lab failed; no claim of protection effectiveness or recovery.");
        }
        finally{_life.StopApplication();}
    }
    private async Task RespondLoop(EtwMonitor monitor,CancellationToken token)
    {
        await foreach(var risk in _incidents.Reader.ReadAllAsync(token))
        {
            try{await Respond(risk,monitor,token);}
            catch(Exception ex){_log.LogError(ex,"Incident processing failed; no automatic action should be inferred.");}
        }
    }
    private ContainmentAuthorizationInput BuildContainmentAuthorizationInput(
        RiskSignal risk,
        ImageEvidence image,
        EtwMonitor monitor,
        ScopedTrustDecision scoped,
        bool confirmedCanary,
        bool isLab)
    {
        var protection=_runtime.Protection();
        var monitorState=_runtime.Monitor();
        var processIdentityVerified=VerifyLiveProcessIdentity(risk);
        var freshImageIdentityVerified=
            string.Equals(image.Status,"Hashed",StringComparison.Ordinal) &&
            WinPaths.Equal(image.Path,risk.ImagePath) &&
            DecisionPolicy.HashEqual(image.Sha256,image.Sha256) &&
            DateTime.UtcNow-image.ObservedUtc<=TimeSpan.FromSeconds(30);
        var protectedScopeResolved=EvidenceScopeResolved(risk);

        return new(
            _settings.Enforce.AutomaticContainment,
            protection,
            monitorState.State,
            monitor.EventsLost ?? -1,
            monitor.Dropped,
            Interlocked.Read(ref _incidentDrops),
            _engine.WindowEvictions,
            _engine.TruncatedWindows,
            IncidentPersisted:true,
            ProcessIdentityVerified:processIdentityVerified,
            FreshImageIdentityVerified:freshImageIdentityVerified,
            ProtectedScopeResolved:protectedScopeResolved,
            IsLab:isLab,
            ScopedTrustApplies:scoped.Applies,
            RiskScore:risk.Score,
            RiskThreshold:_settings.RiskThreshold,
            ConfirmedCanary:confirmedCanary);
    }

    private static bool VerifyLiveProcessIdentity(RiskSignal risk)
    {
        try
        {
            if(risk.ImagePath is null)return false;
            using var handle=Native.OpenProcess(Native.Query|Native.Synchronize,false,risk.Process.Pid);
            var identity=Native.Identity(handle,risk.Process.Pid);
            var imagePath=Native.ImagePath(handle);
            return identity is ProcessKey current &&
                current==risk.Process &&
                WinPaths.Equal(imagePath,risk.ImagePath);
        }
        catch(Exception ex) when(ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private bool EvidenceScopeResolved(RiskSignal risk)
    {
        if(risk.Evidence.Length==0)return false;
        bool Protected(string? path)=>path is not null &&
            _settings.ProtectedRoots.Any(root=>WinPaths.Equal(path,root)||WinPaths.Under(path,root));

        foreach(var evidence in risk.Evidence)
        {
            if(!Protected(evidence.Path))return false;
            if(evidence.Kind==FileKind.Rename)
            {
                // Existing ETW rename telemetry does not guess a destination path. Unknown topology
                // is therefore not sufficient evidence for production containment authorization.
                if(evidence.DestinationPath is null||!Protected(evidence.DestinationPath))return false;
            }
        }
        return true;
    }

    private async Task Respond(RiskSignal risk,EtwMonitor monitor,CancellationToken token)
    {
        var isLab=_lab?.Identity?.Process==risk.Process;
        // No synchronous signature/hash/content work on the ETW consumer.
        var image=_images.Inspect(risk.ImagePath,fresh:isLab);
        var preliminaryChanges=_samples.Compare(risk.Evidence.Select(e=>e.Path));
        var confirmedCanary=preliminaryChanges.Any(c=>c.SampleChanged==true && _settings.CanaryFiles.Any(f=>WinPaths.Equal(f,c.Path)));
        var priority=DecisionPolicy.Priority(risk,image,confirmedCanary);
        string dir;
        try { dir=_store.NewCase(_settings.MaxIncidents); } // Must succeed before any suspend attempt.
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException)
        {
            _log.LogWarning("UNSAVED RISK pid={Pid} score={Score}: evidence storage unavailable; no scoped quieting/action applied.",risk.Process.Pid,risk.Score);
            throw;
        }
        var healthy=monitor.Dropped==0&&monitor.EventsLost==0&&Interlocked.Read(ref _incidentDrops)==0&&_engine.WindowEvictions==0;
        var latencyAtDecision=monitor.Latency();var pathsAtDecision=monitor.PathResolution();
        // EXCLUSIONS ARE PRESENTATION CONTEXT ONLY. Detection, score, evidence, and the audit archive stay intact.
        // Any suspected content transformation is a veto, even for an explicitly approved binary.
        var changedContent=preliminaryChanges.Any(c=>c.SampleChanged==true && c.After is not null &&
            ((c.EntropyDelta??0)>1.0 || !string.Equals(c.Before.Header,c.After.Header,StringComparison.Ordinal)));
        ScopedTrustDecision scoped;
        try { scoped=await _scopedTrust.EvaluateAsync(risk,image,healthy,confirmedCanary,changedContent,isLab,_images,token); }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or ArgumentException or OperationCanceledException)
        { scoped=ScopedTrustDecision.No("ExceptionEvaluationUnavailable"); _log.LogDebug(ex,"Scoped review unavailable; normal audit preserved."); }
        if(scoped.NotificationQuieted)
            _log.LogInformation("RISK (repeated scoped review) pid={Pid} score={Score}; rule={Rule}; all evidence retained.",risk.Process.Pid,risk.Score,scoped.RuleId);
        else _log.LogWarning("RISK pid={Pid} score={Score}: {Reason}; scoped review={Scoped}",risk.Process.Pid,risk.Score,string.Join("; ",risk.Reasons),scoped.Reason);
        var capturedUtc=DateTime.UtcNow;
        var caseId=Path.GetFileName(dir) ?? throw new IOException("Incident case id missing.");
        _store.WriteJson(Path.Combine(dir,"incident.json"),new {SchemaVersion=3,Version=ProductInfo.Version,CapturedUtc=capturedUtc,Risk=risk,Image=image,
            Priority=priority,Content=preliminaryChanges,ScopedTrust=scoped,Telemetry=new{Healthy=healthy,DeliveryLatency=latencyAtDecision,PathResolution=pathsAtDecision,
                IncidentQueueDropped=Interlocked.Read(ref _incidentDrops),WindowEvictions=_engine.WindowEvictions,TruncatedWindows=_engine.TruncatedWindows},
            LabRunId=isLab?_lab!.RunId:null,Action="RecordedBeforeResponse",Note="No action success is implied by the existence of this file."});

        var authorizationInput=BuildContainmentAuthorizationInput(risk,image,monitor,scoped,confirmedCanary,isLab);
        var authorization=ContainmentAuthorizationPolicy.Evaluate(authorizationInput);
        _store.WriteJson(Path.Combine(dir,"authorization.json"),new{
            SchemaVersion=1,Version=ProductInfo.Version,EvaluatedUtc=DateTime.UtcNow,
            Input=authorizationInput,Decision=authorization,
            ActuationAttempted=false,
            Note="Authorization evidence only. No ordinary-process containment actuator is wired in this milestone."
        });
        _runtime.UpdateContainmentAuthorization(authorization);
        _runtime.RecordIncident(new IncidentSummaryDto(caseId,capturedUtc,risk.Process.Pid,risk.Name,risk.Score,priority,risk.DistinctFiles,risk.Writes,risk.Renames,risk.Deletes,
            image.Signature.Status,image.LocalDisposition,isLab?"LabPending":"AuditOnly",risk.Reasons.Take(8).ToArray(),scoped,authorization));
        if(!isLab||_lab!.ResponseClaimed)
        {
            _store.WriteJson(Path.Combine(dir,"response.json"),new{Action="AuditOnly",SuspendAttempted=false,ActuationAttempted=false,ScopedTrust=scoped,
                ContainmentAuthorization=authorization,
                Reason="Automatic response to ordinary processes is disabled; authorization evidence does not execute an action."});
            _store.Audit(new{Utc=DateTime.UtcNow,Event="Incident",Case=Path.GetFileName(dir),risk.Process,Priority=priority,image.Sha256,image.Signature,
                Action="AuditOnly",ScopedTrust=scoped,ContainmentAuthorization=authorization});
            if(scoped.NotificationQuieted)
                _log.LogInformation("AUDIT ONLY repeated scoped event; pid={Pid}; rule={Rule}; case={Case}",risk.Process.Pid,scoped.RuleId,dir);
            else _log.LogWarning("AUDIT ONLY pid={Pid}; signature={Signature}; hash={Hash}; case={Case}",risk.Process.Pid,image.Signature.Status,image.Sha256,dir);
            return;
        }
        _lab.ResponseClaimed=true;
        using var freeze=LabFreeze.OpenAuthorized(_lab.Identity,risk,image,healthy,out var action);
        if(freeze is null)
        {
            _store.WriteJson(Path.Combine(dir,"response.json"),new{Action="Suppressed",action.Reason,SuspendAttempted=false});
            _log.LogError("Lab containment suppressed: {Reason}",action.Reason);_lab.CaptureFinished.TrySetResult(false);return;
        }
        var countBefore=0;var countAfter=0;DumpResult dump=new(false,false,null,"NotAttempted");
        ContentChange[] postFreezeChanges=Array.Empty<ContentChange>();
        try
        {
            freeze.Suspend();countBefore=_lab.LockedFiles();
            _store.WriteJson(Path.Combine(dir,"response.json"),new{Action="LabSuspendAttempt",Freeze=freeze.Report(),LockedFiles=countBefore});
            if(freeze.ApiAccepted&&freeze.AllThreadsObservedSuspended)
            {
                // Gives the fixture test a measurable stopped interval; never used for real user processes.
                await Task.Delay(600,token);
                postFreezeChanges=_samples.Compare(risk.Evidence.Select(e=>e.Path),_lab.ResolveCurrentFixturePath);
                dump=await DumpHelper.Capture(_store,dir,_lab.Identity!,_lab.FullDump,token);
                _lab.LastDump=dump;
                _lab.LastCaseDirectory=dir;
                // No crypto scan while frozen. Resume first; analyze this immutable dump after the lab completes.
                countAfter=_lab.LockedFiles();
            }
            else countAfter=_lab.LockedFiles();
        }
        finally
        {
            // Resume exactly our own API increment using the SAME held process handle, even on dump/verification failure.
            freeze.ResumeOwnedIncrement();
            _store.WriteJson(Path.Combine(dir,"response.json"),new{Action="LabOnly",LabRunId=_lab.RunId,Freeze=freeze.Report(),Dump=dump,
                KeyRecovery="Deferred until after resume; see crypto-recovery.json",PostFreezeContent=postFreezeChanges,
                LockedFilesAtFreeze=countBefore,LockedFilesBeforeResume=countAfter,
                FixtureProgressStable=countBefore==countAfter,DetectionToFreezeStartMs=(freeze.StartedUtc-risk.DetectedUtc)?.TotalMilliseconds,
                FirstEvidenceToDecisionMs=risk.FirstEvidenceToDecisionMs,FirstReceiveToDecisionMs=risk.FirstReceiveToDecisionMs,
                EvidenceDeliveryP95Ms=risk.P95EvidenceDeliveryLagMs,EvidenceDeliveryMaxMs=risk.MaxEvidenceDeliveryLagMs,
                Note="No process trees or ordinary applications were suspended. Thread snapshots are observations, not atomic guarantees. Lab is resumed after capture. Independent key discovery runs after resume without opening the reference-key file."});
            _lab.CaptureFinished.TrySetResult(freeze.ApiAccepted);
        }
        _log.LogWarning("LAB capture: API accepted={Api}; thread snapshot={Threads}; dump={Dump}; own resume status={Resume}; case={Case}. Independent recovery follows after child completion.",
            freeze.ApiAccepted,freeze.AllThreadsObservedSuspended,dump.Status,freeze.ResumeStatus,dir);
    }
}
