using System.Diagnostics;
using System.Runtime.InteropServices;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed class LabFreeze:IDisposable
{
    private readonly ProcessHandle _handle;
    private bool _ownsIncrement;
    private readonly long _createdFileTime;
    public int Pid {get;}
    public int? NtStatus {get;private set;}
    public int? ResumeStatus {get;private set;}
    public bool ResumeAttempted {get;private set;}
    public bool ApiAccepted=>NtStatus is >=0;
    public DateTime? StartedUtc {get;private set;}
    public DateTime? CompletedUtc {get;private set;}
    public double DurationMs {get;private set;}
    public int ThreadsObserved {get;private set;}
    public int ThreadsReportedSuspended {get;private set;}
    public bool ThreadSnapshotComplete {get;private set;}
    public bool AllThreadsObservedSuspended=>ThreadSnapshotComplete&&ThreadsObserved>0&&ThreadsObserved==ThreadsReportedSuspended;
    public string? Error {get;private set;}
    private LabFreeze(ProcessHandle handle,int pid,long created){_handle=handle;Pid=pid;_createdFileTime=created;}
    public static LabFreeze? OpenAuthorized(LabIdentity? lab,RiskSignal risk,ImageEvidence freshImage,bool healthy,out ActionDecision decision)
    {
        // THIS CHECK MUST precede OpenProcess with intervention rights.
        if(lab is null||risk.Process!=lab.Process){decision=new(false,"AuditOnly/not an enrolled lab child");return null;}
        var h=Native.OpenProcess(Native.Query|Native.Synchronize|Native.SuspendResume,false,lab.Process.Pid);
        if(h.IsInvalid){decision=new(false,"OpenProcess failed: "+Marshal.GetLastWin32Error());h.Dispose();return null;}
        var identity=Native.Identity(h,lab.Process.Pid);
        var known=Native.IsProcessCritical(h,out var critical);
        decision=DecisionPolicy.Decide(risk,freshImage,lab,identity==lab.Process&&WinPaths.Equal(Native.ImagePath(h),lab.ImagePath),known,critical,healthy,DateTime.UtcNow);
        if(!decision.AllowLabSuspend){h.Dispose();return null;}
        return new(h,lab.Process.Pid,lab.Process.CreationFileTimeUtc);
    }
    public void Suspend()
    {
        StartedUtc=DateTime.UtcNow;var watch=Stopwatch.StartNew();
        NtStatus=Native.NtSuspendProcess(_handle);
        _ownsIncrement=NtStatus>=0;
        if(!_ownsIncrement)Error=$"NtSuspendProcess failed: 0x{unchecked((uint)NtStatus.Value):X8}";
        CompletedUtc=DateTime.UtcNow;DurationMs=watch.Elapsed.TotalMilliseconds;
        if(!_ownsIncrement)return;
        // Read-only thread snapshot. No SuspendThread probes or fallback increments.
        try
        {
            using var p=Process.GetProcessById(Pid);p.Refresh();
            if(p.StartTime.ToUniversalTime().ToFileTimeUtc()!=_createdFileTime)throw new IOException("Process identity changed before thread snapshot.");
            foreach(ProcessThread t in p.Threads)
            {using(t){ThreadsObserved++;if(t.ThreadState==System.Diagnostics.ThreadState.Wait&&t.WaitReason==ThreadWaitReason.Suspended)ThreadsReportedSuspended++;}}
            ThreadSnapshotComplete=true;
        }
        catch(Exception ex){Error="API accepted, thread snapshot incomplete: "+ex.Message;}
    }
    public void ResumeOwnedIncrement()
    {
        if(!_ownsIncrement)return;
        ResumeAttempted=true;
        ResumeStatus=Native.NtResumeProcess(_handle);
        // Do not repeatedly decrement a process's suspension counts on failure.
        _ownsIncrement=false;
    }
    public object Report()=>new {Pid,StartedUtc,CompletedUtc,DurationMs,
        ApiAccepted,NtStatus=NtStatus.HasValue?$"0x{unchecked((uint)NtStatus.Value):X8}":null,
        ThreadsObserved,ThreadsReportedSuspended,ThreadSnapshotComplete,AllThreadsObservedSuspended,ResumeAttempted,
        ResumeStatus=ResumeStatus.HasValue?$"0x{unchecked((uint)ResumeStatus.Value):X8}":null,Error,
        VerificationLimit="Read-only snapshot, not a kernel-enforced freeze guarantee. Only the enrolled synthetic child can reach this path."};
    public void Dispose(){try{ResumeOwnedIncrement();}finally{_handle.Dispose();}}
}
