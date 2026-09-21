using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed record RawSignal(int Pid,string Path,FileKind Kind,DateTime EventUtc,DateTime ReceivedUtc);
internal sealed record LatencySnapshot(long Samples,double P50Ms,double P95Ms,double P99Ms,double MaxMs);
internal sealed record PathResolutionSnapshot(long Resolved,long Unresolved,IReadOnlyDictionary<string,long> Categories);
internal sealed class EtwMonitor:IDisposable
{
    private readonly ProcessCatalog _catalog;
    private readonly DevicePaths _paths=new();
    private readonly Channel<RawSignal> _queue;
    private readonly ConcurrentDictionary<string,long> _resolution=new(StringComparer.Ordinal);
    private readonly long[] _latencyBits=new long[4096];
    private TraceEventSession? _session;
    private long _dropped,_unresolved,_resolved,_latencySequence;
    public string SessionName { get; } = $"RansomGuardV032-{Environment.ProcessId}-{Guid.NewGuid():N}";
    private int _disposed;
    public Task Completion {get;private set;}=Task.CompletedTask;
    public ChannelReader<RawSignal> Reader=>_queue.Reader;
    public long Dropped=>Interlocked.Read(ref _dropped);
    public long Unresolved=>Interlocked.Read(ref _unresolved);
    public long Resolved=>Interlocked.Read(ref _resolved);
    public int? EventsLost {get {try{return _session?.EventsLost;}catch{return null;}}}
    public EtwMonitor(ProcessCatalog catalog,int capacity)
    {
        _catalog=catalog;
        _queue=Channel.CreateBounded<RawSignal>(new BoundedChannelOptions(capacity){SingleReader=true,SingleWriter=true,FullMode=BoundedChannelFullMode.Wait});
    }
    public void Start()
    {
        if (_session is not null || Volatile.Read(ref _disposed) != 0)
            throw new InvalidOperationException("This ETW monitor cannot be started twice.");
        // No cleanup by prefix, no attachment, no restart of another session.
        var session = new TraceEventSession(SessionName,
            TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate);
        _session = session;
        session.StopOnDispose = true;
        try
        {
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.Process);
            var source = session.Source;
            var p = new KernelTraceEventParser(source);
            p.ProcessStart += e => _catalog.Invalidate(e.ProcessID);
            p.ProcessStop += e => _catalog.Invalidate(e.ProcessID);
            p.FileIOWrite += e => Emit(e.ProcessID, e.FileName, FileKind.Write, e.TimeStamp.ToUniversalTime());
            p.FileIORename += e => Emit(e.ProcessID, e.FileName, FileKind.Rename, e.TimeStamp.ToUniversalTime());
            p.FileIODelete += e => Emit(e.ProcessID, e.FileName, FileKind.Delete, e.TimeStamp.ToUniversalTime());
            // The blocking ETW consumer has its own thread, not a permanently occupied pool worker.
            Completion = Task.Factory.StartNew(() =>
            {
                try { source.Process(); _queue.Writer.TryComplete(); }
                catch (Exception ex) { _queue.Writer.TryComplete(ex); throw; }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        catch (Exception ex)
        {
            // Even with a randomly generated name, never stop a pre-existing session
            // when Windows explicitly tells us creation failed due to a collision.
            if (MonitoringHealth.Win32Code(ex) == 183) session.StopOnDispose = false;
            _session = null;
            try { session.Dispose(); }
            catch (Exception cleanupError) { ex.Data["RansomGuard.EtwCleanupError"] = cleanupError.Message; }
            _queue.Writer.TryComplete();
            throw;
        }
    }
    private void Emit(int pid,string? raw,FileKind kind,DateTime time)
    {
        if(pid<=4||pid==Environment.ProcessId)return;
        var received=DateTime.UtcNow;
        RecordLatency((received-time).TotalMilliseconds);
        var resolution=_paths.ResolveDetailed(raw);
        _resolution.AddOrUpdate(resolution.Category,1,static (_,n)=>n+1);
        if(resolution.Path is null){Interlocked.Increment(ref _unresolved);return;}
        Interlocked.Increment(ref _resolved);
        if(!_queue.Writer.TryWrite(new(pid,resolution.Path,kind,time,received)))Interlocked.Increment(ref _dropped);
    }
    private void RecordLatency(double ms)
    {
        if(double.IsNaN(ms)||double.IsInfinity(ms))return;
        ms=Math.Max(0,ms);
        var seq=Interlocked.Increment(ref _latencySequence)-1;
        var index=(int)(seq%_latencyBits.Length);
        Volatile.Write(ref _latencyBits[index],BitConverter.DoubleToInt64Bits(ms));
    }
    public LatencySnapshot Latency()
    {
        var seq=Interlocked.Read(ref _latencySequence);
        var count=(int)Math.Min(seq,_latencyBits.Length);
        if(count<=0)return new(0,0,0,0,0);
        var values=new double[count];
        for(var i=0;i<count;i++)values[i]=Math.Max(0,BitConverter.Int64BitsToDouble(Volatile.Read(ref _latencyBits[i])));
        Array.Sort(values);
        double P(double q)=>values[Math.Clamp((int)Math.Ceiling(values.Length*q)-1,0,values.Length-1)];
        return new(seq,P(.50),P(.95),P(.99),values[^1]);
    }
    public PathResolutionSnapshot PathResolution()
        =>new(Resolved,Unresolved,new SortedDictionary<string,long>(_resolution,StringComparer.Ordinal));
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        var session = Interlocked.Exchange(ref _session, null);
        try { session?.Dispose(); }
        finally { _queue.Writer.TryComplete(); }
    }
}
