namespace RansomGuard.Core;
// Single-consumer engine. Bounded sliding windows, O(1) insert/expiry; no LINQ scan on every write.
public sealed class RiskEngine
{
    private sealed class Window
    {
        public readonly Queue<FileSignal> Events=new();
        public readonly Dictionary<string,int> Paths=new(StringComparer.OrdinalIgnoreCase);
        public int Writes, Renames, Deletes;
        public DateTime LastAlert=DateTime.MinValue, LastSeen, TruncatedUntil;
    }
    private readonly Dictionary<ProcessKey,Window> _windows=new();
    private readonly GuardSettings _s;
    private readonly HashSet<string> _extensions;
    private readonly HashSet<string> _canaries;
    private readonly string[] _roots;
    public long WindowEvictions { get; private set; }
    public long TruncatedWindows { get; private set; }
    public int ProcessCount => _windows.Count;
    public RiskEngine(GuardSettings settings, IEnumerable<string> roots, IEnumerable<string> canaries)
    {
        settings.Validate(); _s=settings;
        _extensions=new(settings.ProtectedExtensions,StringComparer.OrdinalIgnoreCase);
        _roots=roots.Select(WinPaths.Normalize).Where(p=>p is not null).Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _canaries=new(canaries.Select(WinPaths.Normalize).Where(p=>p is not null).Cast<string>(),StringComparer.OrdinalIgnoreCase);
    }
    public RiskSignal? Evaluate(FileSignal input,bool labFastPath=false)
    {
        var path=WinPaths.Normalize(input.Path);
        if (path is null || input.Kind == FileKind.Open || input.Process.CreationFileTimeUtc<=0) return null;
        var canary=_canaries.Contains(path);
        if (!canary && (!_roots.Any(r=>WinPaths.Under(path,r)) || !_extensions.Contains(WinPaths.Extension(path)))) return null;
        var e=input with {Path=path, CanaryCandidate=canary};
        if (!_windows.TryGetValue(e.Process,out var w))
        {
            if (_windows.Count >= _s.MaxProcesses)
            { var old=_windows.MinBy(p=>p.Value.LastSeen).Key; _windows.Remove(old); WindowEvictions++; }
            _windows[e.Process]=w=new Window();
        }
        var cutoff=e.ReceivedUtc.AddSeconds(-_s.WindowSeconds);
        while(w.Events.Count>0 && w.Events.Peek().ReceivedUtc<cutoff) Remove(w);
        if (w.Events.Count >= _s.MaxEventsPerProcess)
        { Remove(w); w.TruncatedUntil=e.ReceivedUtc.AddSeconds(_s.WindowSeconds); TruncatedWindows++; }
        w.Events.Enqueue(e); w.LastSeen=e.ReceivedUtc;
        w.Paths[path]=w.Paths.GetValueOrDefault(path)+1;
        if(e.Kind==FileKind.Write) w.Writes++;
        if(e.Kind==FileKind.Rename) w.Renames++;
        if(e.Kind==FileKind.Delete) w.Deletes++;
        var reasons=new List<string>(); int score=0;
        if(canary) {score+=120;reasons.Add("operation on explicitly registered canary (content confirmation pending)");}
        if(w.Writes>=20) {score+=20;reasons.Add("many write operations; may include new-file creation");}
        if(w.Paths.Count>=8) {score+=20;reasons.Add("activity spans several configured user files");}
        if(w.Writes>=12 && w.Paths.Count>=3 && w.Renames>=2)
        {score+=90;reasons.Add("write+rename pattern across several files; heuristic, not proof of encryption");}
        if(labFastPath && w.Writes>=6 && w.Paths.Count>=2 && w.Renames>=1)
        {score+=100;reasons.Add("LAB ONLY fast synthetic write+rename threshold; not a production blocking rule");}
        if(w.Deletes>=8 && w.Paths.Count>=8) {score+=50;reasons.Add("multi-file delete pattern");}
        if(score<_s.RiskThreshold || (e.ReceivedUtc-w.LastAlert).TotalSeconds<_s.IncidentCooldownSeconds) return null;
        w.LastAlert=e.ReceivedUtc;
        return new(e.Process,e.ProcessName,e.ImagePath,e.ReceivedUtc,e.EventUtc,
            (e.ReceivedUtc-e.EventUtc).TotalMilliseconds,score,w.Writes,w.Renames,w.Deletes,w.Paths.Count,
            canary,w.TruncatedUntil>e.ReceivedUtc,reasons.ToArray(),w.Events.TakeLast(_s.MaxEvidenceEvents).ToArray());
    }
    private static void Remove(Window w)
    {
        var e=w.Events.Dequeue();
        if(--w.Paths[e.Path]==0) w.Paths.Remove(e.Path);
        if(e.Kind==FileKind.Write) w.Writes--; if(e.Kind==FileKind.Rename) w.Renames--; if(e.Kind==FileKind.Delete) w.Deletes--;
    }
    public void Expire(DateTime now)
    { foreach(var k in _windows.Where(x=>(now-x.Value.LastSeen).TotalSeconds>120).Select(x=>x.Key).ToArray()) _windows.Remove(k); }
}
