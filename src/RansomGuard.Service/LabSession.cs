using System.Diagnostics;
using System.Security.Cryptography;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed class LabSession:IDisposable
{
    public string RunId {get;}=Guid.NewGuid().ToString("N");
    public string SimulatorPath {get;}
    public string Folder=>Path.Combine(Path.GetDirectoryName(SimulatorPath)!,"RansomGuard-TestLab",RunId);
    public volatile LabIdentity? Identity;
    public Process? Child {get;private set;}
    public bool FullDump {get;}
    public DumpResult? LastDump {get;set;}
    public string? LastCaseDirectory {get;set;}
    public Dictionary<string,string> OriginalHashes {get;}=new(StringComparer.OrdinalIgnoreCase);
    public volatile bool ResponseClaimed;
    public TaskCompletionSource<bool> CaptureFinished {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly FileStream _imageLock;
    private readonly string _hash;
    public LabSession(bool fullDump)
    {
        FullDump=fullDump;
        SimulatorPath=Path.Combine(AppContext.BaseDirectory,"Simulator","RansomGuard.Simulator.exe");
        FileSafety.NoReparse(SimulatorPath);
        _imageLock=new FileStream(SimulatorPath,FileMode.Open,FileAccess.Read,FileShare.Read);
        try
        {
            if(_imageLock.Length>512L*1024*1024)throw new IOException("Lab image too large.");
            _hash=Convert.ToHexString(SHA256.HashData(_imageLock));
            var pin=Path.Combine(AppContext.BaseDirectory,"Simulator","simulator.sha256");FileSafety.NoReparse(pin);
            if(!File.Exists(pin)||new FileInfo(pin).Length>256||!DecisionPolicy.HashEqual(_hash,File.ReadAllText(pin).Trim()))
                throw new IOException("Simulator hash does not match this build's manifest. Rebuild; do not replace the simulator binary.");
        }
        catch{_imageLock.Dispose();throw;}
    }
    private Process Start(string mode)
    {
        var start=new ProcessStartInfo(SimulatorPath){UseShellExecute=false,WorkingDirectory=Path.GetDirectoryName(SimulatorPath)!};
        start.ArgumentList.Add(mode);start.ArgumentList.Add(RunId);
        return Process.Start(start)??throw new IOException("Could not start the synthetic lab child.");
    }
    public async Task Prepare(CancellationToken token)
    {
        using var p=Start("--prepare");
        try {await p.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(30),token);}
        catch {if(!p.HasExited)p.Kill();throw;} // Only the child just created by this object.
        if(p.ExitCode!=0)throw new IOException("Lab preparation failed, exit="+p.ExitCode);
        foreach(var file in FixturePaths())
        {
            using var input=RansomGuard.Recovery.SafeInput.OpenRead(file,65536);
            OriginalHashes.Add(Path.GetFileName(file),Convert.ToHexString(SHA256.HashData(input)));
        }
    }
    public void StartRun()
    {
        Child=Start("--run");
        using var h=Native.OpenProcess(Native.Query|Native.Synchronize,false,Child.Id);
        var key=Native.Identity(h,Child.Id)??throw new IOException("Cannot enroll lab process identity.");
        if(!WinPaths.Equal(Native.ImagePath(h),SimulatorPath))throw new IOException("Lab child image mismatch.");
        Identity=new(key,SimulatorPath,_hash,DateTime.UtcNow.AddSeconds(120));
    }
    public int LockedFiles()=>Enumerable.Range(1,10).Count(i=>File.Exists(Path.Combine(Folder,$"RG_TEST_{i:00}.txt.rglocked")));
    public string? ResolveCurrentFixturePath(string baselinePath)
    {
        var normalized=WinPaths.Normalize(baselinePath);
        if(normalized is null||!WinPaths.Under(normalized,Folder))return null;
        var file=Path.GetFileName(normalized);
        if(!System.Text.RegularExpressions.Regex.IsMatch(file,@"\ARG_TEST_(0[1-9]|10)\.txt\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant))return null;
        var original=Path.Combine(Folder,file);
        var locked=original+".rglocked";
        var hasOriginal=File.Exists(original);var hasLocked=File.Exists(locked);
        if(hasOriginal==hasLocked)return null; // Both or neither is ambiguous: do not guess.
        var candidate=hasLocked?locked:original;
        FileSafety.NoReparse(candidate);
        return WinPaths.Normalize(candidate);
    }
    public IEnumerable<string> FixturePaths()=>Enumerable.Range(1,10).Select(i=>Path.Combine(Folder,$"RG_TEST_{i:00}.txt"));
    public void Dispose(){Child?.Dispose();_imageLock.Dispose();}
}
