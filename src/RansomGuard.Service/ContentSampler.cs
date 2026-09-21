using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed class ContentSampler
{
    private readonly Dictionary<string,ContentSample> _before=new(StringComparer.OrdinalIgnoreCase);
    public string[] RegisteredPaths=>_before.Keys.ToArray();
    // Only explicit files and our synthetic lab fixtures are read. No drive scan or user-file backup.
    public void Register(string path)
    {
        if(_before.Count>=64)throw new InvalidOperationException("Baseline quota exceeded.");
        var p=WinPaths.Normalize(path)??throw new IOException("Invalid baseline path.");
        _before[p]=Read(p);
    }
    public ContentChange[] Compare(IEnumerable<string> paths,Func<string,string?>? verifiedAlternatePath=null)
    {
        var results=new List<ContentChange>();
        foreach(var path in paths.Select(WinPaths.Normalize).Where(p=>p is not null).Cast<string>()
                     .Distinct(StringComparer.OrdinalIgnoreCase).Take(32))
        {
            if(!_before.TryGetValue(path,out var before))continue;
            try
            {
                var after=Read(path);
                results.Add(Change(path,"Compared",path,before,after));
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException)
            {
                var alternate=verifiedAlternatePath?.Invoke(path);
                if(alternate is not null)
                {
                    try
                    {
                        var normalized=WinPaths.Normalize(alternate)??throw new IOException("Alternate path is invalid.");
                        var after=Read(normalized);
                        results.Add(Change(path,"ComparedAfterVerifiedLabRename",normalized,before,after));
                        continue;
                    }
                    catch(Exception altEx) when(altEx is IOException or UnauthorizedAccessException)
                    {
                        results.Add(new(path,"UnavailableAfterVerifiedLabRename",before,null,null,null,altEx.Message){ObservedPath=alternate});
                        continue;
                    }
                }
                results.Add(new(path,"UnavailableOrRenamed",before,null,null,null,ex.Message){ObservedPath=null});
            }
        }
        return results.ToArray();
    }
    private static ContentChange Change(string baselinePath,string status,string observedPath,ContentSample before,ContentSample after)
        =>new(baselinePath,status,before,after,!DecisionPolicy.HashEqual(before.Sha256,after.Sha256),after.Entropy-before.Entropy,null)
        {ObservedPath=observedPath};
    private static ContentSample Read(string path)
    {
        FileSafety.NoReparse(path);
        using var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        if(!WinPaths.Equal(path,Native.FinalFilePath(f.SafeFileHandle)))throw new IOException("Unexpected final path.");
        var bytes=new byte[(int)Math.Min(f.Length,65536)];var read=0;
        while(read<bytes.Length){var n=f.Read(bytes,read,bytes.Length-read);if(n==0)break;read+=n;}
        return SampleMath.Make(path,bytes[..read],f.Length);
    }
}
