using System.Security.Cryptography;
using System.Text.Json;
using RansomGuard.Core;
namespace RansomGuard.Service;
internal sealed record TrustEntry(string Sha256,string Disposition,string Reason);
internal sealed record SeenEntry(string Sha256,DateTime FirstSeenUtc,DateTime LastSeenUtc,int Observations);
internal sealed class ImageInspector
{
    private readonly SecureStore _store;
    private readonly Dictionary<string,ImageEvidence> _cache=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,SeenEntry> _seen=new(StringComparer.OrdinalIgnoreCase);
    public ImageInspector(SecureStore store)
    {
        _store=store;
        var p=Path.Combine(store.Root,"seen-images.json");FileSafety.NoReparse(p);
        if(File.Exists(p)&&new FileInfo(p).Length<1024*1024)
            try {foreach(var e in JsonSerializer.Deserialize<SeenEntry[]>(File.ReadAllText(p))??Array.Empty<SeenEntry>())if(e is not null&&_seen.Count<1000&&DecisionPolicy.HashEqual(e.Sha256,e.Sha256))_seen[e.Sha256]=e;}
            catch(JsonException){ /* First/last seen is informational, never a trust decision. */ }
    }
    public ImageEvidence Inspect(string? rawPath,bool fresh=false)
    {
        var path=WinPaths.Normalize(rawPath);var now=DateTime.UtcNow;
        if(path is not null&&!fresh&&_cache.TryGetValue(path,out var hit)&&(now-hit.ObservedUtc).TotalMinutes<2)
            return hit with{Status="HashedCached",LocalDisposition=Lookup(hit.Sha256)};
        try
        {
            if(path is null) throw new IOException("Executable path unavailable or unsupported.");
            FileSafety.NoReparse(path);
            using var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,128*1024,FileOptions.SequentialScan);
            if(f.Length>512L*1024*1024) throw new IOException("Image exceeds hashing size limit.");
            var final=Native.FinalFilePath(f.SafeFileHandle);
            if(!WinPaths.Equal(path,final)) throw new IOException("Final opened-file path differs from reported image path.");
            var fileIdentity=Native.FileIdentity(f.SafeFileHandle);
            var hash=Convert.ToHexString(SHA256.HashData(f));
            f.Position=0;
            var signature=Authenticode.Check(f,path);
            var evidence=new ImageEvidence(path,hash,f.Length,"Hashed",signature,Lookup(hash),now,null)
            {
                FileIdentity=fileIdentity
            };
            if(_cache.Count>=256) _cache.Remove(_cache.MinBy(x=>x.Value.ObservedUtc).Key);
            _cache[path]=evidence;
            if(!_seen.TryGetValue(hash,out var prev))prev=new(hash,now,now,0);
            _seen[hash]=prev with{LastSeenUtc=now,Observations=Math.Min(prev.Observations+1,1000000)};
            if(_seen.Count>1000)_seen.Remove(_seen.MinBy(x=>x.Value.LastSeenUtc).Key);
            _store.WriteJson(Path.Combine(_store.Root,"seen-images.json"),_seen.Values.ToArray());
            return evidence;
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or CryptographicException or System.ComponentModel.Win32Exception)
        {return new(path,null,null,"Unavailable",new("Unavailable",null,null,null),"Unknown",now,ex.Message);}
    }
    internal string Lookup(string? sha)
    {
        if(sha is null)return "Unknown";
        try
        {
            var p=Path.Combine(_store.Root,"trust-store.json");FileSafety.NoReparse(p);
            if(!File.Exists(p))return "Unknown";
            if(new FileInfo(p).Length>256*1024)return "StoreInvalid";
            var entries=JsonSerializer.Deserialize<TrustEntry[]>(File.ReadAllText(p))??Array.Empty<TrustEntry>();
            if(entries.Length>1000 || entries.Any(x=>x is null||!DecisionPolicy.HashEqual(x.Sha256,x.Sha256)||
                x.Disposition is not ("ReviewedTrusted" or "BlockedByAdministrator")||string.IsNullOrWhiteSpace(x.Reason)))return "StoreInvalid";
            var matches=entries.Where(x=>DecisionPolicy.HashEqual(x.Sha256,sha)).ToArray();
            return matches.Length switch {0=>"Unknown",1=>matches[0].Disposition,_=>"StoreInvalid"};
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException){return "StoreUnavailable";}
    }
}
