using System.Security.Cryptography;
namespace RansomGuard.Recovery;
public sealed record RecoveredFile(string InputName,string State,string? OutputName,bool TagVerified,
    bool? OriginalHashMatches,string? RecoveredSha256,string? Note);
public sealed record RecoveryProgress(string State,string? Algorithm,int Candidates,long BytesScanned,int Authenticated,int Total);
public sealed record RecoveryReport(int Schema,string Status,string AlgorithmEvidence,bool KeyRecovered,
    bool ReferenceKeyFileUsed,int SelectedFiles,int AuthenticatedFiles,int WrittenFiles,int OriginalHashVerifiedFiles,
    ScanResult? Scan,RecoveredFile[] Files,string[] Limitations)
{
    public string? Algorithm => KeyRecovered ? "AES-256-GCM" : null;
    public string KeyEvidence => KeyRecovered ? "Dump candidate accepted by GCM authentication" : "No validated key";
}

public static class RecoveryEngine
{
    public const int MaxFiles=64;
    public const int MaxFileBytes=1024*1024;
    private static readonly string[] Limits = {
        "Supported encrypted envelope: RGTEST03 (AES-256-GCM, nonce 12, tag 16, no AAD). Unknown formats are refused.",
        "Key search: CoreCLR x64 byte-array candidates and complete forward AES schedules. Missing/wiped/split keys may not be recoverable.",
        "No reference-key file is opened. No key bytes/addresses are written in reports or sent over IPC.",
        "All output is NEW copies. This is not rollback, an unknown-ransomware universal decryptor, or an assurance that ordinary apps are protected."
    };
    private sealed class Input:IDisposable
    {
        public required string Name;
        public required byte[] Data;
        public byte[]? Plain;
        public byte[]? Scratch;
        public string? Source;
        public bool? HashMatches;
        public string? PlainHash;
        public void Dispose(){CryptographicOperations.ZeroMemory(Data);if(Plain is not null)CryptographicOperations.ZeroMemory(Plain);if(Scratch is not null)CryptographicOperations.ZeroMemory(Scratch);}
    }
    public static RecoveryReport Recover(string dumpPath,IReadOnlyList<string> selectedFiles,string outputDirectory,
        IReadOnlyDictionary<string,string>? expectedHashes=null,Action<RecoveryProgress>? progress=null,CancellationToken token=default)
    {
        if(selectedFiles.Count is 0 or >MaxFiles)throw new ArgumentException("Select 1..64 encrypted files.");
        var inputs=new List<Input>();var results=new List<RecoveredFile>();ScanResult? scan=null;
        int authenticated=0,written=0,hashVerified=0;
        try
        {
            var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(string file in selectedFiles)
            {
                token.ThrowIfCancellationRequested();
                if(!paths.Add(Path.GetFullPath(file)))throw new IOException("Duplicate input path.");
                byte[] bytes=SafeInput.Read(file,MaxFileBytes);
                string name=Path.GetFileName(file);
                if(bytes.Length<=36 || !bytes.AsSpan(0,8).SequenceEqual("RGTEST03"u8))
                {CryptographicOperations.ZeroMemory(bytes);results.Add(new(name,"UnsupportedFormat",null,false,null,null,"No algorithm guessed from entropy."));continue;}
                inputs.Add(new Input{Name=name,Data=bytes});
            }
            if(inputs.Count==0)return new(1,"UnsupportedFormat","Unknown",false,false,selectedFiles.Count,0,0,0,null,results.ToArray(),Limits);
            progress?.Invoke(new("ScanningDump","AES-256-GCM hypothesis from RGTEST03 header",0,0,0,selectedFiles.Count));
            using(var dump=new DumpMemory(dumpPath))
            {
                int attempts=0;int lastAuthenticated=0;
                scan=MemoryCandidates.Scan(dump,(candidate,origin)=>
                {
                    token.ThrowIfCancellationRequested();
                    if(candidate.Length!=32)return false;
                    using var aes=new AesGcm(candidate,16);
                    foreach(var input in inputs)
                    {
                        if(input.Plain is not null)continue;
                        if(++attempts>16384)throw new RecoveryLimitException();
                        byte[] plain=input.Scratch ??= new byte[input.Data.Length-36];
                        try
                        {
                            aes.Decrypt(input.Data.AsSpan(8,12),input.Data.AsSpan(36),input.Data.AsSpan(20,16),plain);
                            input.Plain=plain;input.Source=origin;authenticated++;
                            input.PlainHash=Convert.ToHexString(SHA256.HashData(plain));
                            if(expectedHashes is not null)
                            {
                                string originalName=input.Name.EndsWith(".rglocked",StringComparison.OrdinalIgnoreCase)?input.Name[..^9]:input.Name;
                                input.HashMatches=expectedHashes.TryGetValue(originalName,out var expected)&&
                                    string.Equals(input.PlainHash,expected,StringComparison.OrdinalIgnoreCase);
                            }
                        }
                        catch(AuthenticationTagMismatchException){CryptographicOperations.ZeroMemory(plain);}
                    }
                    if(authenticated!=lastAuthenticated)
                    {progress?.Invoke(new("ValidatingCandidates","AES-256-GCM",0,0,authenticated,selectedFiles.Count));lastAuthenticated=authenticated;}
                    return authenticated==inputs.Count;
                },token,(bytes,candidates)=>progress?.Invoke(new("ScanningDump","AES-256-GCM",candidates,bytes,authenticated,selectedFiles.Count)));
            }
            foreach(var input in inputs.Where(x=>x.Plain is null))results.Add(new(input.Name,"KeyNotFound",null,false,null,null,
                scan.FullScan?"No authenticated candidate found in supported memory layouts.":"Scan incomplete or stopped by its safety limit."));
            foreach(var input in inputs.Where(x=>x.HashMatches==false))results.Add(new(input.Name,"OriginalHashMismatch",null,true,false,input.PlainHash,"Authenticated but differs from baseline; not written."));
            var writable=inputs.Where(x=>x.Plain is not null&&x.HashMatches!=false).ToArray();
            if(writable.Length>0)
            {
                progress?.Invoke(new("WritingVerifiedCopies","AES-256-GCM confirmed by GCM tag",scan.Candidates,scan.BytesScanned,authenticated,selectedFiles.Count));
                using var pin=SafeInput.CreateOutputDirectory(outputDirectory);
                for(int i=0;i<writable.Length;i++)
                {
                    token.ThrowIfCancellationRequested();var input=writable[i];
                    string name=$"file-{i+1:0000}.recovered.bin";
                    if(System.Text.RegularExpressions.Regex.IsMatch(input.Name,@"\ARG_TEST_(0[1-9]|10)\.txt\.rglocked\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                        name=input.Name[..^9];
                    string destination=Path.Combine(outputDirectory,name);
                    // Only authenticated plaintext reaches the new output directory.
                    SafeInput.WriteNew(destination,input.Plain!);
                    using var check=SafeInput.OpenRead(destination,MaxFileBytes);
                    string stored=Convert.ToHexString(SHA256.HashData(check));
                    if(stored!=input.PlainHash)throw new IOException("Written output hash verification failed.");
                    written++;if(input.HashMatches==true)hashVerified++;
                    results.Add(new(input.Name,"RecoveredCopy",name,true,input.HashMatches,stored,"Key source: "+input.Source));
                }
            }
            string status=written==selectedFiles.Count?"RecoveredAllSelected":written>0?"PartialRecovery":authenticated>0?"VerificationFailed":"KeyNotFound";
            progress?.Invoke(new(status,authenticated>0?"AES-256-GCM confirmed by GCM tag":null,scan.Candidates,scan.BytesScanned,authenticated,selectedFiles.Count));
            return new(1,status,authenticated>0?"RGTEST03 header + successful GCM tag verification":"RGTEST03 header only; algorithm not cryptographically confirmed",
                authenticated>0,false,selectedFiles.Count,authenticated,written,hashVerified,scan,results.ToArray(),Limits);
        }
        catch(RecoveryLimitException)
        {return new(1,"ValidationLimit",authenticated>0?"RGTEST03 header + successful GCM tag verification":"RGTEST03 hypothesis only",authenticated>0,false,selectedFiles.Count,authenticated,0,0,scan,results.ToArray(),Limits);}
        finally{foreach(var input in inputs)input.Dispose();}
    }
    private sealed class RecoveryLimitException:Exception { }
}
