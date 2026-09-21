using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RansomGuard.Core;
using RansomGuard.Recovery;

int passed=0;
void Check(bool condition,string name){if(!condition)throw new Exception("FAIL: "+name);Console.WriteLine("PASS: "+name);passed++;}
var dir=Path.Combine(Path.GetTempPath(),"RansomGuard-OfflineTests-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
try
{
    // FIPS-197 schedule known-answer example, NOT the randomly generated recovery key below.
    var known=Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    var schedule=AesSchedules.Expand(known);
    Check(Convert.ToHexString(schedule.AsSpan(16,16))=="D6AA74FDD2AF72FADAA678F1D6AB76FE","AES expansion known round key");
    Check(AesSchedules.Candidate(schedule,16,false)!.SequenceEqual(known),"AES forward schedule recovered");
    for(int size=16;size<=32;size+=8)
    {
        var key=RandomNumberGenerator.GetBytes(size);var expanded=AesSchedules.Expand(key);
        Check(AesSchedules.Candidate(expanded,size,false)!.SequenceEqual(key),"AES schedule "+size);
        for(int i=0;i<expanded.Length;i+=4)Array.Reverse(expanded,i,4);
        Check(AesSchedules.Candidate(expanded,size,true)!.SequenceEqual(key),"AES LE-word schedule "+size);
        expanded[^1]^=1;Check(AesSchedules.Candidate(expanded,size,true) is null,"Corrupt schedule rejected "+size);
        CryptographicOperations.ZeroMemory(key);
    }
    byte[] actualKey=RandomNumberGenerator.GetBytes(32),plain=Encoding.UTF8.GetBytes("Independent encrypted synthetic data; no recovery key file.");
    var file=Path.Combine(dir,"RG_TEST_01.txt.rglocked");
    var envelope=Encrypt(actualKey,plain);File.WriteAllBytes(file,envelope);
    string dump=Path.Combine(dir,"process.dmp");File.WriteAllBytes(dump,MakeDump(actualKey));
    // A poison reference key exists. Recovery must neither read it nor use it.
    var poisonPath=Path.Combine(dir,"recovery-key.bin");File.WriteAllBytes(poisonPath,new byte[32]);
    var hashes=new Dictionary<string,string>{{"RG_TEST_01.txt",Convert.ToHexString(SHA256.HashData(plain))}};
    var result=RecoveryEngine.Recover(dump,new[]{file},Path.Combine(dir,"out"),hashes);
    Check(result.KeyRecovered&&!result.ReferenceKeyFileUsed,"Independent key discovery, reference key unused");
    Check(result.Algorithm=="AES-256-GCM"&&result.Files.Single().TagVerified,"Algorithm confirmed by GCM tag");
    Check(result.WrittenFiles==1&&result.OriginalHashVerifiedFiles==1,"Copy written and original hash verified");
    Check(File.ReadAllBytes(Path.Combine(dir,"out","RG_TEST_01.txt")).SequenceEqual(plain),"Recovered bytes equal original");
    Check(File.ReadAllBytes(file).SequenceEqual(envelope),"Encrypted input untouched");
    Check(File.ReadAllBytes(poisonPath).All(x=>x==0),"Poison reference key untouched");
    var json=System.Text.Json.JsonSerializer.Serialize(result);
    Check(!json.Contains(Convert.ToHexString(actualKey),StringComparison.OrdinalIgnoreCase)&&!json.Contains(Convert.ToBase64String(actualKey)),"Key not leaked in report");
    bool rejected=false;try{RecoveryEngine.Recover(dump,new[]{file},Path.Combine(dir,"out"),hashes);}catch(IOException){rejected=true;}
    Check(rejected,"Existing output rejected without overwrite");
    byte[] corrupt=envelope.ToArray();corrupt[20]^=1;string damaged=Path.Combine(dir,"damaged.rglocked");File.WriteAllBytes(damaged,corrupt);
    var bad=RecoveryEngine.Recover(dump,new[]{damaged},Path.Combine(dir,"bad"));
    Check(!bad.KeyRecovered&&bad.WrittenFiles==0&&!Directory.Exists(Path.Combine(dir,"bad")),"Wrong tag produces no plaintext output");
    var wrongHashes=new Dictionary<string,string>{{"RG_TEST_01.txt",new string('0',64)}};
    var mismatch=RecoveryEngine.Recover(dump,new[]{file},Path.Combine(dir,"mismatch"),wrongHashes);
    Check(mismatch.KeyRecovered&&mismatch.WrittenFiles==0,"Authenticated data with wrong baseline is not written");
    string unknown=Path.Combine(dir,"unknown.rglocked");File.WriteAllBytes(unknown,new byte[60]);
    var unsupported=RecoveryEngine.Recover("missing.dmp",new[]{unknown},Path.Combine(dir,"unknown-output"));
    Check(unsupported.Status=="UnsupportedFormat"&&unsupported.Algorithm is null,"Unknown algorithm not guessed from bytes");
    var partial=RecoveryEngine.Recover(dump,new[]{file,unknown},Path.Combine(dir,"partial"),hashes);
    Check(partial.Status=="PartialRecovery"&&partial.WrittenFiles==1,"Partial recovery not reported as all files recovered");
    string absent=Path.Combine(dir,"absent.dmp");File.WriteAllBytes(absent,MakeDump(RandomNumberGenerator.GetBytes(32)));
    var notFound=RecoveryEngine.Recover(absent,new[]{file},Path.Combine(dir,"not-found"));
    Check(!notFound.KeyRecovered&&!Directory.Exists(Path.Combine(dir,"not-found")),"Missing key fails closed");
    byte[] malformed=MakeDump(actualKey);BinaryPrimitives.WriteUInt64LittleEndian(malformed.AsSpan(80),ulong.MaxValue);
    string malformedPath=Path.Combine(dir,"malformed.dmp");File.WriteAllBytes(malformedPath,malformed);
    rejected=false;try{using var m=new DumpMemory(malformedPath);}catch(IOException){rejected=true;}
    Check(rejected,"Out-of-range dump descriptor rejected");
    var cancel=new CancellationTokenSource();cancel.Cancel();rejected=false;
    try{RecoveryEngine.Recover(dump,new[]{file},Path.Combine(dir,"cancelled"),null,null,cancel.Token);}catch(OperationCanceledException){rejected=true;}
    Check(rejected&&!Directory.Exists(Path.Combine(dir,"cancelled")),"Cancellation before recovery leaves no files");
    // Framing handles multiple frames and fragmented reads; request cap enforced before allocation.
    using var wire=new MemoryStream();
    await PipeFraming.WriteAsync(wire,new ApiRequest(2,"subscribe"),CancellationToken.None);
    await PipeFraming.WriteAsync(wire,new ApiRequest(2,"status"),CancellationToken.None);wire.Position=0;
    using var fragments=new FragmentedStream(wire);
    Check((await PipeFraming.ReadAsync<ApiRequest>(fragments,CancellationToken.None)).Command=="subscribe","Fragmented first frame");
    Check((await PipeFraming.ReadAsync<ApiRequest>(fragments,CancellationToken.None)).Command=="status","Coalesced next frame not discarded");
    using var oversized=new MemoryStream(new byte[]{255,255,255,127});rejected=false;
    try{await PipeFraming.ReadAsync<ApiRequest>(oversized,CancellationToken.None);}catch(IOException){rejected=true;}
    Check(rejected,"Oversized frame rejected before payload allocation");
    var pulse=new ChangePulse();using var one=pulse.Subscribe();using var two=pulse.Subscribe();using var three=pulse.Subscribe();using var four=pulse.Subscribe();
    rejected=false;try{using var fifth=pulse.Subscribe();}catch(IOException){rejected=true;}Check(rejected,"At most four live subscribers");
    for(int i=0;i<100000;i++)pulse.Signal();
    await one.WaitAsync(TimeSpan.FromSeconds(1),CancellationToken.None);Check(true,"Wake-up storm coalesced without blocking producer");
    Check(LocalApiContract.IsKnownCommand("subscribe")&&!LocalApiContract.IsKnownCommand("decrypt"),"Subscription is read-only, no privileged decrypt endpoint");
    CryptographicOperations.ZeroMemory(actualKey);
}
finally{Directory.Delete(dir,true);}
Console.WriteLine($"All {passed} offline recovery/framing tests passed. No live processes or drivers were inspected.");

static byte[] Encrypt(byte[] key,byte[] plain)
{
    byte[] nonce=RandomNumberGenerator.GetBytes(12),tag=new byte[16],cipher=new byte[plain.Length];
    using var aes=new AesGcm(key,16);aes.Encrypt(nonce,plain,cipher,tag);
    return "RGTEST03"u8.ToArray().Concat(nonce).Concat(tag).Concat(cipher).ToArray();
}
static byte[] MakeDump(byte[] key)
{
    // Minimal valid memory64 dump: headers + a captured method table + captured managed array.
    byte[] b=new byte[4096];
    void U32(int o,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o),v);
    void U64(int o,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o),v);
    U32(0,0x504D444D);U32(4,0xA793);U32(8,2);U32(12,32);
    U32(32,7);U32(36,2);U32(40,56);BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(56),9);
    U32(44,9);U32(48,48);U32(52,64);
    U64(64,2);U64(72,128);U64(80,0x10000);U64(88,16);U64(96,0x20000);U64(104,2048);
    U32(128,0x80080001);
    // Three wrong candidates followed by the actual candidate; no magic lab key marker.
    for(int i=0;i<4;i++)
    {
        int o=144+128+i*64;U64(o,0x10000);U32(o+8,32);
        (i==3?key:RandomNumberGenerator.GetBytes(32)).CopyTo(b,o+16);
    }
    return b;
}
sealed class FragmentedStream(Stream inner):Stream
{
    public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
    public override long Length=>inner.Length;public override long Position{get=>inner.Position;set=>throw new NotSupportedException();}
    public override int Read(byte[] b,int o,int n)=>inner.Read(b,o,Math.Min(n,1));
    public override ValueTask<int> ReadAsync(Memory<byte> b,CancellationToken token=default)=>inner.ReadAsync(b[..Math.Min(1,b.Length)],token);
    public override void Flush(){}public override long Seek(long o,SeekOrigin origin)=>throw new NotSupportedException();
    public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] b,int o,int n)=>throw new NotSupportedException();
}
