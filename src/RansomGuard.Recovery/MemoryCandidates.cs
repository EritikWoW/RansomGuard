using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
namespace RansomGuard.Recovery;
public delegate bool CandidateVisitor(ReadOnlySpan<byte> candidate,string origin);
public sealed record ScanResult(long BytesScanned,int Candidates,bool FullScan,string StopReason);

public static class MemoryCandidates
{
    private static readonly int[] KeySizes = [16,24,32];
    private static readonly bool[] WordOrders = [false,true];
    public static ScanResult Scan(DumpMemory dump,CandidateVisitor visitor,CancellationToken token,
        Action<long,int>? progress=null,int maxCandidates=8192)
    {
        var seen=new HashSet<string>(StringComparer.Ordinal);
        var buffer=new byte[1024*1024+256];
        Span<byte> flags=stackalloc byte[4];
        long scanned=0;int candidates=0;var clock=Stopwatch.StartNew();var lastProgress=TimeSpan.Zero;
        bool Offer(ReadOnlySpan<byte> candidate,string origin)
        {
            if(!seen.Add(Convert.ToHexString(SHA256.HashData(candidate))))return false;
            candidates++;return visitor(candidate,origin);
        }
        try
        {
            foreach(var range in dump.Ranges)
            {
                for(int block=0;block<range.Length;)
                {
                    token.ThrowIfCancellationRequested();
                    if(clock.Elapsed>TimeSpan.FromSeconds(90))return new(scanned,candidates,false,"TimeLimit");
                    int main=Math.Min(1024*1024,range.Length-block);
                    int count=Math.Min(buffer.Length,range.Length-block);
                    dump.ReadInto(range.Offset+block,buffer.AsSpan(0,count));
                    int first=(int)((4-((range.Address+(ulong)block)&3))&3);
                    for(int off=first;off<main;off+=4)
                    {
                        if(((off-first)&16383)==0){token.ThrowIfCancellationRequested();if(clock.Elapsed>TimeSpan.FromSeconds(90))return new(scanned+off,candidates,false,"TimeLimit");}
                        var tail=buffer.AsSpan(off,count-off);
                        // CoreCLR x64 array layout is a HEURISTIC, not a memory-type proof.
                        // The candidate becomes a recovered key ONLY after authenticated decryption.
                        if(dump.Architecture==9 && ((range.Address+(ulong)block+(ulong)off)&7)==0 && tail.Length>=48)
                        {
                            uint size=BinaryPrimitives.ReadUInt32LittleEndian(tail[8..]);
                            if(size is 16 or 24 or 32 && BinaryPrimitives.ReadUInt32LittleEndian(tail[12..])==0)
                            {
                                ulong mt=BinaryPrimitives.ReadUInt64LittleEndian(tail);
                                if((mt&7)==0 && dump.TryReadVirtual(mt,flags))
                                {
                                    uint f=BinaryPrimitives.ReadUInt32LittleEndian(flags);
                                    if((f&0x800CFFFF)==0x80080001 && Offer(tail.Slice(16,(int)size),"CoreCLR-x64-byte-array-candidate"))
                                        return new(scanned+off,candidates,false,"AllSelectedFilesAuthenticated");
                                }
                            }
                        }
                        if(tail.Length>=176)
                        {
                            // Linear recurrence precheck inside Candidate makes random memory cheap to reject.
                            foreach(int keySize in KeySizes)
                            {
                                foreach(bool little in WordOrders)
                                {
                                    var key=AesSchedules.Candidate(tail,keySize,little);
                                    if(key is null)continue;
                                    try
                                    {
                                        if(Offer(key,little?"AES-forward-schedule-LE-words":"AES-forward-schedule-BE-words"))
                                            return new(scanned+off,candidates,false,"AllSelectedFilesAuthenticated");
                                    }
                                    finally{CryptographicOperations.ZeroMemory(key);}
                                }
                            }
                        }
                        if(candidates>=maxCandidates)return new(scanned+off,candidates,false,"CandidateLimit");
                    }
                    scanned+=main;block+=main;
                    if(clock.Elapsed-lastProgress>TimeSpan.FromMilliseconds(500))
                    {progress?.Invoke(scanned,candidates);lastProgress=clock.Elapsed;}
                }
            }
            return new(scanned,candidates,true,"EndOfCapturedMemory");
        }
        finally{CryptographicOperations.ZeroMemory(buffer);}
    }
}
