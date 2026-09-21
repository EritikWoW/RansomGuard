using System.Security.Cryptography;
namespace RansomGuard.Core;
public static class SampleMath
{
    public static double Entropy(ReadOnlySpan<byte> bytes)
    {
        if(bytes.IsEmpty) return 0;
        Span<int> counts=stackalloc int[256]; counts.Clear();
        foreach(var b in bytes) counts[b]++;
        double sum=0;
        foreach(var count in counts) if(count>0) {double p=(double)count/bytes.Length;sum-=p*Math.Log2(p);}
        return sum;
    }
    public static ContentSample Make(string path, byte[] bytes, long length) => new(path,
        Convert.ToHexString(SHA256.HashData(bytes)),Entropy(bytes),Convert.ToHexString(bytes.AsSpan(0,Math.Min(16,bytes.Length))),
        bytes.Length,length,DateTime.UtcNow);
}
