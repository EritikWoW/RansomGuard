using System.Buffers.Binary;
namespace RansomGuard.Recovery;

// Recognize complete FORWARD FIPS-197 schedules, with BE or byte-swapped uint32 words.
// Finding an AES schedule alone does not establish mode or that it belongs to an input file.
public static class AesSchedules
{
    private static readonly byte[] Sbox=BuildSbox();
    public static byte[]? Candidate(ReadOnlySpan<byte> data,int keyBytes,bool littleWords)
    {
        if(keyBytes is not (16 or 24 or 32))return null;
        int nk=keyBytes/4,words=4*(nk+7);
        if(data.Length<words*4)return null;
        if(Read(data,(nk+1)*4,littleWords)!=(Read(data,4,littleWords)^Read(data,nk*4,littleWords)) ||
           Read(data,(nk+2)*4,littleWords)!=(Read(data,8,littleWords)^Read(data,(nk+1)*4,littleWords)))return null;
        byte rc=1;
        for(int i=nk;i<words;i++)
        {
            uint temp=Read(data,(i-1)*4,littleWords);
            if(i%nk==0){temp=Sub((temp<<8)|(temp>>24))^((uint)rc<<24);rc=Xtime(rc);}
            else if(nk>6&&i%nk==4)temp=Sub(temp);
            if(Read(data,i*4,littleWords)!=(Read(data,(i-nk)*4,littleWords)^temp))return null;
        }
        var key=new byte[keyBytes];
        for(int i=0;i<nk;i++)BinaryPrimitives.WriteUInt32BigEndian(key.AsSpan(i*4),Read(data,i*4,littleWords));
        return key;
    }
    public static byte[] Expand(ReadOnlySpan<byte> key)
    {
        int nk=key.Length/4;if(key.Length is not(16 or 24 or 32))throw new ArgumentException("AES key size.");
        int words=4*(nk+7);var result=new byte[words*4];key.CopyTo(result);byte rc=1;
        for(int i=nk;i<words;i++)
        {
            uint temp=Read(result,(i-1)*4,false);
            if(i%nk==0){temp=Sub((temp<<8)|(temp>>24))^((uint)rc<<24);rc=Xtime(rc);}
            else if(nk>6&&i%nk==4)temp=Sub(temp);
            uint w=Read(result,(i-nk)*4,false)^temp;
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i*4),w);
        }
        return result;
    }
    private static uint Read(ReadOnlySpan<byte> b,int off,bool little)=>little?
        BinaryPrimitives.ReadUInt32LittleEndian(b[off..]):BinaryPrimitives.ReadUInt32BigEndian(b[off..]);
    private static uint Sub(uint w)=>(uint)Sbox[(int)(w>>24)]<<24|(uint)Sbox[(int)((w>>16)&255)]<<16|
        (uint)Sbox[(int)((w>>8)&255)]<<8|Sbox[(int)(w&255)];
    private static byte Xtime(byte x)=>(byte)((x<<1)^((x&128)!=0?0x11b:0));
    private static byte Multiply(byte a,byte b)
    {byte r=0;for(int i=0;i<8;i++){if((b&1)!=0)r^=a;a=Xtime(a);b>>=1;}return r;}
    private static byte[] BuildSbox()
    {
        var s=new byte[256];
        for(int x=0;x<256;x++)
        {
            byte y=0;if(x!=0){y=1;byte a=(byte)x;int power=254;while(power>0){if((power&1)!=0)y=Multiply(y,a);a=Multiply(a,a);power>>=1;}}
            int z=y;for(int n=1;n<=4;n++)z^=((y<<n)|(y>>(8-n)))&255;s[x]=(byte)(z^0x63);
        }
        return s;
    }
}
