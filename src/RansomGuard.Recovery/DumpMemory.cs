using System.Buffers.Binary;
namespace RansomGuard.Recovery;
public readonly record struct MemoryRange(ulong Address,long Offset,int Length);

// Strict, bounded parser for minidump memory streams; never loads modules from a dump.
public sealed class DumpMemory : IDisposable
{
    public const long MaxDumpBytes=512L*1024*1024;
    private readonly FileStream _stream;
    public IReadOnlyList<MemoryRange> Ranges { get; }
    public ushort Architecture { get; }
    public long Length => _stream.Length;
    public DumpMemory(string path)
    {
        _stream=SafeInput.OpenRead(path,MaxDumpBytes);
        try
        {
            byte[] header=Read(0,32);
            if(BinaryPrimitives.ReadUInt32LittleEndian(header)!=0x504D444D)throw new IOException("Not a Windows minidump.");
            uint count=U32(header,8),directory=U32(header,12);
            if(count is 0 or >1024)throw new IOException("Invalid dump stream count.");
            Check(directory,count*12L);
            (uint Size,uint Rva)? full=null,mini=null;
            ushort architecture=ushort.MaxValue;
            for(int i=0;i<count;i++)
            {
                var d=Read(directory+12L*i,12);uint type=U32(d,0),size=U32(d,4),rva=U32(d,8);
                Check(rva,size);
                if(type==9){if(full is not null)throw new IOException("Duplicate memory64 stream.");full=(size,rva);}
                if(type==5){if(mini is not null)throw new IOException("Duplicate memory stream.");mini=(size,rva);}
                if(type==7&&size>=2)architecture=BinaryPrimitives.ReadUInt16LittleEndian(Read(rva,2));
            }
            Architecture=architecture;
            var ranges=new List<MemoryRange>();
            if(full is { } f)
            {
                if(f.Size<16)throw new IOException("Short memory64 list.");
                byte[] list=Read(f.Rva,16);ulong n=U64(list,0),offset=U64(list,8);
                if(n is 0 or >65536||16+n*16>f.Size||offset>long.MaxValue)throw new IOException("Bad memory64 descriptors.");
                for(ulong i=0;i<n;i++)
                {
                    var d=Read(f.Rva+16+(long)i*16,16);ulong addr=U64(d,0),size=U64(d,8);
                    if(size>int.MaxValue||offset>long.MaxValue||addr>ulong.MaxValue-size)throw new IOException("Memory range overflow.");
                    Check((long)offset,(long)size);if(size>0)ranges.Add(new(addr,(long)offset,(int)size));offset+=size;
                }
            }
            else if(mini is { } m)
            {
                if(m.Size<4)throw new IOException("Short memory list.");
                uint n=U32(Read(m.Rva,4),0);
                if(n is 0 or >65536||4L+n*16L>m.Size)throw new IOException("Bad memory descriptors.");
                for(int i=0;i<n;i++)
                {
                    var d=Read(m.Rva+4+16L*i,16);ulong addr=U64(d,0);uint size=U32(d,8),ptr=U32(d,12);
                    if(size>int.MaxValue||addr>ulong.MaxValue-size)throw new IOException("Memory range overflow.");
                    Check(ptr,size);if(size>0)ranges.Add(new(addr,ptr,(int)size));
                }
            }
            else throw new IOException("Dump has no supported captured memory stream.");
            ranges.Sort((a,b)=>a.Address.CompareTo(b.Address));long total=0;
            for(int i=0;i<ranges.Count;i++)
            {
                total+=ranges[i].Length;
                if(total>MaxDumpBytes)throw new IOException("Captured memory exceeds scan limit.");
                if(i>0 && ranges[i-1].Address+(ulong)ranges[i-1].Length>ranges[i].Address)
                    throw new IOException("Overlapping virtual memory descriptors rejected.");
            }
            Ranges=ranges;
        }
        catch{_stream.Dispose();throw;}
    }
    public byte[] Read(long offset,int length)
    {Check(offset,length);var data=new byte[length];ReadInto(offset,data);return data;}
    public void ReadInto(long offset,Span<byte> data)
    {
        Check(offset,data.Length);int done=0;
        while(done<data.Length)
        {int n=RandomAccess.Read(_stream.SafeFileHandle,data[done..],offset+done);if(n==0)throw new EndOfStreamException();done+=n;}
    }
    public bool TryReadVirtual(ulong address,Span<byte> data)
    {
        int lo=0,hi=Ranges.Count-1;
        while(lo<=hi)
        {
            int mid=lo+(hi-lo)/2;var r=Ranges[mid];
            if(address<r.Address){hi=mid-1;continue;}
            ulong delta=address-r.Address;
            if(delta>=(ulong)r.Length){lo=mid+1;continue;}
            if((ulong)data.Length>(ulong)r.Length-delta)return false;
            ReadInto(r.Offset+(long)delta,data);return true;
        }
        return false;
    }
    private void Check(long offset,long length)
    {if(offset<0||length<0||offset>_stream.Length||length>_stream.Length-offset)throw new IOException("Dump range is outside the input file.");}
    private static uint U32(byte[] b,int i)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i));
    private static ulong U64(byte[] b,int i)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i));
    public void Dispose()=>_stream.Dispose();
}
