using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
// Only 10 generated fixtures; no arbitrary path, recursion, deletion, persistence or network access.
if(!OperatingSystem.IsWindows())return 1;
if(args.Length!=2 || args[0] is not ("--prepare" or "--run" or "--verify" or "--recover") ||
    !Guid.TryParseExact(args[1],"N",out var id))
{Console.Error.WriteLine("Use the provided lab runner. Arguments: --prepare|--run|--verify|--recover and a 32-character run GUID, NEVER a path.");return 2;}
var runId=id.ToString("N");
var folder=Path.Combine(AppContext.BaseDirectory,"RansomGuard-TestLab",runId);
try
{
    Safety.NoReparse(folder);
    var marker=Path.Combine(folder,".ransomguard-lab-v3");
    string Name(int i)=>$"RG_TEST_{i:00}.txt";
    byte[] Original(int i)
    {
        var text=$"RANSOMGUARD SYNTHETIC FIXTURE ONLY | {runId} | {i:00}\r\n";
        return Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(text+"Synthetic row: ABCDE 012345 test-only data.\r\n",128)));
    }
    void WriteNew(string path,byte[] bytes)
    {Safety.NoReparse(path);using var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);f.Write(bytes);f.Flush(true);}
    if(args[0]=="--prepare")
    {
        if(Directory.Exists(folder)||File.Exists(folder))throw new IOException("Run directory already exists; refusing to reuse or erase it.");
        Directory.CreateDirectory(folder);Safety.NoReparse(folder);
        WriteNew(marker,Encoding.ASCII.GetBytes(runId));
        for(var i=1;i<=10;i++)WriteNew(Path.Combine(folder,Name(i)),Original(i));
        WriteNew(Path.Combine(folder,"recovery-key.bin"),RandomNumberGenerator.GetBytes(32));
        Console.WriteLine("Prepared exactly 10 recoverable synthetic fixtures: "+folder);return 0;
    }
    if(!File.Exists(marker)||Encoding.ASCII.GetString(Safety.Read(marker,128))!=runId)throw new IOException("Missing/wrong lab marker.");
    var key=Safety.Read(Path.Combine(folder,"recovery-key.bin"),32);
    if(key.Length!=32)throw new IOException("Invalid lab recovery key.");
    try
    {
        if(args[0]=="--run")
        {
            Console.WriteLine("LAB ENCRYPTION: only the ten generated fixtures in "+folder);
            await Task.Delay(2000);
            for(var i=1;i<=10;i++)
            {
                var path=Path.Combine(folder,Name(i));var locked=path+".rglocked";
                Safety.NoReparse(path);Safety.NoReparse(locked);
                if(File.Exists(locked))throw new IOException("Refusing to overwrite an existing encrypted fixture.");
                using(var f=Safety.OpenExisting(path,FileAccess.ReadWrite))
                {
                    var original=Original(i);
                    if(f.Length!=original.Length)throw new IOException("Fixture size changed. Refusing to write.");
                    var plain=new byte[original.Length];f.ReadExactly(plain);
                    if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(plain),SHA256.HashData(original)))
                        throw new IOException("Fixture content is not our generated data. Refusing to encrypt.");
                    var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[plain.Length];
                    using(var aes=new AesGcm(key,16))aes.Encrypt(nonce,plain,cipher,tag);
                    var output=Encoding.ASCII.GetBytes("RGTEST03").Concat(nonce).Concat(tag).Concat(cipher).ToArray();
                    f.Position=0;
                    for(var offset=0;offset<output.Length;offset+=2048)
                    {f.Write(output,offset,Math.Min(2048,output.Length-offset));f.Flush(true);await Task.Delay(25);}
                    f.SetLength(output.Length);f.Flush(true);
                }
                File.Move(path,locked,false);
                Console.WriteLine($"[{i}/10] fixture encrypted: {Name(i)}");
                await Task.Delay(650);
            }
            Console.WriteLine("Fixture run complete. Recovery key is saved LOCALLY for THIS lab only; this is not a real ransomware decryptor.");
            await Task.Delay(1000);return 0;
        }
        var recovery=args[0]=="--recover"?Path.Combine(folder,"Recovered-"+Guid.NewGuid().ToString("N")):null;
        if(recovery is not null){Directory.CreateDirectory(recovery);Safety.NoReparse(recovery);}
        var encrypted=0;
        for(var i=1;i<=10;i++)
        {
            var plainPath=Path.Combine(folder,Name(i));var lockedPath=plainPath+".rglocked";byte[] plain;
            if(File.Exists(lockedPath))
            {
                var data=Safety.Read(lockedPath,65536);
                if(data.Length<36||Encoding.ASCII.GetString(data,0,8)!="RGTEST03")throw new IOException("Invalid encrypted fixture header.");
                plain=new byte[data.Length-36];
                using(var aes=new AesGcm(key,16))aes.Decrypt(data.AsSpan(8,12),data.AsSpan(36),data.AsSpan(20,16),plain);
                encrypted++;
            }
            else plain=Safety.Read(plainPath,65536);
            if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(plain),SHA256.HashData(Original(i))))
                throw new IOException("Fixture verification failed: "+Name(i));
            if(recovery is not null)WriteNew(Path.Combine(recovery,Name(i)),plain);
        }
        Console.WriteLine($"PASS: all 10 fixture SHA-256 values match their originals; {encrypted} decrypted.");
        if(recovery is not null)Console.WriteLine("Recovered COPIES (encrypted evidence preserved): "+recovery);
        return 0;
    }
    finally{GC.KeepAlive(key);CryptographicOperations.ZeroMemory(key);}
}
catch(Exception ex){Console.Error.WriteLine("LAB REFUSED/FAILED: "+ex.Message);return 10;}
internal static class Safety
{
    public static void NoReparse(string path)
    {
        for(var p=Path.GetFullPath(path);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p))
            if((Directory.Exists(p)||File.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Reparse points are not allowed in the synthetic lab.");
    }
    public static FileStream OpenExisting(string path,FileAccess access)
    {
        NoReparse(path);var f=new FileStream(path,FileMode.Open,access,FileShare.None);
        if(!GetFileInformationByHandle(f.SafeFileHandle,out var info)||info.Links!=1||(info.Attributes&0x400)!=0)
        {f.Dispose();throw new IOException("Cannot verify fixture ownership: hard link/reparse point/metadata error.");}
        return f;
    }
    public static byte[] Read(string path,int max)
    {
        using var f=OpenExisting(path,FileAccess.Read);
        if(f.Length>max)throw new IOException("Fixture exceeds safety size limit.");
        var bytes=new byte[(int)f.Length];f.ReadExactly(bytes);return bytes;
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
     public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfoNative info);
}
