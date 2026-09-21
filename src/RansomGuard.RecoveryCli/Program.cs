using System.Text;
using System.Text.Json;
using RansomGuard.Recovery;
// Offline recovery only. This executable never opens a live process or changes security settings.
if(args.Length!=6 || args[0]!="--dump" || args[2]!="--files" || args[4]!="--output")
{
    Console.WriteLine("RansomGuard independent dump recovery (supported format: RGTEST03 / AES-256-GCM)");
    Console.WriteLine("RansomGuard.Recovery.exe --dump process.dmp --files ENCRYPTED_DIRECTORY --output NEW_OUTPUT_DIRECTORY");
    Console.WriteLine("No recursion. Max 64 files, 1 MiB each; dump <=512 MiB. Original evidence and saved keys are never modified/read respectively.");
    return args.Length==0?0:2;
}
using var cancel=new CancellationTokenSource();
Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;cancel.Cancel();};
try
{
    string dump=Path.GetFullPath(args[1]),folder=Path.GetFullPath(args[3]),output=Path.GetFullPath(args[5]);
    SafeInput.NoLinks(folder);SafeInput.NoLinks(output);
    if(!Directory.Exists(folder))throw new IOException("Encrypted directory does not exist.");
    if(Directory.Exists(output)||File.Exists(output)||File.Exists(output+".report.json"))throw new IOException("Output already exists.");
    var files=Directory.EnumerateFiles(folder,"*.rglocked",SearchOption.TopDirectoryOnly).Take(RecoveryEngine.MaxFiles+1).Order(StringComparer.Ordinal).ToArray();
    var result=RecoveryEngine.Recover(dump,files,output,null,p=>Console.WriteLine($"{p.State}: {p.BytesScanned:N0} bytes; candidates={p.Candidates}; authenticated={p.Authenticated}/{p.Total}"),cancel.Token);
    var json=JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true});
    SafeInput.WriteNew(output+".report.json",Encoding.UTF8.GetBytes(json));
    Console.WriteLine(json);
    return result.WrittenFiles==result.SelectedFiles&&result.SelectedFiles>0?0:4;
}
catch(OperationCanceledException){Console.Error.WriteLine("Cancelled; any already verified new copies remain. Evidence is untouched.");return 5;}
catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or ArgumentException or System.ComponentModel.Win32Exception or System.Security.Cryptography.CryptographicException)
{Console.Error.WriteLine("Recovery refused/failed: "+ex.Message);return 3;}
