using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting.WindowsServices;
using RansomGuard.Core;
using RansomGuard.Rollback;
using RansomGuard.Service;
if(!OperatingSystem.IsWindows()){Console.Error.WriteLine("Windows 10/11 x64 is required for ETW and native security checks.");return 2;}
using(var me=WindowsIdentity.GetCurrent())
    if(!new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator)&&!me.IsSystem)
    {Console.Error.WriteLine("Run elevated. No process will be monitored or suspended without the required rights.");return 3;}
try
{
    // Cooperating UI recovery may not replace state between startup validation and instance ownership.
    using var stateMaintenance=StateMaintenanceGate.Acquire();
    var store=new SecureStore();
    if(args.Length>=1 && args[0]=="--rules")return ScopedRuleAdmin.Run(args[1..],store);
    if(args.Length==2&&args[0]=="--dump-helper")return DumpHelper.Run(args[1],store);
    if(args.Length==2&&args[0]=="--inspect")
    {
        Console.WriteLine(JsonSerializer.Serialize(new ImageInspector(store).Inspect(args[1],true),new JsonSerializerOptions{WriteIndented=true}));return 0;
    }
    if(args.Length==1&&args[0]=="--native-selftest")
    {
        using var h=Native.OpenProcess(Native.Query|Native.Synchronize,false,Environment.ProcessId);
        var k=Native.Identity(h,Environment.ProcessId);
        var image=new ImageInspector(store).Inspect(Environment.ProcessPath,true);
        var ok=k is not null&&image.Status=="Hashed"&&Native.IsProcessCritical(h,out _);
        Console.WriteLine(JsonSerializer.Serialize(new{Ok=ok,Identity=k,Image=image,Note="Read-only native smoke test; no suspend or dump."},new JsonSerializerOptions{WriteIndented=true}));return ok?0:4;
    }
    var isLab=args.Length==1&&(args[0]=="--lab"||args[0]=="--lab-full-dump");
    if(args.Length>0&&!isLab){Console.Error.WriteLine("Usage: no arguments (audit), --lab, --lab-full-dump, --inspect PATH, --native-selftest");return 5;}
    if(isLab&&WindowsServiceHelpers.IsWindowsService())throw new InvalidOperationException("Lab mode must not be installed as a service.");
    using var mutex=new Mutex(false,@"Global\RansomGuardV03-Instance");
    bool locked;
    try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
    if(!locked)throw new InvalidOperationException("Another v0.3 instance is active. Stop its audit console/service before the lab test.");
    stateMaintenance.Dispose(); // Instance mutex now prevents recovery during the service lifetime.
    try
    {
        var configPath=Path.Combine(AppContext.BaseDirectory,"appsettings.json");FileSafety.NoReparse(configPath);
        if(new FileInfo(configPath).Length>65536)throw new IOException("Configuration exceeds size limit.");
        var settings=JsonSerializer.Deserialize<GuardSettings>(File.ReadAllText(configPath),
            new JsonSerializerOptions{UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow})
            ??throw new InvalidOperationException("Missing settings.");
        settings.Validate();
        if(settings.ProtectedRoots.Length==0)
        {
            if(WindowsServiceHelpers.IsWindowsService())throw new InvalidOperationException("Set explicit ProtectedRoots before installing the service. It must not guess the active user's folders.");
            settings.ProtectedRoots=new[]{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Downloads")}
                .Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        // Initialize and verify the durable rollback store before monitoring starts.
        // No pre-image is captured yet in the normal 0.7.1.0 bundle because the production minifilter
        // write gate is intentionally not enabled until Windows VM validation is complete.
        var rollbackRepository=new RollbackRepository(store.Rollback);
        rollbackRepository.VerifyAll();

        var protection=new ProtectionStateMachine(settings.Mode);
        protection.MarkRollbackReady();
        ProtectionPackageAdmission? protectionPackage=null;
        if(string.Equals(settings.Mode,"Enforce",StringComparison.Ordinal))
        {
            protectionPackage=ProtectionPackageVerifier.Inspect(AppContext.BaseDirectory,ProductInfo.Version);
            protection.MarkUnavailable("Protection package admission: "+protectionPackage.Reason);
        }
        store.Audit(new{
            Type="RollbackStoreReady",Utc=DateTime.UtcNow,Root=store.Rollback,
            Sessions=rollbackRepository.SessionIds().Length,RequestedMode=settings.Mode,
            Protection=protection.Snapshot(),ProtectionPackage=protectionPackage
        });
        using var lab=isLab?new LabSession(args[0]=="--lab-full-dump"):null;
        var samples=new ContentSampler();
        foreach(var file in settings.CanaryFiles)
        {
            if(!settings.ProtectedRoots.Any(r=>WinPaths.Under(file,r)))throw new InvalidOperationException("Canary must lie inside an explicit monitored root.");
            samples.Register(file); // Existing opt-in files only. Never creates files in other profiles.
        }
        if(lab is not null)
        {
            lab.Prepare(CancellationToken.None).GetAwaiter().GetResult();
            settings.ProtectedRoots=settings.ProtectedRoots.Append(lab.Folder).ToArray();
            foreach(var file in lab.FixturePaths())samples.Register(file);
        }
        // Baseline fixture samples are not canaries: register only configured canaries in RiskEngine.
        var builder=Host.CreateApplicationBuilder(new HostApplicationBuilderSettings{Args=Array.Empty<string>(),ContentRootPath=AppContext.BaseDirectory});
        builder.Services.AddWindowsService(o=>o.ServiceName="RansomGuardV03");
        var runtime=new RuntimeState(protection.Snapshot());
        builder.Services.AddSingleton(runtime);
        var scopedTrust=new ScopedTrustCoordinator(store,runtime);
        builder.Services.AddHostedService(sp=>new ScopedTrustPublisher(scopedTrust));
        builder.Services.AddHostedService(sp=>new GuardWorker(sp.GetRequiredService<ILogger<GuardWorker>>(),
            sp.GetRequiredService<IHostApplicationLifetime>(),settings,store,new ImageInspector(store),samples,lab,runtime,scopedTrust));
        builder.Services.AddHostedService(sp=>new ReadOnlyPipeServer(sp.GetRequiredService<ILogger<ReadOnlyPipeServer>>(),runtime,settings));
        using var host=builder.Build();
        host.Run();return Environment.ExitCode; // Keep mutex ownership on the main thread; Mutex is thread-affine.
    }
    finally{mutex.ReleaseMutex();}
}
catch(Exception ex){Console.Error.WriteLine("RansomGuard stopped safely: "+ex);return 1;}
