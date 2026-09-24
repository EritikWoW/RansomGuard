using RansomGuard.Core;
var count=0;
void Check(bool yes,string name){if(!yes)throw new Exception("FAIL: "+name);count++;Console.WriteLine("PASS: "+name);}
var now=DateTime.UtcNow;
var key=new ProcessKey(1234,now.AddSeconds(-10).ToFileTimeUtc());
var hash=new string('A',64);var path=@"C:\RG\Simulator\RansomGuard.Simulator.exe";
var risk=new RiskSignal(key,"firefox.exe",path,now,now,0,200,100,20,20,10,true,false,Array.Empty<string>(),Array.Empty<FileSignal>());
var image=new ImageEvidence(path,hash,1,"Hashed",new("ValidCached","0", "Mozilla Corporation",null),"ReviewedTrusted",now,null);
var lab=new LabIdentity(key,path,hash,now.AddSeconds(30));
ActionDecision D(RiskSignal? r=null,ImageEvidence? i=null,LabIdentity? l=null,bool live=true,bool known=true,bool critical=false,bool healthy=true)
    =>DecisionPolicy.Decide(r??risk,i??image,l??lab,live,known,critical,healthy,now);
Check(!DecisionPolicy.Decide(risk,image,null,true,true,false,true,now).AllowLabSuspend,"no lab enrollment: no suspend even for a canary");
Check(D().AllowLabSuspend,"exact lab PID + creation + path + fresh hash accepted");
Check(!D(r:risk with{Process=key with{Pid=999}}).AllowLabSuspend,"different PID rejected");
Check(!D(r:risk with{Process=key with{CreationFileTimeUtc=key.CreationFileTimeUtc+1}}).AllowLabSuspend,"reused PID rejected");
Check(!D(l:lab with{ExpiresUtc=now.AddSeconds(-1)}).AllowLabSuspend,"expired enrollment rejected");
Check(!D(live:false).AllowLabSuspend,"unverified live identity rejected");
Check(!D(known:false).AllowLabSuspend,"unknown critical status rejected");
Check(!D(critical:true).AllowLabSuspend,"critical process rejected");
Check(!D(healthy:false).AllowLabSuspend,"telemetry loss rejects action");
Check(!D(r:risk with{TruncatedWindow=true}).AllowLabSuspend,"truncated evidence rejected");
Check(!D(r:risk with{DeliveryLagMs=4000}).AllowLabSuspend,"old ETW buffer rejected");
Check(!D(r:risk with{DeliveryLagMs=-1}).AllowLabSuspend,"invalid event chronology rejected");
var delayedEvidence=new[]{new FileSignal(now.AddSeconds(-4),now.AddMilliseconds(-500),key,"sim.exe",path,@"C:\Data\a.txt",FileKind.Write)};
var delayedRisk=risk with{DeliveryLagMs=10,Evidence=delayedEvidence};
Check(delayedRisk.MaxEvidenceDeliveryLagMs>3000,"risk computes maximum evidence delivery lag");
Check(!D(r:delayedRisk).AllowLabSuspend,"old evidence inside window rejects lab action even when last event is fresh");
Check(!D(r:risk with{LastEventUtc=now.AddSeconds(-20)}).AllowLabSuspend,"stale decision rejected");
Check(!D(r:risk with{LastEventUtc=now.AddSeconds(20)}).AllowLabSuspend,"future event chronology rejected");
Check(!D(i:image with{Sha256=new string('B',64)}).AllowLabSuspend,"changed executable hash rejected");
Check(!D(i:image with{Sha256=null}).AllowLabSuspend,"missing executable hash rejected");
Check(!D(i:image with{Status="HashedCached"}).AllowLabSuspend,"cached hash insufficient for intervention");
Check(!D(i:image with{Path=@"C:\RG\SimulatorFake\RansomGuard.Simulator.exe"}).AllowLabSuspend,"lookalike directory rejected");
Check(!D(r:risk with{ImagePath=@"C:\Users\User\Downloads\firefox.exe"}).AllowLabSuspend,"renamed downloaded image rejected");
Check(DecisionPolicy.Priority(risk,image,true).StartsWith("UrgentReview"),"trusted hash cannot hide confirmed canary change");
Check(DecisionPolicy.Priority(risk,image with{LocalDisposition="BlockedByAdministrator"},false).StartsWith("UrgentReview"),"exact local deny escalates alert");
Check(!DecisionPolicy.Decide(risk,image with{LocalDisposition="BlockedByAdministrator"},null,true,true,false,true,now).AllowLabSuspend,"local deny not a kill switch");
Check(DecisionPolicy.HashEqual(hash,hash.ToLowerInvariant()),"SHA-256 matching case independent");
Check(!DecisionPolicy.HashEqual(new string('G',64),hash),"invalid hexadecimal rejected");
Check(!DecisionPolicy.HashEqual(new string('A',32),hash),"MD5-length digest rejected");
Check(!DecisionPolicy.HashEqual(null,null),"missing hashes never match");
Check(WinPaths.Equal(@"\\?\C:\Data\test.txt",@"c:\data\test.txt"),"DOS extended namespace normalized");
Check(WinPaths.Equal(@"\??\C:\Data\test.txt",@"C:\Data\test.txt"),"NT DOS namespace normalized");
Check(!WinPaths.Under(@"C:\Data2\test.txt",@"C:\Data"),"root boundary enforced");
Check(WinPaths.Under(@"C:\Data\sub\test.txt",@"C:\Data"),"nested root accepted");
Check(!WinPaths.Under(@"C:\Data\..\Elsewhere\test.txt",@"C:\Data"),"directory traversal normalized then rejected");
Check(WinPaths.Normalize(@"\\server\share\test.txt") is null,"network paths not silently treated as local");
Check(WinPaths.Normalize(@"C:\test.txt:stream") is null,"alternate data stream rejected");
Check(WinPaths.Normalize(@"C:\Data\test. ") is null,"ambiguous trailing dots/spaces rejected");
Check(WinPaths.Normalize(@"\Device\HarddiskVolume3\Data\test.txt") is null,"unresolved device path never guessed");
Check(Math.Abs(SampleMath.Entropy(new byte[128]))<0.000001,"zero entropy measured");
Check(Math.Abs(SampleMath.Entropy(Enumerable.Range(0,256).Select(i=>(byte)i).ToArray())-8)<0.000001,"uniform entropy measured");
Check(SampleMath.Entropy(Array.Empty<byte>())==0,"empty sample handled");
var timingEvidence=new[]{new FileSignal(now.AddSeconds(-2),now.AddSeconds(-1),key,"sim.exe",path,@"C:\Data\a.txt",FileKind.Write),
    new FileSignal(now.AddMilliseconds(-500),now.AddMilliseconds(-250),key,"sim.exe",path,@"C:\Data\b.txt",FileKind.Rename)};
var timingRisk=risk with{Evidence=timingEvidence};
Check(timingRisk.FirstEvidenceToDecisionMs>=1900&&timingRisk.FirstEvidenceToDecisionMs<=2100,"first evidence to decision timing derived from evidence");
Check(timingRisk.P95EvidenceDeliveryLagMs>=900,"evidence p95 delivery lag derived from evidence");
var s=new GuardSettings{MaxProcesses=8,MaxEventsPerProcess=32};s.Validate();
var rejected=false;try{new GuardSettings{Mode="Kill"}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"unsupported protection mode not silently imported");
rejected=false;try{new GuardSettings{SchemaVersion=3}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"pre-0.8 schema rejected until reviewed");
var enforceSettings=new GuardSettings{Mode="Enforce",ProtectedRoots=new[]{@"C:\Data"}};
enforceSettings.Validate();
Check(true,"single-root Enforce foundation settings accepted");
rejected=false;try{new GuardSettings{Mode="Enforce",ProtectedRoots=Array.Empty<string>()}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"Enforce requires an explicit protected root");
rejected=false;try{new GuardSettings{Mode="Enforce",ProtectedRoots=new[]{@"C:\Data",@"D:\Data"}}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"unqualified multi-root Enforce rejected");
rejected=false;try{new GuardSettings{Mode="Enforce",ProtectedRoots=new[]{@"C:\"}}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"whole-drive Enforce root rejected");
rejected=false;try{new GuardSettings{Mode="Enforce",ProtectedRoots=new[]{@"C:\Data"},Enforce=new(){RequireSignedDriver=false}}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"Enforce cannot disable signed-driver requirement");
rejected=false;try{new GuardSettings{Mode="Enforce",ProtectedRoots=new[]{@"C:\Data"},Enforce=new(){AutomaticContainment=true}}.Validate();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"automatic containment stays disabled in 0.8.0 foundation");

var auditProtection=new ProtectionStateMachine("Audit");
var auditSnapshot=auditProtection.Snapshot();
Check(auditSnapshot.State=="AuditOnly"&&!auditSnapshot.KernelEnforcementActive,"Audit state never claims kernel enforcement");
rejected=false;try{auditProtection.BeginKernelStartup();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"Audit mode cannot enter kernel startup");

var enforceProtection=new ProtectionStateMachine("Enforce");
Check(enforceProtection.Snapshot().State=="EnforceStarting"&&!enforceProtection.Snapshot().KernelEnforcementActive,
    "Enforce request starts non-protected");
rejected=false;try{enforceProtection.MarkDegraded("invalid");}catch(InvalidOperationException){rejected=true;}
Check(rejected,"unactivated Enforce cannot forge DegradedProtected enforcement");
rejected=false;try{enforceProtection.BeginMaintenance("invalid");}catch(InvalidOperationException){rejected=true;}
Check(rejected,"unactivated Enforce cannot enter Maintenance");
rejected=false;try{enforceProtection.BeginKernelStartup();}catch(InvalidOperationException){rejected=true;}
Check(rejected,"kernel startup requires rollback readiness");
enforceProtection.MarkRollbackReady();
enforceProtection.BeginKernelStartup();
enforceProtection.MarkKernelConnected();
Check(!enforceProtection.Snapshot().KernelEnforcementActive,"connected kernel channel alone is not protection");
enforceProtection.MarkProtected();
Check(enforceProtection.Snapshot().KernelEnforcementActive&&enforceProtection.Snapshot().State=="Protected",
    "only activated protection state claims kernel enforcement");
enforceProtection.MarkDegraded("GateClient unavailable; kernel fail-safe remains active.");
Check(enforceProtection.Snapshot().KernelEnforcementActive&&!enforceProtection.Snapshot().KernelChannelConnected,
    "DegradedProtected preserves kernel enforcement without a live user-mode channel");
enforceProtection.BeginMaintenance("Authorized maintenance transition.");
Check(!enforceProtection.Snapshot().KernelEnforcementActive&&enforceProtection.Snapshot().State=="Maintenance",
    "maintenance does not claim active kernel enforcement");

var unavailableProtection=new ProtectionStateMachine("Enforce");
unavailableProtection.MarkRollbackReady();
unavailableProtection.MarkUnavailable("Production lifecycle not activated.");
Check(unavailableProtection.Snapshot().State=="EnforceUnavailable"&&!unavailableProtection.Snapshot().KernelEnforcementActive,
    "EnforceUnavailable is explicit and never downgraded to a protected claim");
rejected=false;try{
    ProtectionStateMachine.ValidateSnapshot(unavailableProtection.Snapshot() with { KernelEnforcementActive=true });
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"inconsistent published kernel-enforcement claim rejected");
rejected=false;try{
    ProtectionStateMachine.ValidateSnapshot(new ProtectionStatusDto("Enforce","Protected",true,false,true,false,"invalid",now));
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"Protected claim requires a connected kernel channel");
rejected=false;try{
    ProtectionStateMachine.ValidateSnapshot(new ProtectionStatusDto("Enforce","AuditOnly",true,false,false,false,"invalid downgrade",now));
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"Enforce request cannot silently downgrade to AuditOnly");
rejected=false;try{
    ProtectionStateMachine.ValidateSnapshot(new ProtectionStatusDto("Enforce","Protected",true,true,true,true,"invalid containment claim",now));
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"foundation cannot publish automatic containment even in Protected state");

var productionHash=new string('A',64);
var productionPackage=new ProtectionPackageDescriptor(
    1,"ProductionProtection","0.8.1.0",17,"RansomGuard","385201",
    productionHash,productionHash,productionHash,productionHash);
ProtectionPackagePolicy.ValidateDescriptor(productionPackage,"0.8.1.0");
Check(true,"production protection package descriptor accepted");
rejected=false;try{
    ProtectionPackagePolicy.ValidateDescriptor(productionPackage with{Altitude=ProtectionPackagePolicy.LabPlaceholderAltitude},"0.8.1.0");
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"LAB placeholder altitude rejected from production package");
rejected=false;try{
    ProtectionPackagePolicy.ValidateDescriptor(productionPackage with{Provider="RansomGuard Lab"},"0.8.1.0");
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"LAB provider rejected from production package");
rejected=false;try{
    ProtectionPackagePolicy.ValidateDescriptor(productionPackage with{Protocol=16},"0.8.1.0");
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"wrong protection package protocol rejected");
rejected=false;try{
    ProtectionPackagePolicy.ValidateDescriptor(productionPackage with{DriverSysSha256="not-a-hash"},"0.8.1.0");
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"malformed protection package hash rejected");
rejected=false;try{
    ProtectionPackagePolicy.ValidateDescriptor(productionPackage,"0.8.0.0");
}catch(InvalidOperationException){rejected=true;}
Check(rejected,"protection package version mismatch rejected");

var root=@"C:\Data";var canary=@"C:\Data\canary.txt";
RiskEngine NewEngine()=>new(s,new[]{root},new[]{canary});
FileSignal E(string p,FileKind kind,int ms=0,ProcessKey? pk=null)=>new(now.AddMilliseconds(ms),now.AddMilliseconds(ms),pk??key,"anything.exe",path,p,kind);
var engine=NewEngine();
for(int i=0;i<50;i++)Check(engine.Evaluate(E(canary,FileKind.Open,i)) is null,"canary open not mutation "+i);
Check(engine.Evaluate(E(@"C:\Other\canary.txt",FileKind.Write)) is null,"matching canary basename outside registration not trusted");
Check(engine.Evaluate(E(@"C:\Cache\cache.json",FileKind.Write)) is null,"file outside configured roots not scored");
var canaryRisk=engine.Evaluate(E(canary,FileKind.Write));
Check(canaryRisk?.CanaryCandidate==true,"exact canary write raises candidate (not proof)");
Check(engine.Evaluate(E(canary,FileKind.Write,1)) is null,"incident rate limited");
Check(engine.Evaluate(E(canary,FileKind.Write,2,key with{CreationFileTimeUtc=key.CreationFileTimeUtc+1})) is not null,"PID generations have separate windows");
engine=NewEngine();RiskSignal? triggered=null;
for(var i=1;i<=3;i++)
{
    var testFile=root+@"\f"+i+".txt";
    for(var w=0;w<5;w++)triggered=engine.Evaluate(E(testFile,FileKind.Write,i*10+w))??triggered;
    triggered=engine.Evaluate(E(testFile,FileKind.Rename,i*10+6))??triggered;
}
Check(triggered is not null,"multi-file write/rename produces review candidate");
var normalEngine=NewEngine();var labEngine=NewEngine();RiskSignal? normalFast=null;RiskSignal? labFast=null;
for(var i=1;i<=2;i++)
{
    var testFile=root+@"\lab"+i+".txt";
    for(var w=0;w<4;w++)
    {
        var signal=E(testFile,FileKind.Write,i*20+w);
        normalFast=normalEngine.Evaluate(signal,false)??normalFast;
        labFast=labEngine.Evaluate(signal,true)??labFast;
    }
    var rename=E(testFile,FileKind.Rename,i*20+10);
    normalFast=normalEngine.Evaluate(rename,false)??normalFast;
    labFast=labEngine.Evaluate(rename,true)??labFast;
}
Check(normalFast is null,"lab fast threshold does not apply to ordinary audit evaluation");
Check(labFast is not null&&labFast.Reasons.Any(x=>x.Contains("LAB ONLY",StringComparison.Ordinal)),"lab-only fast threshold can trigger synthetic child earlier");
engine=NewEngine();for(var i=0;i<20;i++)engine.Evaluate(E(canary,FileKind.Write,i,new ProcessKey(100+i,key.CreationFileTimeUtc)));
Check(engine.ProcessCount<=8&&engine.WindowEvictions>0,"global process windows bounded");
engine.Expire(now.AddMinutes(3));Check(engine.ProcessCount==0,"idle process state expires");
engine=NewEngine();for(var i=0;i<60;i++)engine.Evaluate(E(@"C:\Data\f.txt",FileKind.Write,i));
Check(engine.TruncatedWindows>0,"per-process event windows bounded");
Check(LocalApiContract.IsKnownCommand(LocalApiContract.StatusCommand)&&LocalApiContract.IsKnownCommand(LocalApiContract.IncidentsCommand)&&LocalApiContract.IsKnownCommand(LocalApiContract.DiagnosticsCommand),"read-only local API commands recognized");
Check(!LocalApiContract.IsKnownCommand("terminate")&&!LocalApiContract.IsKnownCommand("suspend")&&!LocalApiContract.IsKnownCommand("trust"),"mutating local API commands rejected");
Check(LocalApiContract.ClampIncidentLimit(0)==25&&LocalApiContract.ClampIncidentLimit(500)==50&&LocalApiContract.ClampIncidentLimit(1)==1,"local API incident limit bounded");
var etwFailure = MonitoringHealth.Failed(
    new System.Runtime.InteropServices.COMException("test", unchecked((int)0x800705AA)), "test-session", now);
Check(etwFailure.Win32Error == 1450 && etwFailure.ErrorCode == "0x800705AA", "ETW HRESULT is mapped to Win32 1450");
Check(etwFailure.State == "Failed" && !MonitoringHealth.IsRunning(etwFailure), "ETW startup error is not a running monitor");
Check(MonitoringHealth.ProtectionMode(etwFailure) == "MonitoringUnavailable", "ETW failure never reports AuditOnly monitoring");
Check(MonitoringHealth.ProtectionMode(new("Starting", now, "test-session")) == "MonitoringUnavailable", "starting monitor is not active");
Check(MonitoringHealth.ProtectionMode(new("Running", now, "test-session")) == "AuditOnly", "only running monitor reports audit availability");
Check(!MonitoringHealth.IsRunning(null), "missing monitor status is unknown, not active");
Check(!MonitoringHealth.IsRunning(new("Stopped", now, "test-session")), "stopped ETW is not active");
Check(MonitoringHealth.Win32Code(new System.ComponentModel.Win32Exception(1450)) == 1450, "native Win32 resource error is recognized");
Check(MonitoringHealth.Win32Code(new InvalidOperationException("test")) is null, "non-Win32 exception is not misclassified");
Check(MonitoringHealth.IsOperationalFailure(new System.Runtime.InteropServices.COMException("test", unchecked((int)0x800705AA))), "ETW resource failure can preserve diagnostics");
Check(!MonitoringHealth.IsOperationalFailure(new NullReferenceException("test")), "programming errors retain default host-failure behavior");
Check(!MonitoringHealth.IsOperationalFailure(new OutOfMemoryException("test")), "managed out-of-memory is not swallowed");
var healthRoundTrip = System.Text.Json.JsonSerializer.Deserialize<MonitoringHealthDto>(
    System.Text.Json.JsonSerializer.Serialize(etwFailure));
Check(healthRoundTrip == etwFailure, "ETW failed status round-trips without losing error identity");
Console.WriteLine($"All {count} policy tests passed. These are not Windows ETW/Authenticode integration tests.");
