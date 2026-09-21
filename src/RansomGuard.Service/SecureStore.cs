using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
namespace RansomGuard.Service;
internal static class FileSafety
{
    public static void NoReparse(string path)
    {
        var full=Path.GetFullPath(path);
        for(var current=full; !string.IsNullOrEmpty(current); current=Path.GetDirectoryName(current))
            if((File.Exists(current)||Directory.Exists(current)) && (File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Reparse point is not allowed here: "+current);
    }
}
internal sealed class SecureStore
{
    public string Root {get;}
    public string Cases=>Path.Combine(Root,"Incidents");
    public string Rollback=>Path.Combine(Root,"Rollback");
    private readonly object _gate=new();
    private static readonly JsonSerializerOptions Json=new(){WriteIndented=true};
    private const string TrustedMarkerName = ".ransomguard-state-v1";
    public SecureStore()
    {
        using var maintenance = RansomGuard.Core.StateMaintenanceGate.Acquire();
        Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"RansomGuardV03");
        bool existed = Directory.Exists(Root);
        string marker = Path.Combine(Root, TrustedMarkerName);
        if (existed)
        {
            FileSafety.NoReparse(Root);
            FileSafety.NoReparse(marker);
            if (!File.Exists(marker))
                throw new UnauthorizedAccessException("Existing state directory has no trusted generation marker. Use the RansomGuard setup recovery flow; old content is not reused automatically.");
        }
        EnsureDirectory(Root);
        if (!existed)
        {
            FileSafety.NoReparse(marker);
            using var markerFile = new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(markerFile, new System.Text.UTF8Encoding(false), 1024, leaveOpen: true);
            writer.Write("RansomGuard state generation v1"); writer.Flush(); markerFile.Flush(true);
            FileSafety.NoReparse(marker);
        }
        EnsureDirectory(Cases);
        EnsureDirectory(Rollback);
    }
    public static void EnsureDirectory(string path)
    {
        FileSafety.NoReparse(path);
        var admins=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var dir=new DirectoryInfo(path);
        if(dir.Exists)
        {
            var existing=dir.GetAccessControl();
            var ownerRef=existing.GetOwner(typeof(SecurityIdentifier));
            if(ownerRef is not SecurityIdentifier owner)
                throw new UnauthorizedAccessException("Unable to resolve state directory owner as a SID: "+path);
            if(!owner.Equals(admins)&&!owner.Equals(system))
                throw new UnauthorizedAccessException("Refusing an existing state directory owned by another identity: "+path+
                    ". Do not weaken the ACL check. Run inspect_state_acl.cmd, then repair_state_store.cmd if this is an old test store.");
            foreach(FileSystemAccessRule rule in existing.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            {
                const FileSystemRights writes=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.WriteAttributes|FileSystemRights.WriteExtendedAttributes|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership|FileSystemRights.DeleteSubdirectoriesAndFiles;
                if(rule.AccessControlType==AccessControlType.Allow && (rule.FileSystemRights&writes)!=0 &&
                    !rule.IdentityReference.Equals(admins)&&!rule.IdentityReference.Equals(system))
                    throw new UnauthorizedAccessException("State directory is writable by another principal (SID="+rule.IdentityReference.Value+
                        ", rights="+rule.FileSystemRights+"). Refusing to reuse it: "+path+
                        ". Run inspect_state_acl.cmd, then repair_state_store.cmd. The repair quarantines old state instead of trusting or silently rewriting it.");
            }
        }
        using var caller=WindowsIdentity.GetCurrent();
        var acl=new DirectorySecurity(); acl.SetAccessRuleProtection(true,false); acl.SetOwner(caller.IsSystem?system:admins);
        foreach(var sid in new[]{admins,system}) acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        if(!dir.Exists) dir.Create(acl); else dir.SetAccessControl(acl);
        // Validate the object actually created, including a concurrent create by another principal.
        FileSafety.NoReparse(path);dir.Refresh();
        var applied=dir.GetAccessControl();
        var appliedOwnerRef=applied.GetOwner(typeof(SecurityIdentifier));
        if(appliedOwnerRef is not SecurityIdentifier appliedOwner)
            throw new UnauthorizedAccessException("Unable to resolve applied state directory owner as a SID.");
        if(!appliedOwner.Equals(admins)&&!appliedOwner.Equals(system))
            throw new UnauthorizedAccessException("State directory owner changed during initialization.");
        foreach(FileSystemAccessRule rule in applied.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && !rule.IdentityReference.Equals(admins)&&!rule.IdentityReference.Equals(system))
                throw new UnauthorizedAccessException("State directory ACL is broader than the required private ACL.");
    }
    public string NewCase(int limit)
    {
        lock(_gate)
        {
            if(Directory.EnumerateDirectories(Cases).Take(limit).Count()>=limit)
                throw new IOException("Incident quota reached. Archive cases manually; automatic action is disabled when evidence cannot be saved.");
            // Reserve room for one capped dump before admitting a case. No automatic evidence deletion.
            long used=0;var options=new EnumerationOptions{RecurseSubdirectories=true,IgnoreInaccessible=false,AttributesToSkip=FileAttributes.ReparsePoint};
            foreach(var f in new DirectoryInfo(Cases).EnumerateFiles("*",options))
            { used=checked(used+f.Length); if(used>384L*1024*1024)throw new IOException("Incident storage budget reached. Archive evidence before continuing."); }
            var volume=new DriveInfo(Path.GetPathRoot(Root)!);
            if(volume.AvailableFreeSpace<512L*1024*1024)throw new IOException("Less than 512 MiB free; refusing a new incident/dump.");
            var path=Path.Combine(Cases,DateTime.UtcNow.ToString("yyyyMMdd_HHmmss")+"_"+Guid.NewGuid().ToString("N"));
            EnsureDirectory(path); return path;
        }
    }
    public void WriteJson(string path,object data)
    {
        if(!Path.GetFullPath(path).StartsWith(Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
            throw new IOException("Attempt to write outside the protected state root.");
        FileSafety.NoReparse(path);
        var tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try
        {
            using(var fs=new FileStream(tmp,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {JsonSerializer.Serialize(fs,data,Json);fs.Flush(true);}
            File.Move(tmp,path,true);
        }
        finally {if(File.Exists(tmp)) File.Delete(tmp);}
    }
    public void Audit(object data)
    {
        lock(_gate)
        {
            var p=Path.Combine(Root,"audit.jsonl"); FileSafety.NoReparse(p);
            if(File.Exists(p)&&new FileInfo(p).Length>5*1024*1024)
            {
                for(var i=2;i>=1;i--){var a=Path.Combine(Root,$"audit.{i}.jsonl");var b=Path.Combine(Root,$"audit.{i+1}.jsonl");FileSafety.NoReparse(a);FileSafety.NoReparse(b);if(File.Exists(a))File.Move(a,b,true);}
                File.Move(p,Path.Combine(Root,"audit.1.jsonl"),true);
            }
            File.AppendAllText(p,JsonSerializer.Serialize(data)+Environment.NewLine);
        }
    }
}
