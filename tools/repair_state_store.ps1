$ErrorActionPreference='Stop'
$adminSidObj=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSidObj=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$root=Join-Path $env:ProgramData 'RansomGuardV03'
function Is-Admin {
    $me=[Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-Occupants {
    $items=@()
    foreach($serviceName in @('RansomGuardV03','RansomGuard')) {
        $svc=Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if($svc -and $svc.State -ne 'Stopped') {$items += "service $serviceName state=$($svc.State) pid=$($svc.ProcessId)"}
    }
    foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" -ErrorAction SilentlyContinue)) {
        $items += "process RansomGuard.Service.exe pid=$($p.ProcessId) path=$($p.ExecutablePath)"
    }
    return @($items | Select-Object -Unique)
}
function New-PrivateDirectoryAcl {
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($adminSidObj)
    foreach($sid in @($adminSidObj,$systemSidObj)) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function New-PrivateFileAcl {
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($adminSidObj)
    foreach($sid in @($adminSidObj,$systemSidObj)) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Set-PrivateDirectory([string]$path) {
    $di=[IO.DirectoryInfo]::new($path)
    $di.SetAccessControl((New-PrivateDirectoryAcl))
}
function Set-PrivateFile([string]$path) {
    $fi=[IO.FileInfo]::new($path)
    $fi.SetAccessControl((New-PrivateFileAcl))
}
function Harden-Tree([string]$path) {
    Set-PrivateDirectory $path
    $stack=[Collections.Generic.Stack[string]]::new()
    $dirs=[Collections.Generic.List[string]]::new()
    $files=[Collections.Generic.List[string]]::new()
    $stack.Push($path)
    while($stack.Count -gt 0) {
        $dir=$stack.Pop()
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($dir)) {
            $attr=[IO.File]::GetAttributes($entry)
            if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Write-Warning "Quarantined reparse entry was not followed or trusted: $entry"
                continue
            }
            if(($attr -band [IO.FileAttributes]::Directory) -ne 0) {$dirs.Add($entry);$stack.Push($entry)}
            else {$files.Add($entry)}
        }
    }
    foreach($file in $files){Set-PrivateFile $file}
    foreach($dir in ($dirs | Sort-Object { $_.Length } -Descending)){Set-PrivateDirectory $dir}
    Set-PrivateDirectory $path
}
function Create-FreshStore {
    if(Test-Path -LiteralPath $root){throw "Fresh state root unexpectedly exists: $root"}
    $di=[IO.DirectoryInfo]::new($root)
    $di.Create((New-PrivateDirectoryAcl))
    $inc=Join-Path $root 'Incidents'
    $idi=[IO.DirectoryInfo]::new($inc)
    $idi.Create((New-PrivateDirectoryAcl))
}
if(-not (Is-Admin)) {
    $arg='-NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}"' -f $PSCommandPath
    $p=Start-Process powershell.exe -ArgumentList $arg -Verb RunAs -PassThru -Wait
    exit $p.ExitCode
}
$occupants=@(Get-Occupants)
if($occupants.Count -gt 0) {
    Write-Host 'Stop every RansomGuard instance before repairing state:' -ForegroundColor Red
    $occupants | ForEach-Object {Write-Host "  $_"}
    exit 10
}
if(-not (Test-Path -LiteralPath $root)) {
    Create-FreshStore
    Write-Host "Created a fresh private state store: $root" -ForegroundColor Green
    exit 0
}
$item=Get-Item -LiteralPath $root -Force
if(-not $item.PSIsContainer){throw 'State path exists but is not a directory.'}
if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Refusing repair: state root is a reparse point.'}
Write-Host 'The existing state tree will NOT be trusted or reused.' -ForegroundColor Yellow
Write-Host 'It will be renamed to an UNTRUSTED quarantine, then a fresh private store will be created.' -ForegroundColor Yellow
Write-Host 'No old evidence is deleted.' -ForegroundColor Yellow
$answer=Read-Host 'Type QUARANTINE to continue'
if($answer -cne 'QUARANTINE'){Write-Host 'Cancelled. No changes made.';exit 2}
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$q="$root.UNTRUSTED.$stamp.$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Move-Item -LiteralPath $root -Destination $q
try {
    Harden-Tree $q
} catch {
    Write-Warning "The old tree was quarantined but recursive ACL hardening was incomplete: $($_.Exception.Message)"
    Write-Warning "Do not reuse anything under: $q"
}
Create-FreshStore
Write-Host "Fresh private state store created: $root" -ForegroundColor Green
Write-Host "Old state preserved as UNTRUSTED evidence: $q" -ForegroundColor Yellow
Write-Host 'Run inspect_state_acl.cmd next. Do not copy trust-store.json or seen-images.json back from quarantine.' -ForegroundColor Cyan
