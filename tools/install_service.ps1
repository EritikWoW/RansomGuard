# Optional AUDIT-ONLY service. No automatic upgrade of the earlier unsafe RansomGuard service.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
try {
    $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Run install_service.cmd as Administrator. Read README before installation.' }
    $exe=Join-Path $root 'RansomGuard.Service.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Use the generated deployment package, not the source directory.' }
    $old=Get-Service -Name RansomGuard -ErrorAction SilentlyContinue
    if ($old -and $old.Status -eq 'Running') { throw 'Stop the OLD RansomGuard service first. It is not silently upgraded or deleted.' }
    if (Get-Service -Name RansomGuardV03 -ErrorAction SilentlyContinue) { throw 'RansomGuardV03 already installed. Stop and uninstall it explicitly before replacing binaries.' }
    Write-Host 'Install an AUDIT-ONLY service under LocalSystem? It DOES NOT BLOCK ransomware.'
    if ((Read-Host 'Type INSTALL') -cne 'INSTALL') { exit 2 }
    $config=Get-Content -LiteralPath (Join-Path $root 'appsettings.json') -Raw|ConvertFrom-Json
    if ($config.SchemaVersion -ne 3 -or $config.Mode -cne 'Audit') { throw 'Schema 3 / Audit config required.' }
    if (@($config.ProtectedRoots).Count -eq 0) {
        $config.ProtectedRoots=@([Environment]::GetFolderPath('DesktopDirectory'),[Environment]::GetFolderPath('MyDocuments'),
            [Environment]::GetFolderPath('MyPictures'),(Join-Path $env:USERPROFILE 'Downloads'))|Where-Object {Test-Path -LiteralPath $_ -PathType Container}|Select-Object -Unique
    }
    if (@($config.ProtectedRoots).Count -eq 0) { throw 'No monitored roots. Set concrete paths for the intended user first.' }
    Write-Host 'Folders to monitor:'; $config.ProtectedRoots|ForEach-Object {Write-Host "  $_"}
    if ((Read-Host 'Type ROOTS to approve these exact folders (check the user profile)') -cne 'ROOTS') { exit 2 }
    $dest=Join-Path $env:ProgramFiles 'RansomGuardV03'
    if (Test-Path -LiteralPath $dest) { throw 'Destination exists. Review/archive it first; refusing to overwrite executable files.' }
    New-Item -ItemType Directory -Path $dest|Out-Null
    $acl=Get-Acl -LiteralPath $dest
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sidText in @('S-1-5-32-544','S-1-5-18')) {
        $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $dest -AclObject $acl
    Copy-Item -LiteralPath $exe -Destination (Join-Path $dest 'RansomGuard.Service.exe')
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $dest 'appsettings.json'),($config|ConvertTo-Json -Depth 8),$utf8)
    & sc.exe create RansomGuardV03 binPath= ('"'+(Join-Path $dest 'RansomGuard.Service.exe')+'"') start= auto obj= LocalSystem DisplayName= 'RansomGuard v0.3 Audit (experimental)'
    if ($LASTEXITCODE -ne 0) { throw 'Service creation failed.' }
    & sc.exe description RansomGuardV03 'Experimental read-only behavioral observer. Not a replacement for antivirus or backups.'
    & sc.exe start RansomGuardV03
    if ($LASTEXITCODE -ne 0) { throw 'Service start failed. Check the Application event log; do not assume monitoring is active.' }
    $svc=Get-Service RansomGuardV03
    $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    Write-Host 'Audit service installed. State and incidents: %ProgramData%\RansomGuardV03'
} catch {Write-Error $_ -ErrorAction Continue;exit 1}
