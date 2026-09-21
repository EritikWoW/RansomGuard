$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $arg='-NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}"' -f $PSCommandPath
    $p=Start-Process powershell.exe -ArgumentList $arg -Verb RunAs -PassThru -Wait
    exit $p.ExitCode
}
Write-Host 'RansomGuard services:'
Get-CimInstance Win32_Service -ErrorAction Stop |
    Where-Object { $_.Name -in @('RansomGuardV03','RansomGuard') } |
    Select-Object Name,State,ProcessId,PathName | Format-Table -AutoSize
Write-Host 'RansomGuard processes:'
Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" -ErrorAction SilentlyContinue |
    Select-Object ProcessId,ExecutablePath,CommandLine | Format-List
Write-Host 'This command is read-only. It does not stop or terminate anything.'
