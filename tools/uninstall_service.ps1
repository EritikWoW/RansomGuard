$ErrorActionPreference='Stop'
try {
    $s=Get-Service RansomGuardV03 -ErrorAction SilentlyContinue
    if ($s) {Stop-Service RansomGuardV03;$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20));& sc.exe delete RansomGuardV03;if($LASTEXITCODE -ne 0){throw 'Service deletion failed.'}}
    Write-Host 'v0.3 service removed. Binaries, settings, incident evidence and lab data were NOT deleted.'
} catch {Write-Error $_ -ErrorAction Continue;exit 1}
