param([ValidateSet('Audit','Lab','FullDump','NativeTest')][string]$Mode='Audit')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

function Get-RansomGuardOccupants {
    $items = @()
    foreach ($serviceName in @('RansomGuardV03','RansomGuard')) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.State -ne 'Stopped') {
            $items += [pscustomobject]@{
                Kind='Service'; Name=$serviceName; Pid=[int]$svc.ProcessId; State=$svc.State
                Path=$svc.PathName; CommandLine=$null
            }
        }
    }
    $procs = Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" -ErrorAction SilentlyContinue
    foreach ($p in @($procs)) {
        # Avoid duplicate service rows. A PID of 0 means the service is not currently hosted.
        if ($items | Where-Object { $_.Pid -gt 0 -and $_.Pid -eq [int]$p.ProcessId }) { continue }
        $items += [pscustomobject]@{
            Kind='Process'; Name='RansomGuard.Service.exe'; Pid=[int]$p.ProcessId; State='Running'
            Path=$p.ExecutablePath; CommandLine=$p.CommandLine
        }
    }
    return @($items)
}

function Assert-NoRansomGuardInstance {
    $occupants = @(Get-RansomGuardOccupants)
    if ($occupants.Count -eq 0) { return }
    Write-Host ''
    Write-Host 'RansomGuard instance(s) already active:' -ForegroundColor Yellow
    foreach ($o in $occupants) {
        Write-Host ("  {0} {1}  PID={2}  State={3}" -f $o.Kind,$o.Name,$o.Pid,$o.State) -ForegroundColor Yellow
        if ($o.Path) { Write-Host ("    Path: {0}" -f $o.Path) }
        if ($o.CommandLine) { Write-Host ("    Command: {0}" -f $o.CommandLine) }
    }
    Write-Host ''
    Write-Host 'Do not kill by image name. Stop the exact audit console with Ctrl+C.' -ForegroundColor Yellow
    if ($occupants | Where-Object { $_.Kind -eq 'Service' -and $_.Name -eq 'RansomGuardV03' }) {
        Write-Host 'If the v0.3 audit service is intentional, stop it explicitly with:' -ForegroundColor Yellow
        Write-Host '  Stop-Service RansomGuardV03' -ForegroundColor Cyan
    }
    if ($occupants | Where-Object { $_.Kind -eq 'Service' -and $_.Name -eq 'RansomGuard' }) {
        Write-Host 'The legacy RansomGuard service is also active. Stop/review it separately before testing.' -ForegroundColor Yellow
    }
    throw 'Exclusive RansomGuard instance lock is occupied. No lab process was started.'
}

$me=[Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin=([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arg='-NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}" -Mode {1}' -f $PSCommandPath,$Mode
    $p=Start-Process -FilePath 'powershell.exe' -ArgumentList $arg -Verb RunAs -PassThru -Wait
    exit $p.ExitCode
}
try {
    $exe=Join-Path $root 'RansomGuard.Service.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'This is the SOURCE folder. Build first, then run the launcher from the generated release folder.' }

    # Check BEFORE asking for LAB/full-dump confirmation. This avoids asking the user
    # to approve a sensitive operation that cannot start because an audit process/service
    # already owns the global instance lock. The app still has its mutex as the final race-safe check.
    if ($Mode -ne 'NativeTest') { Assert-NoRansomGuardInstance }

    Set-Location -LiteralPath $root
    Write-Host 'Ordinary applications are AUDIT-ONLY. No automated browser suspension or process-tree actions.'
    switch ($Mode) {
        'Audit' { & $exe }
        'Lab' { & $exe --lab }
        'FullDump' {
            if ((Read-Host 'Full memory dumps may contain secrets. This mode is restricted to our lab child. Type LAB to continue') -cne 'LAB') { exit 2 }
            # Re-check after the confirmation to close the user-interaction race window.
            Assert-NoRansomGuardInstance
            & $exe --lab-full-dump
        }
        'NativeTest' { & $exe --native-selftest }
    }
    if ($LASTEXITCODE -ne 0) { throw "Application exited with code $LASTEXITCODE" }
    if ($Mode -in @('Lab','FullDump')) {
        try { & (Join-Path $PSScriptRoot 'summarize_last_lab.ps1') }
        catch { Write-Warning "Lab completed, but summary helper failed: $($_.Exception.Message)" }
    }
}
catch {Write-Error $_ -ErrorAction Continue;exit 1}
