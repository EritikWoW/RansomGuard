[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$report = Join-Path ([IO.Path]::GetTempPath()) ('RansomGuard-ETW-diagnostics-{0}-{1}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID)
$transcriptStarted = $false
try {
    Start-Transcript -LiteralPath $report | Out-Null
    $transcriptStarted = $true
    Write-Host 'RansomGuard ETW diagnostics -- READ ONLY'
    Write-Host 'No process or trace is stopped. No registry/security settings are modified.'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Host ('Elevated: {0}; 64-bit shell: {1}' -f $elevated, [Environment]::Is64BitProcess)
        if (-not $elevated) { Write-Warning 'Run from an elevated PowerShell for complete visibility. A failed query is NOT an empty list.' }
    } finally { $identity.Dispose() }

    Write-Host "`n--- Active RansomGuard processes (query only) ---"
    try {
        $items = @(Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" |
            Select-Object ProcessId, ParentProcessId, CreationDate, ExecutablePath)
        if ($items.Count -eq 0) { Write-Host 'No matching service executable reported.' }
        else { $items | Format-List | Out-Host }
    } catch { Write-Warning ("Process query failed: " + $_.Exception.Message) }

    Write-Host "`n--- Registered RansomGuard services (query only) ---"
    try {
        $items = @(Get-CimInstance Win32_Service -Filter "Name='RansomGuardV03' OR Name='RansomGuard'" |
            Select-Object Name, State, ProcessId, PathName)
        if ($items.Count -eq 0) { Write-Host 'No matching Windows service reported.' }
        else { $items | Format-List | Out-Host }
    } catch { Write-Warning ("Service query failed: " + $_.Exception.Message) }

    Write-Host "`n--- Running ETW sessions: logman query -ets ---"
    $logman = Join-Path $env:SystemRoot 'System32\logman.exe'
    if (-not (Test-Path -LiteralPath $logman -PathType Leaf)) { throw 'Windows logman.exe was not found.' }
    & $logman query -ets
    $queryExit = $LASTEXITCODE
    Write-Host ("logman exit code: " + $queryExit)
    if ($queryExit -ne 0) { throw 'The ETW query failed. Do not interpret this output as no running sessions.' }

    Write-Host "`nReview RansomGuardV032-* names against running processes."
    Write-Host 'A name or PID alone is not proof that a trace is orphaned; PIDs can be reused.'
    Write-Host 'Do not stop Windows, Defender, EDR, WPR or unrelated application sessions.'
    Write-Host '0x800705AA can indicate ETW session/system-logger limits, not necessarily insufficient physical RAM.'
    Write-Host ("Report: " + $report)
}
catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
