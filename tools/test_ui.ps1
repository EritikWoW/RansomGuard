[CmdletBinding()]
param([string]$Exe='', [string]$OutputDirectory='')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if([string]::IsNullOrWhiteSpace($Exe)) {$Exe=Join-Path $root 'UI\RansomGuard.Ui.exe'}
if([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory=Join-Path $env:LOCALAPPDATA ('RansomGuard\UiTests\'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if(-not(Test-Path -LiteralPath $Exe -PathType Leaf)){throw "Built UI not found: $Exe"}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Write-Host 'WPF UI test: SYNTHETIC DATA ONLY. No service, simulator, ETW or driver is started.'
Write-Host "Screenshots and report: $OutputDirectory"
$exitCode=$null
$p=Start-Process -FilePath $Exe -ArgumentList ('--ui-selftest --out "{0}"' -f $OutputDirectory) -PassThru
try {
    $null=$p.Handle
    if(-not $p.WaitForExit(300000)){
        # This handle refers only to the exact test UI we just created, not another process by name.
        if(-not $p.HasExited){$p.Kill()}
        throw 'UI smoke test exceeded 300 seconds (two languages and two themes).'
    }
    $p.Refresh()
    $exitCode=$p.ExitCode
}
finally {$p.Dispose()}
$reportPath=Join-Path $OutputDirectory 'ui-smoke-test.json'
if(-not(Test-Path -LiteralPath $reportPath)){throw "UI smoke test exited $exitCode without a report: $OutputDirectory"}
$report=Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
if($exitCode -ne 0 -or -not $report.ok -or @($report.bindingErrors).Count -gt 0){
    Write-Host '----- UI failure details -----'
    Write-Host ([string]$report.error)
    foreach($entry in (@($report.bindingErrors) | Select-Object -First 20)) {Write-Host ([string]$entry)}
    Write-Host '----- end UI failure details -----'
    throw "UI smoke test failed, exit=$exitCode. Report: $reportPath"
}
Write-Host "WPF UI TEST PASSED: $(@($report.captures).Count) frames; no recorded binding errors."
