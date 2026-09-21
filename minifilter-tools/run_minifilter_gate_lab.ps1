[CmdletBinding()]
param(
    [string]$Root = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'RansomGuard-Gate-Lab'),
    [switch]$PrepareOnly
)
$ErrorActionPreference='Stop'
$release=Split-Path -Parent $PSScriptRoot
$exe=Join-Path $release 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
if(-not (Test-Path -LiteralPath $exe -PathType Leaf)){throw "Gate client not found: $exe. Build with build_lab.cmd."}
$Root=[IO.Path]::GetFullPath($Root)
if($PrepareOnly){
    & $exe --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "Gate root preparation failed, exit=$LASTEXITCODE"}
    return
}
$marker=Join-Path $Root '.ransomguard-gate-lab-root'
if(-not (Test-Path -LiteralPath $marker -PathType Leaf)){
    Write-Host "Preparing disposable LAB root: $Root" -ForegroundColor Yellow
    & $exe --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "Gate root preparation failed, exit=$LASTEXITCODE"}
}
Write-Warning 'LAB ONLY. The prototype can deny WRITE/RENAME/DELETE inside the selected test root. Do not point it at real user data.'
& $exe --root $Root
if($LASTEXITCODE -ne 0){throw "Gate client exited with code $LASTEXITCODE"}
