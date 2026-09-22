[CmdletBinding()]
param([ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:')

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
& fltmc detach RansomGuardMinifilter $Volume
$detachExit=$LASTEXITCODE
if($detachExit -ne 0){
    Write-Warning "fltmc detach returned $detachExit. Continuing with unload and final-state verification."
}

Write-Host 'Unloading RansomGuardMinifilter ...'
& fltmc unload RansomGuardMinifilter
$unloadExit=$LASTEXITCODE
if($unloadExit -ne 0){
    Write-Warning "fltmc unload returned $unloadExit. Verifying whether the filter is still present."
}

$filters=(& fltmc filters 2>$null | Out-String)
$queryExit=$LASTEXITCODE
if($queryExit -ne 0){
    throw "Could not verify Filter Manager state after cleanup. fltmc filters exit=$queryExit"
}
if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw "RansomGuardMinifilter is still loaded after cleanup. detachExit=$detachExit unloadExit=$unloadExit"
}

Write-Host 'Done. RansomGuardMinifilter is not loaded. The package may remain in Driver Store; revert the VM snapshot after lab testing.' -ForegroundColor Green
