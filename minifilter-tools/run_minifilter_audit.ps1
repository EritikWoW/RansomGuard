[CmdletBinding()]
param([switch]$VerboseEvents,[switch]$AllLocal)
$ErrorActionPreference='Stop'
$release=Split-Path -Parent $PSScriptRoot
$exe=Join-Path $release 'MinifilterLab\Client\RansomGuard.FilterClient.exe'
if(-not (Test-Path -LiteralPath $exe)){throw "Filter client not found: $exe"}
$args=@()
if($VerboseEvents){$args+='--verbose'}
if($AllLocal){$args+='--all-local'}
& $exe @args
if($LASTEXITCODE -ne 0){throw "Filter client exited with code $LASTEXITCODE"}
