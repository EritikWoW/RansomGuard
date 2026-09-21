param([Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{32}$')][string]$RunId,[switch]$VerifyOnly)
$ErrorActionPreference='Stop'
$exe=Join-Path (Split-Path -Parent $PSScriptRoot) 'Simulator\RansomGuard.Simulator.exe'
if ($VerifyOnly) { & $exe --verify $RunId } else { & $exe --recover $RunId }
exit $LASTEXITCODE
