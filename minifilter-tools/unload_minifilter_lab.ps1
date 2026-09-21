[CmdletBinding()]
param([ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:')
$ErrorActionPreference='Continue'
$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run as Administrator.'}
Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
& fltmc detach RansomGuardMinifilter $Volume
Write-Host 'Unloading RansomGuardMinifilter ...'
& fltmc unload RansomGuardMinifilter
Write-Host 'Done. The driver package may remain in Driver Store; revert the VM snapshot after lab testing.'
