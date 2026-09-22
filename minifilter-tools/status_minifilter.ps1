$ErrorActionPreference='Continue'
Write-Host '--- fltmc filters ---'
& fltmc filters
Write-Host "`n--- RansomGuard instances ---"
& fltmc instances -f RansomGuardMinifilter
Write-Host "`n--- service ---"
Get-CimInstance Win32_SystemDriver -Filter "Name='RansomGuardMinifilter'" | Select-Object Name,State,StartMode,PathName | Format-List
