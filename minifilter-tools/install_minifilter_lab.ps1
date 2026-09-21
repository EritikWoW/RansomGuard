[CmdletBinding()]
param([ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:', [string]$PackageDirectory='')
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run as Administrator.'}
$cs=Get-CimInstance Win32_ComputerSystem
$vmText=("$($cs.Manufacturer) $($cs.Model)")
if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
    throw "REFUSED: minifilter lab installation is permitted by this script only in an obvious VM. Detected: $vmText"
}
if(-not $PackageDirectory){
    $root=Split-Path -Parent $PSScriptRoot
    $candidate=Get-ChildItem -LiteralPath (Join-Path $root 'minifilter-build') -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if(-not $candidate){throw 'No minifilter-build package found. Run build_minifilter.cmd on a WDK build VM first.'}
    $PackageDirectory=$candidate.FullName
}
$inf=Join-Path $PackageDirectory 'RansomGuardMinifilter.inf';$sys=Join-Path $PackageDirectory 'RansomGuardMinifilter.sys'
if(-not (Test-Path $inf) -or -not (Test-Path $sys)){throw 'INF/SYS missing from package.'}
$sig=Get-AuthenticodeSignature -LiteralPath $sys
if($sig.Status -ne 'Valid'){
    throw "REFUSED: driver signature is '$($sig.Status)'. This script will NOT enable TESTSIGNING, disable Secure Boot, or install trust roots. Configure driver test signing safely inside the snapshot VM, then retry."
}
$infText=Get-Content -LiteralPath $inf -Raw
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){throw 'REFUSED: INF no longer suppresses automatic attachment.'}
Write-Host "VM detected: $vmText"
Write-Host "Package: $PackageDirectory"
Write-Host "Target volume: $Volume ONLY"
Write-Warning 'Kernel code can crash Windows even when logically read-only. Confirm the VM has a disposable snapshot.'
$confirm=Read-Host 'Type LAB-MINIFILTER to install/load/attach only in this VM'
if($confirm -cne 'LAB-MINIFILTER'){throw 'Cancelled.'}
& pnputil.exe /add-driver $inf /install
if($LASTEXITCODE -ne 0){throw "pnputil failed: $LASTEXITCODE"}
& fltmc load RansomGuardMinifilter
if($LASTEXITCODE -ne 0){
    Write-Warning 'fltmc load returned nonzero. It may already be loaded; checking filter list.'
    $filters=(& fltmc filters | Out-String)
    if($filters -notmatch 'RansomGuardMinifilter'){throw 'Driver did not load.'}
}
# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
& fltmc attach RansomGuardMinifilter $Volume
if($LASTEXITCODE -ne 0){throw "Explicit attach to $Volume failed."}
& fltmc instances RansomGuardMinifilter
Write-Host 'Minifilter is attached READ-ONLY to the requested VM volume. Start run_minifilter_audit.cmd next.' -ForegroundColor Green
