[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:',
    [string]$PackageDirectory='',
    [ValidateSet('','LAB-MINIFILTER')][string]$Confirmation=''
)

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

$cs=Get-CimInstance Win32_ComputerSystem
$vmText="$($cs.Manufacturer) $($cs.Model)"
if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
    throw "REFUSED: minifilter lab installation is permitted only in an obvious VM. Detected: $vmText"
}

if(-not $PackageDirectory){
    $root=Split-Path -Parent $PSScriptRoot
    $candidate=Get-ChildItem -LiteralPath (Join-Path $root 'minifilter-build') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if(-not $candidate){
        throw 'No minifilter-build package found. Run build_minifilter.cmd on a WDK build VM first.'
    }
    $PackageDirectory=$candidate.FullName
}
$PackageDirectory=[IO.Path]::GetFullPath($PackageDirectory)

$inf=Join-Path $PackageDirectory 'RansomGuardMinifilter.inf'
$sys=Join-Path $PackageDirectory 'RansomGuardMinifilter.sys'
$cat=Join-Path $PackageDirectory 'RansomGuardMinifilter.cat'
foreach($required in @($inf,$sys,$cat)){
    if(-not (Test-Path -LiteralPath $required -PathType Leaf)){
        throw "Signed runtime package file missing: $required"
    }
}

foreach($signed in @($sys,$cat)){
    $sig=Get-AuthenticodeSignature -LiteralPath $signed
    if($sig.Status -ne 'Valid'){
        throw "REFUSED: signature for '$signed' is '$($sig.Status)'. This script will NOT enable TESTSIGNING, disable Secure Boot, install trust roots, or change Defender."
    }
}

$infText=Get-Content -LiteralPath $inf -Raw
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){
    throw 'REFUSED: INF no longer suppresses automatic attachment.'
}

Write-Host "VM detected: $vmText"
Write-Host "Package: $PackageDirectory"
Write-Host "Target volume: $Volume ONLY"
Write-Warning 'Kernel code can crash Windows. Confirm the VM has a disposable snapshot.'

$confirm=if($Confirmation){$Confirmation}else{Read-Host 'Type LAB-MINIFILTER to install/load/attach only in this VM'}
if($confirm -cne 'LAB-MINIFILTER'){
    throw 'Cancelled.'
}

# Stage the signed package in Driver Store, then execute the INF DefaultInstall section.
# A filesystem minifilter is not a normal PnP device, so /add-driver /install alone is not
# treated as proof that the service was registered.
& pnputil.exe /add-driver $inf
if($LASTEXITCODE -ne 0){
    throw "pnputil package staging failed: $LASTEXITCODE"
}

& rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $inf
Start-Sleep -Milliseconds 750

$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
if(-not (Test-Path -LiteralPath $serviceKey)){
    throw 'DefaultInstall did not register RansomGuardMinifilter service.'
}

# Prove that the service image on disk is the exact SYS from this signed package.
# Repeated LAB installs often reuse the same DriverVer, and Windows SetupAPI may otherwise
# leave an older System32\drivers image in place. Runtime evidence must never test stale bytes.
$service=Get-ItemProperty -LiteralPath $serviceKey
$imagePath=[string]$service.ImagePath
if([string]::IsNullOrWhiteSpace($imagePath)){
    throw 'RansomGuardMinifilter service ImagePath is missing.'
}
$imagePath=[Environment]::ExpandEnvironmentVariables($imagePath.Trim([char]'"'))
if($imagePath -match '^\\\?\?\\(?<absolute>[A-Za-z]:\\.*)
$imagePath=[IO.Path]::GetFullPath($imagePath)
if(-not (Test-Path -LiteralPath $imagePath -PathType Leaf)){
    throw "Registered minifilter image does not exist: $imagePath"
}
$packageSysHash=(Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
$installedSysHash=(Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash
if(-not [string]::Equals($packageSysHash,$installedSysHash,[StringComparison]::OrdinalIgnoreCase)){
    throw "REFUSED: registered minifilter image is stale or mismatched. package=$packageSysHash installed=$installedSysHash path=$imagePath"
}

& fltmc load RansomGuardMinifilter
if($LASTEXITCODE -ne 0){
    Write-Warning 'fltmc load returned nonzero. It may already be loaded; checking filter list.'
    $filters=(& fltmc filters | Out-String)
    if($filters -notmatch 'RansomGuardMinifilter'){
        throw 'Driver did not load.'
    }
}

# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
& fltmc attach RansomGuardMinifilter $Volume
if($LASTEXITCODE -ne 0){
    throw "Explicit attach to $Volume failed."
}

$instances=(& fltmc instances -f RansomGuardMinifilter -v $Volume 2>&1 | Out-String)
$instancesExit=$LASTEXITCODE
if($instancesExit -ne 0){
    throw "Could not query the attached RansomGuardMinifilter instance on $Volume, exit=$instancesExit. Output: $instances"
}
if($instances -notmatch [regex]::Escape('RansomGuardMinifilter') -or
   $instances -notmatch [regex]::Escape($Volume)){
    throw "RansomGuardMinifilter is loaded but the expected $Volume instance was not confirmed."
}

Write-Host 'Minifilter is loaded and attached only to the requested disposable VM volume.' -ForegroundColor Green
){
    $imagePath=$Matches['absolute']
}
elseif($imagePath -match '^\\SystemRoot\\'){
    $imagePath=Join-Path $env:SystemRoot $imagePath.Substring(12)
}
elseif(-not [IO.Path]::IsPathRooted($imagePath)){
    $imagePath=Join-Path $env:SystemRoot $imagePath
}
$imagePath=[IO.Path]::GetFullPath($imagePath)
if(-not (Test-Path -LiteralPath $imagePath -PathType Leaf)){
    throw "Registered minifilter image does not exist: $imagePath"
}
$packageSysHash=(Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
$installedSysHash=(Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash
if(-not [string]::Equals($packageSysHash,$installedSysHash,[StringComparison]::OrdinalIgnoreCase)){
    throw "REFUSED: registered minifilter image is stale or mismatched. package=$packageSysHash installed=$installedSysHash path=$imagePath"
}

& fltmc load RansomGuardMinifilter
if($LASTEXITCODE -ne 0){
    Write-Warning 'fltmc load returned nonzero. It may already be loaded; checking filter list.'
    $filters=(& fltmc filters | Out-String)
    if($filters -notmatch 'RansomGuardMinifilter'){
        throw 'Driver did not load.'
    }
}

# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
& fltmc attach RansomGuardMinifilter $Volume
if($LASTEXITCODE -ne 0){
    throw "Explicit attach to $Volume failed."
}

$instances=(& fltmc instances -f RansomGuardMinifilter -v $Volume 2>&1 | Out-String)
$instancesExit=$LASTEXITCODE
if($instancesExit -ne 0){
    throw "Could not query the attached RansomGuardMinifilter instance on $Volume, exit=$instancesExit. Output: $instances"
}
if($instances -notmatch [regex]::Escape('RansomGuardMinifilter') -or
   $instances -notmatch [regex]::Escape($Volume)){
    throw "RansomGuardMinifilter is loaded but the expected $Volume instance was not confirmed."
}

Write-Host 'Minifilter is loaded and attached only to the requested disposable VM volume.' -ForegroundColor Green
