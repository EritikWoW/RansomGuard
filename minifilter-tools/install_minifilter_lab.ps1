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

$loadedBefore=(& fltmc filters 2>&1 | Out-String)
$loadedBeforeExit=$LASTEXITCODE
if($loadedBeforeExit -ne 0){
    throw "Could not query Filter Manager before install. exit=$loadedBeforeExit. Output: $loadedBefore"
}
if($loadedBefore -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw 'REFUSED: RansomGuardMinifilter is already loaded before install. Unload it or revert the disposable VM snapshot before continuing.'
}

$serviceKey='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\RansomGuardMinifilter'

function Get-RansomGuardPublishedInfNames {
    $windowsInf=Join-Path $env:SystemRoot 'INF'
    if(-not (Test-Path -LiteralPath $windowsInf -PathType Container)){return @()}

    return @(
        Get-ChildItem -LiteralPath $windowsInf -Filter 'oem*.inf' -File -ErrorAction Stop |
            Where-Object {
                try{
                    $text=Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
                    $text -match '(?im)^\\s*ServiceName\\s*=\\s*"RansomGuardMinifilter"\\s*& pnputil.exe /add-driver $inf
if($LASTEXITCODE -ne 0){
    throw "pnputil package staging failed: $LASTEXITCODE"
}

$defaultInstallOutput=(& rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $inf 2>&1 | Out-String)
$defaultInstallExit=$LASTEXITCODE
if($defaultInstallExit -ne 0){
    throw "rundll32 DefaultInstall failed: exit=$defaultInstallExit. Output: $defaultInstallOutput"
}
Start-Sleep -Milliseconds 750

$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
if(-not (Test-Path -LiteralPath $serviceKey)){
    throw 'DefaultInstall did not register RansomGuardMinifilter service.'
}

# Prove the registered service/instance contract and exact image bytes match this signed package.
$service=Get-ItemProperty -LiteralPath $serviceKey
if([int]$service.Start -ne 3){
    throw "Registered minifilter service StartType is '$($service.Start)', expected demand-start (3)."
}
if([int]$service.Type -ne 2){
    throw "Registered minifilter service Type is '$($service.Type)', expected filesystem driver (2)."
}
$instanceName='RansomGuard ReadOnly LAB Instance'
$instancesKey=Join-Path $serviceKey 'Parameters\Instances'
$instanceKey=Join-Path $instancesKey $instanceName
if(-not (Test-Path -LiteralPath $instanceKey)){
    throw "Registered minifilter instance key is missing: $instanceKey"
}
$instancesConfig=Get-ItemProperty -LiteralPath $instancesKey
$instanceConfig=Get-ItemProperty -LiteralPath $instanceKey
if([string]$instancesConfig.DefaultInstance -ne $instanceName){
    throw "Registered minifilter DefaultInstance is '$($instancesConfig.DefaultInstance)', expected '$instanceName'."
}
if([string]$instanceConfig.Altitude -ne '370099.4242' -or [int]$instanceConfig.Flags -ne 1){
    throw "Registered minifilter instance contract is invalid. Altitude='$($instanceConfig.Altitude)' Flags='$($instanceConfig.Flags)'."
}

$imagePath=[string]$service.ImagePath
if([string]::IsNullOrWhiteSpace($imagePath)){
    throw 'RansomGuardMinifilter service ImagePath is missing.'
}
$imagePath=[Environment]::ExpandEnvironmentVariables($imagePath.Trim([char]'"'))
if($imagePath -match '^\\\?\?\\(?<absolute>[A-Za-z]:\\.*)$'){
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

$loadOutput=(& fltmc load RansomGuardMinifilter 2>&1 | Out-String)
$loadExit=$LASTEXITCODE
if($loadExit -ne 0){
    throw "Driver load failed. fltmc exit=$loadExit. Output: $loadOutput"
}
$loadedAfter=(& fltmc filters 2>&1 | Out-String)
$loadedAfterExit=$LASTEXITCODE
if($loadedAfterExit -ne 0 -or $loadedAfter -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
    throw "Driver load could not be verified. fltmc filters exit=$loadedAfterExit. Output: $loadedAfter"
}

# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
$attachOutput=(& fltmc attach RansomGuardMinifilter $Volume 2>&1 | Out-String)
$attachExit=$LASTEXITCODE
if($attachExit -ne 0){
    throw "Explicit attach to $Volume failed. exit=$attachExit. Output: $attachOutput"
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
 -and
                    $text -match '(?im)^\\s*CatalogFile\\s*=\\s*RansomGuardMinifilter\\.cat\\s*& pnputil.exe /add-driver $inf
if($LASTEXITCODE -ne 0){
    throw "pnputil package staging failed: $LASTEXITCODE"
}

$defaultInstallOutput=(& rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $inf 2>&1 | Out-String)
$defaultInstallExit=$LASTEXITCODE
if($defaultInstallExit -ne 0){
    throw "rundll32 DefaultInstall failed: exit=$defaultInstallExit. Output: $defaultInstallOutput"
}
Start-Sleep -Milliseconds 750

$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
if(-not (Test-Path -LiteralPath $serviceKey)){
    throw 'DefaultInstall did not register RansomGuardMinifilter service.'
}

# Prove the registered service/instance contract and exact image bytes match this signed package.
$service=Get-ItemProperty -LiteralPath $serviceKey
if([int]$service.Start -ne 3){
    throw "Registered minifilter service StartType is '$($service.Start)', expected demand-start (3)."
}
if([int]$service.Type -ne 2){
    throw "Registered minifilter service Type is '$($service.Type)', expected filesystem driver (2)."
}
$instanceName='RansomGuard ReadOnly LAB Instance'
$instancesKey=Join-Path $serviceKey 'Parameters\Instances'
$instanceKey=Join-Path $instancesKey $instanceName
if(-not (Test-Path -LiteralPath $instanceKey)){
    throw "Registered minifilter instance key is missing: $instanceKey"
}
$instancesConfig=Get-ItemProperty -LiteralPath $instancesKey
$instanceConfig=Get-ItemProperty -LiteralPath $instanceKey
if([string]$instancesConfig.DefaultInstance -ne $instanceName){
    throw "Registered minifilter DefaultInstance is '$($instancesConfig.DefaultInstance)', expected '$instanceName'."
}
if([string]$instanceConfig.Altitude -ne '370099.4242' -or [int]$instanceConfig.Flags -ne 1){
    throw "Registered minifilter instance contract is invalid. Altitude='$($instanceConfig.Altitude)' Flags='$($instanceConfig.Flags)'."
}

$imagePath=[string]$service.ImagePath
if([string]::IsNullOrWhiteSpace($imagePath)){
    throw 'RansomGuardMinifilter service ImagePath is missing.'
}
$imagePath=[Environment]::ExpandEnvironmentVariables($imagePath.Trim([char]'"'))
if($imagePath -match '^\\\?\?\\(?<absolute>[A-Za-z]:\\.*)$'){
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

$loadOutput=(& fltmc load RansomGuardMinifilter 2>&1 | Out-String)
$loadExit=$LASTEXITCODE
if($loadExit -ne 0){
    throw "Driver load failed. fltmc exit=$loadExit. Output: $loadOutput"
}
$loadedAfter=(& fltmc filters 2>&1 | Out-String)
$loadedAfterExit=$LASTEXITCODE
if($loadedAfterExit -ne 0 -or $loadedAfter -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
    throw "Driver load could not be verified. fltmc filters exit=$loadedAfterExit. Output: $loadedAfter"
}

# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
$attachOutput=(& fltmc attach RansomGuardMinifilter $Volume 2>&1 | Out-String)
$attachExit=$LASTEXITCODE
if($attachExit -ne 0){
    throw "Explicit attach to $Volume failed. exit=$attachExit. Output: $attachOutput"
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

                }catch{
                    $false
                }
            } |
            Select-Object -ExpandProperty Name
    )
}

# A self-hosted runtime VM is intentionally reusable across workflow attempts. Windows Driver
# Store does not replace a package merely because the SYS bytes changed while DriverVer/INF
# identity stayed the same; pnputil can report "Already exists" and leave ServiceBinary pointed
# at the previous FileRepository image. Refresh only our own LAB package before staging.
$priorPublishedInfNames=@(Get-RansomGuardPublishedInfNames)
if((Test-Path -LiteralPath $serviceKey) -or $priorPublishedInfNames.Count -gt 0){
    Write-Warning ('Refreshing prior RansomGuard LAB driver registration/package before staging: ' +
        $(if($priorPublishedInfNames.Count -gt 0){$priorPublishedInfNames -join ', '}else{'service registration only'}))

    if(Test-Path -LiteralPath $serviceKey){
        $deleteServiceOutput=(& sc.exe delete RansomGuardMinifilter 2>&1 | Out-String)
        $deleteServiceExit=$LASTEXITCODE
        if($deleteServiceExit -ne 0 -and $deleteServiceExit -ne 1060){
            throw "Could not delete stale RansomGuardMinifilter service. sc.exe exit=$deleteServiceExit. Output: $deleteServiceOutput"
        }

        for($attempt=0;$attempt -lt 20 -and (Test-Path -LiteralPath $serviceKey);$attempt++){
            Start-Sleep -Milliseconds 100
        }
        if(Test-Path -LiteralPath $serviceKey){
            throw 'Stale RansomGuardMinifilter service is still registered after sc.exe delete. Revert the disposable VM snapshot before retrying.'
        }
    }

    foreach($publishedInf in $priorPublishedInfNames){
        $deletePackageOutput=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        $deletePackageExit=$LASTEXITCODE
        if($deletePackageExit -ne 0){
            throw "Could not delete stale RansomGuard LAB Driver Store package '$publishedInf'. pnputil exit=$deletePackageExit. Output: $deletePackageOutput"
        }
    }

    $remaining=@(Get-RansomGuardPublishedInfNames)
    if($remaining.Count -gt 0){
        throw "Stale RansomGuard LAB Driver Store package(s) remain after cleanup: $($remaining -join ', ')"
    }
}

# Stage the signed package in Driver Store, then execute the INF DefaultInstall section.
# A filesystem minifilter is not a normal PnP device, so /add-driver /install alone is not
# treated as proof that the service was registered.
& pnputil.exe /add-driver $inf
if($LASTEXITCODE -ne 0){
    throw "pnputil package staging failed: $LASTEXITCODE"
}

$defaultInstallOutput=(& rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $inf 2>&1 | Out-String)
$defaultInstallExit=$LASTEXITCODE
if($defaultInstallExit -ne 0){
    throw "rundll32 DefaultInstall failed: exit=$defaultInstallExit. Output: $defaultInstallOutput"
}
Start-Sleep -Milliseconds 750

$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
if(-not (Test-Path -LiteralPath $serviceKey)){
    throw 'DefaultInstall did not register RansomGuardMinifilter service.'
}

# Prove the registered service/instance contract and exact image bytes match this signed package.
$service=Get-ItemProperty -LiteralPath $serviceKey
if([int]$service.Start -ne 3){
    throw "Registered minifilter service StartType is '$($service.Start)', expected demand-start (3)."
}
if([int]$service.Type -ne 2){
    throw "Registered minifilter service Type is '$($service.Type)', expected filesystem driver (2)."
}
$instanceName='RansomGuard ReadOnly LAB Instance'
$instancesKey=Join-Path $serviceKey 'Parameters\Instances'
$instanceKey=Join-Path $instancesKey $instanceName
if(-not (Test-Path -LiteralPath $instanceKey)){
    throw "Registered minifilter instance key is missing: $instanceKey"
}
$instancesConfig=Get-ItemProperty -LiteralPath $instancesKey
$instanceConfig=Get-ItemProperty -LiteralPath $instanceKey
if([string]$instancesConfig.DefaultInstance -ne $instanceName){
    throw "Registered minifilter DefaultInstance is '$($instancesConfig.DefaultInstance)', expected '$instanceName'."
}
if([string]$instanceConfig.Altitude -ne '370099.4242' -or [int]$instanceConfig.Flags -ne 1){
    throw "Registered minifilter instance contract is invalid. Altitude='$($instanceConfig.Altitude)' Flags='$($instanceConfig.Flags)'."
}

$imagePath=[string]$service.ImagePath
if([string]::IsNullOrWhiteSpace($imagePath)){
    throw 'RansomGuardMinifilter service ImagePath is missing.'
}
$imagePath=[Environment]::ExpandEnvironmentVariables($imagePath.Trim([char]'"'))
if($imagePath -match '^\\\?\?\\(?<absolute>[A-Za-z]:\\.*)$'){
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

$loadOutput=(& fltmc load RansomGuardMinifilter 2>&1 | Out-String)
$loadExit=$LASTEXITCODE
if($loadExit -ne 0){
    throw "Driver load failed. fltmc exit=$loadExit. Output: $loadOutput"
}
$loadedAfter=(& fltmc filters 2>&1 | Out-String)
$loadedAfterExit=$LASTEXITCODE
if($loadedAfterExit -ne 0 -or $loadedAfter -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
    throw "Driver load could not be verified. fltmc filters exit=$loadedAfterExit. Output: $loadedAfter"
}

# INF suppresses automatic attachments. Attach exactly one explicitly requested local volume.
$attachOutput=(& fltmc attach RansomGuardMinifilter $Volume 2>&1 | Out-String)
$attachExit=$LASTEXITCODE
if($attachExit -ne 0){
    throw "Explicit attach to $Volume failed. exit=$attachExit. Output: $attachOutput"
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
