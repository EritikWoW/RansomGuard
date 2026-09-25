[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$NormalReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$QualificationAltitude='385201.806'
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production lifecycle qualification package preparation must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production lifecycle qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: set RANSOMGUARD_LAB_VM=I_UNDERSTAND only inside the disposable snapshot VM.'
    }
    return $vmText
}

function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){throw "$Label has no filesystem root: $full"}
    $cursor=$root.TrimEnd('\')
    $relative=$full.Substring($root.Length)
    foreach($segment in $relative.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}

function Find-X64Tool([string]$Kits,[string]$Name){
    $match=Get-ChildItem -LiteralPath $Kits -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\x64\'} |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

function Find-Inf2CatTool([string]$Kits){
    $x64=Find-X64Tool $Kits 'Inf2Cat.exe'
    if($x64){return $x64}
    $match=Get-ChildItem -LiteralPath $Kits -Filter 'Inf2Cat.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\x86\'} |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

function Invoke-Native([string]$File,[string[]]$Arguments,[string]$Label){
    & $File @Arguments
    if($LASTEXITCODE -ne 0){throw "$Label failed, exit=$LASTEXITCODE"}
}

Assert-Administrator
$vm=Assert-DisposableVm

if($QualificationAltitude -notmatch '^[0-9]{4,6}(?:\.[0-9]{1,8})?$' -or $QualificationAltitude -eq '370099.4242'){
    throw 'QualificationAltitude must be a non-placeholder numeric altitude used only inside the disposable VM.'
}

$NormalReleaseDirectory=[IO.Path]::GetFullPath($NormalReleaseDirectory)
$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
foreach($pair in @(
    @($NormalReleaseDirectory,'NormalReleaseDirectory'),
    @($LabReleaseDirectory,'LabReleaseDirectory'),
    @($DriverPackageDirectory,'DriverPackageDirectory')
)){
    if(-not(Test-Path -LiteralPath $pair[0] -PathType Container)){throw "$($pair[1]) is missing: $($pair[0])"}
    Assert-NoReparsePath $pair[0] $pair[1]
}

if(Test-Path -LiteralPath $OutputDirectory){Remove-Item -LiteralPath $OutputDirectory -Recurse -Force}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Assert-NoReparsePath $OutputDirectory 'OutputDirectory'

$serviceSource=Join-Path $NormalReleaseDirectory 'RansomGuard.Service.exe'
$appSettingsSource=Join-Path $NormalReleaseDirectory 'appsettings.json'
$gateSource=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$sysSource=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.sys'
$infSource=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.inf'
foreach($required in @($serviceSource,$appSettingsSource,$gateSource,$sysSource,$infSource)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required qualification input missing: $required"}
}

$service=Join-Path $OutputDirectory 'RansomGuard.Service.exe'
$appSettings=Join-Path $OutputDirectory 'appsettings.json'
$protection=Join-Path $OutputDirectory 'Protection'
$gateDir=Join-Path $protection 'GateClient'
$driverDir=Join-Path $protection 'Driver'
New-Item -ItemType Directory -Path $gateDir,$driverDir -Force | Out-Null
$gate=Join-Path $gateDir 'RansomGuard.GateClient.exe'
$sys=Join-Path $driverDir 'RansomGuardMinifilter.sys'
$inf=Join-Path $driverDir 'RansomGuardMinifilter.inf'
$cat=Join-Path $driverDir 'RansomGuardMinifilter.cat'
Copy-Item -LiteralPath $serviceSource -Destination $service
Copy-Item -LiteralPath $appSettingsSource -Destination $appSettings
Copy-Item -LiteralPath $gateSource -Destination $gate
Copy-Item -LiteralPath $sysSource -Destination $sys

$repoRoot=Split-Path -Parent $PSScriptRoot
[xml]$props=Get-Content -LiteralPath (Join-Path $repoRoot 'Directory.Build.props') -Raw
$productVersion=[string]$props.Project.PropertyGroup.Version
if($productVersion -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw "Invalid product version: $productVersion"}
foreach($exe in @($service,$gate)){
    $fileVersion=(Get-Item -LiteralPath $exe).VersionInfo.FileVersion
    if($fileVersion -ne $productVersion){throw "Qualification executable version mismatch: $exe expected=$productVersion actual=$fileVersion"}
}

$infText=Get-Content -LiteralPath $infSource -Raw
$infText=$infText -replace '(?im)^; RansomGuard read-only minifilter LAB prototype\.\s*\r?\n',''
$infText=$infText -replace '(?im)^; IMPORTANT: 370099\.4242 is an UNASSIGNED LAB PLACEHOLDER altitude\.\s*\r?\n',''
$infText=$infText -replace '(?im)^; Do not distribute/deploy this driver outside an isolated test VM\.\s*\r?\n',''
$infText=$infText -replace '(?im)^; Request a Microsoft-assigned altitude before any real deployment\.\s*\r?\n',''
$infText=$infText -replace '(?im)^ProviderString\s*=\s*"[^"]*"$','ProviderString      = "RansomGuard"'
$infText=$infText -replace '(?im)^ServiceDescription\s*=\s*"[^"]*"$','ServiceDescription = "RansomGuard production lifecycle qualification minifilter"'
$infText=$infText -replace '(?im)^DiskId1\s*=\s*"[^"]*"$','DiskId1            = "RansomGuard Production Lifecycle Qualification Disk"'
$infText=$infText -replace '(?im)^DefaultInstance\s*=\s*"[^"]*"$','DefaultInstance    = "RansomGuard Production Qualification Instance"'
$infText=$infText -replace '(?im)^Instance1\.Name\s*=\s*"[^"]*"$','Instance1.Name     = "RansomGuard Production Qualification Instance"'
$infText=$infText -replace '(?im)^Instance1\.Altitude\s*=\s*"[^"]*"$',('Instance1.Altitude = "{0}"' -f $QualificationAltitude)
if($infText -match '(?i)UNASSIGNED LAB PLACEHOLDER|RansomGuard Lab|370099\.4242'){
    throw 'Qualification INF still contains a forbidden LAB production-admission identity.'
}
Set-Content -LiteralPath $inf -Value $infText -Encoding ascii -NoNewline

$thumb=$CertificateThumbprint.Replace(' ','').ToUpperInvariant()
$current=Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} | Select-Object -First 1
$machine=Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} | Select-Object -First 1
$cert=if($current){$current}else{$machine}
if(-not $cert){throw "Qualification signing certificate with private key not found: $thumb"}
$machineStore=[bool]$machine -and -not [bool]$current

$kits=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if(-not $kits){throw 'Windows Kits root not found.'}
$kits=$kits.TrimEnd('\')
$signtool=Find-X64Tool $kits 'signtool.exe'
$inf2cat=Find-Inf2CatTool $kits
if(-not $signtool -or -not $inf2cat){throw 'signtool.exe / Inf2Cat.exe not found under Windows Kits.'}

foreach($exe in @($service,$gate)){
    $args=@('sign','/sha1',$thumb,'/fd','SHA256','/v')
    if($machineStore){$args+=@('/sm')}
    $args+=$exe
    Invoke-Native $signtool $args "Signing $(Split-Path -Leaf $exe)"
}

$sysSig=Get-AuthenticodeSignature -LiteralPath $sys
if($sysSig.Status -ne 'Valid' -or
   -not [string]::Equals([string]$sysSig.SignerCertificate.Thumbprint,$thumb,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Runtime SYS is not already signed by the configured qualification certificate.'
}

Invoke-Native $inf2cat @("/driver:$driverDir",'/os:10_X64','/uselocaltime') 'Inf2Cat qualification catalog generation'
if(-not(Test-Path -LiteralPath $cat -PathType Leaf)){throw 'Inf2Cat did not create the qualification catalog.'}
$catArgs=@('sign','/sha1',$thumb,'/fd','SHA256','/v')
if($machineStore){$catArgs+=@('/sm')}
$catArgs+=$cat
Invoke-Native $signtool $catArgs 'Signing qualification catalog'

foreach($signed in @($service,$gate,$cat)){
    $sig=Get-AuthenticodeSignature -LiteralPath $signed
    if($sig.Status -ne 'Valid'){throw "Qualification signature is not trusted: $signed status=$($sig.Status)"}
    if(-not [string]::Equals([string]$sig.SignerCertificate.Thumbprint,$thumb,[StringComparison]::OrdinalIgnoreCase)){
        throw "Qualification signer mismatch: $signed"
    }
}

$descriptor=[ordered]@{
    Schema=1
    Profile='ProductionProtection'
    Version=$productVersion
    Protocol=18
    Provider='RansomGuard'
    Altitude=$QualificationAltitude
    GateClientSha256=(Get-FileHash -LiteralPath $gate -Algorithm SHA256).Hash
    DriverSysSha256=(Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
    DriverInfSha256=(Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash
    DriverCatSha256=(Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash
}
$descriptorPath=Join-Path $protection 'protection-package.json'
$descriptor | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $descriptorPath -Encoding utf8

$commit=(& git -C $repoRoot rev-parse HEAD).Trim()
if($commit -notmatch '^[A-Fa-f0-9]{40}$'){throw "Unable to bind qualification package to exact commit: '$commit'"}

$summary=[ordered]@{
    schema=1
    commit=$commit
    productVersion=$productVersion
    preparedUtc=(Get-Date).ToUniversalTime().ToString('o')
    vm=$vm
    qualificationOnly=$true
    qualificationAltitude=$QualificationAltitude
    certificateThumbprint=$thumb
    serviceSha256=(Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash
    gateClientSha256=$descriptor.GateClientSha256
    driverSysSha256=$descriptor.DriverSysSha256
    driverInfSha256=$descriptor.DriverInfSha256
    driverCatSha256=$descriptor.DriverCatSha256
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'qualification-package.json') -Encoding utf8

Write-Host "PRODUCTION LIFECYCLE QUALIFICATION PACKAGE READY: $OutputDirectory" -ForegroundColor Green
Write-Warning "Qualification altitude $QualificationAltitude is synthetic/unassigned test input. This package must never be distributed or reused outside the disposable VM."
