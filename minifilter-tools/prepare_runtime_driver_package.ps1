[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [ValidateSet('Debug','Release')][string]$Configuration='Release',
    [string]$OutputDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Runtime driver package preparation must run as Administrator inside the disposable VM.'
}
$cs=Get-CimInstance Win32_ComputerSystem
$vmText="$($cs.Manufacturer) $($cs.Model)"
if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
    throw "REFUSED: signed runtime package preparation requires an obvious VM. Detected: $vmText"
}
if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
    throw 'REFUSED: set RANSOMGUARD_LAB_VM=I_UNDERSTAND only inside the disposable snapshot VM.'
}

$root=Split-Path -Parent $PSScriptRoot
$buildScript=Join-Path $PSScriptRoot 'build_minifilter.ps1'
& $buildScript -Configuration $Configuration
# build_minifilter.ps1 throws on failure. $LASTEXITCODE here would describe whichever
# native tool happened to run last inside that script, not the script invocation itself.

$sourcePackage=Get-ChildItem -LiteralPath (Join-Path $root 'minifilter-build') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
if(-not $sourcePackage){throw 'Unsigned minifilter package was not produced.'}

if(-not $OutputDirectory){
    $OutputDirectory=Join-Path $root ('runtime-driver-package\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){Remove-Item -LiteralPath $OutputDirectory -Recurse -Force}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $sourcePackage.FullName 'RansomGuardMinifilter.sys') -Destination $OutputDirectory
Copy-Item -LiteralPath (Join-Path $sourcePackage.FullName 'RansomGuardMinifilter.inf') -Destination $OutputDirectory
Copy-Item -LiteralPath (Join-Path $sourcePackage.FullName 'rg_minifilter_protocol.h') -Destination $OutputDirectory

$thumb=$CertificateThumbprint.Replace(' ','').ToUpperInvariant()
$current=Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} | Select-Object -First 1
$machine=Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} | Select-Object -First 1
$cert=if($current){$current}else{$machine}
if(-not $cert){throw "Lab signing certificate with private key not found in CurrentUser/My or LocalMachine/My: $thumb"}
$machineStore=[bool]$machine -and -not [bool]$current

$kits=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if(-not $kits){throw 'Windows Kits root not found. Install the WDK/SDK on the disposable VM.'}
$kits=$kits.TrimEnd('\')

function Find-X64Tool([string]$Name){
    $match=Get-ChildItem -LiteralPath $kits -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\\x64\\'} |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

function Find-Inf2CatTool {
    $x64=Find-X64Tool 'Inf2Cat.exe'
    if($x64){return $x64}

    $match=Get-ChildItem -LiteralPath $kits -Filter 'Inf2Cat.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\\x86\\'} |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

$signtool=Find-X64Tool 'signtool.exe'
$inf2cat=Find-Inf2CatTool
if(-not $signtool){throw 'x64 signtool.exe not found under Windows Kits.'}
if(-not $inf2cat){throw 'Inf2Cat.exe not found under Windows Kits (x64/x86 checked).'}

$sys=Join-Path $OutputDirectory 'RansomGuardMinifilter.sys'
$inf=Join-Path $OutputDirectory 'RansomGuardMinifilter.inf'
$signArgs=@('sign','/sha1',$thumb,'/fd','SHA256','/v')
if($machineStore){$signArgs+=@('/sm')}
$signArgs+=$sys
& $signtool @signArgs
if($LASTEXITCODE -ne 0){throw "Embedded SYS signing failed, exit=$LASTEXITCODE"}

& $inf2cat "/driver:$OutputDirectory" '/os:10_X64' '/uselocaltime'
if($LASTEXITCODE -ne 0){throw "Inf2Cat failed, exit=$LASTEXITCODE"}

$cat=Join-Path $OutputDirectory 'RansomGuardMinifilter.cat'
if(-not (Test-Path -LiteralPath $cat -PathType Leaf)){throw 'Inf2Cat did not produce RansomGuardMinifilter.cat.'}
$catArgs=@('sign','/sha1',$thumb,'/fd','SHA256','/v')
if($machineStore){$catArgs+=@('/sm')}
$catArgs+=$cat
& $signtool @catArgs
if($LASTEXITCODE -ne 0){throw "Catalog signing failed, exit=$LASTEXITCODE"}

foreach($signed in @($sys,$cat)){
    $sig=Get-AuthenticodeSignature -LiteralPath $signed
    if($sig.Status -ne 'Valid'){
        throw "Signed runtime artifact is not trusted in this VM: $signed status=$($sig.Status)"
    }
}

$commit=''
try{$commit=(& git -C $root rev-parse HEAD).Trim()}catch{}
if($commit -notmatch '^[A-Fa-f0-9]{40}$'){
    throw "Could not resolve an exact 40-character Git commit for runtime package provenance: '$commit'"
}

$propsPath=Join-Path $root 'Directory.Build.props'
if(-not (Test-Path -LiteralPath $propsPath -PathType Leaf)){
    throw 'Directory.Build.props is required for runtime package version provenance.'
}
[xml]$propsXml=Get-Content -LiteralPath $propsPath -Raw
$productVersion=[string]$propsXml.Project.PropertyGroup.Version
if($productVersion -notmatch '^\d+\.\d+\.\d+\.\d+$'){
    throw "Invalid runtime package product version in Directory.Build.props: '$productVersion'"
}

$provenance=[ordered]@{
    schema=2
    commit=$commit
    productVersion=$productVersion
    builtUtc=(Get-Date).ToUniversalTime().ToString('o')
    vm=$vmText
    configuration=$Configuration
    certificateThumbprint=$thumb
    sysSha256=(Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
    infSha256=(Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash
    catSha256=(Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash
}
$provenance | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'runtime-package.json') -Encoding utf8

Get-ChildItem -LiteralPath $OutputDirectory -File |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.Name } |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ascii

Write-Host "SIGNED RUNTIME DRIVER PACKAGE READY: $OutputDirectory" -ForegroundColor Green
Write-Warning 'This script did not enable TESTSIGNING, change Secure Boot, install trust roots, or modify Defender. Those lab prerequisites must already exist in the disposable VM image.'
