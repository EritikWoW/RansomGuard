[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$CertificateThumbprint
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Require-Command([string]$Name){
    $cmd=Get-Command $Name -ErrorAction SilentlyContinue
    if(-not $cmd){throw "Required command not found: $Name"}
    return $cmd.Source
}

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Runtime VM runner must execute elevated as Administrator.'
}

$cs=Get-CimInstance Win32_ComputerSystem
$vmText="$($cs.Manufacturer) $($cs.Model)"
if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
    throw "REFUSED: runtime runner must be an obvious disposable VM. Detected: $vmText"
}
if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
    throw 'RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
}

$thumb=$CertificateThumbprint.Replace(' ','').ToUpperInvariant()
$current=Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} |
    Select-Object -First 1
$machine=Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey} |
    Select-Object -First 1
$cert=if($current){$current}else{$machine}
if(-not $cert){
    throw "Lab signing certificate with private key not found in CurrentUser/My or LocalMachine/My: $thumb"
}
if($cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){
    throw "Lab signing certificate is expired: $($cert.NotAfter.ToUniversalTime().ToString('o'))"
}

$programFilesX86=(Get-Item Env:'ProgramFiles(x86)').Value
$vswhere=Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
if(-not(Test-Path -LiteralPath $vswhere -PathType Leaf)){
    throw 'Visual Studio Installer/vswhere.exe not found.'
}
$vsInstall=& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vsInstall){throw 'Visual Studio C++ x64 toolchain is not installed.'}
$msbuild=Join-Path $vsInstall 'MSBuild\Current\Bin\amd64\MSBuild.exe'
if(-not(Test-Path -LiteralPath $msbuild -PathType Leaf)){throw "64-bit MSBuild not found: $msbuild"}

$kits=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if(-not $kits){throw 'Windows SDK/WDK KitsRoot10 is not registered.'}
$kits=$kits.TrimEnd('\')
$includeRoot=Join-Path $kits 'Include'
$libRoot=Join-Path $kits 'Lib'
$wdkCandidates=@()
if(Test-Path -LiteralPath $includeRoot){
    $wdkCandidates=Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $version=$_.Name
        $flt=Join-Path $_.FullName 'km\fltKernel.h'
        $lib=Join-Path $libRoot "$version\km\x64\FltMgr.lib"
        if((Test-Path -LiteralPath $flt) -and (Test-Path -LiteralPath $lib)){
            try { [pscustomobject]@{Name=$version;Version=[version]$version;Flt=$flt;Lib=$lib} } catch {}
        }
    } | Sort-Object Version -Descending
}
$wdk=$wdkCandidates | Select-Object -First 1
if(-not $wdk){
    throw "Complete x64 WDK not found under $kits (fltKernel.h + FltMgr.lib required)."
}

function Find-X64KitTool([string]$Name,[string]$Version){
    $preferred=@(
        (Join-Path $kits "bin\$Version\x64\$Name"),
        (Join-Path $kits "Tools\$Version\x64\$Name"),
        (Join-Path $kits "Tools\x64\$Name")
    )
    foreach($path in $preferred){if(Test-Path -LiteralPath $path -PathType Leaf){return $path}}
    $match=Get-ChildItem -LiteralPath $kits -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\\x64\\'} |
        Sort-Object @{Expression={if($_.FullName -like "*$Version*"){0}else{1}}},FullName |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

function Find-Inf2CatTool([string]$Version){
    $x64=Find-X64KitTool 'Inf2Cat.exe' $Version
    if($x64){return $x64}

    $preferred=@(
        (Join-Path $kits "bin\$Version\x86\Inf2Cat.exe"),
        (Join-Path $kits "Tools\$Version\x86\Inf2Cat.exe"),
        (Join-Path $kits "Tools\x86\Inf2Cat.exe")
    )
    foreach($path in $preferred){if(Test-Path -LiteralPath $path -PathType Leaf){return $path}}
    $match=Get-ChildItem -LiteralPath $kits -Filter 'Inf2Cat.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.FullName -match '(?i)\\x86\\'} |
        Sort-Object @{Expression={if($_.FullName -like "*$Version*"){0}else{1}}},FullName |
        Select-Object -First 1
    if($match){return $match.FullName}
    return $null
}

$tools=[ordered]@{
    signtool=Find-X64KitTool 'signtool.exe' $wdk.Name
    inf2cat=Find-Inf2CatTool $wdk.Name
    infverif=Find-X64KitTool 'infverif.exe' $wdk.Name
    apiValidator=Find-X64KitTool 'ApiValidator.exe' $wdk.Name
    aitstatic=Find-X64KitTool 'Aitstatic.exe' $wdk.Name
}
foreach($entry in $tools.GetEnumerator()){
    if([string]::IsNullOrWhiteSpace([string]$entry.Value)){
        throw "Required WDK tool not found: $($entry.Key)"
    }
}

$commands=[ordered]@{
    git=Require-Command 'git.exe'
    fltmc=Require-Command 'fltmc.exe'
    pnputil=Require-Command 'pnputil.exe'
    rundll32=Require-Command 'rundll32.exe'
}

$result=[ordered]@{
    schema=1
    ready=$true
    checkedUtc=[DateTime]::UtcNow.ToString('o')
    identity=$id.Name
    vm=$vmText
    visualStudio=$vsInstall
    msbuild=$msbuild
    kitsRoot=$kits
    wdkVersion=$wdk.Name
    certificateThumbprint=$thumb
    certificateStore=$(if($current){'CurrentUser/My'}else{'LocalMachine/My'})
    certificateNotAfterUtc=$cert.NotAfter.ToUniversalTime().ToString('o')
    tools=$tools
    commands=$commands
}

$result | ConvertTo-Json -Depth 6
Write-Host 'RUNTIME VM RUNNER READINESS PASSED. No boot, trust-store, Secure Boot, TESTSIGNING or Defender setting was modified.' -ForegroundColor Green
