[CmdletBinding()]
param([ValidateSet('Debug','Release')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$sourceRoot=if(Test-Path -LiteralPath (Join-Path $root 'driver')){$root}elseif(Test-Path -LiteralPath (Join-Path $root 'MinifilterLab\Source\driver')){Join-Path $root 'MinifilterLab\Source'}else{throw 'Minifilter source tree not found.'}
& (Join-Path $PSScriptRoot 'verify_minifilter_source.ps1')
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if(-not (Test-Path -LiteralPath $vswhere)){throw 'Visual Studio + Desktop C++ tools + Windows Driver Kit (WDK) are required on the DRIVER BUILD VM.'}
$install=& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $install){throw 'Visual Studio C++ toolchain not found.'}
$msbuild=Join-Path $install 'MSBuild\Current\Bin\amd64\MSBuild.exe'
if(-not (Test-Path -LiteralPath $msbuild)){throw '64-bit MSBuild.exe not found. Repair the Visual Studio C++ workload before building the x64 driver.'}
$kits=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if(-not $kits){throw 'Windows 10/11 SDK/WDK root was not found. Install current WDK integrated with Visual Studio.'}
$kits=$kits.TrimEnd('\')
$project=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuard.Minifilter.vcxproj'
$includeRoot=Join-Path $kits 'Include'
$libRoot=Join-Path $kits 'Lib'
$wdkCandidates=@()
if(Test-Path -LiteralPath $includeRoot){
    $wdkCandidates=Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $v=$_.Name
        $flt=Join-Path $_.FullName 'km\fltKernel.h'
        $lib=Join-Path $libRoot "$v\km\x64\FltMgr.lib"
        if((Test-Path -LiteralPath $flt) -and (Test-Path -LiteralPath $lib)){
            try { [pscustomobject]@{Name=$v; Version=[version]$v; Flt=$flt; Lib=$lib} } catch { }
        }
    } | Sort-Object Version -Descending
}
$wdk=$wdkCandidates | Select-Object -First 1
if(-not $wdk){
    throw "A complete x64 WDK was not found under $kits. Expected Include\\<version>\\km\\fltKernel.h and Lib\\<version>\\km\\x64\\FltMgr.lib."
}
function Find-WdkTool([string]$Name,[string]$Version){
    $toolsRoot=Join-Path $kits 'Tools'
    $preferred=@(
        (Join-Path $toolsRoot "$Version\x64\$Name"),
        (Join-Path $toolsRoot "x64\$Name")
    )
    foreach($p in $preferred){if(Test-Path -LiteralPath $p){return $p}}
    if(Test-Path -LiteralPath $toolsRoot){
        $match=Get-ChildItem -LiteralPath $toolsRoot -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\x64\\' } |
            Sort-Object @{Expression={if($_.FullName -like "*$Version*"){0}else{1}}}, FullName |
            Select-Object -First 1
        if($match){return $match.FullName}
    }
    return $null
}
$infVerif=Find-WdkTool 'infverif.exe' $wdk.Name
if(-not $infVerif){throw "Standalone x64 InfVerif.exe was not found under $(Join-Path $kits 'Tools'). Repair/reinstall the matching WDK before building."}
$apiValidator=Join-Path $kits "bin\$($wdk.Name)\x64\ApiValidator.exe"
$aitStatic=Join-Path $kits "bin\$($wdk.Name)\x64\Aitstatic.exe"
if(-not (Test-Path -LiteralPath $apiValidator)){throw "x64 ApiValidator.exe was not found: $apiValidator. Repair/reinstall the matching WDK before building."}
if(-not (Test-Path -LiteralPath $aitStatic)){throw "x64 Aitstatic.exe was not found: $aitStatic. Repair/reinstall the matching WDK before building."}
Write-Host "Visual Studio: $install"
Write-Host "MSBuild x64: $msbuild"
Write-Host "Windows Kits: $kits"
Write-Host "Selected WDK: $($wdk.Name)"
Write-Host "fltKernel.h: $($wdk.Flt)"
Write-Host "FltMgr.lib: $($wdk.Lib)"
Write-Host "InfVerif: $infVerif"
Write-Host "ApiValidator x64: $apiValidator"
Write-Host "Aitstatic x64: $aitStatic"
Write-Host "Building read-only minifilter: $Configuration x64"
Write-Host 'Build signing policy: SignMode=Off; EnableTestSign=false (UNSIGNED build artifact).'
Write-Host 'DriverSign digest metadata: SHA256 (defense-in-depth if a future signing stage is enabled).'
Write-Host 'Tool architecture policy: 64-bit MSBuild + PreferredToolArchitecture=x64; ApiValidator remains enabled.'
# IMPORTANT: RGKitsRoot intentionally has NO trailing backslash. A trailing backslash inside a quoted /p: value can escape the quote
# in the native command-line parser and corrupt later /m, /v and compiler/linker arguments.
# SignMode is set BOTH in the vcxproj Globals and here as a command-line global property.
# This does not weaken Windows driver-signing policy; it only prevents WDK MSBuild from attempting an implicit local signature during compilation.
$buildArguments = @(
    $project,
    '/t:Rebuild',
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    '/p:PreferredToolArchitecture=x64',
    "/p:WindowsTargetPlatformVersion=$($wdk.Name)",
    "/p:RGWdkVersion=$($wdk.Name)",
    "/p:RGKitsRoot=$kits",
    '/p:SignMode=Off',
    '/p:EnableTestSign=false',
    '/m',
    '/v:minimal'
)
& $msbuild @buildArguments
if($LASTEXITCODE -ne 0){throw "MSBuild failed with exit code $LASTEXITCODE"}
$out=Join-Path $sourceRoot "driver\RansomGuard.Minifilter\bin\x64\$Configuration"
$sys=Get-ChildItem -LiteralPath $out -Filter 'RansomGuardMinifilter.sys' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if(-not $sys){throw "Build reported success but RansomGuardMinifilter.sys was not found under $out"}
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$package=Join-Path $root "minifilter-build\$stamp"
New-Item -ItemType Directory -Path $package -Force | Out-Null
Copy-Item -LiteralPath $sys.FullName -Destination $package
$infSource=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.inf'
$packagedInf=Join-Path $package 'RansomGuardMinifilter.inf'
Copy-Item -LiteralPath $infSource -Destination $packagedInf
Write-Host 'Validating packaged INF with standalone x64 InfVerif (/u)...'
& $infVerif /u $packagedInf
if($LASTEXITCODE -ne 0){throw "InfVerif failed with exit code $LASTEXITCODE. Treat INF validation errors as build failures."}
Copy-Item -LiteralPath (Join-Path $sourceRoot 'native\shared\rg_minifilter_protocol.h') -Destination $package
$hashes=Get-ChildItem -LiteralPath $package -File | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash,$_.Name }
$hashes | Set-Content -LiteralPath (Join-Path $package 'SHA256SUMS.txt') -Encoding ascii
$sig=Get-AuthenticodeSignature -LiteralPath (Join-Path $package 'RansomGuardMinifilter.sys')
Write-Host "Driver package: $package" -ForegroundColor Green
Write-Host "Driver signature status: $($sig.Status)"
if ($sig.Status -eq 'Valid') { throw 'Unexpected embedded signature in compile-only artifact. Review build/signing policy before proceeding.' }
Write-Host 'UNSIGNED BUILD + INF CHECK PASSED. Signing and VM testing are still pending.' -ForegroundColor Green
Write-Warning 'This build script DOES NOT install the driver, generate/trust certificates, enable test signing, disable Secure Boot, or change Defender.'
Write-Warning 'No catalog is generated in this build step. Driver-package signing/catalog generation is a separate lab/production packaging step.'
Write-Warning 'Use only a snapshot VM. Production deployment requires a Microsoft-assigned altitude and appropriate driver signing.'
