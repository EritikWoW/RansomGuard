[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$OldVersion='0.8.6.0'
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){throw "$Label has no filesystem root: $full"}
    $cursor=$root.TrimEnd('\')
    foreach($segment in $full.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}
function Invoke-Dotnet([string[]]$Arguments,[string]$Label){
    & dotnet @Arguments
    if($LASTEXITCODE -ne 0){throw "$Label failed, exit=$LASTEXITCODE"}
}
function Remove-BuildFamily([string]$Family){
    foreach($root in @(
        Get-ChildItem -LiteralPath (Join-Path $repoRoot 'src'),(Join-Path $repoRoot 'qualification') -Directory -Recurse -Force |
            Where-Object { $_.Name -eq $Family -and $_.Parent -and $_.Parent.Name -in @('obj','bin') }
    )){
        Remove-Item -LiteralPath $root.FullName -Recurse -Force
    }
}
function Publish-VersionedProject(
    [string]$Project,
    [string]$Version,
    [string]$Family,
    [string]$Output
){
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
    Invoke-Dotnet @(
        'restore',$Project,'--locked-mode','-r','win-x64',
        "-p:Version=$Version",
        "-p:BaseIntermediateOutputPath=obj\$Family\"
    ) "Restore $Family"
    Invoke-Dotnet @(
        'publish',$Project,'-c','Release','-r','win-x64','--self-contained','true','--no-restore',
        "-p:Version=$Version",
        "-p:BaseIntermediateOutputPath=obj\$Family\",
        "-p:BaseOutputPath=bin\$Family\",
        '-o',$Output
    ) "Publish $Family"
}

if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
    throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required for production release-transition qualification package preparation.'
}

$repoRoot=Split-Path -Parent $PSScriptRoot
$actual=(& git -C $repoRoot rev-parse HEAD).Trim()
if(-not [string]::Equals($actual,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Exact source mismatch. expected=$ExpectedCommit actual=$actual"
}

[xml]$props=Get-Content -LiteralPath (Join-Path $repoRoot 'Directory.Build.props') -Raw
$currentVersionText=[string]$props.Project.PropertyGroup.Version
$currentVersion=$null
$oldParsed=$null
if(-not [Version]::TryParse($currentVersionText,[ref]$currentVersion)){throw "Invalid canonical version: $currentVersionText"}
if(-not [Version]::TryParse($OldVersion,[ref]$oldParsed)){throw "Invalid old fixture version: $OldVersion"}
if($currentVersion.Revision -ne 0 -or $oldParsed.Revision -ne 0){throw 'Qualification versions must use revision 0.'}
if($currentVersion -le $oldParsed){throw "Canonical version must be forward of old fixture. old=$oldParsed current=$currentVersion"}
$futureVersion=[Version]::new($currentVersion.Major,$currentVersion.Minor,$currentVersion.Build+1,0)
$futureVersionText=$futureVersion.ToString()

$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
if($OutputRoot -notmatch '(?i)RansomGuard'){throw 'OutputRoot must contain RansomGuard.'}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
Assert-NoReparsePath $OutputRoot 'OutputRoot'

$serviceProject=Join-Path $repoRoot 'src\RansomGuard.Service\RansomGuard.Service.csproj'
$gateProject=Join-Path $repoRoot 'src\RansomGuard.GateClient\RansomGuard.GateClient.csproj'
$helperProject=Join-Path $repoRoot 'qualification\RansomGuard.UpdaterQualification\RansomGuard.UpdaterQualification.csproj'
$failureProject=Join-Path $repoRoot 'qualification\RansomGuard.UpdaterFailureFixture\RansomGuard.UpdaterFailureFixture.csproj'
$appSettings=Join-Path $repoRoot 'src\RansomGuard.Service\appsettings.json'
$prepareLifecycle=Join-Path $repoRoot 'minifilter-tools\prepare_production_lifecycle_qualification_package.ps1'
$prepareDriver=Join-Path $repoRoot 'minifilter-tools\prepare_runtime_driver_package.ps1'
foreach($required in @($serviceProject,$gateProject,$helperProject,$failureProject,$appSettings,$prepareLifecycle,$prepareDriver)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required transition source missing: $required"}
}

$driverPackage=Join-Path $OutputRoot 'driver'
& $prepareDriver -CertificateThumbprint $CertificateThumbprint -OutputDirectory $driverPackage
if($LASTEXITCODE -ne 0){throw 'Exact-source runtime driver package preparation failed.'}
$driverProv=Get-Content -LiteralPath (Join-Path $driverPackage 'runtime-package.json') -Raw | ConvertFrom-Json
if(-not [string]::Equals([string]$driverProv.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Driver package source '$($driverProv.commit)' does not match '$ExpectedCommit'."
}

$versions=[ordered]@{
    old=$OldVersion
    current=$currentVersionText
    future=$futureVersionText
}
$records=[ordered]@{}

foreach($entry in @(
    [pscustomobject]@{Label='old';Version=$OldVersion;ServiceProject=$serviceProject},
    [pscustomobject]@{Label='current';Version=$currentVersionText;ServiceProject=$serviceProject},
    [pscustomobject]@{Label='future';Version=$futureVersionText;ServiceProject=$failureProject}
)){
    $label=[string]$entry.Label
    $version=[string]$entry.Version
    $family="transition-$label"
    $root=Join-Path $OutputRoot $label
    $normal=Join-Path $root 'normal'
    $labGate=Join-Path $root 'lab\MinifilterLab\GateClient'
    $helper=Join-Path $root 'helper'
    New-Item -ItemType Directory -Path $normal,$labGate,$helper -Force | Out-Null

    $serviceOut=Join-Path $root 'service-publish'
    Publish-VersionedProject ([string]$entry.ServiceProject) $version $family $serviceOut
    $sourceExe=if($label -eq 'future'){
        Join-Path $serviceOut 'RansomGuard.UpdaterFailureFixture.exe'
    }else{
        Join-Path $serviceOut 'RansomGuard.Service.exe'
    }
    if(-not(Test-Path -LiteralPath $sourceExe -PathType Leaf)){throw "Versioned service fixture missing: $sourceExe"}
    Copy-Item -LiteralPath $sourceExe -Destination (Join-Path $normal 'RansomGuard.Service.exe')
    Copy-Item -LiteralPath $appSettings -Destination (Join-Path $normal 'appsettings.json')

    Publish-VersionedProject $gateProject $version "$family-gate" $labGate
    Publish-VersionedProject $helperProject $version "$family-helper" $helper

    $serviceVersion=(Get-Item -LiteralPath (Join-Path $normal 'RansomGuard.Service.exe')).VersionInfo.FileVersion
    $gateVersion=(Get-Item -LiteralPath (Join-Path $labGate 'RansomGuard.GateClient.exe')).VersionInfo.FileVersion
    $helperVersion=(Get-Item -LiteralPath (Join-Path $helper 'RansomGuard.UpdaterQualification.exe')).VersionInfo.FileVersion
    foreach($pair in @(@($serviceVersion,'service'),@($gateVersion,'gate'),@($helperVersion,'helper'))){
        if(-not [string]::Equals([string]$pair[0],$version,[StringComparison]::Ordinal)){
            throw "$label $($pair[1]) version mismatch. expected=$version actual=$($pair[0])"
        }
    }

    $package=Join-Path $root 'package'
    if($label -eq 'current'){
        & $prepareLifecycle -NormalReleaseDirectory $normal -LabReleaseDirectory (Join-Path $root 'lab') -DriverPackageDirectory $driverPackage -CertificateThumbprint $CertificateThumbprint -OutputDirectory $package
    }else{
        & $prepareLifecycle -NormalReleaseDirectory $normal -LabReleaseDirectory (Join-Path $root 'lab') -DriverPackageDirectory $driverPackage -CertificateThumbprint $CertificateThumbprint -OutputDirectory $package -ProductVersionOverride $version
    }
    if($LASTEXITCODE -ne 0){throw "$label production lifecycle qualification package preparation failed."}

    $packageSummary=Get-Content -LiteralPath (Join-Path $package 'qualification-package.json') -Raw | ConvertFrom-Json
    if([int]$packageSummary.schema -ne 1 -or $packageSummary.qualificationOnly -ne $true){
        throw "$label production package provenance is invalid."
    }
    if(-not [string]::Equals([string]$packageSummary.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals([string]$packageSummary.productVersion,$version,[StringComparison]::Ordinal)){
        throw "$label production package source/version binding is invalid."
    }

    $records[$label]=[ordered]@{
        version=$version
        package=$package
        helper=(Join-Path $helper 'RansomGuard.UpdaterQualification.exe')
        serviceSha256=[string]$packageSummary.serviceSha256
        gateClientSha256=[string]$packageSummary.gateClientSha256
        driverSysSha256=[string]$packageSummary.driverSysSha256
        driverInfSha256=[string]$packageSummary.driverInfSha256
        driverCatSha256=[string]$packageSummary.driverCatSha256
        altitude=[string]$packageSummary.qualificationAltitude
    }

    Remove-BuildFamily $family
    Remove-BuildFamily "$family-gate"
    Remove-BuildFamily "$family-helper"
}

$old=$records.old
$current=$records.current
$future=$records.future
foreach($record in @($old,$current,$future)){
    if(-not [string]::Equals([string]$record.driverSysSha256,[string]$current.driverSysSha256,[StringComparison]::OrdinalIgnoreCase)){
        throw 'All release-transition packages must bind to the exact same driver SYS bytes.'
    }
    if(-not [string]::Equals([string]$record.altitude,[string]$current.altitude,[StringComparison]::Ordinal)){
        throw 'All release-transition packages must use the exact same production qualification altitude.'
    }
}
if([string]::Equals([string]$old.driverInfSha256,[string]$current.driverInfSha256,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Old/current transition INF bytes unexpectedly match despite different version binding.'
}
if([string]::Equals([string]$current.driverInfSha256,[string]$future.driverInfSha256,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Current/future transition INF bytes unexpectedly match despite different version binding.'
}

$summary=[ordered]@{
    schema=1
    commit=$ExpectedCommit.ToLowerInvariant()
    oldVersion=$OldVersion
    currentVersion=$currentVersionText
    futureFailureVersion=$futureVersionText
    driverPackageCommit=[string]$driverProv.commit
    driverSysSha256=[string]$current.driverSysSha256
    qualificationAltitude=[string]$current.altitude
    old=$old
    current=$current
    future=$future
    generatedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    qualificationOnly=$true
}
$summaryPath=Join-Path $OutputRoot 'production-release-transition-packages.json'
$summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Host "PRODUCTION RELEASE TRANSITION PACKAGES READY: $summaryPath"
