[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

[xml]$props=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Directory.Build.props') -Raw
$version=[string]$props.Project.PropertyGroup.Version
if($version -notmatch '^\d+\.\d+\.\d+\.\d+$'){
    throw "Canonical product version is invalid: '$version'."
}

$readme=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'README.md') -Raw
$guided=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\GUIDED_SETUP.md') -Raw
$quick=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\AUDIT_QUICKSTART.txt') -Raw
$target=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\PRODUCT_TARGET.md') -Raw
$changelog=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\CHANGELOG.md') -Raw

foreach($required in @(
    @('README',"# RansomGuard $version",$readme),
    @('README release path',"RansomGuard-v$version-<timestamp>",$readme),
    @('Guided setup',"# RansomGuard $version - guided setup",$guided),
    @('Audit quick start',"RansomGuard $version - audit-only quick start",$quick),
    @('Changelog',"# RansomGuard $version",$changelog),
    @('Product target protocol','current engineering branch uses protocol v15',$target),
    @('Product target build hardening','0.7.27 hardens build provenance',$target),
    @('Product target current stress','0.7.28 adds a dedicated bounded-concurrency runtime qualification',$target)
)){
    $label=[string]$required[0]
    $needle=[string]$required[1]
    $text=[string]$required[2]
    if(-not $text.Contains($needle)){
        throw "$label documentation is stale or missing current invariant: $needle"
    }
}

foreach($stale in @(
    'RansomGuard 0.6.3.0 - experimental audit build',
    'RansomGuard 0.7.1.0 - guided setup',
    'current engineering branch uses protocol v13'
)){
    if(($readme+$guided+$quick+$target) -match [regex]::Escape($stale)){
        throw "Current operator/product documentation contains a known stale statement: $stale"
    }
}

Write-Host "Documentation consistency gate PASSED: operator docs, product target, README and changelog match version $version, protocol v15 and the 0.7.28 concurrency-stress milestone."
