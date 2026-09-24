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
    @('Product target protocol','current engineering branch uses protocol v17',$target),
    @('Product target build hardening','0.7.27 hardens build provenance',$target),
    @('Product target concurrency stress','0.7.28 adds a dedicated bounded-concurrency runtime qualification',$target),
    @('Product target fault campaign','0.7.29 adds separate storage-pressure and real-reboot fault qualifications',$target),
    @('Product target current verifier campaign','0.7.30 adds a dedicated Driver Verifier qualification',$target),
    @('Product target mixed endurance campaign','0.7.31 adds a dedicated long-duration/mixed-workload qualification contract',$target),
    @('Product target disconnect fail-safe','0.7.32 introduced protocol v16 and an explicit GateClient-loss protection state',$target),
    @('Product target protected-volume scope','0.7.33 introduces protocol v17 and closes the previous ordinary user-mode name-query fail-open on the negotiated protected volume',$target),
    @('Product target Enforce foundation','0.8.0 starts the production-enforcement integration layer above the already qualified protocol-v17 LAB core',$target)
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

Write-Host "Documentation consistency gate PASSED: operator docs, product target, README and changelog match version $version, protocol v17, qualified 0.7.x kernel milestones and the 0.8.0 Production Enforce foundation boundary."
