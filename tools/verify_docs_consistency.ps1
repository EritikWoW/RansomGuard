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
$protectionPackage=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\PRODUCTION_PROTECTION_PACKAGE.md') -Raw

foreach($required in @(
    @('README',"# RansomGuard $version",$readme),
    @('README release path',"RansomGuard-v$version-<timestamp>",$readme),
    @('Guided setup',"# RansomGuard $version - guided setup",$guided),
    @('Audit quick start',"RansomGuard $version - audit-only quick start",$quick),
    @('Changelog',"# RansomGuard $version",$changelog),
    @('Product target protocol','current engineering branch uses protocol v18',$target),
    @('Product target build hardening','0.7.27 hardens build provenance',$target),
    @('Product target concurrency stress','0.7.28 adds a dedicated bounded-concurrency runtime qualification',$target),
    @('Product target fault campaign','0.7.29 adds separate storage-pressure and real-reboot fault qualifications',$target),
    @('Product target current verifier campaign','0.7.30 adds a dedicated Driver Verifier qualification',$target),
    @('Product target mixed endurance campaign','0.7.31 adds a dedicated long-duration/mixed-workload qualification contract',$target),
    @('Product target disconnect fail-safe','0.7.32 introduced protocol v16 and an explicit GateClient-loss protection state',$target),
    @('Product target protected-volume scope','0.7.33 introduces protocol v17 and closes the previous ordinary user-mode name-query fail-open on the negotiated protected volume',$target),
    @('Product target Enforce foundation','0.8.0 starts the production-enforcement integration layer above the already qualified protocol-v17 LAB core',$target),
    @('Product target protection package','0.8.1 adds the production protection-package trust/admission boundary above the 0.8.0 Enforce state foundation',$target),
    @('Product target ProductionGate','0.8.2 introduces protocol v18 and a distinct ProductionGate client mode',$target),
    @('Protection package document','Version 0.8.2 retains the trust/admission boundary for the future Production Enforce driver lifecycle',$protectionPackage),
    @('Protection package catalog membership','The driver SYS and INF must each verify as members of the supplied signed CAT',$protectionPackage)
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

Write-Host "Documentation consistency gate PASSED: operator docs, product target, README and changelog match version $version, protocol v18, qualified 0.7.x kernel milestones, 0.8.0 Enforce state foundation, 0.8.1 package admission and the 0.8.2 ProductionGate contract."
