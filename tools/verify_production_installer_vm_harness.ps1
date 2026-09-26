[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){$RepositoryRoot=Join-Path $PSScriptRoot '..'}
$root=[IO.Path]::GetFullPath($RepositoryRoot)
$workflowPath=Join-Path $root '.github\workflows\production-installer-vm.yml'
$harnessPath=Join-Path $root 'qualification\run_production_installer_vm.ps1'
$helperPath=Join-Path $root 'qualification\RansomGuard.UpdaterQualification\Program.cs'
$servicePath=Join-Path $root 'src\RansomGuard.Management\ServiceAdministration.cs'
$transitionPath=Join-Path $root 'src\RansomGuard.Management\ServiceUpdateProtectionTransition.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'

foreach($path in @($workflowPath,$harnessPath,$helperPath,$servicePath,$transitionPath,$dispatcherPath,$windowsCiPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Production installer qualification source missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$helper=Get-Content -LiteralPath $helperPath -Raw
$service=Get-Content -LiteralPath $servicePath -Raw
$transition=Get-Content -LiteralPath $transitionPath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$windows=Get-Content -LiteralPath $windowsCiPath -Raw

foreach($required in @(
    'RansomGuard production installer VM qualification',
    'expected_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RANSOMGUARD_LAB_CERT_THUMBPRINT',
    'ref: ${{ inputs.expected_sha }}',
    'git rev-parse HEAD',
    'prepare_runtime_driver_package.ps1',
    'prepare_production_lifecycle_qualification_package.ps1',
    'RansomGuard.UpdaterQualification',
    'run_production_installer_vm.ps1',
    'ransomguard-production-installer-${{ inputs.expected_sha }}'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Production installer workflow invariant missing: $required"}
}
if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Production installer workflow must not continue after qualification failure.'
}

foreach($required in @(
    'dotnet restore $project --locked-mode -r win-x64',
    'dotnet publish $project -c Release -r win-x64 --self-contained true --no-restore -o $out',
    'ransomguard-production-installer-helper'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Production installer helper publish invariant missing: $required"
    }
}
if($workflow -match [regex]::Escape('-p:BaseIntermediateOutputPath=obj\installer\')){
    throw 'Production installer helper must not switch BaseIntermediateOutputPath after build_lab; prior generated obj sources would become compile inputs.'
}

foreach($required in @(
    "Invoke-Helper @('install-production'",
    "Invoke-Helper @('start')",
    "Invoke-Helper @('stop')",
    "Invoke-Helper @('uninstall')",
    'ServiceInstallPrepared',
    'ProductionProtectionActivated',
    'AutomaticContainmentReady',
    'ProductionProtectionMaintenanceStop',
    'Assert-InstalledPackage',
    'productionPackageStaged',
    'driverUnloaded',
    'serviceUnregistered',
    'PRODUCTION-INSTALLER-EVIDENCE PASS'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "Production installer harness invariant missing: $required"}
}

foreach($forbidden in @(
    '(?im)\bsc(?:\.exe)?\s+create\b',
    '(?im)\bsc(?:\.exe)?\s+config\b',
    '(?im)\bNew-Service\b',
    '(?im)\bSet-Service\b',
    '(?im)\bStop-Process\b',
    '(?im)\btaskkill(?:\.exe)?\b'
)){
    if($harness -match $forbidden){throw "Production installer harness bypasses the administration path: $forbidden"}
}

foreach($required in @(
    'case "install-production"',
    'ServiceAdministration.ReviewInstallInput',
    'productionEnforce: true',
    'ServiceAdministration.Install',
    'case "start"',
    'ServiceAdministration.Execute("start", "START")',
    'case "stop"',
    'ServiceAdministration.Execute("stop", "STOP")'
)){
    if($helper -notmatch [regex]::Escape($required)){throw "Administration helper installer invariant missing: $required"}
}

foreach($required in @(
    'Production Enforce installation requires exactly one explicit protected root.',
    'Production Enforce installation requires the version-bound Protection package.',
    'ValidateInitialProtectionPackage',
    'StageUpdateProtectionPackage',
    'Mode = productionEnforce ? "Enforce" : "Audit"',
    'settings.Enforce.AutomaticContainment = productionEnforce'
)){
    if($service -notmatch [regex]::Escape($required)){throw "Production ServiceAdministration installer invariant missing: $required"}
}

foreach($required in @(
    'ValidateInitialProtectionPackage',
    'ReadRegisteredProtectionIdentity',
    'DriverSysSha256',
    'Altitude'
)){
    if($transition -notmatch [regex]::Escape($required)){throw "Initial Protection compatibility invariant missing: $required"}
}

foreach($required in @(
    '/run-production-installer-vm ',
    'production-installer-vm.yml',
    'Dispatched production installer VM qualification for exact SHA',
    'RansomGuard production installer VM qualification'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){throw "Production installer dispatcher invariant missing: $required"}
}

if($windows -notmatch [regex]::Escape('verify_production_installer_vm_harness.ps1')){
    throw 'Windows CI must run the production installer VM source gate.'
}

Write-Host 'Production installer VM harness gate PASSED: exact-SHA disposable VM, ServiceAdministration production install path, immutable Protection staging, Protected/AutomaticContainmentReady startup and clean Maintenance stop.'
