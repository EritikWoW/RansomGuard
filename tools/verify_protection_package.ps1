[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$corePath=Join-Path $RepositoryRoot 'src\RansomGuard.Core\ProtectionPackage.cs'
$verifierPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\ProtectionPackageVerifier.cs'
$programPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\Program.cs'
$lifecyclePath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\ProductionProtectionLifecycle.cs'
$authPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\Authenticode.cs'
$catalogTrustPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\DriverCatalogTrust.cs'
$updatePath=Join-Path $RepositoryRoot 'src\RansomGuard.Management\ServiceUpdateAdministration.cs'
$updateTransitionPath=Join-Path $RepositoryRoot 'src\RansomGuard.Management\ServiceUpdateProtectionTransition.cs'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
foreach($path in @($corePath,$verifierPath,$programPath,$lifecyclePath,$authPath,$catalogTrustPath,$updatePath,$updateTransitionPath,$buildPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Production package gate source missing: $path"}
}

$core=Get-Content -LiteralPath $corePath -Raw
$verifier=Get-Content -LiteralPath $verifierPath -Raw
$program=Get-Content -LiteralPath $programPath -Raw
$lifecycle=Get-Content -LiteralPath $lifecyclePath -Raw
$auth=Get-Content -LiteralPath $authPath -Raw
$catalogTrust=Get-Content -LiteralPath $catalogTrustPath -Raw
$update=Get-Content -LiteralPath $updatePath -Raw
$updateTransition=Get-Content -LiteralPath $updateTransitionPath -Raw
$build=Get-Content -LiteralPath $buildPath -Raw

if($core -notmatch [regex]::Escape('bool ReadyForLifecycle')){
    throw 'ProtectionPackageAdmission must expose an explicit ReadyForLifecycle claim.'
}
if($core -notmatch [regex]::Escape('string? SignerCertificateSha256 = null')){
    throw 'ProtectionPackageAdmission must retain the admitted signer certificate identity.'
}

foreach($required in @(
    'ProductionProtection',
    'ProductionProvider = "RansomGuard"',
    'LabPlaceholderAltitude = "370099.4242"',
    'LAB/unassigned placeholder altitude is forbidden for production admission.',
    'Protection package version does not match the service.',
    'Protection package protocol does not match the service.',
    'public const int ProtocolVersion = 18;',
    'Protection package contains an invalid SHA-256 digest.',
    'IsInPlaceTransitionCompatible'
)){
    if($core -notmatch [regex]::Escape($required)){throw "Protection package policy invariant missing: $required"}
}

foreach($required in @(
    'Path.Combine(Path.GetFullPath(applicationBaseDirectory), DirectoryName)',
    'Path.Combine(Path.GetFullPath(applicationBaseDirectory), "RansomGuard.Service.exe")',
    'Environment.ProcessPath',
    'The running process image is not the fixed RansomGuard.Service.exe beside the protection package.',
    'Path.Combine(root, "GateClient", "RansomGuard.GateClient.exe")',
    'ValidateExactLayout(root)',
    'Protection package root contains missing or unexpected entries.',
    'Protection/GateClient contains missing or unexpected entries.',
    'Protection/Driver contains missing or unexpected entries.',
    'Path.Combine(driverDirectory, "RansomGuardMinifilter.sys")',
    'Path.Combine(driverDirectory, "RansomGuardMinifilter.inf")',
    'Path.Combine(driverDirectory, "RansomGuardMinifilter.cat")',
    'FileSafety.NoReparse(path)',
    'Native.FinalFilePath(file.SafeFileHandle)',
    'ProtectionPackagePolicy.ValidateDescriptor(descriptor, expectedVersion)',
    'DecisionPolicy.HashEqual(gateHash, descriptor.GateClientSha256)',
    'DecisionPolicy.HashEqual(sysHash, descriptor.DriverSysSha256)',
    'DecisionPolicy.HashEqual(infHash, descriptor.DriverInfSha256)',
    'DecisionPolicy.HashEqual(catHash, descriptor.DriverCatSha256)',
    'FileVersionInfo.GetVersionInfo(servicePath).FileVersion',
    'FileVersionInfo.GetVersionInfo(gatePath).FileVersion',
    'Authenticode.Check(service, servicePath)',
    'Authenticode.Check(gate, gatePath)',
    'Authenticode.Check(cat, catPath)',
    'GateClient signer certificate does not match the running service signer.',
    'Driver catalog signer certificate does not match the running service signer.',
    'LAB identity/placeholder altitude is forbidden in a production protection package.',
    'INF altitude does not match the production package descriptor.',
    'INF provider does not match the production package descriptor.',
    'INF DriverVer does not match the production package descriptor.',
    'DriverCatalogTrust.VerifyMember(sys, sysPath, catPath)',
    'DriverCatalogTrust.VerifyMember(inf, infPath, catPath)',
    '"ValidCatalogMember"',
    '"Admitted"',
    'package is admitted for the production lifecycle.'
)){
    if($verifier -notmatch [regex]::Escape($required)){throw "Protection package verifier invariant missing: $required"}
}

if($auth -notmatch [regex]::Escape('Catalog lookup is not implemented.')){
    throw 'Embedded Authenticode checker must keep its catalog-lookup limitation explicit; driver membership is verified separately.'
}
foreach($required in @(
    'CryptCATAdminAcquireContext2',
    'CryptCATAdminCalcHashFromFileHandle2',
    'WinTrustCatalogInfo',
    'UnionChoice = 2',
    'CalculatedFileHash',
    'MemberTag',
    'ValidCatalogMember'
)){
    if($catalogTrust -notmatch [regex]::Escape($required)){
        throw "Driver catalog-membership verifier invariant missing: $required"
    }
}

$inspect=$program.IndexOf('ProtectionPackageVerifier.Inspect(AppContext.BaseDirectory,ProductInfo.Version)')
$admissionCheck=$program.IndexOf('!protectionPackage.ReadyForLifecycle',$inspect)
$lifecycleRegistration=$program.IndexOf('new ProductionProtectionLifecycle(',$admissionCheck)
if($inspect -lt 0 -or $admissionCheck -lt 0 -or $lifecycleRegistration -lt 0 -or
   $inspect -gt $admissionCheck -or $admissionCheck -gt $lifecycleRegistration){
    throw 'Enforce startup must inspect the fixed protection package and register lifecycle mutation only after ReadyForLifecycle admission.'
}
if($lifecycle -notmatch [regex]::Escape('_admission.ReadyForLifecycle')){
    throw 'Production lifecycle must independently refuse a package that is not ReadyForLifecycle.'
}

foreach($forbidden in @(
    'FilterLoad(',
    'StartServiceW(',
    'CreateServiceW(',
    'fltmc.exe',
    'pnputil.exe',
    'rundll32.exe'
)){
    if($verifier -match [regex]::Escape($forbidden)){
        throw "ProtectionPackageVerifier must remain inspection-only even though the separately gated lifecycle now mutates driver state: $forbidden"
    }
}

foreach($required in @(
    "'.sys','.cat','.inf'",
    "*GateClient*",
    'driverInstalledByBuild=$false',
    'kernelWriteGateActive=$false'
)){
    if($build -notmatch [regex]::Escape($required)){
        throw "Normal package exclusion boundary changed before lifecycle qualification: $required"
    }
}

foreach($required in @(
    'ValidateUpdateProtectionTransition(',
    'StageUpdateProtectionPackage(targetProtection, targetFolder)',
    'CleanupStagedProtectionPackage(targetFolder)',
    'ProtectionTransition = targetProtection is null'
)){
    if($update -notmatch [regex]::Escape($required)){
        throw "Service updater protection-transition invariant missing: $required"
    }
}

foreach($required in @(
    'InspectUpdateProtectionPackage(',
    'ProtectionPackagePolicy.IsInPlaceTransitionCompatible',
    'ReadRegisteredProtectionIdentity()',
    'target update must carry its own compatible version-bound Protection package.',
    'requires a separate explicit maintenance transition',
    'DriverSysSha256',
    'Staged Protection descriptor changed during the update transition.',
    'ProtectionPackagePolicy.ValidateDescriptor(descriptor, expectedVersion)'
)){
    if($updateTransition -notmatch [regex]::Escape($required)){
        throw "Protection updater compatibility invariant missing: $required"
    }
}

Write-Host 'Production protection-package admission gate PASSED: exact layout, running-service signer binding, hashes/version/protocol, LAB identity rejection, Authenticode and SYS/INF catalog-membership verification; updater transition is version-bound and refuses incompatible in-place filter replacement.' -ForegroundColor Green
