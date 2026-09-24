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
$authPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\Authenticode.cs'
$catalogTrustPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\DriverCatalogTrust.cs'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
foreach($path in @($corePath,$verifierPath,$programPath,$authPath,$catalogTrustPath,$buildPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Production package gate source missing: $path"}
}

$core=Get-Content -LiteralPath $corePath -Raw
$verifier=Get-Content -LiteralPath $verifierPath -Raw
$program=Get-Content -LiteralPath $programPath -Raw
$auth=Get-Content -LiteralPath $authPath -Raw
$catalogTrust=Get-Content -LiteralPath $catalogTrustPath -Raw
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
    'Protection package contains an invalid SHA-256 digest.'
)){
    if($core -notmatch [regex]::Escape($required)){throw "Protection package policy invariant missing: $required"}
}

foreach($required in @(
    'Path.Combine(Path.GetFullPath(applicationBaseDirectory), DirectoryName)',
    'Path.Combine(Path.GetFullPath(applicationBaseDirectory), "RansomGuard.Service.exe")',
    'Environment.ProcessPath',
    'The running process image is not the fixed RansomGuard.Service.exe beside the protection package.',
    'Path.Combine(root, "GateClient", "RansomGuard.GateClient.exe")',
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
    'Lifecycle activation is a separate milestone.'
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
$unavailable=$program.IndexOf('protection.MarkUnavailable("Protection package admission: "+protectionPackage.Reason)',$inspect)
if($inspect -lt 0 -or $unavailable -lt 0 -or $inspect -gt $unavailable){
    throw 'Enforce startup must inspect the fixed protection package and remain EnforceUnavailable with the admission reason.'
}

foreach($forbidden in @(
    'FilterLoad(',
    'StartServiceW(',
    'CreateServiceW(',
    'fltmc.exe',
    'sc.exe start RansomGuardMinifilter'
)){
    if(($verifier+$program) -match [regex]::Escape($forbidden)){
        throw "Protection package admission must remain inspection-only before lifecycle qualification: $forbidden"
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

Write-Host 'Production protection-package admission gate PASSED: fixed layout, exact hashes/version/protocol, LAB identity rejection, signature inspection and explicit SYS-to-CAT membership fail-closed boundary.' -ForegroundColor Green
