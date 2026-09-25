param(
    [Parameter(Mandatory=$true)][string]$CandidateRoot,
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$NormalReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedSha,
    [Parameter(Mandatory=$true)][string]$RootBase,
    [Parameter(Mandatory=$true)][string]$ResultsRoot,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Require-True($Object,[string[]]$Names,[string]$Label){
    foreach($name in $Names){
        if($Object.$name -ne $true){
            throw "$Label invariant '$name' was not true."
        }
    }
}

function Load-Json([string]$Path,[string]$Label){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){
        throw "$Label result is missing: $Path"
    }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 40)
}

function Assert-PackageHashes($Summary,$Import,[string]$Label){
    foreach($pair in @(
        @('driverSysSha256','RansomGuardMinifilter.sys'),
        @('driverInfSha256','RansomGuardMinifilter.inf'),
        @('driverCatSha256','RansomGuardMinifilter.cat')
    )){
        $property=$pair[0]
        if(-not ($Summary.PSObject.Properties.Name -contains $property)){continue}
        $actual=[string]$Summary.$property
        $expected=[string]$Import.artifacts.($pair[1]).sha256
        if(-not [string]::Equals($actual,$expected,[StringComparison]::OrdinalIgnoreCase)){
            throw "$Label used a different $($pair[1]) than the immutable frozen package. expected=$expected actual=$actual"
        }
    }
}

if($ExpectedSha -notmatch '^[0-9a-fA-F]{40}$'){throw 'ExpectedSha must be exactly 40 hexadecimal characters.'}
$candidate=[IO.Path]::GetFullPath($CandidateRoot)
$lab=[IO.Path]::GetFullPath($LabReleaseDirectory)
$normal=[IO.Path]::GetFullPath($NormalReleaseDirectory)
$driver=[IO.Path]::GetFullPath($DriverPackageDirectory)
$root=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
$results=[IO.Path]::GetFullPath($ResultsRoot)
$importPath=Join-Path $driver 'frozen-package-import-result.json'

foreach($path in @($candidate,$lab,$normal,$driver)){
    if(-not(Test-Path -LiteralPath $path -PathType Container)){throw "Required directory is missing: $path"}
}
if(-not(Test-Path -LiteralPath $importPath -PathType Leaf)){throw "Frozen package import result is missing: $importPath"}
$import=Get-Content -LiteralPath $importPath -Raw | ConvertFrom-Json -Depth 30
if(-not [string]::Equals([string]$import.frozenCandidateSha,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Frozen package import SHA '$($import.frozenCandidateSha)' does not match '$ExpectedSha'."
}

if(Test-Path -LiteralPath $results){Remove-Item -LiteralPath $results -Recurse -Force}
New-Item -ItemType Directory -Path $results -Force | Out-Null

$runtimeResults=Join-Path $results 'runtime'
$matrixResults=Join-Path $results 'filesystem-matrix'
$productionResults=Join-Path $results 'production-gate'
$lifecycleResults=Join-Path $results 'production-lifecycle'
$qualificationPackage=Join-Path $results 'production-lifecycle-package'
$matrixScratch=Join-Path $results 'filesystem-matrix-scratch'
foreach($path in @($runtimeResults,$matrixResults,$productionResults,$lifecycleResults,$matrixScratch)){
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

$summary=[ordered]@{
    schema=1
    frozenCandidateSha=$ExpectedSha.ToLowerInvariant()
    frozenPackageArtifactId=[long]$import.artifactId
    driverSysSha256=[string]$import.artifacts.'RansomGuardMinifilter.sys'.sha256
    driverInfSha256=[string]$import.artifacts.'RansomGuardMinifilter.inf'.sha256
    driverCatSha256=[string]$import.artifacts.'RansomGuardMinifilter.cat'.sha256
    runtimePassed=$false
    filesystemMatrixPassed=$false
    productionGatePassed=$false
    productionLifecyclePassed=$false
    cleanupPassed=$false
    passed=$false
    error=$null
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    completedUtc=$null
}

try{
    Push-Location $candidate
    try{
        & .\minifilter-tools\run_runtime_integration_lab.ps1 -LabReleaseDirectory $lab -DriverPackageDirectory $driver -RootBase $root -ResultsDirectory $runtimeResults
        $runtime=Load-Json (Join-Path $runtimeResults 'runtime-result.json') 'Runtime integration'
        if([int]$runtime.schema -ne 2){throw "Runtime result schema must be 2. Found '$($runtime.schema)'."}
        Require-True $runtime @(
            'spoofedClientProcessIdRejected','preexistingDirectoryHandleRejected','dormantWritableHandleRejected',
            'preexistingHardLinkRejected','hardLinkInsideToOutsideDenied','hardLinkOutsideToInsideDenied',
            'hardLinkOutsideToOutsideAllowed','hardLinkExInsideToOutsideDenied','hardLinkExOutsideToInsideDenied',
            'hardLinkExOutsideToOutsideAllowed','fsctlZeroAllowedWithBaseline','fsctlZeroMutatedTarget',
            'fsctlZeroPreimageHashMatched','preexistingMappingRejected','postActivationBaselineVerified',
            'postActivationPagingObserved','preimageHashMatched','disconnectDeniedMutation',
            'disconnectPreservedTargetHash','disconnectReadAllowed','disconnectOutOfRootAllowed',
            'wrongRootReconnectRejected','sameRootReconnectActivated','sameRootMutationAllowed',
            'gracefulReleaseSucceeded','scopeAmbiguityDeniedMutation','scopeAmbiguityPreservedTargetHash',
            'crossBoundaryRenameDenied','crossBoundaryRenameSourcePreserved','crossBoundaryRenameDestinationAbsent',
            'containmentDeniedTarget','containmentPreservedTargetHash','containmentAllowedPeer',
            'transitionRequested','transitionKernelActive','transitionDeniedNextWrite','cleanupPassed','passed'
        ) 'Runtime integration'
        if(-not [string]::Equals([string]$runtime.driverCommit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
            throw "Runtime integration driver commit '$($runtime.driverCommit)' does not match '$ExpectedSha'."
        }
        Assert-PackageHashes $runtime $import 'Runtime integration'
        $summary.runtimePassed=$true

        & .\minifilter-tools\run_filesystem_matrix_lab.ps1 -LabReleaseDirectory $lab -DriverPackageDirectory $driver -ScratchDirectory $matrixScratch -ResultsDirectory $matrixResults
        $matrix=Load-Json (Join-Path $matrixResults 'filesystem-matrix-result.json') 'Filesystem matrix'
        Require-True $matrix @('ntfsAttempted','ntfsSupported','ntfsPassed','refsAttempted','cleanupPassed','passed') 'Filesystem matrix'
        $ntfsScenarios=@($matrix.scenarios | Where-Object {
            [string]::Equals([string]$_.fileSystem,'NTFS',[StringComparison]::OrdinalIgnoreCase) -and $_.supported -eq $true
        })
        if($ntfsScenarios.Count -ne 1 -or $ntfsScenarios[0].unrelatedVolumeAmbiguityAllowed -ne $true){
            throw 'NTFS matrix must prove unrelated-volume ambiguity remains outside the protected-volume gate.'
        }
        if($matrix.refsSupported -eq $true -and $matrix.refsPassed -ne $true){throw 'ReFS was supported but its scenario did not pass.'}
        if($matrix.refsSupported -ne $true -and [string]::IsNullOrWhiteSpace([string]$matrix.refsUnsupportedReason)){
            throw 'ReFS unsupported result must include a reason.'
        }
        Assert-PackageHashes $matrix $import 'Filesystem matrix'
        $summary.filesystemMatrixPassed=$true

        $productionRoot=$root+'-ProductionGate'
        & .\minifilter-tools\run_production_gate_profile_lab.ps1 -LabReleaseDirectory $lab -DriverPackageDirectory $driver -RootBase $productionRoot -ResultsDirectory $productionResults
        $production=Load-Json (Join-Path $productionResults 'production-gate-result.json') 'ProductionGate'
        if([int]$production.schema -ne 1){throw "ProductionGate result schema must be 1. Found '$($production.schema)'."}
        Require-True $production @(
            'productionCliRejectedLabOption','productionActivated','productionMutationAllowed',
            'degradedReadAllowed','degradedDeniedMutation','degradedPreservedHash',
            'labProfileReconnectRejected','productionReconnectActivated','productionReconnectMutationAllowed',
            'cleanupPassed','passed'
        ) 'ProductionGate'
        if(-not [string]::Equals([string]$production.driverCommit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
            throw "ProductionGate driver commit '$($production.driverCommit)' does not match '$ExpectedSha'."
        }
        Assert-PackageHashes $production $import 'ProductionGate'
        $summary.productionGatePassed=$true

        & .\minifilter-tools\prepare_production_lifecycle_qualification_package.ps1 -NormalReleaseDirectory $normal -LabReleaseDirectory $lab -DriverPackageDirectory $driver -CertificateThumbprint $CertificateThumbprint -OutputDirectory $qualificationPackage
        $packageSummary=Load-Json (Join-Path $qualificationPackage 'qualification-package.json') 'Production lifecycle qualification package'
        if([int]$packageSummary.schema -ne 1 -or $packageSummary.qualificationOnly -ne $true){
            throw 'Production lifecycle qualification package provenance is invalid.'
        }
        if(-not [string]::Equals([string]$packageSummary.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
            throw "Production lifecycle package commit '$($packageSummary.commit)' does not match '$ExpectedSha'."
        }

        $lifecycleRoot=$root+'-ProductionLifecycle'
        & .\minifilter-tools\run_production_lifecycle_lab.ps1 -QualificationDirectory $qualificationPackage -ExpectedCommit $ExpectedSha -RootBase $lifecycleRoot -ResultsDirectory $lifecycleResults
        $lifecycle=Load-Json (Join-Path $lifecycleResults 'production-lifecycle-result.json') 'Production lifecycle'
        if([int]$lifecycle.schema -ne 1){throw "Production lifecycle result schema must be 1. Found '$($lifecycle.schema)'."}
        Require-True $lifecycle @(
            'serviceStarted','admittedAndProtected','productionMutationAllowed','gateClientLossObserved',
            'degradedDeniedMutation','degradedPreservedHash','reconnectProtected','reconnectReplacementObserved',
            'reconnectMutationAllowed','serviceCrashObserved','serviceCrashGateExited','serviceCrashDeniedMutation',
            'serviceCrashPreservedHash','serviceRestartProtected','serviceRestartMutationAllowed',
            'maintenanceStopObserved','driverUnloadedAfterMaintenance','serviceStopped','cleanupPassed','passed'
        ) 'Production lifecycle'
        if(-not [string]::Equals([string]$lifecycle.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
            throw "Production lifecycle commit '$($lifecycle.commit)' does not match '$ExpectedSha'."
        }
        if([int]$lifecycle.auditEvidenceCount -le 0){throw 'Production lifecycle must retain filtered audit evidence.'}
        $summary.productionLifecyclePassed=$true
    }finally{
        Pop-Location
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager during frozen suite cleanup, exit=$LASTEXITCODE"}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
        Push-Location $candidate
        try{ & .\minifilter-tools\unload_minifilter_lab.ps1 -Volume $volume }finally{Pop-Location}
    }

    $filtersAfter=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager after frozen suite cleanup, exit=$LASTEXITCODE"}
    if($filtersAfter -match '(?m)^\s*RansomGuardMinifilter\b'){throw 'Frozen runtime suite left RansomGuardMinifilter loaded.'}

    $summary.cleanupPassed=$true
    $summary.passed=$true
}catch{
    $summary.error=$_.Exception.Message
    throw
}finally{
    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $results 'frozen-runtime-suite-result.json') -Encoding utf8
}
