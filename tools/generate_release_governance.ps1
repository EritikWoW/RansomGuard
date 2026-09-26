param(
    [string]$RepositoryRoot = "",
    [string]$ReleaseRoot = "",
    [string]$OutputDir = "",
    [string]$SourceSha = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Get-SpdxSafeId([string]$Value) {
    $safe = [regex]::Replace($Value, '[^A-Za-z0-9.-]+', '-')
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'item' }
    return $safe.Trim('-')
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$repoRoot = [IO.Path]::GetFullPath($RepositoryRoot)

$propsPath = Join-Path $repoRoot 'Directory.Build.props'
if (-not (Test-Path -LiteralPath $propsPath -PathType Leaf)) {
    throw "Canonical version source not found: $propsPath"
}
[xml]$propsXml = Get-Content -LiteralPath $propsPath -Raw
$productVersion = [string]$propsXml.Project.PropertyGroup.Version
if ($productVersion -notmatch '^\d+\.\d+\.\d+\.\d+if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    $ReleaseRoot = Join-Path $repoRoot 'release'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'build-logs\release-governance'
}

$releasePath = [IO.Path]::GetFullPath($ReleaseRoot)
$outPath = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
    throw "Release root not found: $releasePath"
}

if ([string]::IsNullOrWhiteSpace($SourceSha)) {
    try {
        $SourceSha = (& git -C $repoRoot rev-parse HEAD).Trim()
    }
    catch {
        throw "SourceSha was not supplied and git rev-parse HEAD failed."
    }
}

if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw "SourceSha must be a full 40-character Git SHA."
}
$SourceSha = $SourceSha.ToLowerInvariant()

$files = @(Get-ChildItem -LiteralPath $releasePath -Recurse -File | Sort-Object FullName)
if ($files.Count -eq 0) {
    throw "Release root contains no files: $releasePath"
}

$releaseZipSubjects = @(
    $files | Where-Object {
        $_.Extension -ieq '.zip' -and
        [string]::Equals($_.DirectoryName, $releasePath, [StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object {
        $expectedPrefix = "RansomGuard-v$productVersion-"
        if (-not $_.Name.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
            throw "Release ZIP '$($_.Name)' is not version-bound to canonical product version '$productVersion'."
        }
        [pscustomobject]@{
            path = [IO.Path]::GetRelativePath($releasePath, $_.FullName).Replace('\','/')
            sha256 = Get-Sha256 $_.FullName
        }
    }
)
if ($releaseZipSubjects.Count -eq 0) {
    throw "No top-level release ZIP was found under '$releasePath'."
}

$inventory = foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($releasePath, $file.FullName).Replace('\','/')
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    [pscustomobject]@{
        path = $relative
        length = $file.Length
        sha256 = Get-Sha256 $file.FullName
        authenticodeStatus = [string]$sig.Status
        signerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        signerThumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
    }
}

$lockFiles = @(
    Get-ChildItem -LiteralPath $repoRoot -Recurse -Filter packages.lock.json -File |
        Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' } |
        Sort-Object FullName
)

$nuget = New-Object System.Collections.Generic.List[object]
foreach ($lockFile in $lockFiles) {
    $lockRelative = [IO.Path]::GetRelativePath($repoRoot, $lockFile.FullName).Replace('\','/')
    $json = Get-Content -Raw -LiteralPath $lockFile.FullName | ConvertFrom-Json -Depth 100
    foreach ($tfmProp in $json.dependencies.PSObject.Properties) {
        $tfm = $tfmProp.Name
        foreach ($depProp in $tfmProp.Value.PSObject.Properties) {
            $dep = $depProp.Value
            $typeProperty = $dep.PSObject.Properties['type']
            $resolvedProperty = $dep.PSObject.Properties['resolved']
            $dependencyType = if ($typeProperty) { [string]$typeProperty.Value } else { '' }

            # Project-reference nodes intentionally have no resolved NuGet version.
            # They are source components, not package-manager dependencies.
            if (-not $resolvedProperty) {
                if ($dependencyType -eq 'Project') { continue }
                throw "Lock entry '$($depProp.Name)' in '$lockRelative' ($tfm) has no resolved version."
            }

            $resolved = [string]$resolvedProperty.Value
            if ([string]::IsNullOrWhiteSpace($resolved)) {
                throw "Lock entry '$($depProp.Name)' in '$lockRelative' ($tfm) has an empty resolved version."
            }

            $nuget.Add([pscustomobject]@{
                name = $depProp.Name
                version = $resolved
                type = $dependencyType
                targetFramework = $tfm
                lockFile = $lockRelative
            })
        }
    }
}

$nugetUnique = @(
    $nuget |
        Sort-Object name, version, targetFramework, lockFile -Unique
)

$manifest = [ordered]@{
    schema = 1
    product = 'RansomGuard'
    productVersion = $productVersion
    sourceSha = $SourceSha
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    releaseRoot = 'release'
    files = @($inventory)
    dependencyLocks = @($lockFiles | ForEach-Object {
        [pscustomobject]@{
            path = [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace('\','/')
            sha256 = Get-Sha256 $_.FullName
        }
    })
    nugetDependencies = $nugetUnique
}

$inventoryPath = Join-Path $outPath 'release-artifact-inventory.json'
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $inventoryPath -Encoding utf8NoBOM

$sumLines = foreach ($item in $inventory) {
    "$($item.sha256)  $($item.path)"
}
$sumPath = Join-Path $outPath 'SHA256SUMS.txt'
$sumLines | Set-Content -LiteralPath $sumPath -Encoding ascii

$spdxFiles = @()
foreach ($item in $inventory) {
    $spdxFiles += [ordered]@{
        SPDXID = "SPDXRef-File-$(Get-SpdxSafeId $item.path)"
        fileName = "./release/$($item.path)"
        checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = $item.sha256.ToLowerInvariant() })
    }
}

$spdxPackages = @()
$seenPackageIds = @{}
foreach ($dep in $nugetUnique) {
    $key = "$($dep.name)@$($dep.version)"
    if ($seenPackageIds.ContainsKey($key)) { continue }
    $seenPackageIds[$key] = $true
    $spdxPackages += [ordered]@{
        SPDXID = "SPDXRef-Package-$(Get-SpdxSafeId $dep.name)-$(Get-SpdxSafeId $dep.version)"
        name = $dep.name
        versionInfo = $dep.version
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        supplier = 'NOASSERTION'
        externalRefs = @([ordered]@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:nuget/$([uri]::EscapeDataString($dep.name))@$([uri]::EscapeDataString($dep.version))"
        })
    }
}

$namespaceSeed = "ransomguard-$SourceSha"
$spdx = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "RansomGuard-$($SourceSha.Substring(0,12))"
    documentNamespace = "https://github.com/EritikWoW/RansomGuard/sbom/$namespaceSeed"
    creationInfo = [ordered]@{
        created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        creators = @('Tool: RansomGuard release-governance.ps1')
    }
    packages = $spdxPackages
    files = $spdxFiles
}

$sbomPath = Join-Path $outPath 'ransomguard.spdx.json'
$spdx | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $sbomPath -Encoding utf8NoBOM

$attestation = [ordered]@{
    schema = 2
    product = 'RansomGuard'
    productVersion = $productVersion
    sourceSha = $SourceSha
    releaseSubjects = $releaseZipSubjects
    inventorySha256 = Get-Sha256 $inventoryPath
    sha256SumsSha256 = Get-Sha256 $sumPath
    sbomSha256 = Get-Sha256 $sbomPath
    productionSigningPerformed = $false
    signingBoundary = 'external-controlled-signing'
    provenanceSigning = 'github-oidc-sigstore-artifact-attestation'
    note = 'CI release ZIPs are cryptographically attributable through GitHub OIDC/Sigstore attestations. Production/EV Authenticode signing remains a separate controlled trust boundary.'
}
$attestationPath = Join-Path $outPath 'release-governance-attestation.json'
$attestation | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $attestationPath -Encoding utf8NoBOM

Write-Host "Release governance evidence generated:"
Write-Host "  $inventoryPath"
Write-Host "  $sumPath"
Write-Host "  $sbomPath"
Write-Host "  $attestationPath"
) {
    throw "Canonical product Version must contain exactly four numeric components. Found '$productVersion'."
}

if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    $ReleaseRoot = Join-Path $repoRoot 'release'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'build-logs\release-governance'
}

$releasePath = [IO.Path]::GetFullPath($ReleaseRoot)
$outPath = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
    throw "Release root not found: $releasePath"
}

if ([string]::IsNullOrWhiteSpace($SourceSha)) {
    try {
        $SourceSha = (& git -C $repoRoot rev-parse HEAD).Trim()
    }
    catch {
        throw "SourceSha was not supplied and git rev-parse HEAD failed."
    }
}

if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw "SourceSha must be a full 40-character Git SHA."
}
$SourceSha = $SourceSha.ToLowerInvariant()

$files = @(Get-ChildItem -LiteralPath $releasePath -Recurse -File | Sort-Object FullName)
if ($files.Count -eq 0) {
    throw "Release root contains no files: $releasePath"
}

$inventory = foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($releasePath, $file.FullName).Replace('\','/')
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    [pscustomobject]@{
        path = $relative
        length = $file.Length
        sha256 = Get-Sha256 $file.FullName
        authenticodeStatus = [string]$sig.Status
        signerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        signerThumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
    }
}

$lockFiles = @(
    Get-ChildItem -LiteralPath $repoRoot -Recurse -Filter packages.lock.json -File |
        Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' } |
        Sort-Object FullName
)

$nuget = New-Object System.Collections.Generic.List[object]
foreach ($lockFile in $lockFiles) {
    $lockRelative = [IO.Path]::GetRelativePath($repoRoot, $lockFile.FullName).Replace('\','/')
    $json = Get-Content -Raw -LiteralPath $lockFile.FullName | ConvertFrom-Json -Depth 100
    foreach ($tfmProp in $json.dependencies.PSObject.Properties) {
        $tfm = $tfmProp.Name
        foreach ($depProp in $tfmProp.Value.PSObject.Properties) {
            $dep = $depProp.Value
            $typeProperty = $dep.PSObject.Properties['type']
            $resolvedProperty = $dep.PSObject.Properties['resolved']
            $dependencyType = if ($typeProperty) { [string]$typeProperty.Value } else { '' }

            # Project-reference nodes intentionally have no resolved NuGet version.
            # They are source components, not package-manager dependencies.
            if (-not $resolvedProperty) {
                if ($dependencyType -eq 'Project') { continue }
                throw "Lock entry '$($depProp.Name)' in '$lockRelative' ($tfm) has no resolved version."
            }

            $resolved = [string]$resolvedProperty.Value
            if ([string]::IsNullOrWhiteSpace($resolved)) {
                throw "Lock entry '$($depProp.Name)' in '$lockRelative' ($tfm) has an empty resolved version."
            }

            $nuget.Add([pscustomobject]@{
                name = $depProp.Name
                version = $resolved
                type = $dependencyType
                targetFramework = $tfm
                lockFile = $lockRelative
            })
        }
    }
}

$nugetUnique = @(
    $nuget |
        Sort-Object name, version, targetFramework, lockFile -Unique
)

$manifest = [ordered]@{
    schema = 1
    product = 'RansomGuard'
    sourceSha = $SourceSha
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    releaseRoot = 'release'
    files = @($inventory)
    dependencyLocks = @($lockFiles | ForEach-Object {
        [pscustomobject]@{
            path = [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace('\','/')
            sha256 = Get-Sha256 $_.FullName
        }
    })
    nugetDependencies = $nugetUnique
}

$inventoryPath = Join-Path $outPath 'release-artifact-inventory.json'
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $inventoryPath -Encoding utf8NoBOM

$sumLines = foreach ($item in $inventory) {
    "$($item.sha256)  $($item.path)"
}
$sumPath = Join-Path $outPath 'SHA256SUMS.txt'
$sumLines | Set-Content -LiteralPath $sumPath -Encoding ascii

$spdxFiles = @()
foreach ($item in $inventory) {
    $spdxFiles += [ordered]@{
        SPDXID = "SPDXRef-File-$(Get-SpdxSafeId $item.path)"
        fileName = "./release/$($item.path)"
        checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = $item.sha256.ToLowerInvariant() })
    }
}

$spdxPackages = @()
$seenPackageIds = @{}
foreach ($dep in $nugetUnique) {
    $key = "$($dep.name)@$($dep.version)"
    if ($seenPackageIds.ContainsKey($key)) { continue }
    $seenPackageIds[$key] = $true
    $spdxPackages += [ordered]@{
        SPDXID = "SPDXRef-Package-$(Get-SpdxSafeId $dep.name)-$(Get-SpdxSafeId $dep.version)"
        name = $dep.name
        versionInfo = $dep.version
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        supplier = 'NOASSERTION'
        externalRefs = @([ordered]@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:nuget/$([uri]::EscapeDataString($dep.name))@$([uri]::EscapeDataString($dep.version))"
        })
    }
}

$namespaceSeed = "ransomguard-$SourceSha"
$spdx = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "RansomGuard-$($SourceSha.Substring(0,12))"
    documentNamespace = "https://github.com/EritikWoW/RansomGuard/sbom/$namespaceSeed"
    creationInfo = [ordered]@{
        created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        creators = @('Tool: RansomGuard release-governance.ps1')
    }
    packages = $spdxPackages
    files = $spdxFiles
}

$sbomPath = Join-Path $outPath 'ransomguard.spdx.json'
$spdx | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $sbomPath -Encoding utf8NoBOM

$attestation = [ordered]@{
    schema = 1
    sourceSha = $SourceSha
    inventorySha256 = Get-Sha256 $inventoryPath
    sha256SumsSha256 = Get-Sha256 $sumPath
    sbomSha256 = Get-Sha256 $sbomPath
    productionSigningPerformed = $false
    signingBoundary = 'external-controlled-signing'
    note = 'CI produces unsigned release-governance evidence only. Production/EV signing keys must not be stored in ordinary repository secrets.'
}
$attestationPath = Join-Path $outPath 'release-governance-attestation.json'
$attestation | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $attestationPath -Encoding utf8NoBOM

Write-Host "Release governance evidence generated:"
Write-Host "  $inventoryPath"
Write-Host "  $sumPath"
Write-Host "  $sbomPath"
Write-Host "  $attestationPath"
