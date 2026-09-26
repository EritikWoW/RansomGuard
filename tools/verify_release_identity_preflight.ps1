param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$TagName,

    [Parameter(Mandatory = $true)]
    [string]$SourceSha,

    [string]$OutputPath = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [IO.Path]::GetFullPath($RepositoryRoot)
if (-not (Test-Path -LiteralPath $repoRoot -PathType Container)) {
    throw "Repository root not found: $repoRoot"
}

if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'SourceSha must be a full 40-character Git SHA.'
}
$sourceShaNormalized = $SourceSha.ToLowerInvariant()

$tagPattern = '^v(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-rc\.(?<rc>[1-9][0-9]*))?$'
$tagMatch = [regex]::Match($TagName, $tagPattern)
if (-not $tagMatch.Success) {
    throw "Release tag '$TagName' is invalid. Expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N."
}

$propsPath = Join-Path $repoRoot 'Directory.Build.props'
if (-not (Test-Path -LiteralPath $propsPath -PathType Leaf)) {
    throw "Directory.Build.props not found: $propsPath"
}

[xml]$props = Get-Content -Raw -LiteralPath $propsPath
$versionValues = @(
    $props.Project.PropertyGroup |
        ForEach-Object { $_.Version } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ }
)
if ($versionValues.Count -ne 1) {
    throw "Expected exactly one product Version in Directory.Build.props; found $($versionValues.Count)."
}

$productVersionText = $versionValues[0].Trim()
$productVersion = $null
if (-not [version]::TryParse($productVersionText, [ref]$productVersion)) {
    throw "Product Version '$productVersionText' is not a valid numeric version."
}
if ($productVersion.Build -lt 0) {
    throw "Product Version '$productVersionText' must include major.minor.patch."
}
if ($productVersion.Revision -gt 0) {
    throw "Product Version '$productVersionText' has non-zero revision. Release identity requires revision 0 and tags the first three components."
}

$tagVersion = "$($tagMatch.Groups['major'].Value).$($tagMatch.Groups['minor'].Value).$($tagMatch.Groups['patch'].Value)"
$productReleaseVersion = "$($productVersion.Major).$($productVersion.Minor).$($productVersion.Build)"
if (-not [string]::Equals($tagVersion, $productReleaseVersion, [StringComparison]::Ordinal)) {
    throw "Tag version '$tagVersion' does not match product version '$productReleaseVersion' from Directory.Build.props."
}

$actualSha = (& git -C $repoRoot rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0) {
    throw 'git rev-parse HEAD failed.'
}
if (-not [string]::Equals($actualSha, $sourceShaNormalized, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Exact source mismatch. expected=$sourceShaNormalized actual=$actualSha"
}

$channel = if ($tagMatch.Groups['rc'].Success) { 'rc' } else { 'production' }
$rcNumber = if ($tagMatch.Groups['rc'].Success) { [int]$tagMatch.Groups['rc'].Value } else { $null }

$evidence = [ordered]@{
    schema = 1
    product = 'RansomGuard'
    tagName = $TagName
    releaseVersion = $tagVersion
    productVersion = $productVersionText
    channel = $channel
    rcNumber = $rcNumber
    sourceSha = $sourceShaNormalized
    exactCheckout = $true
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    passed = $true
    note = 'Preflight validates naming/version/source identity only. It does not create a tag or claim that a production tag is signed.'
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFull = [IO.Path]::GetFullPath($OutputPath)
    $outputDir = Split-Path -Parent $outputFull
    if (-not [string]::IsNullOrWhiteSpace($outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }
    $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outputFull -Encoding utf8NoBOM
    Write-Host "Release identity preflight evidence: $outputFull"
}

Write-Host "RELEASE IDENTITY PREFLIGHT PASSED: tag=$TagName source=$sourceShaNormalized productVersion=$productVersionText channel=$channel"
