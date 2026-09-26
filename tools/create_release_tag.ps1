[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TagName,

    [Parameter(Mandatory = $true)]
    [string]$SourceSha,

    [string]$Repository = 'EritikWoW/RansomGuard',

    [string]$Remote = 'origin'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($TagName -notmatch '^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$') {
    throw "TagName '$TagName' is not a RansomGuard release tag."
}
if ($SourceSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'SourceSha must be a full 40-character Git SHA.'
}
$SourceSha = $SourceSha.ToLowerInvariant()

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    git rev-parse --is-inside-work-tree | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'This helper must run from a RansomGuard Git checkout.'
    }

    $origin = (git remote get-url $Remote).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($origin)) {
        throw "Git remote '$Remote' is unavailable."
    }

    gh auth status | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'GitHub CLI authentication is required so live release-tag rulesets can be verified.'
    }

    $summaryRaw = gh api "repos/$Repository/rulesets"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read repository rulesets for '$Repository'."
    }
    $summary = @($summaryRaw | ConvertFrom-Json)
    $details = @()
    foreach ($item in $summary) {
        $raw = gh api "repos/$Repository/rulesets/$($item.id)"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to read repository ruleset $($item.id)."
        }
        $details += ($raw | ConvertFrom-Json)
    }

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('ransomguard-release-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $rulesetsPath = Join-Path $tempRoot 'rulesets.json'
    $preflightPath = Join-Path $tempRoot 'preflight.json'
    try {
        $details | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $rulesetsPath -Encoding utf8NoBOM
        & (Join-Path $PSScriptRoot 'verify_release_tag_rulesets.ps1') -RulesetsJsonPath $rulesetsPath -TagName $TagName
        if ($LASTEXITCODE -ne 0) {
            throw 'Live release-tag ruleset verification failed.'
        }

        git fetch $Remote main --tags
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to fetch '$Remote/main' and release tags."
        }

        $preflightArgs = @{
            RepositoryRoot = $repoRoot
            TagName = $TagName
            SourceSha = $SourceSha
            OutputPath = $preflightPath
        }
        & (Join-Path $PSScriptRoot 'verify_release_identity_preflight.ps1') @preflightArgs
        if ($LASTEXITCODE -ne 0) {
            throw 'Release identity preflight failed.'
        }

        git show-ref --verify --quiet "refs/tags/$TagName"
        if ($LASTEXITCODE -eq 0) {
            throw "Tag '$TagName' already exists locally; refusing to replace it."
        }

        $remoteTag = git ls-remote --tags $Remote "refs/tags/$TagName"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to query remote tag '$TagName'."
        }
        if (-not [string]::IsNullOrWhiteSpace(($remoteTag -join [Environment]::NewLine))) {
            throw "Tag '$TagName' already exists on '$Remote'; immutable release tags are never moved."
        }

        $message = 'RansomGuard ' + $TagName + [Environment]::NewLine + [Environment]::NewLine + 'Source: ' + $SourceSha
        git tag -a $TagName $SourceSha -m $message
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to create annotated tag '$TagName'."
        }

        try {
            git push $Remote "refs/tags/$TagName:refs/tags/$TagName"
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to push protected release tag '$TagName'."
            }
        }
        catch {
            git tag -d $TagName | Out-Null
            throw
        }

        Write-Host "RELEASE TAG CREATED: tag=$TagName source=$SourceSha remote=$Remote"
        Write-Host 'The tag is now immutable by repository policy. Run the release identity attestation workflow next.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}
finally {
    Pop-Location
}
