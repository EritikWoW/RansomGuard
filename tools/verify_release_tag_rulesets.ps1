param(
    [Parameter(Mandatory = $true)]
    [string]$RulesetsJsonPath,

    [Parameter(Mandatory = $true)]
    [string]$TagName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($TagName -notmatch '^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$') {
    throw "TagName '$TagName' is not a RansomGuard release tag."
}

if (-not (Test-Path -LiteralPath $RulesetsJsonPath -PathType Leaf)) {
    throw "Ruleset evidence file not found: $RulesetsJsonPath"
}

$rulesets = @(Get-Content -Raw -LiteralPath $RulesetsJsonPath | ConvertFrom-Json -Depth 100)
if ($rulesets.Count -eq 0) {
    throw 'No repository rulesets were returned.'
}

function Targets-ReleaseTags([object]$Ruleset) {
    if ([string]$Ruleset.target -ne 'tag' -or [string]$Ruleset.enforcement -ne 'active') {
        return $false
    }

    $refCondition = $Ruleset.conditions.PSObject.Properties['ref_name']
    if (-not $refCondition) { return $false }

    $include = @($refCondition.Value.include)
    $exclude = @($refCondition.Value.exclude)
    if ($exclude.Count -ne 0) {
        return $false
    }

    return $include -contains 'refs/tags/v*' -or $include -contains 'v*'
}

function Get-BypassActors([object]$Ruleset) {
    $property = $Ruleset.PSObject.Properties['bypass_actors']
    if ($null -eq $property) {
        return @()
    }
    return @($property.Value)
}

$tagRulesets = @($rulesets | Where-Object { Targets-ReleaseTags $_ })
if ($tagRulesets.Count -eq 0) {
    throw 'No active tag ruleset exactly covers release tags v* without exclusions.'
}

$immutable = @(
    $tagRulesets | Where-Object {
        $types = @($_.rules | ForEach-Object { [string]$_.type })
        $bypass = @(Get-BypassActors $_)
        $types -contains 'deletion' -and
        $types -contains 'update' -and
        $bypass.Count -eq 0
    }
)
if ($immutable.Count -eq 0) {
    throw 'Release tags are not protected by an active no-bypass update + deletion ruleset.'
}

$creation = @(
    $tagRulesets | Where-Object {
        $types = @($_.rules | ForEach-Object { [string]$_.type })
        $bypass = @(Get-BypassActors $_)
        $types -contains 'creation' -and $bypass.Count -ge 1
    }
)
if ($creation.Count -eq 0) {
    throw 'Release-tag creation is not restricted by an active creation rule with an explicit release actor bypass.'
}

$immutableIds = @($immutable | ForEach-Object { [long]$_.id })
$creationIds = @($creation | ForEach-Object { [long]$_.id })
if (@($immutableIds | Where-Object { $creationIds -contains $_ }).Count -ne 0) {
    throw 'Creation-control and immutable-tag protection must be separate rulesets so the release actor cannot bypass tag immutability.'
}

Write-Host "RELEASE TAG RULESETS PASSED: tag=$TagName immutable=$($immutableIds -join ',') creation=$($creationIds -join ',')"
