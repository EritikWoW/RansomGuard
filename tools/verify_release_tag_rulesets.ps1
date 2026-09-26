param(
    [Parameter(Mandatory = $true)]
    [string]$RulesetsJsonPath,

    [Parameter(Mandatory = $true)]
    [string]$TagName,

    [switch]$AllowRedactedBypassActors
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

function Get-BypassActorState([object]$Ruleset) {
    $property = $Ruleset.PSObject.Properties['bypass_actors']
    if ($null -eq $property) {
        return [pscustomobject]@{
            Known = $false
            Actors = @()
        }
    }

    return [pscustomobject]@{
        Known = $true
        Actors = @($property.Value)
    }
}

function Test-ImmutableBypassPolicy([object]$Ruleset) {
    $state = Get-BypassActorState $Ruleset
    if ($state.Known) {
        return @($state.Actors).Count -eq 0
    }

    return [bool]$AllowRedactedBypassActors -and
        [string]$Ruleset.name -eq 'Protect immutable release tags'
}

function Test-CreationBypassPolicy([object]$Ruleset) {
    $state = Get-BypassActorState $Ruleset
    if ($state.Known) {
        return @($state.Actors).Count -ge 1
    }

    return [bool]$AllowRedactedBypassActors -and
        [string]$Ruleset.name -eq 'Control release tag creation'
}

$tagRulesets = @($rulesets | Where-Object { Targets-ReleaseTags $_ })
if ($tagRulesets.Count -eq 0) {
    throw 'No active tag ruleset exactly covers release tags v* without exclusions.'
}

$immutable = @(
    $tagRulesets | Where-Object {
        $types = @($_.rules | ForEach-Object { [string]$_.type })
        $types -contains 'deletion' -and
        $types -contains 'update' -and
        (Test-ImmutableBypassPolicy $_)
    }
)
if ($immutable.Count -eq 0) {
    throw 'Release tags are not protected by an active no-bypass update + deletion ruleset.'
}

$creation = @(
    $tagRulesets | Where-Object {
        $types = @($_.rules | ForEach-Object { [string]$_.type })
        $types -contains 'creation' -and
        (Test-CreationBypassPolicy $_)
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

$mode = if ($AllowRedactedBypassActors) { 'redacted-actions-token' } else { 'full-admin-view' }
Write-Host "RELEASE TAG RULESETS PASSED: tag=$TagName immutable=$($immutableIds -join ',') creation=$($creationIds -join ',') bypassEvidence=$mode"
