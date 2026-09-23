[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$globalPath=Join-Path $RepositoryRoot 'global.json'
if(-not(Test-Path -LiteralPath $globalPath -PathType Leaf)){
    throw 'global.json is required to pin the build SDK.'
}
$global=Get-Content -LiteralPath $globalPath -Raw | ConvertFrom-Json
if([string]$global.sdk.version -ne '10.0.401'){
    throw "global.json must pin .NET SDK 10.0.401 exactly. Found '$($global.sdk.version)'."
}
if([string]$global.sdk.rollForward -ne 'disable'){
    throw 'global.json must set sdk.rollForward=disable for deterministic SDK selection.'
}
if($global.sdk.allowPrerelease -ne $false){
    throw 'global.json must explicitly disable prerelease SDK selection.'
}

$propsPath=Join-Path $RepositoryRoot 'Directory.Build.props'
[xml]$props=Get-Content -LiteralPath $propsPath -Raw
if([string]$props.Project.PropertyGroup.RestorePackagesWithLockFile -ne 'true'){
    throw 'Directory.Build.props must keep RestorePackagesWithLockFile=true.'
}
if([string]$props.Project.PropertyGroup.Deterministic -ne 'true'){
    throw 'Directory.Build.props must keep Deterministic=true.'
}

$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
$workflows=@(Get-ChildItem -LiteralPath $workflowRoot -Filter '*.yml' -File)
if($workflows.Count -eq 0){throw 'No GitHub Actions workflows found.'}

$expectedPins=@{
    'actions/checkout'='11d5960a326750d5838078e36cf38b85af677262'
    'actions/setup-dotnet'='67a3573c9a986a3f9c594539f4ab511d57bb3ce9'
    'actions/upload-artifact'='ea165f8d65b6e75b540449e92b4886f43607fa02'
    'actions/cache'='0057852bfaa89a56745cba8c7296529d2fc39830'
    'microsoft/setup-msbuild'='6fb02220983dee41ce7ae257b6f4d8f9bf5ed4ce'
    'NuGet/setup-nuget'='d105a947828025cd7a980103c35ba2bfae586d0f'
}

foreach($workflow in $workflows){
    $lines=Get-Content -LiteralPath $workflow.FullName
    foreach($line in $lines){
        if($line -notmatch '^\s*uses:\s*([^\s#]+)'){continue}
        $use=$Matches[1]
        if($use -notmatch '^([^@]+)@([0-9a-fA-F]{40})$'){
            throw "Workflow action must be pinned to a full immutable commit SHA: $($workflow.Name): $use"
        }
        $action=$Matches[1]
        $sha=$Matches[2].ToLowerInvariant()
        if(-not $expectedPins.ContainsKey($action)){
            throw "Workflow action is not in the reviewed pin allow-list: $action"
        }
        if($sha -ne $expectedPins[$action]){
            throw "Workflow action pin changed without supply-chain review: $action@$sha"
        }
    }

    $raw=$lines -join [Environment]::NewLine
    if($raw -match '(?m)^\s*dotnet-version:\s*[^\r\n]*[xX*]'){
        throw "Workflow contains a floating .NET SDK selector: $($workflow.Name)"
    }
    if($raw -match '(?m)^\s*dotnet-version:\s*(?<sdk>[^\s#]+)'){
        if($Matches['sdk'] -ne '10.0.401'){
            throw "Workflow must install exactly .NET SDK 10.0.401: $($workflow.Name)"
        }
    }
}

$gitignorePath=Join-Path $RepositoryRoot '.gitignore'
$gitignore=Get-Content -LiteralPath $gitignorePath -Raw
foreach($pattern in @('*.pfx','*.p12','*.key','.env','.env.*')){
    if($gitignore -notmatch ('(?m)^'+[regex]::Escape($pattern)+'$')){
        throw ".gitignore must exclude sensitive file pattern '$pattern'."
    }
}

Write-Host "Supply-chain gate PASSED: SDK 10.0.401 is exact, roll-forward is disabled, $($workflows.Count) workflows use reviewed full-SHA action pins, and sensitive key/env file patterns are ignored."
