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
if([string]$props.Project.PropertyGroup.RestoreLockedMode -ne 'true'){
    throw 'Directory.Build.props must keep RestoreLockedMode=true.'
}
if([string]$props.Project.PropertyGroup.Deterministic -ne 'true'){
    throw 'Directory.Build.props must keep Deterministic=true.'
}

$projects=@(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') -Filter '*.csproj' -File -Recurse)
$projects+=@(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'tests') -Filter '*.csproj' -File -Recurse)
$projects=@($projects | Sort-Object FullName)
if($projects.Count -eq 0){
    throw 'No managed project files found for lock-file verification.'
}
foreach($project in $projects){
    $lock=Join-Path $project.DirectoryName 'packages.lock.json'
    if(-not(Test-Path -LiteralPath $lock -PathType Leaf)){
        throw "Managed project is missing committed NuGet lock file: $($project.FullName)"
    }
    $parsed=Get-Content -LiteralPath $lock -Raw | ConvertFrom-Json
    if([int]$parsed.version -ne 1 -or $null -eq $parsed.dependencies){
        throw "Invalid NuGet lock file: $lock"
    }
    $targets=@($parsed.dependencies.PSObject.Properties.Name)
    if(-not($targets | Where-Object { $_ -like '*/win-x64' })){
        throw "Committed NuGet lock file is missing the win-x64 target graph used by release restore: $lock"
    }
}

$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
$buildLines=Get-Content -LiteralPath $buildPath
$restoreLines=@($buildLines | Where-Object { $_ -match "Run-Dotnet\s+-Arguments\s+@\('restore'," })
if($restoreLines.Count -eq 0){
    throw 'Central build contains no managed restore commands.'
}
foreach($line in $restoreLines){
    if($line -notmatch [regex]::Escape("'--locked-mode'")){
        throw "Managed restore is not explicitly locked-mode: $($line.Trim())"
    }
    if($line -notmatch [regex]::Escape("'-r','win-x64'") -or
       $line -notmatch [regex]::Escape("'-p:SelfContained=true'")){
        throw "Managed restore does not use the release win-x64/self-contained graph: $($line.Trim())"
    }
}

$windowsWorkflowPath=Join-Path $RepositoryRoot '.github\workflows\windows-ci.yml'
$windowsWorkflow=Get-Content -LiteralPath $windowsWorkflowPath -Raw
if($windowsWorkflow -match 'regenerate_nuget_locks\.ps1|--force-evaluate'){
    throw 'Normal Windows CI must validate committed NuGet locks; lock regeneration is maintenance-only.'
}

$dependabotPath=Join-Path $RepositoryRoot '.github\dependabot.yml'
if(-not(Test-Path -LiteralPath $dependabotPath -PathType Leaf)){
    throw 'Dependabot configuration is required for NuGet and GitHub Actions update PRs.'
}
$dependabot=Get-Content -LiteralPath $dependabotPath -Raw
foreach($ecosystem in @('nuget','github-actions')){
    $needle='package-ecosystem: "'+$ecosystem+'"'
    if(-not $dependabot.Contains($needle)){
        throw "Dependabot configuration is missing package ecosystem '$ecosystem'."
    }
}

$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
$workflows=@(Get-ChildItem -LiteralPath $workflowRoot -Filter '*.yml' -File)
if($workflows.Count -eq 0){
    throw 'No GitHub Actions workflows found.'
}

$expectedPins=@{
    'actions/checkout'='3d3c42e5aac5ba805825da76410c181273ba90b1'
    'actions/setup-dotnet'='a98b56852c35b8e3190ac28c8c2271da59106c68'
    'actions/upload-artifact'='043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
    'actions/cache'='55cc8345863c7cc4c66a329aec7e433d2d1c52a9'
    'microsoft/setup-msbuild'='30375c66a4eea26614e0d39710365f22f8b0af57'
    'NuGet/setup-nuget'='fd55a6f3b34392fa83fde1454582407d8c714123'
}

foreach($workflow in $workflows){
    $lines=Get-Content -LiteralPath $workflow.FullName
    foreach($line in $lines){
        if($line -notmatch '^\s*uses:\s*([^\s#]+)'){
            continue
        }
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
$gitignoreLines=@(Get-Content -LiteralPath $gitignorePath | ForEach-Object { $_.Trim() })
foreach($pattern in @('*.pfx','*.p12','*.key','.env','.env.*')){
    if($gitignoreLines -notcontains $pattern){
        throw ".gitignore must exclude sensitive file pattern '$pattern'."
    }
}

Write-Host "Supply-chain gate PASSED: SDK 10.0.401 is exact, restore drift is disabled, $($projects.Count) managed projects have committed win-x64 lock graphs, normal CI cannot regenerate them, Dependabot tracks NuGet/Actions updates, $($workflows.Count) workflows use reviewed Node 24 full-SHA action pins, and sensitive key/env file patterns are ignored."
