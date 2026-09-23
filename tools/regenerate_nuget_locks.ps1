[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)
Set-Location -LiteralPath $RepositoryRoot

if(-not(Get-Command dotnet -ErrorAction SilentlyContinue)){
    throw 'dotnet is required to regenerate NuGet lock files.'
}
$version=(& dotnet --version).Trim()
if($version -ne '10.0.401'){
    throw "Exact .NET SDK 10.0.401 required for lock regeneration. Found: $version"
}

$projects=@(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') -Filter '*.csproj' -File -Recurse)
$projects+=@(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'tests') -Filter '*.csproj' -File -Recurse)
$projects=@($projects | Sort-Object FullName)
if($projects.Count -eq 0){throw 'No managed projects found.'}

& dotnet nuget locals all --clear
if($LASTEXITCODE -ne 0){throw "dotnet nuget locals failed, exit=$LASTEXITCODE"}

$auditErrors='-warnaserror:NU1900,NU1901,NU1902,NU1903,NU1904,NU1801'
foreach($project in $projects){
    Write-Host "Regenerating lock graph: $($project.FullName)"
    & dotnet restore $project.FullName --force-evaluate -r win-x64 -p:SelfContained=true $auditErrors
    if($LASTEXITCODE -ne 0){
        throw "Lock regeneration failed for $($project.FullName), exit=$LASTEXITCODE"
    }
    $lock=Join-Path $project.DirectoryName 'packages.lock.json'
    if(-not(Test-Path -LiteralPath $lock -PathType Leaf)){
        throw "Restore did not produce lock file: $lock"
    }
    $parsed=Get-Content -LiteralPath $lock -Raw | ConvertFrom-Json
    $keys=@($parsed.dependencies.PSObject.Properties.Name)
    if($keys.Count -eq 0){
        throw "Lock file has no target graph: $lock"
    }
    if(-not($keys | Where-Object { $_ -match '/win-x64$' })){
        throw "Lock file is missing win-x64 graph: $lock"
    }
}

Write-Host "NuGet lock regeneration PASSED: $($projects.Count) projects, SDK 10.0.401, win-x64/self-contained graph."
