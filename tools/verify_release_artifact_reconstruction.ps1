[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WindowsArtifactDirectory,
    [Parameter(Mandatory=$true)][string]$InventoryPath,
    [Parameter(Mandatory=$true)][string]$ReconstructedRoot,
    [string]$ExpectedSourceSha=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Full([string]$Path){[IO.Path]::GetFullPath($Path)}
function Sha256([string]$Path){(Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()}

$artifactRoot=Full $WindowsArtifactDirectory
$inventoryFile=Full $InventoryPath
$outputRoot=Full $ReconstructedRoot

if(-not(Test-Path -LiteralPath $artifactRoot -PathType Container)){
    throw "Windows artifact directory not found: $artifactRoot"
}
if(-not(Test-Path -LiteralPath $inventoryFile -PathType Leaf)){
    throw "Release artifact inventory not found: $inventoryFile"
}
if(Test-Path -LiteralPath $outputRoot){
    throw "Reconstructed release root must not already exist: $outputRoot"
}

$inventory=Get-Content -LiteralPath $inventoryFile -Raw | ConvertFrom-Json -Depth 100
if([int]$inventory.schema -ne 1 -or $null -eq $inventory.files -or @($inventory.files).Count -eq 0){
    throw 'Release artifact inventory is invalid or empty.'
}
if(-not [string]::IsNullOrWhiteSpace($ExpectedSourceSha)){
    if($ExpectedSourceSha -notmatch '^[0-9a-fA-F]{40}$'){
        throw 'ExpectedSourceSha must be a full 40-character Git SHA.'
    }
    if(-not [string]::Equals([string]$inventory.sourceSha,$ExpectedSourceSha,[StringComparison]::OrdinalIgnoreCase)){
        throw "Release inventory source SHA mismatch. inventory=$($inventory.sourceSha) expected=$ExpectedSourceSha"
    }
}

$inputFiles=@(Get-ChildItem -LiteralPath $artifactRoot -File)
if($inputFiles.Count -eq 0){throw 'Downloaded ransomguard-windows artifact is empty.'}
$nonZip=@($inputFiles | Where-Object {$_.Extension -notlike '.zip'})
if($nonZip.Count -ne 0){
    throw "Downloaded ransomguard-windows artifact contains non-ZIP top-level files: $($nonZip.Name -join ', ')"
}
$releaseZips=@($inputFiles | Where-Object {$_.Extension -ieq '.zip'} | Sort-Object Name)
if($releaseZips.Count -lt 1){throw 'Downloaded ransomguard-windows artifact contains no release ZIPs.'}

$duplicateBundleNames=@(
    $releaseZips |
        Group-Object {[IO.Path]::GetFileNameWithoutExtension($_.Name).ToUpperInvariant()} |
        Where-Object Count -gt 1
)
if($duplicateBundleNames.Count -ne 0){throw 'Release ZIP basenames are not unique.'}

New-Item -ItemType Directory -Path $outputRoot | Out-Null
try{
    foreach($zip in $releaseZips){
        $zipDestination=Join-Path $outputRoot $zip.Name
        Copy-Item -LiteralPath $zip.FullName -Destination $zipDestination

        $bundleName=[IO.Path]::GetFileNameWithoutExtension($zip.Name)
        $bundleRoot=Join-Path $outputRoot $bundleName
        if(Test-Path -LiteralPath $bundleRoot){throw "Duplicate release bundle extraction target: $bundleRoot"}
        Expand-Archive -LiteralPath $zip.FullName -DestinationPath $bundleRoot
    }

    $actualFiles=@(Get-ChildItem -LiteralPath $outputRoot -Recurse -File)
    $byRelative=[Collections.Generic.Dictionary[string,IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($file in $actualFiles){
        $relative=[IO.Path]::GetRelativePath($outputRoot,$file.FullName).Replace('\','/')
        if(-not $byRelative.TryAdd($relative,$file)){
            throw "Duplicate reconstructed release path: $relative"
        }
    }

    $expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in @($inventory.files)){
        $relative=([string]$item.path).Replace('\','/')
        if([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative)){
            throw "Governance inventory contains an unsafe release path: '$relative'."
        }
        $resolved=Full (Join-Path $outputRoot ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar)))
        if(-not($resolved.StartsWith($outputRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase))){
            throw "Governance inventory path escapes reconstructed release root: '$relative'."
        }
        if(-not $expectedPaths.Add($relative)){throw "Duplicate governance inventory path: '$relative'."}
        if(-not $byRelative.ContainsKey($relative)){
            throw "Governed release path is missing from reconstructed artifact: '$relative'."
        }

        $file=$byRelative[$relative]
        if([long]$file.Length -ne [long]$item.length){
            throw "Length mismatch for '$relative'. expected=$($item.length) actual=$($file.Length)"
        }
        $actualSha=Sha256 $file.FullName
        if(-not [string]::Equals($actualSha,[string]$item.sha256,[StringComparison]::OrdinalIgnoreCase)){
            throw "SHA-256 mismatch for '$relative'."
        }
    }

    if($byRelative.Count -ne $expectedPaths.Count){
        $extras=@($byRelative.Keys | Where-Object {-not $expectedPaths.Contains($_)})
        throw "Reconstructed release contains files not present in governance inventory. actual=$($byRelative.Count) expected=$($expectedPaths.Count) extras=$($extras -join ', ')"
    }

    $summary=[ordered]@{
        schema=1
        sourceSha=[string]$inventory.sourceSha
        zipCount=$releaseZips.Count
        fileCount=$byRelative.Count
        verifiedUtc=[DateTimeOffset]::UtcNow.ToString('o')
        passed=$true
    }
    $summaryPath=$outputRoot+'.verification.json'
    $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryPath -Encoding utf8NoBOM
    # Verification evidence stays beside, never inside, the exact reconstructed release tree.
    Write-Host "Release artifact reconstruction PASSED: zips=$($releaseZips.Count) files=$($byRelative.Count) root=$outputRoot"
}catch{
    try{if(Test-Path -LiteralPath $outputRoot){Remove-Item -LiteralPath $outputRoot -Recurse -Force}}catch{}
    throw
}
