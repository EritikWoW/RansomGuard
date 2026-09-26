[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Join-Path $PSScriptRoot '..'
}
$repo=[IO.Path]::GetFullPath($RepositoryRoot)
$verify=Join-Path $repo 'tools\verify_release_artifact_reconstruction.ps1'
$generate=Join-Path $repo 'tools\generate_release_governance.ps1'
foreach($path in @($verify,$generate)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Required regression helper missing: $path"}
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('ransomguard-release-reconstruction-test-'+[Guid]::NewGuid().ToString('N'))
$sourceRoot=Join-Path $root 'release'
$artifactInput=Join-Path $root 'artifact'
$governance=Join-Path $root 'governance'
$reconstructed=Join-Path $root 'reconstructed'
$fakeSha=('a'*40)

function Expect-Failure([scriptblock]$Action,[string]$Label){
    $failed=$false
    try{& $Action}catch{$failed=$true}
    if(-not $failed){throw "Expected failure did not occur: $Label"}
}

try{
    New-Item -ItemType Directory -Path $sourceRoot,$artifactInput,$governance -Force | Out-Null

    $bundleA=Join-Path $sourceRoot 'RansomGuard-v0.0.0-testA'
    $bundleB=Join-Path $sourceRoot 'RansomGuard-Lab-v0.0.0-testB'
    New-Item -ItemType Directory -Path (Join-Path $bundleA 'UI'),(Join-Path $bundleB 'UI'),(Join-Path $bundleB 'Nested') -Force | Out-Null

    [IO.File]::WriteAllText((Join-Path $bundleA 'root.txt'),'audit-root',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $bundleA 'UI\shared.dll'),'audit-shared',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $bundleB 'UI\shared.dll'),'lab-shared',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $bundleB 'Nested\payload.bin'),'lab-payload',[Text.UTF8Encoding]::new($false))

    $zipA=$bundleA+'.zip'
    $zipB=$bundleB+'.zip'
    Compress-Archive -Path (Join-Path $bundleA '*') -DestinationPath $zipA
    Compress-Archive -Path (Join-Path $bundleB '*') -DestinationPath $zipB

    & $generate -RepositoryRoot $root -ReleaseRoot $sourceRoot -OutputDir $governance -SourceSha $fakeSha
    $inventory=Join-Path $governance 'release-artifact-inventory.json'
    if(-not(Test-Path -LiteralPath $inventory -PathType Leaf)){throw 'Synthetic release inventory was not generated.'}

    Copy-Item -LiteralPath $zipA,$zipB -Destination $artifactInput
    & $verify -WindowsArtifactDirectory $artifactInput -InventoryPath $inventory -ReconstructedRoot $reconstructed -ExpectedSourceSha $fakeSha

    foreach($expected in @(
        'RansomGuard-v0.0.0-testA.zip',
        'RansomGuard-Lab-v0.0.0-testB.zip',
        'RansomGuard-v0.0.0-testA\UI\shared.dll',
        'RansomGuard-Lab-v0.0.0-testB\UI\shared.dll',
        'RansomGuard-Lab-v0.0.0-testB\Nested\payload.bin'
    )){
        if(-not(Test-Path -LiteralPath (Join-Path $reconstructed $expected) -PathType Leaf)){
            throw "Successful reconstruction is missing expected path: $expected"
        }
    }
    $a=(Get-Content -LiteralPath (Join-Path $reconstructed 'RansomGuard-v0.0.0-testA\UI\shared.dll') -Raw)
    $b=(Get-Content -LiteralPath (Join-Path $reconstructed 'RansomGuard-Lab-v0.0.0-testB\UI\shared.dll') -Raw)
    if($a -eq $b){throw 'Duplicate basenames from distinct release paths were incorrectly conflated.'}

    $tamperedInventory=Join-Path $root 'tampered-inventory.json'
    $json=Get-Content -LiteralPath $inventory -Raw | ConvertFrom-Json -Depth 100
    $json.files[0].sha256=('0'*64)
    $json | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $tamperedInventory -Encoding utf8NoBOM
    $tamperedOutput=Join-Path $root 'tampered-output'
    Expect-Failure {
        & $verify -WindowsArtifactDirectory $artifactInput -InventoryPath $tamperedInventory -ReconstructedRoot $tamperedOutput -ExpectedSourceSha $fakeSha
    } 'tampered governance digest'

    $corruptInput=Join-Path $root 'corrupt-artifact'
    New-Item -ItemType Directory -Path $corruptInput | Out-Null
    Copy-Item -LiteralPath $zipA,$zipB -Destination $corruptInput
    [IO.File]::WriteAllBytes((Join-Path $corruptInput ([IO.Path]::GetFileName($zipA))),[byte[]](1,2,3,4,5,6,7,8))
    $corruptOutput=Join-Path $root 'corrupt-output'
    Expect-Failure {
        & $verify -WindowsArtifactDirectory $corruptInput -InventoryPath $inventory -ReconstructedRoot $corruptOutput -ExpectedSourceSha $fakeSha
    } 'corrupt release ZIP'

    Write-Host 'Release artifact reconstruction regression PASSED.'
}finally{
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
}
