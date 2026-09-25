param(
    [Parameter(Mandatory=$true)][long]$ArtifactId,
    [Parameter(Mandatory=$true)][string]$ExpectedSha,
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Require-Leaf([string]$Path,[string]$Label){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){
        throw "$Label is missing: $Path"
    }
}

if($ArtifactId -le 0){throw 'ArtifactId must be positive.'}
if($ExpectedSha -notmatch '^[0-9a-fA-F]{40}$'){throw 'ExpectedSha must be exactly 40 hexadecimal characters.'}
if($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'){throw "Repository '$Repository' is not owner/name."}
if([string]::IsNullOrWhiteSpace($env:GH_TOKEN)){throw 'GH_TOKEN is required to download the frozen package artifact.'}

$expectedShaNormalized=$ExpectedSha.ToLowerInvariant()
$expectedName="ransomguard-frozen-candidate-package-$expectedShaNormalized"
$output=[IO.Path]::GetFullPath($OutputDirectory)

if(Test-Path -LiteralPath $output){Remove-Item -LiteralPath $output -Recurse -Force}
New-Item -ItemType Directory -Path $output -Force | Out-Null

$metaJson=gh api "repos/$Repository/actions/artifacts/$ArtifactId"
if($LASTEXITCODE -ne 0){throw "Unable to query artifact $ArtifactId from $Repository."}
$meta=$metaJson | ConvertFrom-Json -Depth 20

if([long]$meta.id -ne $ArtifactId){throw "Artifact id mismatch. expected=$ArtifactId actual=$($meta.id)"}
if([bool]$meta.expired){throw "Artifact $ArtifactId is expired."}
if(-not [string]::Equals([string]$meta.name,$expectedName,[StringComparison]::Ordinal)){
    throw "Artifact name '$($meta.name)' does not match expected '$expectedName'."
}
if([string]::IsNullOrWhiteSpace([string]$meta.archive_download_url)){
    throw "Artifact $ArtifactId has no archive download URL."
}
if([string]$meta.digest -notmatch '^sha256:[0-9a-fA-F]{64}
$zip=Join-Path $env:RUNNER_TEMP "ransomguard-frozen-package-$ArtifactId.zip"
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

$headers=@(
    '-H',"Authorization: Bearer $env:GH_TOKEN",
    '-H','Accept: application/vnd.github+json',
    '-H','X-GitHub-Api-Version: 2022-11-28'
)
& curl.exe -fL @headers -o $zip ([string]$meta.archive_download_url)
if($LASTEXITCODE -ne 0){throw "Unable to download frozen package artifact $ArtifactId."}
Require-Leaf $zip 'Downloaded artifact ZIP'

Expand-Archive -LiteralPath $zip -DestinationPath $output -Force
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

$attestationPath=Join-Path $output 'frozen-candidate-attestation.json'
$runtimePath=Join-Path $output 'runtime-package.json'
Require-Leaf $attestationPath 'Frozen candidate attestation'
Require-Leaf $runtimePath 'Runtime package provenance'

$attestation=Get-Content -LiteralPath $attestationPath -Raw | ConvertFrom-Json -Depth 30
$runtime=Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json -Depth 30

if([int]$attestation.schema -ne 1){throw "Frozen candidate attestation schema must be 1. Found '$($attestation.schema)'."}
if($attestation.qualificationOnly -ne $true){throw 'Frozen candidate artifact must be explicitly qualificationOnly=true.'}
if(-not [string]::Equals([string]$attestation.frozenCandidateSha,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Frozen candidate attestation SHA '$($attestation.frozenCandidateSha)' does not match '$ExpectedSha'."
}
if([int]$runtime.schema -ne 2){throw "Runtime package schema must be 2. Found '$($runtime.schema)'."}
if(-not [string]::Equals([string]$runtime.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Runtime package commit '$($runtime.commit)' does not match '$ExpectedSha'."
}

$mapping=@(
    [pscustomobject]@{Name='RansomGuardMinifilter.sys'; Attestation='RansomGuardMinifilter.sys'; Runtime='sysSha256'},
    [pscustomobject]@{Name='RansomGuardMinifilter.inf'; Attestation='RansomGuardMinifilter.inf'; Runtime='infSha256'},
    [pscustomobject]@{Name='RansomGuardMinifilter.cat'; Attestation='RansomGuardMinifilter.cat'; Runtime='catSha256'}
)

$verified=[ordered]@{}
foreach($item in $mapping){
    $path=Join-Path $output $item.Name
    Require-Leaf $path "Frozen package $($item.Name)"
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $fromAttestation=[string]$attestation.artifacts.($item.Attestation).sha256
    $fromRuntime=[string]$runtime.($item.Runtime)

    if(-not [string]::Equals($actual,$fromAttestation,[StringComparison]::OrdinalIgnoreCase)){
        throw "$($item.Name) hash does not match frozen-candidate-attestation.json."
    }
    if(-not [string]::Equals($actual,$fromRuntime,[StringComparison]::OrdinalIgnoreCase)){
        throw "$($item.Name) hash does not match runtime-package.json."
    }

    $verified[$item.Name]=[ordered]@{
        sha256=$actual
        bytes=(Get-Item -LiteralPath $path).Length
    }
}

$result=[ordered]@{
    schema=1
    artifactId=$ArtifactId
    artifactName=[string]$meta.name
    artifactDigest=[string]$meta.digest
    provenanceWorkflowRunId=if($null -ne $meta.workflow_run){[long]$meta.workflow_run.id}else{$null}
    frozenCandidateSha=$expectedShaNormalized
    packageDirectory=$output
    qualificationOnly=$true
    signingBoundary=[string]$attestation.signingBoundary
    artifacts=$verified
    importedUtc=[DateTimeOffset]::UtcNow.ToString('o')
}

$resultPath=Join-Path $output 'frozen-package-import-result.json'
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | ConvertTo-Json -Depth 20
){
    throw "Artifact $ArtifactId does not expose a valid GitHub SHA-256 digest."
}

$zip=Join-Path $env:RUNNER_TEMP "ransomguard-frozen-package-$ArtifactId.zip"
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

$headers=@(
    '-H',"Authorization: Bearer $env:GH_TOKEN",
    '-H','Accept: application/vnd.github+json',
    '-H','X-GitHub-Api-Version: 2022-11-28'
)
& curl.exe -fL @headers -o $zip ([string]$meta.archive_download_url)
if($LASTEXITCODE -ne 0){throw "Unable to download frozen package artifact $ArtifactId."}
Require-Leaf $zip 'Downloaded artifact ZIP'

Expand-Archive -LiteralPath $zip -DestinationPath $output -Force
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

$attestationPath=Join-Path $output 'frozen-candidate-attestation.json'
$runtimePath=Join-Path $output 'runtime-package.json'
Require-Leaf $attestationPath 'Frozen candidate attestation'
Require-Leaf $runtimePath 'Runtime package provenance'

$attestation=Get-Content -LiteralPath $attestationPath -Raw | ConvertFrom-Json -Depth 30
$runtime=Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json -Depth 30

if([int]$attestation.schema -ne 1){throw "Frozen candidate attestation schema must be 1. Found '$($attestation.schema)'."}
if($attestation.qualificationOnly -ne $true){throw 'Frozen candidate artifact must be explicitly qualificationOnly=true.'}
if(-not [string]::Equals([string]$attestation.frozenCandidateSha,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Frozen candidate attestation SHA '$($attestation.frozenCandidateSha)' does not match '$ExpectedSha'."
}
if([int]$runtime.schema -ne 2){throw "Runtime package schema must be 2. Found '$($runtime.schema)'."}
if(-not [string]::Equals([string]$runtime.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Runtime package commit '$($runtime.commit)' does not match '$ExpectedSha'."
}

$mapping=@(
    [pscustomobject]@{Name='RansomGuardMinifilter.sys'; Attestation='RansomGuardMinifilter.sys'; Runtime='sysSha256'},
    [pscustomobject]@{Name='RansomGuardMinifilter.inf'; Attestation='RansomGuardMinifilter.inf'; Runtime='infSha256'},
    [pscustomobject]@{Name='RansomGuardMinifilter.cat'; Attestation='RansomGuardMinifilter.cat'; Runtime='catSha256'}
)

$verified=[ordered]@{}
foreach($item in $mapping){
    $path=Join-Path $output $item.Name
    Require-Leaf $path "Frozen package $($item.Name)"
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $fromAttestation=[string]$attestation.artifacts.($item.Attestation).sha256
    $fromRuntime=[string]$runtime.($item.Runtime)

    if(-not [string]::Equals($actual,$fromAttestation,[StringComparison]::OrdinalIgnoreCase)){
        throw "$($item.Name) hash does not match frozen-candidate-attestation.json."
    }
    if(-not [string]::Equals($actual,$fromRuntime,[StringComparison]::OrdinalIgnoreCase)){
        throw "$($item.Name) hash does not match runtime-package.json."
    }

    $verified[$item.Name]=[ordered]@{
        sha256=$actual
        bytes=(Get-Item -LiteralPath $path).Length
    }
}

$result=[ordered]@{
    schema=1
    artifactId=$ArtifactId
    artifactName=[string]$meta.name
    frozenCandidateSha=$expectedShaNormalized
    packageDirectory=$output
    qualificationOnly=$true
    signingBoundary=[string]$attestation.signingBoundary
    artifacts=$verified
    importedUtc=[DateTimeOffset]::UtcNow.ToString('o')
}

$resultPath=Join-Path $output 'frozen-package-import-result.json'
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | ConvertTo-Json -Depth 20
