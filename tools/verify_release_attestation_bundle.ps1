[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReleaseRoot,
    [Parameter(Mandatory=$true)][string]$ChecksumsPath,
    [Parameter(Mandatory=$true)][string]$ArtifactBundlePath,
    [Parameter(Mandatory=$true)][string]$IdentityPath,
    [Parameter(Mandatory=$true)][string]$IdentityBundlePath,
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$SignerWorkflow,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SignerDigest,
    [string]$ArtifactVerificationOutput='',
    [string]$IdentityVerificationOutput=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Full([string]$Path){[IO.Path]::GetFullPath($Path)}
function Sha256([string]$Path){(Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()}
function Normalize-SubjectName([string]$Name){
    if([string]::IsNullOrWhiteSpace($Name)){throw 'Attestation subject name is empty.'}
    return $Name.Replace('\','/').TrimStart('./')
}
function Read-Checksums([string]$Path){
    $map=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($line in Get-Content -LiteralPath $Path){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        if($line -notmatch '^([0-9A-Fa-f]{64})\s{2}(.+)$'){
            throw "Invalid SHA256SUMS line: $line"
        }
        $name=Normalize-SubjectName $Matches[2]
        $digest=$Matches[1].ToLowerInvariant()
        if(-not $map.TryAdd($name,$digest)){throw "Duplicate SHA256SUMS subject: $name"}
    }
    if($map.Count -eq 0){throw 'SHA256SUMS is empty.'}
    return $map
}
function Invoke-BundleVerify(
    [string]$SubjectPath,
    [string]$BundlePath,
    [string]$Repo,
    [string]$Workflow,
    [string]$Digest
){
    $json=(& gh attestation verify $SubjectPath --repo $Repo --bundle $BundlePath --signer-workflow $Workflow --signer-digest $Digest --source-ref 'refs/heads/main' --deny-self-hosted-runners --format json | Out-String)
    if($LASTEXITCODE -ne 0){throw "Sigstore bundle verification failed for: $SubjectPath"}
    if([string]::IsNullOrWhiteSpace($json)){throw "Sigstore verification returned no JSON for: $SubjectPath"}
    try{return @($json | ConvertFrom-Json -Depth 100)}
    catch{throw "Sigstore verification JSON was invalid for '$SubjectPath': $($_.Exception.Message)"}
}
function Subjects-FromVerification([object[]]$Verification){
    $subjects=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $Verification){
        $vr=$entry.PSObject.Properties['verificationResult']
        if($null -eq $vr){throw 'Verified attestation JSON is missing verificationResult.'}
        $statement=$vr.Value.PSObject.Properties['statement']
        if($null -eq $statement){throw 'Verified attestation JSON is missing statement.'}
        $subjectProperty=$statement.Value.PSObject.Properties['subject']
        if($null -eq $subjectProperty){throw 'Verified attestation statement is missing subject.'}
        foreach($subject in @($subjectProperty.Value)){
            $name=Normalize-SubjectName ([string]$subject.name)
            $digestProperty=$subject.PSObject.Properties['digest']
            if($null -eq $digestProperty){throw "Verified subject '$name' has no digest."}
            $shaProperty=$digestProperty.Value.PSObject.Properties['sha256']
            if($null -eq $shaProperty -or [string]$shaProperty.Value -notmatch '^[0-9A-Fa-f]{64}$'){
                throw "Verified subject '$name' has no valid sha256 digest."
            }
            $sha=([string]$shaProperty.Value).ToLowerInvariant()
            if($subjects.ContainsKey($name)){
                if(-not [string]::Equals($subjects[$name],$sha,[StringComparison]::OrdinalIgnoreCase)){
                    throw "Conflicting verified digest for subject '$name'."
                }
            }else{
                $subjects.Add($name,$sha)
            }
        }
    }
    return $subjects
}

$release=Full $ReleaseRoot
$sums=Full $ChecksumsPath
$artifactBundle=Full $ArtifactBundlePath
$identity=Full $IdentityPath
$identityBundle=Full $IdentityBundlePath
foreach($path in @($release,$sums,$artifactBundle,$identity,$identityBundle)){
    if(-not(Test-Path -LiteralPath $path)){throw "Release attestation verification input missing: $path"}
}

$expected=Read-Checksums $sums
$releaseFiles=[Collections.Generic.Dictionary[string,IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($file in Get-ChildItem -LiteralPath $release -Recurse -File){
    $relative=Normalize-SubjectName ([IO.Path]::GetRelativePath($release,$file.FullName))
    if(-not $releaseFiles.TryAdd($relative,$file)){throw "Duplicate reconstructed release path: $relative"}
}
if($releaseFiles.Count -ne $expected.Count){
    throw "Reconstructed release subject count does not match SHA256SUMS. release=$($releaseFiles.Count) sums=$($expected.Count)"
}
foreach($pair in $expected.GetEnumerator()){
    if(-not $releaseFiles.ContainsKey($pair.Key)){throw "SHA256SUMS subject missing from reconstructed release: $($pair.Key)"}
    $actual=Sha256 $releaseFiles[$pair.Key].FullName
    if(-not [string]::Equals($actual,$pair.Value,[StringComparison]::OrdinalIgnoreCase)){
        throw "Reconstructed release digest differs from SHA256SUMS: $($pair.Key)"
    }
}

$representativeName=($expected.Keys | Sort-Object | Select-Object -First 1)
$artifactVerification=Invoke-BundleVerify -SubjectPath $releaseFiles[$representativeName].FullName -BundlePath $artifactBundle -Repo $Repository -Workflow $SignerWorkflow -Digest $SignerDigest
$verifiedSubjects=Subjects-FromVerification $artifactVerification
if($verifiedSubjects.Count -ne $expected.Count){
    throw "Signed artifact subject count does not match SHA256SUMS. signed=$($verifiedSubjects.Count) expected=$($expected.Count)"
}
foreach($pair in $expected.GetEnumerator()){
    if(-not $verifiedSubjects.ContainsKey($pair.Key)){throw "Signed attestation is missing subject: $($pair.Key)"}
    if(-not [string]::Equals($verifiedSubjects[$pair.Key],$pair.Value,[StringComparison]::OrdinalIgnoreCase)){
        throw "Signed attestation digest differs from SHA256SUMS: $($pair.Key)"
    }
}

$identityVerification=Invoke-BundleVerify -SubjectPath $identity -BundlePath $identityBundle -Repo $Repository -Workflow $SignerWorkflow -Digest $SignerDigest
$identitySubjects=Subjects-FromVerification $identityVerification
$identityName=Normalize-SubjectName ([IO.Path]::GetFileName($identity))
$identitySha=Sha256 $identity
if($identitySubjects.Count -ne 1 -or -not $identitySubjects.ContainsKey($identityName)){
    throw "Release identity bundle must contain exactly the release identity manifest subject '$identityName'."
}
if(-not [string]::Equals($identitySubjects[$identityName],$identitySha,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Release identity bundle digest does not match release-identity.json.'
}

if(-not [string]::IsNullOrWhiteSpace($ArtifactVerificationOutput)){
    $out=Full $ArtifactVerificationOutput
    $parent=Split-Path -Parent $out
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $artifactVerification | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $out -Encoding utf8NoBOM
}
if(-not [string]::IsNullOrWhiteSpace($IdentityVerificationOutput)){
    $out=Full $IdentityVerificationOutput
    $parent=Split-Path -Parent $out
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $identityVerification | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $out -Encoding utf8NoBOM
}

Write-Host "Sigstore release bundle verification PASSED: artifactSubjects=$($verifiedSubjects.Count) identitySubjects=$($identitySubjects.Count) signer=$SignerWorkflow@$SignerDigest"
