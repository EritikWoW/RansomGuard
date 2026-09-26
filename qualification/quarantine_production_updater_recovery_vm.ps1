[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCampaignCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$RepairSourceCommit,
    [Parameter(Mandatory=$true)][string]$AdminHelper,
    [string]$RootBase='C:\RansomGuard-VM-UpdaterRecovery',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Updater recovery campaign quarantine must run as Administrator.'
    }
}
function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: updater recovery quarantine requires a disposable VM. Detected: $text"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required.'
    }
    return $text
}
function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){throw "$Label has no filesystem root: $full"}
    $cursor=$root.TrimEnd('\')
    foreach($segment in $full.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}
function Require-Path([string]$Path,[string]$Label){
    if([string]::IsNullOrWhiteSpace($Path)){throw "$Label path is required."}
    $full=[IO.Path]::GetFullPath($Path)
    Assert-NoReparsePath $full $Label
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw "$Label missing: $full"}
    return $full
}
function Invoke-Helper([string]$Helper,[string[]]$Arguments){
    $output=(& $Helper @Arguments 2>&1 | Out-String).Trim()
    $exit=$LASTEXITCODE
    if($exit -ne 0){throw "Administration helper failed exit=$exit args='$($Arguments -join ' ')'. $output"}
    if([string]::IsNullOrWhiteSpace($output)){throw "Administration helper returned no output for '$($Arguments -join ' ')'."}
    return ($output | ConvertFrom-Json -Depth 100)
}

Assert-Administrator
$vm=Assert-DisposableVm
$AdminHelper=Require-Path $AdminHelper 'AdminHelper'
$RootBase=[IO.Path]::GetFullPath($RootBase)
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
Assert-NoReparsePath $RootBase 'RootBase'

$active=[IO.Path]::GetFullPath([IO.Path]::Combine($RootBase,'Active'))
$statePath=[IO.Path]::GetFullPath([IO.Path]::Combine($active,'updater-recovery-campaign.json'))
$hashPath=$statePath+'.sha256'
foreach($p in @($statePath,$hashPath)){
    Assert-NoReparsePath $p 'Campaign state'
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Campaign state missing: $p"}
}

$expectedHash=(Get-Content -LiteralPath $hashPath -Raw).Trim()
if($expectedHash -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Campaign state SHA-256 sidecar is invalid.'}
$actualHash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
if(-not [string]::Equals($expectedHash,$actualHash,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Campaign state SHA-256 mismatch.'
}

$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -Depth 100 -AsHashtable
if([int]$state.schema -ne 1){throw 'Campaign state schema must be 1.'}
if(-not [string]::Equals([string]$state.commit,$ExpectedCampaignCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Campaign state commit '$($state.commit)' does not match expected stale campaign '$ExpectedCampaignCommit'."
}
if([string]$state.phase -ne 'armed'){throw "Only an armed failed campaign may be quarantined; found phase '$($state.phase)'."}
if([string]$state.crashTransaction -notmatch '^[A-Fa-f0-9]{32}$'){throw 'Campaign crash transaction id is invalid.'}
foreach($name in @('previousImage','targetImage','crashJournal','abortJournal')){
    if([string]::IsNullOrWhiteSpace([string]$state[$name])){throw "Campaign state field '$name' is required."}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if([string]::IsNullOrWhiteSpace($ResultsDirectory)){
    $ResultsDirectory=[IO.Path]::Combine($RootBase,'Evidence',("quarantine-$ExpectedCampaignCommit-$stamp"))
}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

Copy-Item -LiteralPath $statePath -Destination (Join-Path $ResultsDirectory 'campaign-state-pre-quarantine.json') -Force
Copy-Item -LiteralPath $hashPath -Destination (Join-Path $ResultsDirectory 'campaign-state-pre-quarantine.json.sha256') -Force
foreach($pair in @(
    @([string]$state.crashJournal,'crash-journal-pre-recovery.json'),
    @([string]$state.abortJournal,'abort-journal.json')
)){
    $source=[IO.Path]::GetFullPath([string]$pair[0])
    Assert-NoReparsePath $source 'Campaign journal'
    if(-not(Test-Path -LiteralPath $source -PathType Leaf)){throw "Campaign journal missing: $source"}
    Copy-Item -LiteralPath $source -Destination (Join-Path $ResultsDirectory ([string]$pair[1])) -Force
}

$before=Invoke-Helper $AdminHelper @('query')
$before | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'service-before.json') -Encoding utf8

$crashJournal=[IO.Path]::GetFullPath([string]$state.crashJournal)
$crashBefore=Get-Content -LiteralPath $crashJournal -Raw | ConvertFrom-Json -Depth 50
if([string]$crashBefore.TransactionId -ne [string]$state.crashTransaction -or
   [string]$crashBefore.Phase -ne 'Prepared'){
    throw 'Stale crash journal is not the exact expected Prepared transaction.'
}

$recoveryPerformed=$false
$serviceAbsentAtQuarantine=$false
$incompleteJournalQuarantined=$false
$reviewRequiredAction=$null
$recoveryOutcome=$null

if($before.Installed -eq $true){
    if([string]$before.State -ne 'Stopped'){
        throw 'Stale updater campaign service must be stopped before quarantine.'
    }
    if(-not [string]::Equals(
        [IO.Path]::GetFullPath([string]$before.ImagePath),
        [IO.Path]::GetFullPath([string]$state.targetImage),
        [StringComparison]::OrdinalIgnoreCase)){
        throw 'SCM image does not match the stale campaign target image.'
    }

    $review=Invoke-Helper $AdminHelper @('review-recovery')
    $review | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'recovery-review.json') -Encoding utf8
    if([string]$review.TransactionId -ne [string]$state.crashTransaction -or
       [string]$review.JournalPhase -ne 'Prepared' -or
       [string]$review.RequiredAction -ne 'RollbackToPrevious'){
        throw 'Stale updater campaign is not the expected Prepared -> RollbackToPrevious transaction.'
    }
    $reviewRequiredAction=[string]$review.RequiredAction

    $recovered=Invoke-Helper $AdminHelper @('recover-update',[string]$state.crashTransaction)
    $recovered | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'recovery-result.json') -Encoding utf8
    if([string]$recovered.Outcome -ne 'RolledBack'){throw "Stale updater recovery outcome was '$($recovered.Outcome)'."}
    $recoveryOutcome=[string]$recovered.Outcome
    $recoveryPerformed=$true

    $afterRecovery=Invoke-Helper $AdminHelper @('query')
    $afterRecovery | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'service-after-recovery.json') -Encoding utf8
    if($afterRecovery.Installed -ne $true -or [string]$afterRecovery.State -ne 'Stopped' -or
       -not [string]::Equals(
           [IO.Path]::GetFullPath([string]$afterRecovery.ImagePath),
           [IO.Path]::GetFullPath([string]$state.previousImage),
           [StringComparison]::OrdinalIgnoreCase)){
        throw 'Stale updater quarantine did not restore the recorded previous service image.'
    }

    $terminal=Get-Content -LiteralPath $crashJournal -Raw | ConvertFrom-Json -Depth 50
    if([string]$terminal.Phase -ne 'RolledBack'){throw 'Recovered stale transaction did not reach terminal RolledBack.'}
    Copy-Item -LiteralPath $crashJournal -Destination (Join-Path $ResultsDirectory 'crash-journal-post-recovery.json') -Force

    [void](Invoke-Helper $AdminHelper @('uninstall'))
    $gone=Invoke-Helper $AdminHelper @('query')
    $gone | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'service-after-uninstall.json') -Encoding utf8
    if($gone.Installed -eq $true){throw 'Stale updater campaign quarantine left RansomGuardV03 registered.'}
}else{
    $serviceAbsentAtQuarantine=$true
    $reviewRequiredAction='UnavailableServiceAbsent'
    $recoveryOutcome='NotRecoverableServiceAbsent'

    # A later failed qualification already removed the SCM registration. Recovery can
    # no longer be honestly executed. Preserve the exact Prepared journal, then move
    # only that verified incomplete record out of the live ServiceUpdates namespace.
    $journalQuarantine=Join-Path $ResultsDirectory 'ServiceUpdates-quarantined'
    New-Item -ItemType Directory -Path $journalQuarantine -Force | Out-Null
    $journalDestination=Join-Path $journalQuarantine ([IO.Path]::GetFileName($crashJournal))
    if(Test-Path -LiteralPath $journalDestination){throw "Journal quarantine destination already exists: $journalDestination"}
    Move-Item -LiteralPath $crashJournal -Destination $journalDestination
    $incompleteJournalQuarantined=$true

    [void](Invoke-Helper $AdminHelper @('expect-recovery-review-failure','No interrupted service update transaction exists'))
}

$quarantinedActive=Join-Path $ResultsDirectory 'Active-quarantined'
if(Test-Path -LiteralPath $quarantinedActive){throw "Quarantine evidence destination already exists: $quarantinedActive"}
Move-Item -LiteralPath $active -Destination $quarantinedActive

$summary=[ordered]@{
    schema=1
    repairSourceCommit=$RepairSourceCommit
    staleCampaignCommit=$ExpectedCampaignCommit
    staleCampaignPhase='armed'
    crashTransaction=[string]$state.crashTransaction
    reviewRequiredAction=$reviewRequiredAction
    recoveryOutcome=$recoveryOutcome
    recoveryPerformed=$recoveryPerformed
    serviceAbsentAtQuarantine=$serviceAbsentAtQuarantine
    incompleteJournalQuarantined=$incompleteJournalQuarantined
    previousImage=[string]$state.previousImage
    targetImage=[string]$state.targetImage
    serviceAbsentAfterQuarantine=$true
    activeStateQuarantined=$true
    vm=$vm
    completedUtc=[DateTime]::UtcNow.ToString('O')
    passed=$true
}
$summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'updater-recovery-quarantine-result.json') -Encoding utf8
Write-Host "UPDATER-RECOVERY-QUARANTINE PASS stale=$ExpectedCampaignCommit repair=$RepairSourceCommit transaction=$($state.crashTransaction) evidence=$ResultsDirectory"
