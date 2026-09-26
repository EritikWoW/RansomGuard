[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('arm','resume','verify')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-UpdaterRecovery',
    [string]$OldAdminHelper='',
    [string]$CurrentAdminHelper='',
    [string]$OldPackage='',
    [string]$CurrentPackage=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Updater interrupted-recovery qualification must run as Administrator.'
    }
}
function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: interrupted updater recovery qualification requires an obvious disposable VM. Detected: $text"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required.'
    }
    return $text
}
function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    $cursor=$root.TrimEnd('\')
    foreach($segment in $full.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point: $cursor"
        }
    }
}
function Invoke-Helper([string]$Exe,[string[]]$Arguments){
    $output=(& $Exe @Arguments 2>&1 | Out-String).Trim()
    $exit=$LASTEXITCODE
    if($exit -ne 0){throw "Qualification helper failed exit=$exit args='$($Arguments -join ' ')'. $output"}
    if([string]::IsNullOrWhiteSpace($output)){return $null}
    try{return $output | ConvertFrom-Json -Depth 100}
    catch{throw "Qualification helper returned non-JSON output. $output"}
}
function Write-Utf8Durable([string]$Path,[string]$Text){
    $parent=Split-Path -Parent $Path
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $tmp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        $fs=[IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
            $fs.Write($bytes,0,$bytes.Length)
            $fs.Flush($true)
        }finally{$fs.Dispose()}
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }finally{
        if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}
    }
}
function Write-State([hashtable]$State,[string]$Path){
    $json=$State | ConvertTo-Json -Depth 50
    Write-Utf8Durable $Path $json
    $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Write-Utf8Durable ($Path+'.sha256') ($hash+[Environment]::NewLine)
}
function Read-State(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StateFile,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedSha
){
    $StateFile=[IO.Path]::GetFullPath($StateFile)
    $hashFile=$StateFile+'.sha256'
    foreach($p in @($StateFile,$hashFile)){
        if([string]::IsNullOrWhiteSpace($p)){
            throw 'Campaign state path resolved to an empty value.'
        }
        if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Campaign state missing: $p"}
        Assert-NoReparsePath $p 'Campaign state'
    }
    $expected=(Get-Content -LiteralPath $hashFile -Raw).Trim()
    $actual=(Get-FileHash -LiteralPath $StateFile -Algorithm SHA256).Hash
    if(-not [string]::Equals($expected,$actual,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Campaign state SHA-256 mismatch.'
    }
    $state=Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json -Depth 100 -AsHashtable
    if([int]$state.schema -ne 1){throw 'Campaign state schema must be 1.'}
    if(-not [string]::Equals([string]$state.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
        throw "Campaign state commit '$($state.commit)' does not match '$ExpectedSha'."
    }
    return $state
}
function Get-InstallRecord([string]$Image){
    $path=Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($Image))) 'install.json'
    Assert-NoReparsePath $path 'Install record'
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Install record missing: $path"}
    $record=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
    if([int]$record.Schema -ne 1 -or [string]$record.ImageSha256 -notmatch '^[A-Fa-f0-9]{64}$'){
        throw "Install record is invalid: $path"
    }
    $actual=(Get-FileHash -LiteralPath $Image -Algorithm SHA256).Hash
    if(-not [string]::Equals([string]$record.ImageSha256,$actual,[StringComparison]::OrdinalIgnoreCase)){
        throw "Installed image hash mismatch: $Image"
    }
    return $record
}
function Get-JournalRoot {
    return Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\ServiceUpdates'
}
function Write-InterruptedRecord(
    [string]$TransactionId,
    [string]$PhaseName,
    [string]$PreviousImage,
    [object]$PreviousRecord,
    [string]$TargetImage,
    [object]$TargetRecord
){
    if($TransactionId -notmatch '^[A-Fa-f0-9]{32}$'){throw 'Transaction id must be 32 hex characters.'}
    $root=Get-JournalRoot
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    Assert-NoReparsePath $root 'ServiceUpdates root'
    $path=Join-Path $root ($TransactionId+'.json')
    if(Test-Path -LiteralPath $path){throw "Synthetic transaction already exists: $path"}
    $now=[DateTime]::UtcNow.ToString('O')
    $record=[ordered]@{
        Schema=1
        TransactionId=$TransactionId
        Phase=$PhaseName
        PreviousImage=[IO.Path]::GetFullPath($PreviousImage)
        PreviousVersion=[string]$PreviousRecord.Version
        PreviousSha256=[string]$PreviousRecord.ImageSha256
        TargetImage=[IO.Path]::GetFullPath($TargetImage)
        TargetVersion=[string]$TargetRecord.Version
        TargetSha256=[string]$TargetRecord.ImageSha256
        CreatedUtc=$now
        UpdatedUtc=$now
        Error=$null
    }
    Write-Utf8Durable $path ($record | ConvertTo-Json -Depth 20)
    return $path
}
function Set-ScmImage([string]$Image){
    $image=[IO.Path]::GetFullPath($Image)
    $sc=Join-Path $env:SystemRoot 'System32\sc.exe'
    $output=(& $sc config RansomGuardV03 'binPath=' ('"'+$image+'"') 2>&1 | Out-String).Trim()
    if($LASTEXITCODE -ne 0){throw "sc.exe config failed exit=$LASTEXITCODE. $output"}
}
function Save-Summary([hashtable]$Summary,[string]$EvidenceRoot){
    New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
    Write-Utf8Durable (Join-Path $EvidenceRoot 'production-updater-interrupted-recovery-result.json') ($Summary | ConvertTo-Json -Depth 60)
}
function Require-Path([string]$Path,[string]$Name){
    if([string]::IsNullOrWhiteSpace($Path)){throw "$Name is required for phase '$Phase'."}
    $full=[IO.Path]::GetFullPath($Path)
    if(-not(Test-Path -LiteralPath $full)){throw "$Name missing: $full"}
    Assert-NoReparsePath $full $Name
    return $full
}

Assert-Administrator
$vm=Assert-DisposableVm
$ExpectedCommit=$ExpectedCommit.ToLowerInvariant()
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$active=[IO.Path]::Combine($RootBase,'Active')
$statePath=[IO.Path]::GetFullPath([IO.Path]::Combine($active,'updater-recovery-campaign.json'))
$evidenceRoot=[IO.Path]::GetFullPath([IO.Path]::Combine($RootBase,'Evidence',$ExpectedCommit))
New-Item -ItemType Directory -Path $active -Force | Out-Null
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

if($Phase -eq 'arm'){
    $OldAdminHelper=Require-Path $OldAdminHelper 'OldAdminHelper'
    $CurrentAdminHelper=Require-Path $CurrentAdminHelper 'CurrentAdminHelper'
    $OldPackage=Require-Path $OldPackage 'OldPackage'
    $CurrentPackage=Require-Path $CurrentPackage 'CurrentPackage'
    if(Test-Path -LiteralPath $statePath){throw 'An updater recovery campaign is already armed. Finish or revert the disposable VM.'}

    $initial=Invoke-Helper $CurrentAdminHelper @('query')
    if($initial.Installed -eq $true){
        throw "REFUSED: RansomGuardV03 is already installed at '$($initial.ImagePath)'. Revert/clean the disposable VM."
    }

    $protectedRoot=Join-Path $RootBase ('Protected-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null

    $oldFirst=Invoke-Helper $OldAdminHelper @('install',$OldPackage,$protectedRoot)
    $successful=Invoke-Helper $CurrentAdminHelper @('update',$CurrentPackage)
    if([string]$successful.Outcome -ne 'Completed'){throw "Fixture forward update did not complete: $($successful.Outcome)"}
    $targetImage=[IO.Path]::GetFullPath([string]$successful.TargetImage)
    $targetRecord=Get-InstallRecord $targetImage
    [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))

    $oldSecond=Invoke-Helper $OldAdminHelper @('install',$OldPackage,$protectedRoot)
    $previousImage=[IO.Path]::GetFullPath([string]$oldSecond.image)
    $previousRecord=Get-InstallRecord $previousImage

    $abortId=[Guid]::NewGuid().ToString('N')
    $abortPath=Write-InterruptedRecord $abortId 'Prepared' $previousImage $previousRecord $targetImage $targetRecord
    $abortReview=Invoke-Helper $CurrentAdminHelper @('review-recovery')
    if([string]$abortReview.TransactionId -ne $abortId -or
       [string]$abortReview.JournalPhase -ne 'Prepared' -or
       [string]$abortReview.RequiredAction -ne 'AbortBeforeCommit'){
        throw 'Prepared-before-SCM recovery review did not select AbortBeforeCommit.'
    }
    $aborted=Invoke-Helper $CurrentAdminHelper @('recover-update',$abortId)
    if([string]$aborted.Outcome -ne 'AbortedBeforeCommit'){throw "Expected AbortedBeforeCommit, got '$($aborted.Outcome)'."}
    $afterAbort=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterAbort.State -ne 'Stopped' -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$afterAbort.ImagePath),$previousImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Abort-before-commit recovery changed the previous service registration unexpectedly.'
    }

    $crashId=[Guid]::NewGuid().ToString('N')
    $crashPath=Write-InterruptedRecord $crashId 'Prepared' $previousImage $previousRecord $targetImage $targetRecord

    Set-ScmImage $targetImage
    $afterCommit=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterCommit.State -ne 'Stopped' -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$afterCommit.ImagePath),$targetImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Failed to model the post-SCM/pre-journal crash window.'
    }
    $crashReview=Invoke-Helper $CurrentAdminHelper @('review-recovery')
    if([string]$crashReview.TransactionId -ne $crashId -or
       [string]$crashReview.JournalPhase -ne 'Prepared' -or
       [string]$crashReview.RequiredAction -ne 'RollbackToPrevious'){
        throw 'Post-SCM/pre-journal crash window was not recognized as RollbackToPrevious.'
    }

    $summary=[ordered]@{
        schema=1
        commit=$ExpectedCommit
        vm=$vm
        phase='armed'
        protectedRoot=$protectedRoot
        successfulFixtureTransaction=[string]$successful.TransactionId
        targetImage=$targetImage
        targetVersion=[string]$targetRecord.Version
        targetSha256=[string]$targetRecord.ImageSha256
        previousImage=$previousImage
        previousVersion=[string]$previousRecord.Version
        previousSha256=[string]$previousRecord.ImageSha256
        abortTransaction=$abortId
        abortJournal=$abortPath
        abortBeforeCommitPassed=$true
        crashTransaction=$crashId
        crashJournal=$crashPath
        crashWindow='SCM target committed while durable journal remains Prepared'
        scmTargetSelected=$true
        preRebootReviewPassed=$true
        firstRebootObserved=$false
        rollbackRecoveryPassed=$false
        secondRebootObserved=$false
        idempotentTerminalStatePassed=$false
        truncatedJournalRejected=$false
        cleanupPassed=$false
        passed=$false
        armedUtc=[DateTime]::UtcNow.ToString('O')
    }
    Write-State $summary $statePath
    Save-Summary $summary $evidenceRoot
    Write-Host "PRODUCTION-UPDATER-RECOVERY ARM PASS transaction=$crashId commit=$ExpectedCommit"
    exit 0
}

$CurrentAdminHelper=Require-Path $CurrentAdminHelper 'CurrentAdminHelper'
$state=Read-State -StateFile $statePath -ExpectedSha $ExpectedCommit

if($Phase -eq 'resume'){
    if([string]$state.phase -ne 'armed'){throw "Resume requires armed state; found '$($state.phase)'."}
    $before=Invoke-Helper $CurrentAdminHelper @('query')
    if($before.State -ne 'Stopped' -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$before.ImagePath),[string]$state.targetImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'First reboot did not preserve the modeled committed target SCM registration.'
    }

    $review=Invoke-Helper $CurrentAdminHelper @('review-recovery')
    if([string]$review.TransactionId -ne [string]$state.crashTransaction -or
       [string]$review.JournalPhase -ne 'Prepared' -or
       [string]$review.RequiredAction -ne 'RollbackToPrevious'){
        throw 'Post-reboot recovery review did not bind to the armed interrupted transaction.'
    }

    $recovered=Invoke-Helper $CurrentAdminHelper @('recover-update',[string]$state.crashTransaction)
    if([string]$recovered.Outcome -ne 'RolledBack'){throw "Interrupted update recovery outcome was '$($recovered.Outcome)'."}
    $after=Invoke-Helper $CurrentAdminHelper @('query')
    if($after.State -ne 'Stopped' -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$after.ImagePath),[string]$state.previousImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Interrupted update recovery did not restore the previous stopped SCM registration.'
    }
    [void](Invoke-Helper $CurrentAdminHelper @('expect-recovery-review-failure','No interrupted service update transaction exists'))

    $journal=Get-Content -LiteralPath ([string]$state.crashJournal) -Raw | ConvertFrom-Json -Depth 50
    if([string]$journal.Phase -ne 'RolledBack'){throw "Recovered transaction is not terminal RolledBack: $($journal.Phase)"}

    $state.phase='recovered'
    $state.firstRebootObserved=$true
    $state.rollbackRecoveryPassed=$true
    $state.recoveredUtc=[DateTime]::UtcNow.ToString('O')
    Write-State $state $statePath
    Save-Summary $state $evidenceRoot
    Write-Host "PRODUCTION-UPDATER-RECOVERY RESUME PASS transaction=$($state.crashTransaction) commit=$ExpectedCommit"
    exit 0
}

if([string]$state.phase -ne 'recovered'){throw "Verify requires recovered state; found '$($state.phase)'."}
$finalQuery=Invoke-Helper $CurrentAdminHelper @('query')
if($finalQuery.State -ne 'Stopped' -or
   -not [string]::Equals([IO.Path]::GetFullPath([string]$finalQuery.ImagePath),[string]$state.previousImage,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Second reboot did not preserve the recovered previous SCM registration.'
}
[void](Invoke-Helper $CurrentAdminHelper @('expect-recovery-review-failure','No interrupted service update transaction exists'))

$terminal=Get-Content -LiteralPath ([string]$state.crashJournal) -Raw | ConvertFrom-Json -Depth 50
if([string]$terminal.Phase -ne 'RolledBack'){throw 'Recovered transaction lost its terminal RolledBack phase after the second reboot.'}

$corruptId=[Guid]::NewGuid().ToString('N')
$corruptPath=Join-Path (Get-JournalRoot) ($corruptId+'.json')
try{
    Write-Utf8Durable $corruptPath '{'
    [void](Invoke-Helper $CurrentAdminHelper @('expect-recovery-review-failure','Update transaction record invalid'))
    $state.truncatedJournalRejected=$true
}finally{
    if(Test-Path -LiteralPath $corruptPath){Remove-Item -LiteralPath $corruptPath -Force}
}
[void](Invoke-Helper $CurrentAdminHelper @('expect-recovery-review-failure','No interrupted service update transaction exists'))

[void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
$gone=Invoke-Helper $CurrentAdminHelper @('query')
if($gone.Installed -eq $true){throw 'Qualification cleanup left RansomGuardV03 registered.'}

$state.phase='complete'
$state.secondRebootObserved=$true
$state.idempotentTerminalStatePassed=$true
$state.cleanupPassed=$true
$state.passed=$true
$state.completedUtc=[DateTime]::UtcNow.ToString('O')
Write-State $state $statePath
Save-Summary $state $evidenceRoot
Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceRoot 'campaign-state-final.json') -Force
Copy-Item -LiteralPath ($statePath+'.sha256') -Destination (Join-Path $evidenceRoot 'campaign-state-final.json.sha256') -Force
Remove-Item -LiteralPath $statePath -Force
Remove-Item -LiteralPath ($statePath+'.sha256') -Force
Write-Host "PRODUCTION-UPDATER-RECOVERY VERIFY PASS transaction=$($state.crashTransaction) commit=$ExpectedCommit evidence=$evidenceRoot"
