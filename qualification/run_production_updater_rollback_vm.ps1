[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OldAdminHelper,
    [Parameter(Mandatory=$true)][string]$CurrentAdminHelper,
    [Parameter(Mandatory=$true)][string]$OldPackage,
    [Parameter(Mandatory=$true)][string]$CurrentPackage,
    [Parameter(Mandatory=$true)][string]$FailurePackage,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-UpdaterRollback',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Updater rollback qualification must run as Administrator.'
    }
}
function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: updater rollback qualification requires an obvious disposable VM. Detected: $text"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
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
function Get-ServiceHash([string]$Package){
    $exe=Join-Path $Package 'RansomGuard.Service.exe'
    if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw "Service package missing: $exe"}
    return (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
}
function Get-UpdateRecords {
    $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\ServiceUpdates'
    if(-not(Test-Path -LiteralPath $root -PathType Container)){return @()}
    $records=@()
    foreach($file in Get-ChildItem -LiteralPath $root -Filter '*.json' -File -ErrorAction Stop){
        try{
            $item=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -Depth 50
            if([string]$item.TransactionId -match '^[A-Fa-f0-9]{32}$'){$records += $item}
        }catch{}
    }
    return $records
}
function Get-UpdateRecord([string]$TransactionId){
    $matches=@(Get-UpdateRecords | Where-Object {
        [string]::Equals([string]$_.TransactionId,$TransactionId,[StringComparison]::OrdinalIgnoreCase)
    })
    if($matches.Count -ne 1){
        throw "Expected exactly one durable update transaction '$TransactionId'; found $($matches.Count)."
    }
    return $matches[0]
}
function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
    $paths=@(
        (Join-Path $root 'audit.jsonl'),
        (Join-Path $root 'audit.1.jsonl'),
        (Join-Path $root 'audit.2.jsonl'),
        (Join-Path $root 'audit.3.jsonl')
    )
    $items=@()
    foreach($path in $paths){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        Assert-NoReparsePath $path 'Audit evidence'
        foreach($line in Get-Content -LiteralPath $path -ErrorAction SilentlyContinue){
            if([string]::IsNullOrWhiteSpace($line)){continue}
            try{
                $item=$line | ConvertFrom-Json
                if($item.PSObject.Properties['Utc'] -and [DateTimeOffset]::Parse([string]$item.Utc) -ge $SinceUtc){$items += $item}
            }catch{}
        }
    }
    return @($items | Sort-Object {[DateTimeOffset]::Parse([string]$_.Utc)})
}

Assert-Administrator
$vm=Assert-DisposableVm

foreach($name in @('OldAdminHelper','CurrentAdminHelper','OldPackage','CurrentPackage','FailurePackage')){
    $value=Get-Variable -Name $name -ValueOnly
    $value=[IO.Path]::GetFullPath([string]$value)
    Set-Variable -Name $name -Value $value
    if(-not(Test-Path -LiteralPath $value)){throw "$name missing: $value"}
    Assert-NoReparsePath $value $name
}
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-UpdaterRollback-$stamp"}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$root=Join-Path $RootBase "data-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$startedUtc=[DateTimeOffset]::UtcNow
$currentHash=Get-ServiceHash $CurrentPackage
$failureHash=Get-ServiceHash $FailurePackage
$wrongHash=('0'*64)
if([string]::Equals($wrongHash,$currentHash,[StringComparison]::OrdinalIgnoreCase)){$wrongHash=('F'*64)}

$summary=[ordered]@{
    schema=1
    commit=$ExpectedCommit.ToLowerInvariant()
    startedUtc=$startedUtc.ToString('o')
    vm=$vm
    protectedRoot=$root
    initialServiceAbsent=$false
    oldInstallForSuccess=$false
    tamperedExpectedHashRejected=$false
    forwardReviewPassed=$false
    forwardUpdateCompleted=$false
    forwardTransactionId=$null
    forwardTargetSelected=$false
    sameVersionReplayRejected=$false
    firstUninstallPassed=$false
    oldInstallForRollback=$false
    postCommitFailureObserved=$false
    rollbackTransactionId=$null
    previousImageRestored=$false
    rollbackJournalTerminal=$false
    completedJournalTerminal=$false
    completionAuditObserved=$false
    rollbackAuditObserved=$false
    finalUninstallPassed=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}
$failure=$null

try{
    $initial=Invoke-Helper $CurrentAdminHelper @('query')
    if($initial.Installed -eq $true){
        throw "REFUSED: RansomGuardV03 is already installed at '$($initial.ImagePath)'. Revert/clean the disposable VM."
    }
    $summary.initialServiceAbsent=$true

    $old1=Invoke-Helper $OldAdminHelper @('install',$OldPackage,$root)
    $oldImage1=[IO.Path]::GetFullPath([string]$old1.image)
    $summary.oldInstallForSuccess=$true

    [void](Invoke-Helper $CurrentAdminHelper @('expect-review-failure',$CurrentPackage,$wrongHash,'bytes do not match'))
    $summary.tamperedExpectedHashRejected=$true

    $review=Invoke-Helper $CurrentAdminHelper @('review-update',$CurrentPackage)
    if([string]::IsNullOrWhiteSpace([string]$review.version)){throw 'Forward update review returned no target version.'}
    $summary.forwardReviewPassed=$true

    $updated=Invoke-Helper $CurrentAdminHelper @('update',$CurrentPackage)
    if([string]$updated.Outcome -ne 'Completed'){throw "Forward update outcome was '$($updated.Outcome)'."}
    $summary.forwardUpdateCompleted=$true
    $summary.forwardTransactionId=[string]$updated.TransactionId
    $completedRecord=Get-UpdateRecord ([string]$updated.TransactionId)
    if([string]$completedRecord.Phase -ne 'Completed'){
        throw "Forward update transaction '$($updated.TransactionId)' is not terminal Completed: $($completedRecord.Phase)"
    }
    $summary.completedJournalTerminal=$true
    $completedRecord | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'forward-completed-transaction.json') -Encoding utf8

    $afterUpdate=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterUpdate.State -ne 'Stopped'){throw "Successful update did not leave service Stopped: $($afterUpdate.State)"}
    if([string]::Equals([IO.Path]::GetFullPath([string]$afterUpdate.ImagePath),$oldImage1,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Successful update did not select a new immutable version image.'
    }
    $summary.forwardTargetSelected=$true

    [void](Invoke-Helper $CurrentAdminHelper @('expect-review-failure',$CurrentPackage,$currentHash,'replay/downgrade rejected'))
    $summary.sameVersionReplayRejected=$true

    [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
    $summary.firstUninstallPassed=$true

    $old2=Invoke-Helper $OldAdminHelper @('install',$OldPackage,$root)
    $oldImage2=[IO.Path]::GetFullPath([string]$old2.image)
    $summary.oldInstallForRollback=$true
    $baselineBeforeRollback=@(Get-UpdateRecords | ForEach-Object {[string]$_.TransactionId})

    [void](Invoke-Helper $CurrentAdminHelper @('expect-update-failure',$FailurePackage,'rolled back to the previous verified image'))
    $summary.postCommitFailureObserved=$true

    $afterRollback=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterRollback.State -ne 'Stopped'){throw "Rollback did not leave service Stopped: $($afterRollback.State)"}
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$afterRollback.ImagePath),$oldImage2,[StringComparison]::OrdinalIgnoreCase)){
        throw "SCM rollback selected '$($afterRollback.ImagePath)' instead of '$oldImage2'."
    }
    $summary.previousImageRestored=$true

    $records=@(Get-UpdateRecords)
    $newRollback=@($records | Where-Object {
        $id=[string]$_.TransactionId
        $baselineBeforeRollback -notcontains $id -and [string]$_.Phase -eq 'RolledBack'
    })
    if($newRollback.Count -ne 1){
        throw "Expected exactly one new terminal RolledBack transaction; found $($newRollback.Count)."
    }
    $rollbackRecord=$newRollback[0]
    $summary.rollbackTransactionId=[string]$rollbackRecord.TransactionId
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$rollbackRecord.PreviousImage),$oldImage2,[StringComparison]::OrdinalIgnoreCase)){
        throw 'RolledBack transaction does not bind to the exact previous immutable image used by this scenario.'
    }
    $summary.rollbackJournalTerminal=$true
    $records | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'updater-transactions.json') -Encoding utf8

    $audit=@(Get-AuditEntries $startedUtc)
    if(@($audit | Where-Object {
        $_.Event -eq 'ServiceUpdateCompleted' -and
        [string]::Equals([string]$_.Transaction,[string]$summary.forwardTransactionId,[StringComparison]::OrdinalIgnoreCase)
    }).Count -lt 1){throw 'Exact ServiceUpdateCompleted audit evidence missing.'}
    if(@($audit | Where-Object {
        $_.Event -eq 'ServiceUpdateRolledBack' -and
        [string]::Equals([string]$_.Transaction,[string]$summary.rollbackTransactionId,[StringComparison]::OrdinalIgnoreCase)
    }).Count -lt 1){throw 'Exact ServiceUpdateRolledBack audit evidence missing.'}
    $summary.completionAuditObserved=$true
    $summary.rollbackAuditObserved=$true
    $audit | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'updater-audit.json') -Encoding utf8

    [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
    $summary.finalUninstallPassed=$true
    $summary.cleanupPassed=$true
    $summary.passed=$true
}catch{
    $failure=$_.Exception
}finally{
    if(-not $summary.finalUninstallPassed){
        try{
            [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
            $summary.finalUninstallPassed=$true
            $summary.cleanupPassed=$true
        }catch{
            $summary.cleanupError=$_.Exception.Message
        }
    }
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-updater-rollback-result.json') -Encoding utf8
}

if($null -ne $failure){throw $failure}
if(-not $summary.passed){throw 'Updater rollback qualification did not reach PASS.'}
Write-Host "PRODUCTION-UPDATER-ROLLBACK-EVIDENCE PASS commit=$ExpectedCommit results=$ResultsDirectory"
