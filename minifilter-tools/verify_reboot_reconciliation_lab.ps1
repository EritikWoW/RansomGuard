[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Reboot',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Reboot VERIFY harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: reboot campaign requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
    }
    return $vmText
}

function Assert-SafePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root) -or $full.TrimEnd('\') -eq $root.TrimEnd('\')){
        throw "$Label cannot be an entire drive: $full"
    }
    if($full -notmatch '(?i)RansomGuard'){
        throw "$Label must contain RansomGuard: $full"
    }
    $cursor=$root.TrimEnd('\')
    $relative=$full.Substring($root.Length)
    foreach($segment in $relative.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        if(((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point: $cursor"
        }
    }
    return $full
}

function Quote-Arg([string]$Value){
    return '"' + $Value.Replace('"','\"') + '"'
}

function Start-LoggedProcess([string]$FilePath,[string[]]$Arguments,[string]$StdOut,[string]$StdErr){
    foreach($p in @($StdOut,$StdErr)){
        $parent=Split-Path -Parent $p
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
    return Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Read-JsonLines([string]$Path){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    $items=@()
    foreach($line in Get-Content -LiteralPath $Path){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        $items+=@($line | ConvertFrom-Json -Depth 40)
    }
    return @($items)
}

Assert-Administrator
$vm=Assert-DisposableVm
if([string]::IsNullOrWhiteSpace($env:RG_WORKFLOW_SHA)){throw 'RG_WORKFLOW_SHA is required for exact reboot campaign binding.'}

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) 'RansomGuard-Reboot-Verify-Results'}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$active=Join-Path $RootBase 'Active'
$statePath=Join-Path $active 'reboot-arm-state.json'
$stateHashPath=$statePath+'.sha256'
if(-not(Test-Path -LiteralPath $statePath -PathType Leaf)){throw "No armed reboot campaign state exists: $statePath"}
if(-not(Test-Path -LiteralPath $stateHashPath -PathType Leaf)){throw "Armed reboot campaign state hash is missing: $stateHashPath"}

$expectedStateHash=(Get-Content -LiteralPath $stateHashPath -Raw).Trim()
$actualStateHash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
if(-not [string]::Equals($expectedStateHash,$actualStateHash,[StringComparison]::OrdinalIgnoreCase)){
    throw "Reboot ARM state SHA-256 mismatch. expected=$expectedStateHash actual=$actualStateHash"
}

$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -Depth 30
if([int]$state.schema -ne 1 -or [string]$state.phase -ne 'armed'){throw 'Invalid reboot ARM state schema/phase.'}
if(-not [string]::Equals([string]$state.workflowSha,$env:RG_WORKFLOW_SHA,[StringComparison]::OrdinalIgnoreCase)){
    throw "VERIFY commit '$env:RG_WORKFLOW_SHA' does not match ARM commit '$($state.workflowSha)'. Re-arm on the exact current commit."
}

$root=Assert-SafePath ([string]$state.root) 'ArmedRoot'
$store=Assert-SafePath ([string]$state.store) 'ArmedStore'
$target=[IO.Path]::GetFullPath([string]$state.target)
$session=[string]$state.session
$requestSequence=[uint64]$state.requestSequence
$requestedLength=[int64]$state.requestedLength
$originalLength=[int64]$state.originalLength
$originalHash=[string]$state.originalSha256
$originalFileId=[string]$state.originalFileIdHex
$preservationRecordSha256=[string]$state.preservationRecordSha256
$snapshotRelativePath=[string]$state.snapshotRelativePath
$snapshotSha256=[string]$state.snapshotSha256

$expectedRoot=[IO.Path]::GetFullPath((Join-Path $active 'protected'))
$expectedStore=[IO.Path]::GetFullPath((Join-Path $active 'rollback-store'))
$expectedTarget=[IO.Path]::GetFullPath((Join-Path $expectedRoot 'truncate-across-reboot.bin'))
if(-not [string]::Equals($root,$expectedRoot,[StringComparison]::OrdinalIgnoreCase) -or
   -not [string]::Equals($store,$expectedStore,[StringComparison]::OrdinalIgnoreCase) -or
   -not [string]::Equals($target,$expectedTarget,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Reboot ARM state topology does not match the fixed Active/protected/rollback-store campaign layout.'
}
if([string]::IsNullOrWhiteSpace($preservationRecordSha256) -or
   [string]::IsNullOrWhiteSpace($snapshotRelativePath) -or
   [string]::IsNullOrWhiteSpace($snapshotSha256)){
    throw 'Reboot ARM state is missing pre-image binding metadata.'
}

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$recoveryExe=Join-Path $LabReleaseDirectory 'RollbackRecovery\RansomGuard.RollbackRecovery.exe'
foreach($required in @($gateExe,$recoveryExe)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Reboot VERIFY dependency missing: $required"}
}

$reconcileOut=Join-Path $ResultsDirectory 'reboot-verify-reconcile.out.log'
$reconcileErr=$reconcileOut+'.err'
$planPath=Join-Path $ResultsDirectory 'reboot-recovery-plan.json'
$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    workflowSha=$env:RG_WORKFLOW_SHA
    armStateSha256=$actualStateHash
    bootChanged=$false
    filterClearedByReboot=$false
    targetMutationSurvivedReboot=$false
    intentSurvivedReboot=$false
    completionStillAbsent=$false
    stateTopologyVerified=$true
    preimageBindingVerified=$false
    restartObserved=$false
    restartSupportsCompleted=$false
    recoveryTransactionNotReady=$false
    readyPreimageCopyOutPresent=$false
    preimageHashMatched=$false
    evidenceCopied=$false
    activeCampaignArchived=$false
    passed=$false
    error=$null
}

try{
    $armedBoot=[DateTime]::Parse(
        [string]$state.bootUpUtc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $currentBoot=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime()
    $summary.armedBootUtc=$armedBoot.ToString('o')
    $summary.currentBootUtc=$currentBoot.ToString('o')
    if($currentBoot -le $armedBoot.AddSeconds(1)){
        throw "No VM reboot was observed between ARM and VERIFY. armedBoot=$($armedBoot.ToString('o')) currentBoot=$($currentBoot.ToString('o'))"
    }
    $summary.bootChanged=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager after reboot, exit=$LASTEXITCODE"}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter is unexpectedly still loaded after reboot. Revert the disposable VM snapshot before retrying.'
    }
    $summary.filterClearedByReboot=$true

    if(-not(Test-Path -LiteralPath $target -PathType Leaf)){throw "Reboot target is missing: $target"}
    if((Get-Item -LiteralPath $target).Length -ne $requestedLength){
        throw "TRUNCATE mutation did not survive reboot. expectedLength=$requestedLength actual=$((Get-Item -LiteralPath $target).Length)"
    }
    $summary.targetMutationSurvivedReboot=$true

    $sessionRoot=Join-Path $store "Sessions\$session"
    $intentJournal=Join-Path $sessionRoot 'truncate-state\truncate-intent-journal.jsonl'
    $completionJournal=Join-Path $sessionRoot 'truncate-state\truncate-completion-journal.jsonl'
    $restartJournal=Join-Path $sessionRoot 'truncate-state\truncate-restart-journal.jsonl'

    $intents=@(Read-JsonLines $intentJournal)
    $intent=@($intents | Where-Object {[uint64]$_.requestSequence -eq $requestSequence})
    if($intent.Count -ne 1){throw "Expected one durable armed TRUNCATE intent after reboot. Found $($intent.Count)."}
    if([int64]$intent[0].requestedLength -ne $requestedLength -or
       [int64]$intent[0].originalObservedLength -ne $originalLength -or
       -not [string]::Equals([string]$intent[0].originalFileIdHex,$originalFileId,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals([string]$intent[0].preservationRecordSha256,$preservationRecordSha256,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Reboot-surviving TRUNCATE intent fields do not match ARM state.'
    }
    $summary.intentSurvivedReboot=$true

    $completions=@(Read-JsonLines $completionJournal)
    if(@($completions | Where-Object {[uint64]$_.requestSequence -eq $requestSequence}).Count -ne 0){
        throw 'Authoritative TRUNCATE completion unexpectedly appeared across reboot.'
    }
    $summary.completionStillAbsent=$true

    $rollback=@(Read-JsonLines (Join-Path $sessionRoot 'journal.jsonl'))
    $capture=@($rollback | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.originalPath) -and
        [string]::Equals([IO.Path]::GetFullPath([string]$_.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)
    })
    if($capture.Count -ne 1){throw "Expected one reboot-surviving full pre-image. Found $($capture.Count)."}
    if(-not [string]::Equals([string]$capture[0].originalSha256,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "Reboot-surviving pre-image journal hash mismatch. expected=$originalHash actual=$($capture[0].originalSha256)"
    }
    if(-not [string]::Equals([string]$capture[0].recordSha256,$preservationRecordSha256,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals([string]$capture[0].snapshotRelativePath,$snapshotRelativePath,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Reboot-surviving pre-image journal is not bound to the ARM state and TRUNCATE intent.'
    }
    $summary.preimageBindingVerified=$true

    $snapshot=Join-Path $sessionRoot $snapshotRelativePath
    if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){throw "Reboot-surviving pre-image object is missing: $snapshot"}
    if((Get-Item -LiteralPath $snapshot).Length -ne $originalLength){
        throw "Reboot-surviving pre-image object length mismatch. expected=$originalLength actual=$((Get-Item -LiteralPath $snapshot).Length)"
    }
    $actualSnapshotHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
    if(-not [string]::Equals($actualSnapshotHash,$originalHash,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals($actualSnapshotHash,$snapshotSha256,[StringComparison]::OrdinalIgnoreCase)){
        throw "Reboot-surviving pre-image object SHA-256 mismatch. original=$originalHash armed=$snapshotSha256 actual=$actualSnapshotHash"
    }
    $summary.preimageHashMatched=$true

    $reconcile=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--reconcile-only'
    ) $reconcileOut $reconcileErr
    if(-not $reconcile.WaitForExit(30000)){
        Stop-Process -Id $reconcile.Id -Force -ErrorAction SilentlyContinue
        throw 'Post-reboot reconcile-only GateClient did not exit.'
    }
    if($reconcile.ExitCode -ne 0){
        $err=if(Test-Path -LiteralPath $reconcileErr){Get-Content -LiteralPath $reconcileErr -Raw}else{''}
        throw "Post-reboot reconcile-only GateClient failed, exit=$($reconcile.ExitCode). $err"
    }
    $reconcileText=Get-Content -LiteralPath $reconcileOut -Raw
    if($reconcileText -notmatch 'RECONCILE ONLY: observed=1; completed-evidence=1; not-completed-evidence=0; ambiguous=0'){
        throw "Unexpected post-reboot reconciliation summary: $reconcileText"
    }
    $summary.restartObserved=$true

    $restart=@(Read-JsonLines $restartJournal | Where-Object {[uint64]$_.requestSequence -eq $requestSequence})
    if($restart.Count -ne 1){throw "Expected exactly one post-reboot TRUNCATE restart observation. Found $($restart.Count)."}
    $restartRecord=$restart[0]
    if([int]$restartRecord.evidence -ne 1 -or
       [int]$restartRecord.pathState -ne 2 -or
       [int64]$restartRecord.observedLength -ne $requestedLength -or
       -not [string]::Equals([string]$restartRecord.currentFileIdHex,$originalFileId,[StringComparison]::OrdinalIgnoreCase)){
        throw "Post-reboot restart observation is not exact SupportsCompleted evidence: $($restartRecord | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.restartSupportsCompleted=$true

    $completionsAfter=@(Read-JsonLines $completionJournal)
    if(@($completionsAfter | Where-Object {[uint64]$_.requestSequence -eq $requestSequence}).Count -ne 0){
        throw 'Restart reconciliation manufactured an authoritative TRUNCATE completion.'
    }

    & $recoveryExe plan --repository $store --session $session --output $planPath
    if($LASTEXITCODE -ne 0){throw "Post-reboot recovery planner failed, exit=$LASTEXITCODE"}
    $plan=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -Depth 40
    $transaction=@($plan.actions | Where-Object {
        [int]$_.kind -eq 6 -and [uint64]$_.evidenceSequence -eq $requestSequence
    })
    if($transaction.Count -ne 1){throw "Expected one ReviewTruncateTransaction action. Found $($transaction.Count)."}
    if([int]$transaction[0].state -ne 2){throw "Post-reboot TRUNCATE transaction must remain Review, state=$($transaction[0].state)."}
    if($plan.automaticTopologyMutationAllowed -ne $false){throw 'Post-reboot recovery plan must not allow automatic live topology mutation.'}
    $summary.recoveryTransactionNotReady=$true

    $ready=@($plan.actions | Where-Object {
        [int]$_.kind -eq 1 -and [int]$_.state -eq 1 -and
        [string]::Equals([IO.Path]::GetFullPath([string]$_.primaryPath),$target,[StringComparison]::OrdinalIgnoreCase)
    })
    if($ready.Count -ne 1){throw "Expected one Ready full-preimage copy-out action after reboot. Found $($ready.Count)."}
    $summary.readyPreimageCopyOutPresent=$true

    $evidenceCopy=Join-Path $ResultsDirectory 'reboot-store-evidence'
    if(Test-Path -LiteralPath $evidenceCopy){Remove-Item -LiteralPath $evidenceCopy -Recurse -Force}
    Copy-Item -LiteralPath $sessionRoot -Destination $evidenceCopy -Recurse -Force
    Copy-Item -LiteralPath $statePath,$stateHashPath -Destination $ResultsDirectory -Force
    $summary.evidenceCopied=$true

    $completed=Join-Path $RootBase ("Completed-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if(Test-Path -LiteralPath $completed){throw "Completed reboot campaign archive already exists: $completed"}
    Move-Item -LiteralPath $active -Destination $completed
    $summary.completedCampaignPath=$completed
    $summary.activeCampaignArchived=$true

    $summary.passed=$summary.bootChanged -and
        $summary.filterClearedByReboot -and
        $summary.targetMutationSurvivedReboot -and
        $summary.intentSurvivedReboot -and
        $summary.completionStillAbsent -and
        $summary.stateTopologyVerified -and
        $summary.preimageBindingVerified -and
        $summary.restartObserved -and
        $summary.restartSupportsCompleted -and
        $summary.recoveryTransactionNotReady -and
        $summary.readyPreimageCopyOutPresent -and
        $summary.preimageHashMatched -and
        $summary.evidenceCopied -and
        $summary.activeCampaignArchived
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'reboot-verify-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Reboot VERIFY failed. error='$($summary.error)' Evidence: $ResultsDirectory"
}

Write-Host "REBOOT RECOVERY LAB PASSED. Boot changed, pending TRUNCATE evidence survived reboot, restart reconciliation stayed conservative, and the hash-verified pre-image remains Ready for copy-out only. Evidence: $ResultsDirectory" -ForegroundColor Green
