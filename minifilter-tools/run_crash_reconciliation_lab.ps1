[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Crash',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Crash/fault runtime harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: crash/fault runtime harness requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: set RANSOMGUARD_LAB_VM=I_UNDERSTAND only inside the disposable snapshot VM.'
    }
    return $vmText
}

function Assert-NoReparsePath {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){
        throw "$Label has no filesystem root: $full"
    }

    $cursor=$root.TrimEnd('\')
    $relative=$full.Substring($root.Length)
    foreach($segment in $relative.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not (Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}

function Quote-Arg([string]$Value){
    return '"' + $Value.Replace('"','\"') + '"'
}

function Start-LoggedProcess(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$StdOut,
    [string]$StdErr
){
    foreach($p in @($StdOut,$StdErr)){
        $parent=Split-Path -Parent $p
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
    return Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Wait-LogPattern(
    [string]$Path,
    [string]$Pattern,
    [System.Diagnostics.Process]$Process,
    [int]$Seconds
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){
            $text=Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if($text -match $Pattern){return}
        }
        if($Process.HasExited){
            $errPath=$Path + '.err'
            $err=if(Test-Path -LiteralPath $errPath){Get-Content -LiteralPath $errPath -Raw}else{''}
            throw "Process exited before expected log pattern '$Pattern'. Exit=$($Process.ExitCode). $err"
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for log pattern '$Pattern'."
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    & $GateExe --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "Gate root preparation failed for $Root, exit=$LASTEXITCODE"}
}

function Read-JsonLines([string]$Path){
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    $records=@()
    foreach($line in Get-Content -LiteralPath $Path -ErrorAction Stop){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        $records+=($line | ConvertFrom-Json -Depth 30)
    }
    return @($records)
}

Assert-Administrator
$vm=Assert-DisposableVm

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
Assert-NoReparsePath -Path $RootBase -Label 'RootBase'
if($RootBase -notmatch '(?i)RansomGuard'){
    throw 'RootBase must contain RansomGuard so an accidental broad/system path is not accepted.'
}
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
if($RootBase -eq $volume){throw 'RootBase cannot be an entire drive.'}

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$recoveryExe=Join-Path $LabReleaseDirectory 'RollbackRecovery\RansomGuard.RollbackRecovery.exe'
foreach($required in @($gateExe,$helperExe,$recoveryExe)){
    if(-not (Test-Path -LiteralPath $required -PathType Leaf)){throw "Required LAB artifact missing: $required"}
}

$driverSys=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.sys'
$driverInf=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.inf'
$driverCat=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.cat'
foreach($required in @($driverSys,$driverInf,$driverCat)){
    if(-not (Test-Path -LiteralPath $required -PathType Leaf)){throw "Required driver package artifact missing: $required"}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){
    $ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-Crash-Lab-$stamp"
}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath -Path $ResultsDirectory -Label 'ResultsDirectory'
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath -Path $RootBase -Label 'RootBase'

$root=Join-Path $RootBase "create-intent-crash-$stamp"
$store=Join-Path $ResultsDirectory 'create-intent-store'
$session='create-intent-crash'
$target=Join-Path $root 'must-remain-absent.bin'
$gateOut=Join-Path $ResultsDirectory 'create-intent-gate.out.log'
$gateErr=$gateOut + '.err'
$triggerOut=Join-Path $ResultsDirectory 'create-intent-trigger.out.log'
$triggerErr=$triggerOut + '.err'
$reconcileOut=Join-Path $ResultsDirectory 'reconcile-only.out.log'
$reconcileErr=$reconcileOut + '.err'
$planPath=Join-Path $ResultsDirectory 'create-intent-recovery-plan.json'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'

$summary=[ordered]@{
    schema=1
    startedUtc=(Get-Date).ToUniversalTime().ToString('o')
    vm=$vm
    root=$root
    store=$store
    session=$session
    target=$target
    gateCrashObserved=$false
    createIntentDurable=$false
    createCompletionAbsent=$false
    targetRemainedAbsent=$false
    restartObserved=$false
    restartSupportsNotCompleted=$false
    recoveryTransactionNotReady=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}

$installed=$false
$gate=$null
$trigger=$null
$runtimeFailure=$null
$cleanupFailure=$null

try{
    $existing=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager before crash lab, exit=$LASTEXITCODE"}
    if($existing -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the VM before running the crash harness.'
    }

    $installed=$true
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER'

    Prepare-GateRoot $gateExe $root
    if(Test-Path -LiteralPath $target){throw "Crash target must start absent: $target"}

    $gate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--session',$session,
        '--fault-after-create-intent'
    ) $gateOut $gateErr

    Wait-LogPattern $gateOut 'LAB fault injection\s+: ARMED' $gate 45
    Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

    $trigger=Start-LoggedProcess $helperExe @(
        'create-new','--file',(Quote-Arg $target)
    ) $triggerOut $triggerErr

    if(-not $gate.WaitForExit(45000)){
        Stop-Process -Id $gate.Id -Force -ErrorAction SilentlyContinue
        throw 'GateClient did not terminate at the armed CREATE-intent fault point.'
    }
    if($gate.ExitCode -eq 0){
        throw 'GateClient fault injection unexpectedly exited with code 0.'
    }

    if(-not $trigger.WaitForExit(45000)){
        Stop-Process -Id $trigger.Id -Force -ErrorAction SilentlyContinue
        throw 'CREATE crash trigger did not return after GateClient termination.'
    }
    if($trigger.ExitCode -eq 0){
        throw 'CREATE_NEW unexpectedly succeeded even though GateClient terminated before FilterReplyMessage.'
    }

    $gateCombined=(Get-Content -LiteralPath $gateOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $gateErr -Raw -ErrorAction SilentlyContinue)
    if($gateCombined -notmatch 'LAB FAULT INJECTION: terminating after durable CREATE intent'){
        throw "GateClient did not prove the intended crash point. Output: $gateCombined"
    }
    $summary.gateCrashObserved=$true

    if(Test-Path -LiteralPath $target){
        throw "CREATE target exists even though crash occurred before kernel reply: $target"
    }
    $summary.targetRemainedAbsent=$true

    $sessionRoot=Join-Path $store "Sessions\$session"
    $intentJournal=Join-Path $sessionRoot 'create-state\create-intent-journal.jsonl'
    $completionJournal=Join-Path $sessionRoot 'create-state\create-completion-journal.jsonl'
    $intents=Read-JsonLines $intentJournal
    if($intents.Count -ne 1){
        throw "Expected exactly one durable CREATE intent after crash. Found $($intents.Count)."
    }
    $intent=$intents[0]
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$intent.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)){
        throw "Durable CREATE intent path mismatch. Expected '$target', got '$($intent.originalPath)'."
    }
    if([uint64]$intent.requestSequence -eq 0){
        throw 'Durable CREATE intent requestSequence must be nonzero.'
    }
    $summary.createIntentDurable=$true

    $completions=Read-JsonLines $completionJournal
    if($completions.Count -ne 0){
        throw "Authoritative CREATE completion must be absent after pre-reply crash. Found $($completions.Count)."
    }
    $summary.createCompletionAbsent=$true

    $reconcile=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--reconcile-only'
    ) $reconcileOut $reconcileErr
    if(-not $reconcile.WaitForExit(30000)){
        Stop-Process -Id $reconcile.Id -Force -ErrorAction SilentlyContinue
        throw 'Reconcile-only GateClient did not exit.'
    }
    if($reconcile.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $reconcileErr -Raw -ErrorAction SilentlyContinue
        throw "Reconcile-only GateClient failed, exit=$($reconcile.ExitCode). $err"
    }

    $reconcileText=(Get-Content -LiteralPath $reconcileOut -Raw)
    if($reconcileText -notmatch 'RECONCILE ONLY: observed=1; completed-evidence=0; not-completed-evidence=1; ambiguous=0'){
        throw "Unexpected restart reconciliation summary: $reconcileText"
    }
    $summary.restartObserved=$true

    $restartJournal=Join-Path $sessionRoot 'restart-state\restart-reconciliation-journal.jsonl'
    $restart=Read-JsonLines $restartJournal
    if($restart.Count -ne 1){
        throw "Expected exactly one restart observation. Found $($restart.Count)."
    }
    $restartRecord=$restart[0]
    if([int]$restartRecord.operationKind -ne 1 -or
       [uint64]$restartRecord.requestSequence -ne [uint64]$intent.requestSequence -or
       [int]$restartRecord.evidence -ne 2){
        throw "Restart observation is not exact CREATE SupportsNotCompleted evidence: $($restartRecord | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.restartSupportsNotCompleted=$true

    & $recoveryExe plan --repository $store --session $session --output $planPath
    if($LASTEXITCODE -ne 0){throw "Recovery planner failed, exit=$LASTEXITCODE"}
    $plan=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -Depth 40
    $transaction=@($plan.actions | Where-Object {
        [int]$_.kind -eq 4 -and [uint64]$_.evidenceSequence -eq [uint64]$intent.requestSequence
    })
    if($transaction.Count -ne 1){
        throw "Expected exactly one ReviewCreateTransaction action bound to the pending CREATE intent. Found $($transaction.Count)."
    }
    if([int]$transaction[0].state -eq 1){
        throw 'Crash-reconciled CREATE transaction was incorrectly promoted to Ready.'
    }
    if([int]$transaction[0].state -ne 2){
        throw "Consistent SupportsNotCompleted CREATE transaction should be Review, found state=$($transaction[0].state)."
    }
    if([int]$plan.readyCount -ne 0){
        throw "Originally-absent pre-reply crash plan must contain no Ready actions. readyCount=$($plan.readyCount)"
    }
    $summary.recoveryTransactionNotReady=$true
    $summary.passed=$true
}
catch{
    $runtimeFailure=$_
}
finally{
    foreach($p in @($trigger,$gate)){
        if($p -and -not $p.HasExited){
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }

    if($installed){
        try{
            & $unloadScript -Volume $volume
            $summary.cleanupPassed=$true
        }
        catch{
            $cleanupFailure=$_
            $summary.cleanupError=$_.Exception.Message
            $summary.passed=$false
        }
    }
    else{
        $summary.cleanupPassed=$true
    }

    $summary.finishedUtc=(Get-Date).ToUniversalTime().ToString('o')
    $summaryPath=Join-Path $ResultsDirectory 'crash-runtime-result.json'
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
}

if($cleanupFailure){throw $cleanupFailure}
if($runtimeFailure){throw $runtimeFailure}
if(-not $summary.passed){throw 'Crash/fault runtime harness did not pass all invariants.'}

Write-Host "Crash/fault runtime LAB PASSED. Evidence: $ResultsDirectory"
