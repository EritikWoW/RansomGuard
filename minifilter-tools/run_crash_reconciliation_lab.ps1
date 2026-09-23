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

function Wait-File(
    [string]$Path,
    [System.Diagnostics.Process]$Process,
    [int]$Seconds
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){return}
        if($Process.HasExited){
            throw "Process exited before expected marker '$Path'. Exit=$($Process.ExitCode)."
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for marker '$Path'."
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

$root=Join-Path $RootBase "create-result-loss-$stamp"
$store=Join-Path $ResultsDirectory 'create-result-loss-store'
$session='create-result-loss'
$target=Join-Path $root 'created-before-completion-loss.bin'
$gateOut=Join-Path $ResultsDirectory 'create-intent-gate.out.log'
$gateErr=$gateOut + '.err'
$triggerOut=Join-Path $ResultsDirectory 'create-intent-trigger.out.log'
$triggerErr=$triggerOut + '.err'
$reconcileOut=Join-Path $ResultsDirectory 'reconcile-only.out.log'
$reconcileErr=$reconcileOut + '.err'
$planPath=Join-Path $ResultsDirectory 'create-intent-recovery-plan.json'

$renameRoot=Join-Path $RootBase "rename-result-loss-$stamp"
$renameStore=Join-Path $ResultsDirectory 'rename-result-loss-store'
$renameSession='rename-result-loss'
$renameSource=Join-Path $renameRoot 'source-before-rename.bin'
$renameDestination=Join-Path $renameRoot 'destination-after-rename.bin'
$renameGateOut=Join-Path $ResultsDirectory 'rename-gate.out.log'
$renameGateErr=$renameGateOut + '.err'
$renameTriggerOut=Join-Path $ResultsDirectory 'rename-trigger.out.log'
$renameTriggerErr=$renameTriggerOut + '.err'
$renameReconcileOut=Join-Path $ResultsDirectory 'rename-reconcile-only.out.log'
$renameReconcileErr=$renameReconcileOut + '.err'
$renamePlanPath=Join-Path $ResultsDirectory 'rename-recovery-plan.json'

$truncateRoot=Join-Path $RootBase "truncate-result-loss-$stamp"
$truncateStore=Join-Path $ResultsDirectory 'truncate-result-loss-store'
$truncateSession='truncate-result-loss'
$truncateTarget=Join-Path $truncateRoot 'truncate-before-completion-loss.bin'
$truncateOriginalLength=8192
$truncateRequestedLength=1024
$truncateGateOut=Join-Path $ResultsDirectory 'truncate-gate.out.log'
$truncateGateErr=$truncateGateOut + '.err'
$truncateTriggerOut=Join-Path $ResultsDirectory 'truncate-trigger.out.log'
$truncateTriggerErr=$truncateTriggerOut + '.err'
$truncateReady=Join-Path $ResultsDirectory 'truncate-open.ready'
$truncateGo=Join-Path $ResultsDirectory 'truncate-open.go'
$truncateReconcileOut=Join-Path $ResultsDirectory 'truncate-reconcile-only.out.log'
$truncateReconcileErr=$truncateReconcileOut + '.err'
$truncatePlanPath=Join-Path $ResultsDirectory 'truncate-recovery-plan.json'

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
    completionLossObserved=$false
    createIntentDurable=$false
    createCompletionAbsent=$false
    targetCreated=$false
    restartObserved=$false
    restartSupportsCompleted=$false
    recoveryTransactionNotReady=$false
    renameCompletionLossObserved=$false
    renameIntentDurable=$false
    renameCompletionAbsent=$false
    renameTopologyChanged=$false
    renameRestartObserved=$false
    renameRestartSupportsCompleted=$false
    renameRecoveryTopologyNotReady=$false
    truncateCompletionLossObserved=$false
    truncateIntentDurable=$false
    truncateCompletionAbsent=$false
    truncateLengthChanged=$false
    truncateRestartObserved=$false
    truncateRestartSupportsCompleted=$false
    truncateRecoveryTransactionNotReady=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}

$installed=$false
$gate=$null
$trigger=$null
$renameGate=$null
$renameTrigger=$null
$truncateGate=$null
$truncateTrigger=$null
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
        '--drop-first-create-completion'
    ) $gateOut $gateErr

    Wait-LogPattern $gateOut 'LAB completion-loss injection\s+: ARMED' $gate 45
    Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

    $trigger=Start-LoggedProcess $helperExe @(
        'create-new','--file',(Quote-Arg $target)
    ) $triggerOut $triggerErr

    if(-not $trigger.WaitForExit(45000)){
        Stop-Process -Id $trigger.Id -Force -ErrorAction SilentlyContinue
        throw 'CREATE completion-loss trigger did not return.'
    }
    if($trigger.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $triggerErr -Raw -ErrorAction SilentlyContinue
        throw "CREATE_NEW must complete before completion evidence is intentionally dropped. exit=$($trigger.ExitCode). $err"
    }

    if(-not $gate.WaitForExit(30000)){
        Stop-Process -Id $gate.Id -Force -ErrorAction SilentlyContinue
        throw 'GateClient did not exit cleanly after dropping the authoritative CREATE result.'
    }
    if($gate.ExitCode -ne 0){
        throw "GateClient completion-loss injection should exit cleanly. exit=$($gate.ExitCode)"
    }

    $gateCombined=(Get-Content -LiteralPath $gateOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $gateErr -Raw -ErrorAction SilentlyContinue)
    if($gateCombined -notmatch 'LAB COMPLETION LOSS: intentionally dropping authoritative CREATE result'){
        throw "GateClient did not prove the intended completion-loss point. Output: $gateCombined"
    }
    $summary.completionLossObserved=$true

    if(-not (Test-Path -LiteralPath $target -PathType Leaf)){
        throw "CREATE target must exist because the filesystem operation completed before result loss: $target"
    }
    $summary.targetCreated=$true

    $sessionRoot=Join-Path $store "Sessions\$session"
    $intentJournal=Join-Path $sessionRoot 'create-state\create-intent-journal.jsonl'
    $completionJournal=Join-Path $sessionRoot 'create-state\create-completion-journal.jsonl'
    $intents=@(Read-JsonLines $intentJournal)
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

    $completions=@(Read-JsonLines $completionJournal)
    if($completions.Count -ne 0){
        throw "Authoritative CREATE completion must be absent after intentional result loss. Found $($completions.Count)."
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
    if($reconcileText -notmatch 'RECONCILE ONLY: observed=1; completed-evidence=1; not-completed-evidence=0; ambiguous=0'){
        throw "Unexpected restart reconciliation summary: $reconcileText"
    }
    $summary.restartObserved=$true

    $restartJournal=Join-Path $sessionRoot 'restart-state\restart-reconciliation-journal.jsonl'
    $restart=@(Read-JsonLines $restartJournal)
    if($restart.Count -ne 1){
        throw "Expected exactly one restart observation. Found $($restart.Count)."
    }
    $restartRecord=$restart[0]
    if([int]$restartRecord.operationKind -ne 1 -or
       [uint64]$restartRecord.requestSequence -ne [uint64]$intent.requestSequence -or
       [int]$restartRecord.evidence -ne 1){
        throw "Restart observation is not exact CREATE SupportsCompleted evidence: $($restartRecord | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.restartSupportsCompleted=$true

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
        throw "Consistent SupportsCompleted CREATE transaction should be Review, found state=$($transaction[0].state)."
    }
    if([int]$plan.readyCount -ne 0){
        throw "Crash-reconciled CREATE transaction must contain no Ready actions. readyCount=$($plan.readyCount)"
    }
    $summary.recoveryTransactionNotReady=$true

    # Scenario 2: the RENAME itself succeeds, but its authoritative post-operation result is
    # intentionally omitted before user-mode persistence. Restart reconciliation must prove the
    # source identity moved to the destination without manufacturing a kernel completion.
    Prepare-GateRoot $gateExe $renameRoot
    [IO.File]::WriteAllBytes(
        $renameSource,
        [Text.Encoding]::UTF8.GetBytes('RANSOMGUARD-RENAME-COMPLETION-LOSS-V1'))
    if(Test-Path -LiteralPath $renameDestination){
        throw "RENAME destination must start absent: $renameDestination"
    }

    $renameGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $renameRoot),
        '--store',(Quote-Arg $renameStore),
        '--session',$renameSession,
        '--drop-first-rename-completion'
    ) $renameGateOut $renameGateErr

    Wait-LogPattern $renameGateOut 'LAB completion-loss injection\s+: ARMED for the first authoritative RENAME result' $renameGate 45
    Wait-LogPattern $renameGateOut 'kernel gate ACTIVE' $renameGate 45

    $renameTrigger=Start-LoggedProcess $helperExe @(
        'rename-file',
        '--source',(Quote-Arg $renameSource),
        '--destination',(Quote-Arg $renameDestination)
    ) $renameTriggerOut $renameTriggerErr

    if(-not $renameTrigger.WaitForExit(45000)){
        Stop-Process -Id $renameTrigger.Id -Force -ErrorAction SilentlyContinue
        throw 'RENAME completion-loss trigger did not return.'
    }
    if($renameTrigger.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $renameTriggerErr -Raw -ErrorAction SilentlyContinue
        throw "RENAME must complete before completion evidence is intentionally dropped. exit=$($renameTrigger.ExitCode). $err"
    }

    if(-not $renameGate.WaitForExit(30000)){
        Stop-Process -Id $renameGate.Id -Force -ErrorAction SilentlyContinue
        throw 'GateClient did not exit cleanly after dropping the authoritative RENAME result.'
    }
    if($renameGate.ExitCode -ne 0){
        throw "GateClient RENAME completion-loss injection should exit cleanly. exit=$($renameGate.ExitCode)"
    }

    $renameGateCombined=(Get-Content -LiteralPath $renameGateOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $renameGateErr -Raw -ErrorAction SilentlyContinue)
    if($renameGateCombined -notmatch 'LAB COMPLETION LOSS: intentionally dropping authoritative RENAME result'){
        throw "GateClient did not prove the intended RENAME completion-loss point. Output: $renameGateCombined"
    }
    $summary.renameCompletionLossObserved=$true

    if(Test-Path -LiteralPath $renameSource){
        throw "RENAME source still exists even though the filesystem operation completed: $renameSource"
    }
    if(-not (Test-Path -LiteralPath $renameDestination -PathType Leaf)){
        throw "RENAME destination does not exist after the completed operation: $renameDestination"
    }
    $summary.renameTopologyChanged=$true

    $renameSessionRoot=Join-Path $renameStore "Sessions\$renameSession"
    $renameIntentJournal=Join-Path $renameSessionRoot 'rename-state\rename-journal.jsonl'
    $renameCompletionJournal=Join-Path $renameSessionRoot 'rename-state\rename-completion-journal.jsonl'
    $renameIntents=@(Read-JsonLines $renameIntentJournal)
    if($renameIntents.Count -ne 1){
        throw "Expected exactly one durable RENAME intent after result loss. Found $($renameIntents.Count)."
    }
    $renameIntent=$renameIntents[0]
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$renameIntent.sourcePath),$renameSource,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$renameIntent.destinationPath),$renameDestination,[StringComparison]::OrdinalIgnoreCase)){
        throw "Durable RENAME intent path mismatch. source='$($renameIntent.sourcePath)' destination='$($renameIntent.destinationPath)'."
    }
    if([uint64]$renameIntent.requestSequence -eq 0){
        throw 'Durable RENAME intent requestSequence must be nonzero.'
    }
    $summary.renameIntentDurable=$true

    $renameCompletions=@(Read-JsonLines $renameCompletionJournal)
    if($renameCompletions.Count -ne 0){
        throw "Authoritative RENAME completion must be absent after intentional result loss. Found $($renameCompletions.Count)."
    }
    $summary.renameCompletionAbsent=$true

    $renameReconcile=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $renameRoot),
        '--store',(Quote-Arg $renameStore),
        '--reconcile-only'
    ) $renameReconcileOut $renameReconcileErr
    if(-not $renameReconcile.WaitForExit(30000)){
        Stop-Process -Id $renameReconcile.Id -Force -ErrorAction SilentlyContinue
        throw 'RENAME reconcile-only GateClient did not exit.'
    }
    if($renameReconcile.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $renameReconcileErr -Raw -ErrorAction SilentlyContinue
        throw "RENAME reconcile-only GateClient failed, exit=$($renameReconcile.ExitCode). $err"
    }

    $renameReconcileText=(Get-Content -LiteralPath $renameReconcileOut -Raw)
    if($renameReconcileText -notmatch 'RECONCILE ONLY: observed=1; completed-evidence=1; not-completed-evidence=0; ambiguous=0'){
        throw "Unexpected RENAME restart reconciliation summary: $renameReconcileText"
    }
    $summary.renameRestartObserved=$true

    $renameRestartJournal=Join-Path $renameSessionRoot 'restart-state\restart-reconciliation-journal.jsonl'
    $renameRestart=@(Read-JsonLines $renameRestartJournal)
    if($renameRestart.Count -ne 1){
        throw "Expected exactly one RENAME restart observation. Found $($renameRestart.Count)."
    }
    $renameRestartRecord=$renameRestart[0]
    if([int]$renameRestartRecord.operationKind -ne 2 -or
       [uint64]$renameRestartRecord.requestSequence -ne [uint64]$renameIntent.requestSequence -or
       [int]$renameRestartRecord.evidence -ne 1 -or
       [int]$renameRestartRecord.sourceState -ne 1 -or
       [int]$renameRestartRecord.destinationState -ne 2){
        throw "Restart observation is not exact RENAME SupportsCompleted evidence: $($renameRestartRecord | ConvertTo-Json -Compress -Depth 20)"
    }
    if(-not [string]::Equals(
        ([string]$renameRestartRecord.destinationFileIdHex),
        ([string]$renameIntent.sourceFileIdHex),
        [StringComparison]::OrdinalIgnoreCase)){
        throw 'RENAME restart destination identity does not match the durable source identity.'
    }
    $summary.renameRestartSupportsCompleted=$true

    & $recoveryExe plan --repository $renameStore --session $renameSession --output $renamePlanPath
    if($LASTEXITCODE -ne 0){throw "RENAME recovery planner failed, exit=$LASTEXITCODE"}
    $renamePlan=Get-Content -LiteralPath $renamePlanPath -Raw | ConvertFrom-Json -Depth 40
    $renameTopology=@($renamePlan.actions | Where-Object {
        [int]$_.kind -eq 5 -and [uint64]$_.evidenceSequence -eq [uint64]$renameIntent.requestSequence
    })
    if($renameTopology.Count -ne 1){
        throw "Expected exactly one ReviewRenameTopology action bound to the pending RENAME intent. Found $($renameTopology.Count)."
    }
    if([int]$renameTopology[0].state -eq 1){
        throw 'Crash-reconciled RENAME topology was incorrectly promoted to Ready.'
    }
    if([int]$renameTopology[0].state -ne 2){
        throw "Consistent SupportsCompleted RENAME topology should be Review, found state=$($renameTopology[0].state)."
    }
    if($renamePlan.automaticTopologyMutationAllowed -ne $false){
        throw 'Recovery planner must not enable automatic topology mutation for crash-reconciled RENAME.'
    }
    $summary.renameRecoveryTopologyNotReady=$true

    # Scenario 3: EOF truncation succeeds, but TruncateResult is intentionally omitted before
    # user-mode persistence. Restart reconciliation must use exact FILE_ID + EOF evidence and
    # recovery must keep the transaction review-only while the verified pre-image remains copy-out ready.
    Prepare-GateRoot $gateExe $truncateRoot
    [IO.File]::WriteAllBytes($truncateTarget,[byte[]]::new($truncateOriginalLength))
    if((Get-Item -LiteralPath $truncateTarget).Length -ne $truncateOriginalLength){
        throw "TRUNCATE source length setup mismatch: $truncateTarget"
    }

    $truncateGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $truncateRoot),
        '--store',(Quote-Arg $truncateStore),
        '--session',$truncateSession,
        '--drop-first-truncate-completion'
    ) $truncateGateOut $truncateGateErr

    Wait-LogPattern $truncateGateOut 'LAB completion-loss injection\s+: ARMED for the first authoritative TRUNCATE result' $truncateGate 45
    Wait-LogPattern $truncateGateOut 'kernel gate ACTIVE' $truncateGate 45

    $truncateTrigger=Start-LoggedProcess $helperExe @(
        'truncate-eof',
        '--file',(Quote-Arg $truncateTarget),
        '--length',([string]$truncateRequestedLength),
        '--ready',(Quote-Arg $truncateReady),
        '--go',(Quote-Arg $truncateGo)
    ) $truncateTriggerOut $truncateTriggerErr

    Wait-File $truncateReady $truncateTrigger 30
    Wait-LogPattern $truncateGateOut 'CreateResult\s+request=' $truncateGate 30
    Set-Content -LiteralPath $truncateGo -Value 'go' -Encoding ASCII

    if(-not $truncateTrigger.WaitForExit(45000)){
        Stop-Process -Id $truncateTrigger.Id -Force -ErrorAction SilentlyContinue
        throw 'TRUNCATE completion-loss trigger did not return.'
    }
    if($truncateTrigger.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $truncateTriggerErr -Raw -ErrorAction SilentlyContinue
        throw "TRUNCATE EOF must complete before completion evidence is intentionally dropped. exit=$($truncateTrigger.ExitCode). $err"
    }

    if(-not $truncateGate.WaitForExit(30000)){
        Stop-Process -Id $truncateGate.Id -Force -ErrorAction SilentlyContinue
        throw 'GateClient did not exit cleanly after dropping the authoritative TRUNCATE result.'
    }
    if($truncateGate.ExitCode -ne 0){
        throw "GateClient TRUNCATE completion-loss injection should exit cleanly. exit=$($truncateGate.ExitCode)"
    }

    $truncateGateCombined=(Get-Content -LiteralPath $truncateGateOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $truncateGateErr -Raw -ErrorAction SilentlyContinue)
    if($truncateGateCombined -notmatch 'LAB COMPLETION LOSS: intentionally dropping authoritative TRUNCATE result'){
        throw "GateClient did not prove the intended TRUNCATE completion-loss point. Output: $truncateGateCombined"
    }
    $summary.truncateCompletionLossObserved=$true

    $actualTruncateLength=(Get-Item -LiteralPath $truncateTarget).Length
    if($actualTruncateLength -ne $truncateRequestedLength){
        throw "TRUNCATE EOF did not persist the requested length. expected=$truncateRequestedLength actual=$actualTruncateLength"
    }
    $summary.truncateLengthChanged=$true

    $truncateSessionRoot=Join-Path $truncateStore "Sessions\$truncateSession"
    $truncateIntentJournal=Join-Path $truncateSessionRoot 'truncate-state\truncate-intent-journal.jsonl'
    $truncateCompletionJournal=Join-Path $truncateSessionRoot 'truncate-state\truncate-completion-journal.jsonl'
    $truncateIntents=@(Read-JsonLines $truncateIntentJournal)
    if($truncateIntents.Count -ne 1){
        throw "Expected exactly one durable TRUNCATE intent after result loss. Found $($truncateIntents.Count)."
    }
    $truncateIntent=$truncateIntents[0]
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$truncateIntent.originalPath),$truncateTarget,[StringComparison]::OrdinalIgnoreCase) -or
       [uint64]$truncateIntent.requestSequence -eq 0 -or
       [uint32]$truncateIntent.fileInformationClass -ne 20 -or
       [int64]$truncateIntent.requestedLength -ne $truncateRequestedLength -or
       [int64]$truncateIntent.originalObservedLength -ne $truncateOriginalLength){
        throw "Durable TRUNCATE intent mismatch: $($truncateIntent | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.truncateIntentDurable=$true

    $truncateCompletions=@(Read-JsonLines $truncateCompletionJournal)
    if($truncateCompletions.Count -ne 0){
        throw "Authoritative TRUNCATE completion must be absent after intentional result loss. Found $($truncateCompletions.Count)."
    }
    $summary.truncateCompletionAbsent=$true

    $truncateReconcile=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $truncateRoot),
        '--store',(Quote-Arg $truncateStore),
        '--reconcile-only'
    ) $truncateReconcileOut $truncateReconcileErr
    if(-not $truncateReconcile.WaitForExit(30000)){
        Stop-Process -Id $truncateReconcile.Id -Force -ErrorAction SilentlyContinue
        throw 'TRUNCATE reconcile-only GateClient did not exit.'
    }
    if($truncateReconcile.ExitCode -ne 0){
        $err=Get-Content -LiteralPath $truncateReconcileErr -Raw -ErrorAction SilentlyContinue
        throw "TRUNCATE reconcile-only GateClient failed, exit=$($truncateReconcile.ExitCode). $err"
    }

    $truncateReconcileText=(Get-Content -LiteralPath $truncateReconcileOut -Raw)
    if($truncateReconcileText -notmatch 'RECONCILE ONLY: observed=1; completed-evidence=1; not-completed-evidence=0; ambiguous=0'){
        throw "Unexpected TRUNCATE restart reconciliation summary: $truncateReconcileText"
    }
    $summary.truncateRestartObserved=$true

    $truncateRestartJournal=Join-Path $truncateSessionRoot 'truncate-state\truncate-restart-journal.jsonl'
    $truncateRestart=@(Read-JsonLines $truncateRestartJournal)
    if($truncateRestart.Count -ne 1){
        throw "Expected exactly one TRUNCATE restart observation. Found $($truncateRestart.Count)."
    }
    $truncateRestartRecord=$truncateRestart[0]
    if([uint64]$truncateRestartRecord.requestSequence -ne [uint64]$truncateIntent.requestSequence -or
       [int]$truncateRestartRecord.evidence -ne 1 -or
       [int]$truncateRestartRecord.pathState -ne 2 -or
       [int64]$truncateRestartRecord.observedLength -ne $truncateRequestedLength -or
       -not [string]::Equals(
            ([string]$truncateRestartRecord.currentFileIdHex),
            ([string]$truncateIntent.originalFileIdHex),
            [StringComparison]::OrdinalIgnoreCase)){
        throw "Restart observation is not exact TRUNCATE SupportsCompleted EOF evidence: $($truncateRestartRecord | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.truncateRestartSupportsCompleted=$true

    & $recoveryExe plan --repository $truncateStore --session $truncateSession --output $truncatePlanPath
    if($LASTEXITCODE -ne 0){throw "TRUNCATE recovery planner failed, exit=$LASTEXITCODE"}
    $truncatePlan=Get-Content -LiteralPath $truncatePlanPath -Raw | ConvertFrom-Json -Depth 40
    $truncateTransaction=@($truncatePlan.actions | Where-Object {
        [int]$_.kind -eq 6 -and [uint64]$_.evidenceSequence -eq [uint64]$truncateIntent.requestSequence
    })
    if($truncateTransaction.Count -ne 1){
        throw "Expected exactly one ReviewTruncateTransaction action bound to the pending TRUNCATE intent. Found $($truncateTransaction.Count)."
    }
    if([int]$truncateTransaction[0].state -eq 1){
        throw 'Crash-reconciled TRUNCATE transaction was incorrectly promoted to Ready.'
    }
    if([int]$truncateTransaction[0].state -ne 2){
        throw "Consistent SupportsCompleted TRUNCATE transaction should be Review, found state=$($truncateTransaction[0].state)."
    }
    $truncateCopyOut=@($truncatePlan.actions | Where-Object {
        [int]$_.kind -eq 1 -and [int]$_.state -eq 1 -and
        [string]::Equals([IO.Path]::GetFullPath([string]$_.primaryPath),$truncateTarget,[StringComparison]::OrdinalIgnoreCase)
    })
    if($truncateCopyOut.Count -ne 1){
        throw "TRUNCATE must retain exactly one verified Ready full-preimage copy-out action. Found $($truncateCopyOut.Count)."
    }
    if($truncatePlan.automaticTopologyMutationAllowed -ne $false){
        throw 'Recovery planner must not enable automatic live mutation for crash-reconciled TRUNCATE.'
    }
    $summary.truncateRecoveryTransactionNotReady=$true

    $summary.passed=$true
}
catch{
    $runtimeFailure=$_
}
finally{
    foreach($p in @($trigger,$gate,$renameTrigger,$renameGate,$truncateTrigger,$truncateGate)){
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

Write-Host "CREATE/RENAME/TRUNCATE completion-loss restart reconciliation LAB PASSED. Evidence: $ResultsDirectory"
