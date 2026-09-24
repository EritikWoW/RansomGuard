[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-GateLoss',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'GateClient-loss harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: GateClient-loss qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
    }
    return $vmText
}

function Assert-SafePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $drive=[IO.Path]::GetPathRoot($full).TrimEnd('\')
    if([string]::IsNullOrWhiteSpace($drive) -or $full -eq $drive){
        throw "$Label cannot be an entire drive: $full"
    }
    if($full -notmatch '(?i)RansomGuard'){
        throw "$Label must contain RansomGuard: $full"
    }
    $windows=[Environment]::GetFolderPath('Windows')
    $programFiles=[Environment]::GetFolderPath('ProgramFiles')
    if(($windows -and $full.StartsWith($windows,[StringComparison]::OrdinalIgnoreCase)) -or
       ($programFiles -and $full.StartsWith($programFiles,[StringComparison]::OrdinalIgnoreCase))){
        throw "$Label cannot be under Windows or Program Files."
    }
    return $full
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
            $err=if(Test-Path -LiteralPath ($Path+'.err')){Get-Content -LiteralPath ($Path+'.err') -Raw}else{''}
            throw "Process exited before log pattern '$Pattern'. exit=$($Process.ExitCode) $err"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for log pattern '$Pattern'."
}

function Wait-Path([string]$Path,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for ${Description}: $Path"
}

function Wait-JournalMatch(
    [string]$Path,
    [scriptblock]$Predicate,
    [int]$Seconds,
    [string]$Description
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){
            foreach($line in Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue){
                if([string]::IsNullOrWhiteSpace($line)){continue}
                try{$obj=$line | ConvertFrom-Json -Depth 20}catch{continue}
                if(& $Predicate $obj){return $obj}
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description in $Path"
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    & $GateExe --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "Gate root preparation failed for $Root, exit=$LASTEXITCODE"}
}

function New-TestFile([string]$Path){
    $parent=Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*29+11)%251)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Stop-GateClientClean(
    [System.Diagnostics.Process]$Process,
    [string]$ShutdownMarker,
    [string]$StdOut,
    [string]$Description
){
    if($Process.HasExited){throw "$Description exited before orderly shutdown, exit=$($Process.ExitCode)."}
    Remove-Item -LiteralPath $ShutdownMarker -Force -ErrorAction SilentlyContinue
    New-Item -ItemType File -Path $ShutdownMarker -Force | Out-Null
    if(-not $Process.WaitForExit(15000)){
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        throw "Timed out waiting for orderly $Description shutdown."
    }
    if($Process.ExitCode -ne 0){
        $err=if(Test-Path -LiteralPath ($StdOut+'.err')){Get-Content -LiteralPath ($StdOut+'.err') -Raw}else{''}
        throw "$Description orderly shutdown failed, exit=$($Process.ExitCode). $err"
    }
    $log=Get-Content -LiteralPath $StdOut -Raw
    if($log -notmatch 'Rollback session lifecycle:\s+Completed' -or
       $log -notmatch 'Kernel disconnect authorization:\s+GRANTED'){
        throw "$Description did not prove Completed lifecycle plus kernel orderly-disconnect authorization."
    }
}

Assert-Administrator
$vm=Assert-DisposableVm
$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-GateClient-Loss-Results'
}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
if(Test-Path -LiteralPath $ResultsDirectory){Remove-Item -LiteralPath $ResultsDirectory -Recurse -Force}
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "GateClient-loss dependency missing: $required"}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$rootA=Join-Path $RootBase "protected-a-$stamp"
$rootB=Join-Path $RootBase "protected-b-$stamp"
$storeA=Join-Path $ResultsDirectory 'store-a'
$differentStore=Join-Path $ResultsDirectory 'different-root-store'
$postCleanStore=Join-Path $ResultsDirectory 'post-clean-store'
$target=Join-Path $rootA 'existing-target.bin'
$createDenied=Join-Path $rootA 'should-stay-absent.bin'
$afterReconnect=Join-Path $rootA 'after-reconnect.bin'
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')

$initialOut=Join-Path $ResultsDirectory 'initial-gate.out.log'
$initialErr=$initialOut+'.err'
$differentOut=Join-Path $ResultsDirectory 'different-root-gate.out.log'
$differentErr=$differentOut+'.err'
$reconnectOut=Join-Path $ResultsDirectory 'same-root-reconnect.out.log'
$reconnectErr=$reconnectOut+'.err'
$postCleanOut=Join-Path $ResultsDirectory 'post-clean-different-root.out.log'
$postCleanErr=$postCleanOut+'.err'
$reconnectShutdown=Join-Path $ResultsDirectory 'same-root-reconnect.shutdown'
$postCleanShutdown=Join-Path $ResultsDirectory 'post-clean-different-root.shutdown'

$initialGate=$null
$differentGate=$null
$reconnectGate=$null
$postCleanGate=$null
$probe=$null
$installed=$false
$failure=$null
$cleanupFailure=$null

$summary=[ordered]@{
    schema=1
    version=(Get-Item -LiteralPath $gateExe).VersionInfo.FileVersion
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    rootA=$rootA
    rootB=$rootB
    initialGateActivated=$false
    unexpectedDisconnectObserved=$false
    failSafeWriteDenied=$false
    failSafeCreateDenied=$false
    differentRootRejected=$false
    sameRootReconnectActivated=$false
    sameRootMutationAllowed=$false
    sameRootCompletionDurable=$false
    orderlyDisconnectAuthorized=$false
    postCleanDifferentRootActivated=$false
    postCleanOrderlyDisconnectAuthorized=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
    finishedUtc=$null
}

try{
    Prepare-GateRoot $gateExe $rootA
    Prepare-GateRoot $gateExe $rootB
    New-TestFile $target
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    $installed=$true
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER'

    $initialGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootA),
        '--store',(Quote-Arg $storeA),
        '--session','initial'
    ) $initialOut $initialErr
    Wait-LogPattern $initialOut 'kernel gate ACTIVE' $initialGate 45
    $summary.initialGateActivated=$true

    # This force-kill is the subject of the qualification: no orderly-disconnect
    # authorization is issued, so the activated exact root must remain fail-safe.
    Stop-Process -Id $initialGate.Id -Force -ErrorAction Stop
    if(-not $initialGate.WaitForExit(10000)){throw 'Initial GateClient did not exit after forced termination.'}
    $summary.unexpectedDisconnectObserved=$true
    $initialGate=$null
    Start-Sleep -Milliseconds 500

    $probeReady=Join-Path $ResultsDirectory 'failsafe-write.ready'
    $probeGo=Join-Path $ResultsDirectory 'failsafe-write.go'
    $probeResult=Join-Path $ResultsDirectory 'failsafe-write.result'
    $probeOut=Join-Path $ResultsDirectory 'failsafe-write.out.log'
    $probeErr=$probeOut+'.err'
    $probe=Start-LoggedProcess $helperExe @(
        'containment-probe',
        '--file',(Quote-Arg $target),
        '--ready',(Quote-Arg $probeReady),
        '--go',(Quote-Arg $probeGo),
        '--result',(Quote-Arg $probeResult)
    ) $probeOut $probeErr
    Wait-Path $probeReady 15 'fail-safe write probe readiness'
    New-Item -ItemType File -Path $probeGo -Force | Out-Null
    Wait-Path $probeResult 15 'fail-safe write probe result'
    if(-not $probe.WaitForExit(15000)){
        Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue
        throw 'Fail-safe write probe did not exit.'
    }
    $writeOutcome=(Get-Content -LiteralPath $probeResult -Raw).Trim()
    if($probe.ExitCode -ne 0 -or $writeOutcome -ne 'denied'){
        throw "Unexpected fail-safe WRITE outcome='$writeOutcome' exit=$($probe.ExitCode)."
    }
    $probe=$null
    $afterDeniedHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if(-not [string]::Equals($afterDeniedHash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Protected target changed while GateClient was absent under fail-safe latch.'
    }
    $summary.failSafeWriteDenied=$true

    $createOut=Join-Path $ResultsDirectory 'failsafe-create.out.log'
    $createErr=$createOut+'.err'
    $createProbe=Start-LoggedProcess $helperExe @(
        'create-new','--file',(Quote-Arg $createDenied)
    ) $createOut $createErr
    if(-not $createProbe.WaitForExit(15000)){
        Stop-Process -Id $createProbe.Id -Force -ErrorAction SilentlyContinue
        throw 'Fail-safe CREATE probe did not exit.'
    }
    $createFailure=if(Test-Path -LiteralPath $createErr){Get-Content -LiteralPath $createErr -Raw}else{''}
    if($createProbe.ExitCode -eq 0 -or (Test-Path -LiteralPath $createDenied) -or
       $createFailure -notmatch '(?m)^Win32Error:\s*5\s*$'){
        throw "Mutation-capable CREATE was not proven ACCESS_DENIED without GateClient. exit=$($createProbe.ExitCode) stderr=$createFailure"
    }
    $summary.failSafeCreateDenied=$true
    $differentGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootB),
        '--store',(Quote-Arg $differentStore),
        '--session','different-root-rejected'
    ) $differentOut $differentErr
    if(-not $differentGate.WaitForExit(15000)){
        Stop-Process -Id $differentGate.Id -Force -ErrorAction SilentlyContinue
        throw 'Different-root GateClient unexpectedly stayed connected while fail-safe root A was latched.'
    }
    if($differentGate.ExitCode -eq 0){
        throw 'Different-root GateClient unexpectedly connected successfully while fail-safe root A was latched.'
    }
    $summary.differentRootRejected=$true
    $differentGate=$null

    Remove-Item -LiteralPath $reconnectShutdown -Force -ErrorAction SilentlyContinue
    $reconnectGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootA),
        '--store',(Quote-Arg $storeA),
        '--session','same-root-reconnect',
        '--shutdown-marker',(Quote-Arg $reconnectShutdown)
    ) $reconnectOut $reconnectErr
    Wait-LogPattern $reconnectOut 'kernel gate ACTIVE' $reconnectGate 45
    $summary.sameRootReconnectActivated=$true

    & $helperExe create-new --file $afterReconnect
    if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $afterReconnect -PathType Leaf)){
        throw "Same-root reconnect did not restore preserved mutation flow. helperExit=$LASTEXITCODE"
    }
    $summary.sameRootMutationAllowed=$true

    $completionJournal=Join-Path $storeA 'Sessions\same-root-reconnect\create-state\create-completion-journal.jsonl'
    $null=Wait-JournalMatch $completionJournal {
        param($x)
        -not [string]::IsNullOrWhiteSpace([string]$x.finalPath) -and
        [string]::Equals([IO.Path]::GetFullPath([string]$x.finalPath),$afterReconnect,[StringComparison]::OrdinalIgnoreCase)
    } 20 'same-root CREATE authoritative completion'
    $summary.sameRootCompletionDurable=$true

    Stop-GateClientClean $reconnectGate $reconnectShutdown $reconnectOut 'same-root reconnect GateClient'
    $summary.orderlyDisconnectAuthorized=$true
    $reconnectGate=$null

    # Without unloading the driver, a different root must now be able to connect
    # and activate. This proves the authorized disconnect cleared the prior latch.
    Remove-Item -LiteralPath $postCleanShutdown -Force -ErrorAction SilentlyContinue
    $postCleanGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootB),
        '--store',(Quote-Arg $postCleanStore),
        '--session','post-clean-different-root',
        '--shutdown-marker',(Quote-Arg $postCleanShutdown)
    ) $postCleanOut $postCleanErr
    Wait-LogPattern $postCleanOut 'kernel gate ACTIVE' $postCleanGate 45
    $summary.postCleanDifferentRootActivated=$true

    Stop-GateClientClean $postCleanGate $postCleanShutdown $postCleanOut 'post-clean different-root GateClient'
    $summary.postCleanOrderlyDisconnectAuthorized=$true
    $postCleanGate=$null

    $summary.passed=$true
}
catch{
    $failure=$_
    $summary.passed=$false
}
finally{
    if($probe -and -not $probe.HasExited){Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue}
    foreach($p in @($initialGate,$differentGate,$reconnectGate,$postCleanGate)){
        if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
    }

    if($installed){
        try{
            & $unloadScript -Volume $volume
            $summary.cleanupPassed=$true
        }catch{
            $cleanupFailure=$_
            $summary.cleanupPassed=$false
            $summary.cleanupError=$_.Exception.Message
            $summary.passed=$false
        }
    }else{
        $summary.cleanupPassed=$true
    }

    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'gateclient-loss-result.json') -Encoding UTF8
}

if($failure){
    if($cleanupFailure){
        throw "GateClient-loss qualification failed: $($failure.Exception.Message) Cleanup also failed: $($cleanupFailure.Exception.Message)"
    }
    throw $failure
}
if(-not $summary.cleanupPassed){throw "GateClient-loss cleanup failed: $($summary.cleanupError)"}
if(-not $summary.passed){throw 'GateClient-loss qualification did not pass.'}

Write-Host "GATECLIENT-LOSS LAB PASSED. kill-deny WRITE/CREATE, different-root rejection, same-root revalidation, durable completion, orderly disconnect and post-clean different-root activation all verified. Evidence: $ResultsDirectory" -ForegroundColor Green
){
        throw "Mutation-capable CREATE was not proven ACCESS_DENIED without GateClient. exit=$($createProbe.ExitCode) stderr=$createFailure"
    }
    $summary.failSafeCreateDenied=$true

    $differentGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootB),
        '--store',(Quote-Arg $differentStore),
        '--session','different-root-rejected'
    ) $differentOut $differentErr
    if(-not $differentGate.WaitForExit(15000)){
        Stop-Process -Id $differentGate.Id -Force -ErrorAction SilentlyContinue
        throw 'Different-root GateClient unexpectedly stayed connected while fail-safe root A was latched.'
    }
    if($differentGate.ExitCode -eq 0){
        throw 'Different-root GateClient unexpectedly connected successfully while fail-safe root A was latched.'
    }
    $summary.differentRootRejected=$true
    $differentGate=$null

    Remove-Item -LiteralPath $reconnectShutdown -Force -ErrorAction SilentlyContinue
    $reconnectGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootA),
        '--store',(Quote-Arg $storeA),
        '--session','same-root-reconnect',
        '--shutdown-marker',(Quote-Arg $reconnectShutdown)
    ) $reconnectOut $reconnectErr
    Wait-LogPattern $reconnectOut 'kernel gate ACTIVE' $reconnectGate 45
    $summary.sameRootReconnectActivated=$true

    & $helperExe create-new --file $afterReconnect
    if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $afterReconnect -PathType Leaf)){
        throw "Same-root reconnect did not restore preserved mutation flow. helperExit=$LASTEXITCODE"
    }
    $summary.sameRootMutationAllowed=$true

    $completionJournal=Join-Path $storeA 'Sessions\same-root-reconnect\create-state\create-completion-journal.jsonl'
    $null=Wait-JournalMatch $completionJournal {
        param($x)
        -not [string]::IsNullOrWhiteSpace([string]$x.finalPath) -and
        [string]::Equals([IO.Path]::GetFullPath([string]$x.finalPath),$afterReconnect,[StringComparison]::OrdinalIgnoreCase)
    } 20 'same-root CREATE authoritative completion'
    $summary.sameRootCompletionDurable=$true

    Stop-GateClientClean $reconnectGate $reconnectShutdown $reconnectOut 'same-root reconnect GateClient'
    $summary.orderlyDisconnectAuthorized=$true
    $reconnectGate=$null

    # Without unloading the driver, a different root must now be able to connect
    # and activate. This proves the authorized disconnect cleared the prior latch.
    Remove-Item -LiteralPath $postCleanShutdown -Force -ErrorAction SilentlyContinue
    $postCleanGate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $rootB),
        '--store',(Quote-Arg $postCleanStore),
        '--session','post-clean-different-root',
        '--shutdown-marker',(Quote-Arg $postCleanShutdown)
    ) $postCleanOut $postCleanErr
    Wait-LogPattern $postCleanOut 'kernel gate ACTIVE' $postCleanGate 45
    $summary.postCleanDifferentRootActivated=$true

    Stop-GateClientClean $postCleanGate $postCleanShutdown $postCleanOut 'post-clean different-root GateClient'
    $summary.postCleanOrderlyDisconnectAuthorized=$true
    $postCleanGate=$null

    $summary.passed=$true
}
catch{
    $failure=$_
    $summary.passed=$false
}
finally{
    if($probe -and -not $probe.HasExited){Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue}
    foreach($p in @($initialGate,$differentGate,$reconnectGate,$postCleanGate)){
        if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
    }

    if($installed){
        try{
            & $unloadScript -Volume $volume
            $summary.cleanupPassed=$true
        }catch{
            $cleanupFailure=$_
            $summary.cleanupPassed=$false
            $summary.cleanupError=$_.Exception.Message
            $summary.passed=$false
        }
    }else{
        $summary.cleanupPassed=$true
    }

    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'gateclient-loss-result.json') -Encoding UTF8
}

if($failure){
    if($cleanupFailure){
        throw "GateClient-loss qualification failed: $($failure.Exception.Message) Cleanup also failed: $($cleanupFailure.Exception.Message)"
    }
    throw $failure
}
if(-not $summary.cleanupPassed){throw "GateClient-loss cleanup failed: $($summary.cleanupError)"}
if(-not $summary.passed){throw 'GateClient-loss qualification did not pass.'}

Write-Host "GATECLIENT-LOSS LAB PASSED. kill-deny WRITE/CREATE, different-root rejection, same-root revalidation, durable completion, orderly disconnect and post-clean different-root activation all verified. Evidence: $ResultsDirectory" -ForegroundColor Green
