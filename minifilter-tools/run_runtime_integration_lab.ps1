[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Integration',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Runtime minifilter integration harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: runtime minifilter harness requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: set RANSOMGUARD_LAB_VM=I_UNDERSTAND only inside the disposable snapshot VM.'
    }
    return $vmText
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

function Wait-Path([string]$Path,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for ${Description}: $Path"
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
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for $Description in $Path"
}

function New-TestFile([string]$Path){
    $parent=Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*17+23)%251)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    & $GateExe --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "Gate root preparation failed for $Root, exit=$LASTEXITCODE"}
}

Assert-Administrator
$vm=Assert-DisposableVm

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){
    throw 'RootBase must contain RansomGuard so an accidental broad/system path is not accepted.'
}
$drive=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
if($RootBase -eq $drive){throw 'RootBase cannot be an entire drive.'}
$windows=[Environment]::GetFolderPath('Windows')
$programFiles=[Environment]::GetFolderPath('ProgramFiles')
if(($windows -and $RootBase.StartsWith($windows,[StringComparison]::OrdinalIgnoreCase)) -or
   ($programFiles -and $RootBase.StartsWith($programFiles,[StringComparison]::OrdinalIgnoreCase))){
    throw 'RootBase cannot be under Windows or Program Files.'
}

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
foreach($required in @($gateExe,$helperExe,(Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.sys'),(Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.inf'))){
    if(-not (Test-Path -LiteralPath $required -PathType Leaf)){throw "Required runtime artifact missing: $required"}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){
    $ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-Runtime-Lab-$stamp"
}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$dirRoot=Join-Path $RootBase "predirectory-$stamp"
$preRoot=Join-Path $RootBase "preexisting-$stamp"
$postRoot=Join-Path $RootBase "postactivation-$stamp"
$containRoot=Join-Path $RootBase "containment-$stamp"
$transitionRoot=Join-Path $RootBase "containment-transition-$stamp"
$dirStore=Join-Path $ResultsDirectory 'predirectory-store'
$preStore=Join-Path $ResultsDirectory 'preexisting-store'
$postStore=Join-Path $ResultsDirectory 'postactivation-store'
$containStore=Join-Path $ResultsDirectory 'containment-store'
$transitionStore=Join-Path $ResultsDirectory 'containment-transition-store'
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'

$summary=[ordered]@{
    schema=1
    version='0.7.21.0'
    startedUtc=(Get-Date).ToUniversalTime().ToString('o')
    vm=$vm
    rootBase=$RootBase
    driverPackage=$DriverPackageDirectory
    preexistingDirectoryHandleRejected=$false
    preexistingMappingRejected=$false
    postActivationBaselineVerified=$false
    postActivationPagingObserved=$false
    preimageHashMatched=$false
    containmentDeniedTarget=$false
    containmentPreservedTargetHash=$false
    containmentAllowedPeer=$false
    transitionRequested=$false
    transitionKernelActive=$false
    transitionDeniedNextWrite=$false
    passed=$false
}

$installed=$false
$dirHolder=$null
$holder=$null
$gateDir=$null
$gatePre=$null
$gatePost=$null
$gateContain=$null
$gateTransition=$null
$containProbe=$null
$transitionProbe=$null
$dirRelease=$null
$release=$null
$containGo=$null
$transitionGo=$null
try{
    $existing=(& fltmc filters 2>$null | Out-String)
    if($existing -match 'RansomGuardMinifilter'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the VM before running the integration harness.'
    }

    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER'
    # install_minifilter_lab.ps1 throws on failure. Do not inspect $LASTEXITCODE here:
    # it belongs to the last native command executed inside the child script and may remain
    # nonzero even after the script has independently verified a successful load/attach.
    $installed=$true

    # Scenario 0: a directory handle that already owns DELETE access must prevent activation.
    Prepare-GateRoot $gateExe $dirRoot
    $lockedDirectory=Join-Path $dirRoot 'locked-directory'
    New-Item -ItemType Directory -Path $lockedDirectory -Force | Out-Null
    $dirReady=Join-Path $ResultsDirectory 'predirectory.ready'
    $dirRelease=Join-Path $ResultsDirectory 'predirectory.release'
    $dirHolderOut=Join-Path $ResultsDirectory 'predirectory-holder.out.log'
    $dirHolderErr=Join-Path $ResultsDirectory 'predirectory-holder.err.log'
    $dirHolder=Start-LoggedProcess $helperExe @(
        'hold-dir-delete','--directory',(Quote-Arg $lockedDirectory),'--ready',(Quote-Arg $dirReady),'--release',(Quote-Arg $dirRelease)
    ) $dirHolderOut $dirHolderErr
    Wait-Path $dirReady 15 'pre-existing DELETE directory handle'

    $dirOut=Join-Path $ResultsDirectory 'predirectory-gate.out.log'
    $dirErr=$dirOut + '.err'
    $gateDir=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $dirRoot),'--store',(Quote-Arg $dirStore),'--session','predirectory'
    ) $dirOut $dirErr

    if(-not $gateDir.WaitForExit(30000)){
        Stop-Process -Id $gateDir.Id -Force -ErrorAction SilentlyContinue
        throw 'Activation unexpectedly stayed alive with a pre-existing DELETE directory handle.'
    }
    if($gateDir.ExitCode -eq 0){throw 'Activation unexpectedly succeeded with a pre-existing DELETE directory handle.'}
    $dirFailure=((Get-Content -LiteralPath $dirOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $dirErr -Raw -ErrorAction SilentlyContinue))
    if($dirFailure -notmatch '(?i)Activation topology preflight|sharing|used by another process|could not hold directory'){
        throw "Directory-handle activation failed for an unexpected reason: $dirFailure"
    }
    $summary.preexistingDirectoryHandleRejected=$true

    New-Item -ItemType File -Path $dirRelease -Force | Out-Null
    if(-not $dirHolder.WaitForExit(15000)){
        Stop-Process -Id $dirHolder.Id -Force -ErrorAction SilentlyContinue
        throw 'Directory DELETE-handle holder did not exit.'
    }
    if($dirHolder.ExitCode -ne 0){throw "Directory DELETE-handle holder failed, exit=$($dirHolder.ExitCode)"}
    $dirHolder=$null
    $gateDir=$null

    Prepare-GateRoot $gateExe $preRoot
    $preFile=Join-Path $preRoot 'preexisting-map.bin'
    New-TestFile $preFile
    $ready=Join-Path $ResultsDirectory 'preexisting.ready'
    $release=Join-Path $ResultsDirectory 'preexisting.release'
    $holderOut=Join-Path $ResultsDirectory 'preexisting-holder.out.log'
    $holderErr=Join-Path $ResultsDirectory 'preexisting-holder.err.log'
    $holder=Start-LoggedProcess $helperExe @(
        'hold-map','--file',(Quote-Arg $preFile),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) $holderOut $holderErr
    Wait-Path $ready 15 'pre-existing writable mapping'

    $preOut=Join-Path $ResultsDirectory 'preexisting-gate.out.log'
    $preErr=$preOut + '.err'
    $gatePre=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $preRoot),'--store',(Quote-Arg $preStore),'--session','preexisting'
    ) $preOut $preErr

    if(-not $gatePre.WaitForExit(30000)){
        Stop-Process -Id $gatePre.Id -Force -ErrorAction SilentlyContinue
        throw 'Activation unexpectedly stayed alive with a pre-existing writable mapped view.'
    }
    if($gatePre.ExitCode -eq 0){throw 'Activation unexpectedly succeeded with a pre-existing writable mapped view.'}

    $preJournal=Join-Path $preStore 'Sessions\preexisting\activation-state\activation-preflight-journal.jsonl'
    $null=Wait-JournalMatch $preJournal {
        param($x)
        $x.writableViewPresent -eq $true -and
        [string]::Equals([IO.Path]::GetFullPath([string]$x.path),$preFile,[StringComparison]::OrdinalIgnoreCase)
    } 15 'writableViewPresent=true activation evidence'
    $summary.preexistingMappingRejected=$true

    New-Item -ItemType File -Path $release -Force | Out-Null
    if(-not $holder.WaitForExit(15000)){
        Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
        throw 'Mapped-view holder did not exit.'
    }
    if($holder.ExitCode -ne 0){throw "Mapped-view holder failed, exit=$($holder.ExitCode)"}
    $holder=$null

    Prepare-GateRoot $gateExe $postRoot
    $postFile=Join-Path $postRoot 'postactivation-map.bin'
    New-TestFile $postFile
    $originalHash=(Get-FileHash -LiteralPath $postFile -Algorithm SHA256).Hash

    $postOut=Join-Path $ResultsDirectory 'postactivation-gate.out.log'
    $postErr=$postOut + '.err'
    $gatePost=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $postRoot),'--store',(Quote-Arg $postStore),'--session','postactivation'
    ) $postOut $postErr
    Wait-LogPattern $postOut 'kernel gate ACTIVE' $gatePost 45

    & $helperExe map-write --file $postFile
    if($LASTEXITCODE -ne 0){throw "Post-activation mapped write helper failed, exit=$LASTEXITCODE"}

    $session=Join-Path $postStore 'Sessions\postactivation'
    $sectionJournal=Join-Path $session 'section-state\writable-section-journal.jsonl'
    $null=Wait-JournalMatch $sectionJournal {
        param($x)
        [int]$x.state -eq 1 -and
        [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),$postFile,[StringComparison]::OrdinalIgnoreCase)
    } 30 'BaselineVerified writable-section evidence'
    $summary.postActivationBaselineVerified=$true

    $pagingJournal=Join-Path $session 'paging-state\paging-write-journal.jsonl'
    $null=Wait-JournalMatch $pagingJournal {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),$postFile,[StringComparison]::OrdinalIgnoreCase) -and
        [uint64]$x.length -gt 0
    } 30 'paging-write evidence'
    $summary.postActivationPagingObserved=$true

    $rollbackJournal=Join-Path $session 'journal.jsonl'
    $capture=Wait-JournalMatch $rollbackJournal {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$postFile,[StringComparison]::OrdinalIgnoreCase)
    } 15 'full pre-image journal record'
    if(-not [string]::Equals([string]$capture.originalSha256,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "Full pre-image hash does not match the original mapped file. expected=$originalHash actual=$($capture.originalSha256)"
    }
    $snapshot=Join-Path $session ([string]$capture.snapshotRelativePath)
    if(-not (Test-Path -LiteralPath $snapshot -PathType Leaf)){throw "Full pre-image object missing: $snapshot"}
    $snapshotHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
    if(-not [string]::Equals($snapshotHash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "Full pre-image object hash mismatch. expected=$originalHash actual=$snapshotHash"
    }
    $mutatedHash=(Get-FileHash -LiteralPath $postFile -Algorithm SHA256).Hash
    if([string]::Equals($mutatedHash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Mapped write did not mutate the test file.'
    }
    $summary.preimageHashMatched=$true

    # Scenario 3: activation-bound containment is scoped to one kernel process identity.
    Prepare-GateRoot $gateExe $containRoot
    $containedFile=Join-Path $containRoot 'contained-target.bin'
    $peerFile=Join-Path $containRoot 'ordinary-peer.bin'
    New-TestFile $containedFile
    New-TestFile $peerFile
    $containedOriginalHash=(Get-FileHash -LiteralPath $containedFile -Algorithm SHA256).Hash
    $peerOriginalHash=(Get-FileHash -LiteralPath $peerFile -Algorithm SHA256).Hash

    $containReady=Join-Path $ResultsDirectory 'containment.ready'
    $containGo=Join-Path $ResultsDirectory 'containment.go'
    $containResult=Join-Path $ResultsDirectory 'containment.result'
    $containProbeOut=Join-Path $ResultsDirectory 'containment-probe.out.log'
    $containProbeErr=Join-Path $ResultsDirectory 'containment-probe.err.log'
    $containProbe=Start-LoggedProcess $helperExe @(
        'containment-probe','--file',(Quote-Arg $containedFile),
        '--ready',(Quote-Arg $containReady),
        '--go',(Quote-Arg $containGo),
        '--result',(Quote-Arg $containResult)
    ) $containProbeOut $containProbeErr
    Wait-Path $containReady 15 'containment probe readiness'

    $containOut=Join-Path $ResultsDirectory 'containment-gate.out.log'
    $containErr=$containOut + '.err'
    $gateContain=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $containRoot),
        '--store',(Quote-Arg $containStore),
        '--session','containment',
        '--contain-pid',([string]$containProbe.Id)
    ) $containOut $containErr
    Wait-LogPattern $containOut 'LAB containment\s+: ACTIVE' $gateContain 45

    New-Item -ItemType File -Path $containGo -Force | Out-Null
    Wait-Path $containResult 15 'containment probe result'
    if(-not $containProbe.WaitForExit(15000)){
        Stop-Process -Id $containProbe.Id -Force -ErrorAction SilentlyContinue
        throw 'Contained runtime probe did not exit.'
    }
    $containOutcome=(Get-Content -LiteralPath $containResult -Raw).Trim()
    if($containOutcome -ne 'denied'){
        throw "Contained process mutation was not denied. outcome=$containOutcome exit=$($containProbe.ExitCode)"
    }
    if($containProbe.ExitCode -ne 0){
        throw "Contained runtime probe returned unexpected exit=$($containProbe.ExitCode), outcome=$containOutcome"
    }
    $summary.containmentDeniedTarget=$true
    $containedAfterHash=(Get-FileHash -LiteralPath $containedFile -Algorithm SHA256).Hash
    if(-not [string]::Equals($containedAfterHash,$containedOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Contained process changed the protected target despite kernel containment.'
    }
    $summary.containmentPreservedTargetHash=$true
    $containProbe=$null

    & $helperExe map-write --file $peerFile
    if($LASTEXITCODE -ne 0){throw "Ordinary peer mapped-write failed under PID-scoped containment, exit=$LASTEXITCODE"}
    $peerAfterHash=(Get-FileHash -LiteralPath $peerFile -Algorithm SHA256).Hash
    if([string]::Equals($peerAfterHash,$peerOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Ordinary peer was unexpectedly prevented from mutating under single-process containment.'
    }
    $summary.containmentAllowedPeer=$true

    # Scenario 4: a preserved gate reply can atomically transition the exact requestor into containment.
    Prepare-GateRoot $gateExe $transitionRoot
    $transitionFileA=Join-Path $transitionRoot 'transition-a.bin'
    $transitionFileB=Join-Path $transitionRoot 'transition-b.bin'
    New-TestFile $transitionFileA
    New-TestFile $transitionFileB

    $transitionReady=Join-Path $ResultsDirectory 'containment-transition.ready'
    $transitionGo=Join-Path $ResultsDirectory 'containment-transition.go'
    $transitionResult=Join-Path $ResultsDirectory 'containment-transition.result'
    $transitionProbeOut=Join-Path $ResultsDirectory 'containment-transition-probe.out.log'
    $transitionProbeErr=Join-Path $ResultsDirectory 'containment-transition-probe.err.log'
    $transitionProbe=Start-LoggedProcess $helperExe @(
        'containment-transition',
        '--file-a',(Quote-Arg $transitionFileA),
        '--file-b',(Quote-Arg $transitionFileB),
        '--ready',(Quote-Arg $transitionReady),
        '--go',(Quote-Arg $transitionGo),
        '--result',(Quote-Arg $transitionResult)
    ) $transitionProbeOut $transitionProbeErr
    Wait-Path $transitionReady 15 'event-bound containment probe readiness'

    $transitionOut=Join-Path $ResultsDirectory 'containment-transition-gate.out.log'
    $transitionErr=$transitionOut + '.err'
    $gateTransition=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $transitionRoot),
        '--store',(Quote-Arg $transitionStore),
        '--session','containment-transition',
        '--contain-after-pid',([string]$transitionProbe.Id),
        '--contain-after-events','4',
        '--contain-after-paths','2'
    ) $transitionOut $transitionErr
    Wait-LogPattern $transitionOut 'LAB transition\s+: pid=' $gateTransition 45
    Wait-LogPattern $transitionOut 'kernel gate ACTIVE' $gateTransition 45

    New-Item -ItemType File -Path $transitionGo -Force | Out-Null
    Wait-Path $transitionResult 30 'event-bound containment probe result'
    if(-not $transitionProbe.WaitForExit(15000)){
        Stop-Process -Id $transitionProbe.Id -Force -ErrorAction SilentlyContinue
        throw 'Event-bound containment runtime probe did not exit.'
    }
    $transitionOutcome=(Get-Content -LiteralPath $transitionResult -Raw).Trim()
    if($transitionOutcome -ne 'denied-after-threshold'){
        throw "Event-bound containment did not deny the next mutation. outcome=$transitionOutcome exit=$($transitionProbe.ExitCode)"
    }
    if($transitionProbe.ExitCode -ne 0){
        throw "Event-bound containment runtime probe returned unexpected exit=$($transitionProbe.ExitCode), outcome=$transitionOutcome"
    }
    $summary.transitionDeniedNextWrite=$true

    $transitionJournal=Join-Path $transitionStore 'Sessions\containment-transition\containment-state\containment-journal.jsonl'
    $transitionRequest=Wait-JournalMatch $transitionJournal {
        param($x)
        [int]$x.phase -eq 1 -and
        [uint64]$x.processId -eq [uint64]$transitionProbe.Id -and
        [int]$x.evidenceCount -eq 4 -and
        [int]$x.distinctPathCount -eq 2 -and
        $x.containmentActive -eq $false
    } 30 'durable event-bound containment request'
    $summary.transitionRequested=$true

    $transitionActive=Wait-JournalMatch $transitionJournal {
        param($x)
        [int]$x.phase -eq 2 -and
        [uint64]$x.kernelSequence -eq [uint64]$transitionRequest.kernelSequence -and
        [uint64]$x.processId -eq [uint64]$transitionRequest.processId -and
        $x.containmentActive -eq $true -and
        [uint64]$x.containedProcessId -eq [uint64]$transitionRequest.processId
    } 30 'kernel-active event-bound containment receipt'
    $summary.transitionKernelActive=$true
    Wait-LogPattern $transitionOut 'LAB CONTAINMENT ACTIVE' $gateTransition 30
    $transitionProbe=$null

    $summary.passed=$true
    $summary.completedUtc=(Get-Date).ToUniversalTime().ToString('o')
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'runtime-result.json') -Encoding utf8
    Write-Host "RUNTIME MINIFILTER LAB PASSED: $ResultsDirectory" -ForegroundColor Green
}
finally{
    if($dirHolder -and -not $dirHolder.HasExited){
        if($dirRelease){New-Item -ItemType File -Path $dirRelease -Force -ErrorAction SilentlyContinue | Out-Null}
        Stop-Process -Id $dirHolder.Id -Force -ErrorAction SilentlyContinue
    }
    if($holder -and -not $holder.HasExited){
        if($release){New-Item -ItemType File -Path $release -Force -ErrorAction SilentlyContinue | Out-Null}
        Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
    }
    if($containProbe -and -not $containProbe.HasExited){
        if($containGo){New-Item -ItemType File -Path $containGo -Force -ErrorAction SilentlyContinue | Out-Null}
        Stop-Process -Id $containProbe.Id -Force -ErrorAction SilentlyContinue
    }
    if($transitionProbe -and -not $transitionProbe.HasExited){
        if($transitionGo){New-Item -ItemType File -Path $transitionGo -Force -ErrorAction SilentlyContinue | Out-Null}
        Stop-Process -Id $transitionProbe.Id -Force -ErrorAction SilentlyContinue
    }
    foreach($p in @($gateDir,$gatePre,$gatePost,$gateContain,$gateTransition)){
        if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
    }
    if($installed){
        & $unloadScript -Volume $volume
    }
    if(-not $summary.passed){
        $summary.completedUtc=(Get-Date).ToUniversalTime().ToString('o')
        $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'runtime-result.json') -Encoding utf8
    }
}
