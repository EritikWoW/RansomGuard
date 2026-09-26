[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CandidateRoot,
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [Parameter(Mandatory=$true)][string]$FsctlHelperExe,
    [Parameter(Mandatory=$true)][string]$ExpectedSha,
    [string]$RootBase='C:\RansomGuard-VM-ProductionMutation',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production mutation qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production mutation qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required only inside the disposable VM.'
    }
    return $vmText
}

function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){throw "$Label has no filesystem root: $full"}
    $cursor=$root.TrimEnd('\')
    $relative=$full.Substring($root.Length)
    foreach($segment in $relative.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}

function Reset-QualificationStateRoot([string]$StateRoot){
    $expected=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'))
    $full=[IO.Path]::GetFullPath($StateRoot)
    if(-not [string]::Equals($full,$expected,[StringComparison]::OrdinalIgnoreCase)){
        throw "REFUSED: state reset escaped the exact RansomGuardV03 ProgramData root: $full"
    }
    if(Test-Path -LiteralPath $full){
        Assert-NoReparsePath $full 'QualificationStateRoot'
        Remove-Item -LiteralPath $full -Recurse -Force
    }
    if(Test-Path -LiteralPath $full){throw "Qualification state root remained after reset: $full"}
}

function Quote-Arg([string]$Value){return '"' + $Value.Replace('"','\"') + '"'}

function Start-LoggedProcess([string]$FilePath,[string[]]$Arguments,[string]$StdOut,[string]$StdErr){
    foreach($path in @($StdOut,$StdErr)){
        $parent=Split-Path -Parent $path
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Read-Log([string]$Path){
    if(Test-Path -LiteralPath $Path -PathType Leaf){
        return [string](Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)
    }
    return ''
}

function Wait-Path([string]$Path,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description at $Path"
}

function Wait-LogPattern([string]$Path,[string]$Pattern,[System.Diagnostics.Process]$Process,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){
            $text=Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if($text -match $Pattern){return}
        }
        if($Process.HasExited){
            $err=Read-Log ($Path+'.err')
            throw "Process exited before '$Pattern'. Exit=$($Process.ExitCode). $err"
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for '$Pattern' in $Path"
}

function Stop-ProcessHard([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Description pid=$($Process.Id)."}
}

function Wait-ExpectedGateRejection(
    [System.Diagnostics.Process]$Process,
    [string]$StdOut,
    [string]$StdErr,
    [string]$ExpectedPattern,
    [string]$Description,
    [int]$Seconds=30
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $combined=(Read-Log $StdOut)+[Environment]::NewLine+(Read-Log $StdErr)
        if($combined -match '(?i)kernel gate ACTIVE'){
            if(-not $Process.HasExited){Stop-ProcessHard $Process "$Description unexpectedly activated"}
            throw "Kernel gate unexpectedly became ACTIVE during $Description. $combined"
        }
        if($combined -match $ExpectedPattern){
            if(-not $Process.HasExited){Stop-ProcessHard $Process "$Description rejection cleanup"}
            elseif($Process.ExitCode -eq 0){throw "Gate returned exit=0 despite rejection evidence during $Description."}
            return $combined
        }
        if($Process.HasExited){
            if($Process.ExitCode -eq 0){throw "Gate unexpectedly succeeded during $Description."}
            throw "Gate failed for an unexpected reason during $Description. $combined"
        }
        Start-Sleep -Milliseconds 100
    }
    $combined=(Read-Log $StdOut)+[Environment]::NewLine+(Read-Log $StdErr)
    if(-not $Process.HasExited){Stop-ProcessHard $Process "$Description timeout cleanup"}
    throw "Timed out waiting for expected rejection during $Description. $combined"
}

function Wait-JournalMatch([string]$Path,[scriptblock]$Predicate,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            $lines=@(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
            foreach($line in $lines){
                if([string]::IsNullOrWhiteSpace($line)){continue}
                try{$entry=$line | ConvertFrom-Json -ErrorAction Stop}catch{continue}
                if(& $Predicate $entry){return $entry}
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description in $Path"
}

function New-TestFile([string]$Path,[int]$Salt=41){
    $parent=Split-Path -Parent $Path
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*17+$Salt) -band 0xFF)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Invoke-FsctlQualificationProbe(
    [string[]]$Arguments,
    [string]$ResultPath,
    [string]$Description
){
    Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue
    $invokeArgs=@($Arguments)+@('--result',$ResultPath)
    & $FsctlHelperExe @invokeArgs
    if($LASTEXITCODE -ne 0){
        throw "$Description helper failed with exit=$LASTEXITCODE."
    }
    if(-not(Test-Path -LiteralPath $ResultPath -PathType Leaf)){
        throw "$Description helper produced no result marker."
    }
    $value=(Get-Content -LiteralPath $ResultPath -Raw).Trim()
    if([string]::IsNullOrWhiteSpace($value)){
        throw "$Description helper produced an empty result marker."
    }
    return $value
}

function Test-FsctlAllowedResult([string]$Result){
    return $Result -match '^allowed(?:$|:)'
}

function Assert-FsctlCapabilityConsistency(
    [string]$CapabilityResult,
    [string]$ProtectedResult,
    [string]$Description
){
    if($CapabilityResult -match '^open-error:'){
        throw "$Description capability preflight could not open its file: $CapabilityResult"
    }
    if($ProtectedResult -match '^open-error:'){
        throw "$Description could not open the protected target after ProductionGate activation: $ProtectedResult"
    }

    if(Test-FsctlAllowedResult $CapabilityResult){
        if(-not(Test-FsctlAllowedResult $ProtectedResult)){
            throw "$Description is supported outside protection but did not reach the filesystem under ProductionGate. capability=$CapabilityResult protected=$ProtectedResult"
        }
        return
    }

    if(-not [string]::Equals($CapabilityResult,$ProtectedResult,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description changed the filesystem result under ProductionGate. capability=$CapabilityResult protected=$ProtectedResult"
    }
}

function Assert-DurablePreimage(
    [string]$Session,
    [string]$Target,
    [string]$OriginalHash,
    [string]$Description
){
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$Session)
    $capture=Wait-JournalMatch (Join-Path $sessionRoot 'journal.jsonl') {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$Target,[StringComparison]::OrdinalIgnoreCase)
    } 20 "$Description durable full pre-image"
    if(-not [string]::Equals([string]$capture.originalSha256,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description pre-image hash mismatch."
    }
    $snapshot=Join-Path $sessionRoot ([string]$capture.snapshotRelativePath)
    if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){
        throw "$Description pre-image snapshot missing."
    }
    if(-not [string]::Equals((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description snapshot hash mismatch."
    }
}


function Test-SafeMutationRejection([Exception]$Exception){
    $cursor=$Exception
    while($null -ne $cursor){
        if($cursor -is [UnauthorizedAccessException]){return $true}
        $code=([int]$cursor.HResult -band 0xFFFF)
        if($code -in @(5,32,1224)){return $true}
        $cursor=$cursor.InnerException
    }
    return $false
}

function Assert-DurableRangePreimage(
    [string]$Session,
    [string]$Target,
    [string]$OriginalHash,
    [string]$Description
){
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$Session)
    $entry=Wait-JournalMatch (Join-Path $sessionRoot 'write-cow\range-journal.jsonl') {
        param($x)
        [int]$x.kind -eq 2 -and
        [string]::Equals([string]$x.originalPath,$Target,[StringComparison]::OrdinalIgnoreCase) -and
        [int64]$x.blockOffset -eq 0
    } 20 "$Description durable range pre-image"

    if([string]::IsNullOrWhiteSpace([string]$entry.snapshotRelativePath)){
        throw "$Description range pre-image has no snapshot path."
    }
    $snapshot=Join-Path (Join-Path $sessionRoot 'write-cow') ([string]$entry.snapshotRelativePath)
    if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){
        throw "$Description range snapshot missing: $snapshot"
    }
    $snapshotHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
    if(-not [string]::Equals($snapshotHash,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description range snapshot hash mismatch. expected=$OriginalHash actual=$snapshotHash"
    }
}

function Assert-OriginallyAbsentBaseline(
    [string]$Session,
    [string]$Target,
    [string]$Description
){
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$Session)
    $null=Wait-JournalMatch (Join-Path $sessionRoot 'create-state\create-journal.jsonl') {
        param($x)
        [string]::Equals([string]$x.originalPath,$Target,[StringComparison]::OrdinalIgnoreCase)
    } 20 "$Description originally-absent baseline"
}

Assert-Administrator
$vm=Assert-DisposableVm

if($ExpectedSha -notmatch '^[0-9A-Fa-f]{40}$'){throw 'ExpectedSha must be exactly 40 hexadecimal characters.'}
$ExpectedSha=$ExpectedSha.ToLowerInvariant()
$CandidateRoot=[IO.Path]::GetFullPath($CandidateRoot)
$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$FsctlHelperExe=[IO.Path]::GetFullPath($FsctlHelperExe)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
$drive=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
if($RootBase -eq $drive){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionMutation-$stamp"}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $CandidateRoot 'minifilter-tools\install_minifilter_lab.ps1'
$unloadScript=Join-Path $CandidateRoot 'minifilter-tools\unload_minifilter_lab.ps1'
$driverSys=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.sys'
$driverInf=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.inf'
$driverCat=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.cat'
$driverProvenancePath=Join-Path $DriverPackageDirectory 'runtime-package.json'
foreach($required in @($gateExe,$helperExe,$FsctlHelperExe,$installScript,$unloadScript,$driverSys,$driverInf,$driverCat,$driverProvenancePath)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required candidate artifact missing: $required"}
}

$provenance=Get-Content -LiteralPath $driverProvenancePath -Raw | ConvertFrom-Json
if([int]$provenance.schema -ne 2){throw 'Runtime package provenance schema must be 2.'}
if(-not [string]::Equals([string]$provenance.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Driver package commit '$($provenance.commit)' does not match frozen candidate '$ExpectedSha'."
}
$actualSys=(Get-FileHash -LiteralPath $driverSys -Algorithm SHA256).Hash
$actualInf=(Get-FileHash -LiteralPath $driverInf -Algorithm SHA256).Hash
$actualCat=(Get-FileHash -LiteralPath $driverCat -Algorithm SHA256).Hash
if(-not [string]::Equals([string]$provenance.sysSha256,$actualSys,[StringComparison]::OrdinalIgnoreCase)){throw 'SYS provenance hash mismatch.'}
if(-not [string]::Equals([string]$provenance.infSha256,$actualInf,[StringComparison]::OrdinalIgnoreCase)){throw 'INF provenance hash mismatch.'}
if(-not [string]::Equals([string]$provenance.catSha256,$actualCat,[StringComparison]::OrdinalIgnoreCase)){throw 'CAT provenance hash mismatch.'}

$stateRoot=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'))
$fixedStore=[IO.Path]::GetFullPath((Join-Path $stateRoot 'Rollback'))
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
$logicalDisk=Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $volume)
if($null -eq $logicalDisk -or [string]::IsNullOrWhiteSpace([string]$logicalDisk.FileSystem)){
    throw "Unable to determine filesystem for qualification volume '$volume'."
}
$filesystem=([string]$logicalDisk.FileSystem).ToUpperInvariant()
if($filesystem -ne 'NTFS'){
    throw "Frozen 0.8.6 production mutation qualification currently declares only NTFS support. Found '$filesystem' on '$volume'."
}

$summary=[ordered]@{
    schema=1
    frozenCandidateSha=$ExpectedSha
    driverSysSha256=$actualSys
    driverInfSha256=$actualInf
    driverCatSha256=$actualCat
    vm=$vm
    filesystem=$filesystem
    ntfsQualified=$true
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    dormantWritableHandleRejected=$false
    preexistingWritableMappingRejected=$false
    preexistingHardLinkRejected=$false
    descendantReparseRejected=$false
    postActivationReparseMutationDenied=$false
    hardLinkInsideToOutsideDenied=$false
    hardLinkOutsideToInsideDenied=$false
    hardLinkOutsideToOutsideAllowed=$false
    hardLinkExInsideToOutsideDenied=$false
    hardLinkExOutsideToInsideDenied=$false
    hardLinkExOutsideToOutsideAllowed=$false
    hardLinkDeleteStreamSafe=$false
    hardLinkDeleteStreamPreimageProven=$false
    hardLinkDeleteStreamOutcome=''
    adsAlternateAliasSafe=$false
    adsAlternateAliasPreimageProven=$false
    adsAlternateAliasOutcome=''
    fsctlZeroAllowedWithBaseline=$false
    fsctlZeroMutatedTarget=$false
    fsctlZeroPreimageHashMatched=$false
    fsctlSetSparseCapability=''
    fsctlSetSparseResult=''
    fsctlSetSparseQualified=$false
    fsctlFileLevelTrimCapability=''
    fsctlFileLevelTrimResult=''
    fsctlFileLevelTrimQualified=$false
    fsctlDuplicateExtentsCapability=''
    fsctlDuplicateExtentsResult=''
    fsctlDuplicateExtentsQualified=$false
    fsctlDuplicateExtentsExCapability=''
    fsctlDuplicateExtentsExResult=''
    fsctlDuplicateExtentsExQualified=$false
    fsctlOffloadWriteCapability=''
    fsctlOffloadWriteResult=''
    fsctlOffloadWriteQualified=$false
    postActivationMappedWriteMutatedTarget=$false
    postActivationMappedWritePreimageHashMatched=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}

$activeProcesses=New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$holderProcesses=New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$installed=$false
$runtimeFailure=$null
$cleanupFailure=$null

function Ensure-CleanStart {
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager before scenario.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded before production mutation scenario.'
    }
    Reset-QualificationStateRoot $stateRoot
    New-Item -ItemType Directory -Path $fixedStore -Force | Out-Null
    Assert-NoReparsePath $fixedStore 'ProductionRollbackStore'
}

function Install-ScenarioDriver {
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER'
    $script:installed=$true
}

function Cleanup-Scenario([string]$Name){
    foreach($p in @($activeProcesses)){
        if($p -and -not $p.HasExited){
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $activeProcesses.Clear()
    foreach($p in @($holderProcesses)){
        if($p -and -not $p.HasExited){
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $holderProcesses.Clear()

    if($script:installed){
        & $unloadScript -Volume $volume -RemovePackage
        $script:installed=$false
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw "$Name left RansomGuardMinifilter loaded."
    }
    Reset-QualificationStateRoot $stateRoot
}

function Start-ProductionGate([string]$Root,[string]$Session,[string]$Prefix){
    $out=Join-Path $ResultsDirectory ($Prefix+'.out.log')
    $err=$out+'.err'
    $process=Start-LoggedProcess $gateExe @('--production','--root',(Quote-Arg $Root),'--session',$Session) $out $err
    $activeProcesses.Add($process)
    return [pscustomobject]@{Process=$process;StdOut=$out;StdErr=$err}
}

try{
    # Scenario 1: a user-writable handle that predates ProductionGate activation must fail preflight.
    Ensure-CleanStart
    $root=Join-Path $RootBase "dormant-handle-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'victim.bin'
    New-TestFile $target
    $ready=Join-Path $ResultsDirectory 'dormant.ready'
    $release=Join-Path $ResultsDirectory 'dormant.release'
    $holder=Start-LoggedProcess $helperExe @(
        'hold-write-handle','--file',(Quote-Arg $target),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) (Join-Path $ResultsDirectory 'dormant-holder.out.log') (Join-Path $ResultsDirectory 'dormant-holder.err.log')
    $holderProcesses.Add($holder)
    Wait-Path $ready 15 'dormant writable handle readiness'
    Install-ScenarioDriver
    $gate=Start-ProductionGate $root "prod-mut-dormant-$stamp" 'dormant-production-gate'
    $evidence=Wait-ExpectedGateRejection $gate.Process $gate.StdOut $gate.StdErr '(?i)Activation topology preflight|sharing|used by another process|could not hold file' 'ProductionGate dormant writable handle'
    if($evidence -match 'already has a user-writable mapped view'){throw 'Dormant-handle proof used the mapped-view rejection path.'}
    $summary.dormantWritableHandleRejected=$true
    New-Item -ItemType File -Path $release -Force | Out-Null
    if(-not $holder.WaitForExit(15000)){throw 'Dormant writable-handle holder did not exit.'}
    Cleanup-Scenario 'dormant writable handle'

    # Scenario 2: a writable mapping that predates ProductionGate activation must fail preflight.
    Ensure-CleanStart
    $root=Join-Path $RootBase "preexisting-map-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'victim.bin'
    New-TestFile $target
    $ready=Join-Path $ResultsDirectory 'preexisting-map.ready'
    $release=Join-Path $ResultsDirectory 'preexisting-map.release'
    $holder=Start-LoggedProcess $helperExe @(
        'hold-map','--file',(Quote-Arg $target),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) (Join-Path $ResultsDirectory 'preexisting-map-holder.out.log') (Join-Path $ResultsDirectory 'preexisting-map-holder.err.log')
    $holderProcesses.Add($holder)
    Wait-Path $ready 15 'pre-existing writable mapping readiness'
    Install-ScenarioDriver
    $gate=Start-ProductionGate $root "prod-mut-premap-$stamp" 'preexisting-map-production-gate'
    [void](Wait-ExpectedGateRejection $gate.Process $gate.StdOut $gate.StdErr '(?i)already has a user-writable mapped view' 'ProductionGate pre-existing writable mapping')
    $summary.preexistingWritableMappingRejected=$true
    New-Item -ItemType File -Path $release -Force | Out-Null
    if(-not $holder.WaitForExit(15000)){throw 'Pre-existing mapping holder did not exit.'}
    Cleanup-Scenario 'pre-existing mapping'

    # Scenario 3: a descendant junction/reparse point must make ProductionGate activation fail closed.
    # Protecting a pathname root while silently skipping a namespace escape would let an attacker
    # route I/O through an in-root name to an out-of-root target.
    Ensure-CleanStart
    $root=Join-Path $RootBase "descendant-reparse-$stamp"
    $outsideDir=Join-Path $RootBase "descendant-reparse-target-$stamp"
    $junction=Join-Path $root 'escape'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path $outsideDir -Force | Out-Null
    New-TestFile (Join-Path $outsideDir 'outside.bin')
    $created=New-Item -ItemType Junction -Path $junction -Target $outsideDir -Force
    if($null -eq $created -or -not(Test-Path -LiteralPath $junction)){
        throw 'Unable to create descendant junction required for ProductionGate qualification.'
    }
    if(((Get-Item -LiteralPath $junction -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0){
        throw 'Qualification junction was not reported as a reparse point.'
    }
    try{
        Install-ScenarioDriver
        $gate=Start-ProductionGate $root "prod-mut-reparse-$stamp" 'descendant-reparse-production-gate'
        [void](Wait-ExpectedGateRejection $gate.Process $gate.StdOut $gate.StdErr '(?i)Activation preflight refuses descendant reparse point:' 'ProductionGate descendant reparse point')
        $summary.descendantReparseRejected=$true
        Cleanup-Scenario 'descendant reparse point'
    }
    finally{
        if(Test-Path -LiteralPath $junction){
            & $env:ComSpec /d /c rmdir "$junction"
            if($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $junction)){
                throw "Unable to remove qualification junction '$junction' without traversing its target. exit=$LASTEXITCODE"
            }
        }
    }

    # Scenario 4: once ProductionGate is ACTIVE, an attacker must not be able to
    # create a junction/reparse point inside the protected root and invalidate the
    # namespace topology that activation preflight proved.
    Ensure-CleanStart
    $root=Join-Path $RootBase "postactivation-reparse-$stamp"
    $outsideDir=Join-Path $RootBase "postactivation-reparse-target-$stamp"
    $junction=Join-Path $root 'escape'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path $outsideDir -Force | Out-Null
    New-TestFile (Join-Path $outsideDir 'outside.bin')
    Install-ScenarioDriver
    $gate=Start-ProductionGate $root "prod-mut-postreparse-$stamp" 'postactivation-reparse-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45

    $reparseDenied=$false
    try{
        $null=New-Item -ItemType Junction -Path $junction -Target $outsideDir -Force -ErrorAction Stop
        throw 'ProductionGate unexpectedly allowed post-activation descendant junction creation.'
    }
    catch{
        if($_.Exception.Message -eq 'ProductionGate unexpectedly allowed post-activation descendant junction creation.'){
            throw
        }

        $permissionDenied=([string]$_.CategoryInfo.Category -eq 'PermissionDenied')
        $exceptionChain=New-Object System.Collections.Generic.List[string]
        $cursor=$_.Exception
        while($null -ne $cursor){
            $hr=([int64]$cursor.HResult) -band 0xFFFFFFFFL
            $low=[int]($hr -band 0xFFFFL)
            $exceptionChain.Add("$($cursor.GetType().FullName):HResult=0x$('{0:X8}' -f $hr):$($cursor.Message)")
            if($cursor -is [System.ComponentModel.Win32Exception] -and $cursor.NativeErrorCode -eq 5){
                $permissionDenied=$true
            }
            if($low -eq 5){
                $permissionDenied=$true
            }
            $cursor=$cursor.InnerException
        }

        $wrappedAccessDenied=(
            [string]::Equals([string]$_.FullyQualifiedErrorId,'System.IO.IOException,Microsoft.PowerShell.Commands.NewItemCommand',[StringComparison]::Ordinal) -and
            $_.Exception -is [System.IO.IOException] -and
            $_.Exception.Message -like 'Access to the path * is denied.'
        )
        if($wrappedAccessDenied){
            # New-Item -ItemType Junction wraps ERROR_ACCESS_DENIED from the underlying
            # reparse FSCTL in a generic IOException (0x80131620) and discards Win32=5.
            # The pre-activation scenario proves junction creation is supported on this
            # VM; the postcondition below still requires that no reparse point appeared.
            $permissionDenied=$true
        }

        if(-not $permissionDenied){
            throw "Post-activation junction creation failed for an unexpected reason. Category=$($_.CategoryInfo.Category); FullyQualifiedErrorId=$($_.FullyQualifiedErrorId); ExceptionChain=$($exceptionChain -join ' -> ')"
        }
        $reparseDenied=$true
    }

    if(-not $reparseDenied){throw 'Post-activation reparse mutation denial was not observed.'}
    $junctionResidue=$false
    if(Test-Path -LiteralPath $junction){
        $createdItem=Get-Item -LiteralPath $junction -Force
        if(($createdItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            & $env:ComSpec /d /c rmdir "$junction"
            throw 'Post-activation reparse mutation returned an error but still created a reparse point.'
        }

        # New-Item may leave the ordinary directory it created before the reparse FSCTL
        # is denied. While ProductionGate is active that residue is itself protected, so
        # deleting it here would test another protected mutation and can correctly return
        # ACCESS_DENIED. Record the residue and remove it only after GateClient is stopped
        # and the minifilter has been unloaded.
        $junctionResidue=$true
    }
    $summary.postActivationReparseMutationDenied=$true
    Stop-ProcessHard $gate.Process 'ProductionGate post-activation reparse scenario'
    Cleanup-Scenario 'post-activation reparse mutation'
    if($junctionResidue -and (Test-Path -LiteralPath $junction)){
        Remove-Item -LiteralPath $junction -Recurse -Force -ErrorAction Stop
    }

    # Scenario 5: pre-existing alias of an in-root file must fail ProductionGate activation.
    Ensure-CleanStart
    $root=Join-Path $RootBase "preexisting-hardlink-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'victim.bin'
    $alias=Join-Path $RootBase "preexisting-hardlink-alias-$stamp.bin"
    $linkResult=Join-Path $ResultsDirectory 'preexisting-hardlink-create.result'
    New-TestFile $target
    & $helperExe hard-link --existing $target --link $alias --result $linkResult
    if($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath $linkResult -Raw).Trim() -ne 'allowed' -or -not(Test-Path -LiteralPath $alias -PathType Leaf)){
        throw 'Unable to create pre-existing hard-link alias for ProductionGate qualification.'
    }
    Install-ScenarioDriver
    $gate=Start-ProductionGate $root "prod-mut-prelink-$stamp" 'preexisting-hardlink-production-gate'
    [void](Wait-ExpectedGateRejection $gate.Process $gate.StdOut $gate.StdErr 'NumberOfLinks=2' 'ProductionGate pre-existing hard-link alias')
    $summary.preexistingHardLinkRejected=$true
    Remove-Item -LiteralPath $alias -Force
    Cleanup-Scenario 'pre-existing hard-link'

    # Scenario 5: active ProductionGate must enforce hard-link topology for both Win32 and FileLinkInformationEx.
    Ensure-CleanStart
    $root=Join-Path $RootBase "active-hardlink-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $inside=Join-Path $root 'inside.bin'
    $outside=Join-Path $RootBase "outside-source-$stamp.bin"
    New-TestFile $inside
    New-TestFile $outside
    Install-ScenarioDriver
    $session="prod-mut-hardlink-$stamp"
    $gate=Start-ProductionGate $root $session 'active-hardlink-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45

    $insideOutside=Join-Path $RootBase "inside-to-outside-$stamp.bin"
    $outsideInside=Join-Path $root 'outside-to-inside.bin'
    $outsideOutside=Join-Path $RootBase "outside-to-outside-$stamp.bin"
    $result=Join-Path $ResultsDirectory 'hardlink-inside-outside.result'
    & $helperExe hard-link --existing $inside --link $insideOutside --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'denied' -or (Test-Path $insideOutside)){throw 'ProductionGate inside-to-outside hard-link was not denied.'}
    $summary.hardLinkInsideToOutsideDenied=$true

    $result=Join-Path $ResultsDirectory 'hardlink-outside-inside.result'
    & $helperExe hard-link --existing $outside --link $outsideInside --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'denied' -or (Test-Path $outsideInside)){throw 'ProductionGate outside-to-inside hard-link was not denied.'}
    $summary.hardLinkOutsideToInsideDenied=$true

    $result=Join-Path $ResultsDirectory 'hardlink-outside-outside.result'
    & $helperExe hard-link --existing $outside --link $outsideOutside --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'allowed' -or -not(Test-Path $outsideOutside)){throw 'ProductionGate over-blocked outside-to-outside hard-link.'}
    $summary.hardLinkOutsideToOutsideAllowed=$true
    Remove-Item $outsideOutside -Force

    $insideOutsideEx=Join-Path $RootBase "inside-to-outside-ex-$stamp.bin"
    $outsideInsideEx=Join-Path $root 'outside-to-inside-ex.bin'
    $outsideOutsideEx=Join-Path $RootBase "outside-to-outside-ex-$stamp.bin"
    $result=Join-Path $ResultsDirectory 'hardlink-ex-inside-outside.result'
    & $helperExe hard-link-ex --existing $inside --link $insideOutsideEx --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'denied-ex' -or (Test-Path $insideOutsideEx)){throw 'ProductionGate FileLinkInformationEx inside-to-outside was not denied.'}
    $summary.hardLinkExInsideToOutsideDenied=$true

    $result=Join-Path $ResultsDirectory 'hardlink-ex-outside-inside.result'
    & $helperExe hard-link-ex --existing $outside --link $outsideInsideEx --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'denied-ex' -or (Test-Path $outsideInsideEx)){throw 'ProductionGate FileLinkInformationEx outside-to-inside was not denied.'}
    $summary.hardLinkExOutsideToInsideDenied=$true

    $result=Join-Path $ResultsDirectory 'hardlink-ex-outside-outside.result'
    & $helperExe hard-link-ex --existing $outside --link $outsideOutsideEx --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'allowed-ex' -or -not(Test-Path $outsideOutsideEx)){throw 'ProductionGate over-blocked outside-to-outside FileLinkInformationEx.'}
    $summary.hardLinkExOutsideToOutsideAllowed=$true
    Remove-Item $outsideOutsideEx -Force

    # Scenario 5b: distinguish deletion of one in-root hard-link pathname from mutation
    # of the shared underlying stream. If inside->inside hard-link creation is unsupported
    # under ProductionGate, that is an explicit fail-safe outcome. If it is supported,
    # deleting one name must not corrupt the remaining stream, and a later stream mutation
    # must either be denied or have a durable range pre-image.
    $aliasBase=Join-Path $root 'alias-delete-base.bin'
    $aliasPath=Join-Path $root 'alias-delete-link.bin'
    New-TestFile $aliasBase 73
    $aliasOriginalHash=(Get-FileHash -LiteralPath $aliasBase -Algorithm SHA256).Hash
    $aliasResult=Join-Path $ResultsDirectory 'hardlink-inside-inside-delete.result'
    & $helperExe hard-link --existing $aliasBase --link $aliasPath --result $aliasResult
    if($LASTEXITCODE -ne 0){throw 'Inside-to-inside hard-link helper failed.'}
    $aliasCreateOutcome=(Get-Content -LiteralPath $aliasResult -Raw).Trim()

    if($aliasCreateOutcome -eq 'denied'){
        if(Test-Path -LiteralPath $aliasPath){throw 'Denied inside-to-inside hard-link unexpectedly exists.'}
        $summary.hardLinkDeleteStreamSafe=$true
        $summary.hardLinkDeleteStreamPreimageProven=$true
        $summary.hardLinkDeleteStreamOutcome='inside-inside-link-denied'
    }elseif($aliasCreateOutcome -eq 'allowed'){
        if(-not(Test-Path -LiteralPath $aliasPath -PathType Leaf)){throw 'Allowed inside-to-inside hard-link was not created.'}
        $deleteDenied=$false
        try{Remove-Item -LiteralPath $aliasPath -Force -ErrorAction Stop}
        catch{
            if(Test-SafeMutationRejection $_.Exception){$deleteDenied=$true}else{throw}
        }

        if($deleteDenied){
            if(-not(Test-Path -LiteralPath $aliasPath -PathType Leaf) -or -not(Test-Path -LiteralPath $aliasBase -PathType Leaf)){
                throw 'Denied single-link deletion changed namespace state.'
            }
            if(-not [string]::Equals((Get-FileHash -LiteralPath $aliasBase -Algorithm SHA256).Hash,$aliasOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Denied single-link deletion changed the underlying stream.'
            }
            $summary.hardLinkDeleteStreamSafe=$true
            $summary.hardLinkDeleteStreamPreimageProven=$true
            $summary.hardLinkDeleteStreamOutcome='single-link-delete-denied'
        }else{
            if(Test-Path -LiteralPath $aliasPath){throw 'Single-link deletion left the removed alias present.'}
            if(-not(Test-Path -LiteralPath $aliasBase -PathType Leaf)){throw 'Single-link deletion removed the shared underlying stream.'}
            if(-not [string]::Equals((Get-FileHash -LiteralPath $aliasBase -Algorithm SHA256).Hash,$aliasOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Single-link deletion changed the shared stream before mutation.'
            }

            $writeDenied=$false
            try{
                $stream=[IO.File]::Open($aliasBase,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                try{
                    $stream.Position=0
                    $stream.WriteByte(0xA7)
                    $stream.Flush($true)
                }finally{$stream.Dispose()}
            }catch{
                if(Test-SafeMutationRejection $_.Exception){$writeDenied=$true}else{throw}
            }

            if($writeDenied){
                if(-not [string]::Equals((Get-FileHash -LiteralPath $aliasBase -Algorithm SHA256).Hash,$aliasOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                    throw 'Denied underlying-stream mutation changed content after single-link deletion.'
                }
                $summary.hardLinkDeleteStreamOutcome='delete-allowed-stream-write-denied'
                $summary.hardLinkDeleteStreamPreimageProven=$true
            }else{
                if([string]::Equals((Get-FileHash -LiteralPath $aliasBase -Algorithm SHA256).Hash,$aliasOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                    throw 'Allowed underlying-stream write did not mutate the remaining hard-link target.'
                }
                Assert-DurableRangePreimage $session $aliasBase $aliasOriginalHash 'hard-link delete then stream mutation'
                $summary.hardLinkDeleteStreamOutcome='delete-allowed-stream-write-preserved'
                $summary.hardLinkDeleteStreamPreimageProven=$true
            }
            $summary.hardLinkDeleteStreamSafe=$true
        }
    }else{
        throw "Unexpected inside-to-inside hard-link outcome '$aliasCreateOutcome'."
    }

    # Scenario 5c: ADS creation/mutation through an alternate in-root hard-link alias.
    # If alternate aliases are denied, the route is explicitly unsupported/fail-safe.
    # If the alias and ADS are allowed, the ADS must have a durable originally-absent
    # baseline so rollback can remove the stream rather than inventing prior contents.
    $adsBase=Join-Path $root 'ads-alias-base.bin'
    $adsAlias=Join-Path $root 'ads-alias-link.bin'
    New-TestFile $adsBase 91
    $adsAliasResult=Join-Path $ResultsDirectory 'hardlink-inside-inside-ads.result'
    & $helperExe hard-link --existing $adsBase --link $adsAlias --result $adsAliasResult
    if($LASTEXITCODE -ne 0){throw 'ADS alternate-alias hard-link helper failed.'}
    $adsAliasOutcome=(Get-Content -LiteralPath $adsAliasResult -Raw).Trim()

    if($adsAliasOutcome -eq 'denied'){
        if(Test-Path -LiteralPath $adsAlias){throw 'Denied ADS alternate alias unexpectedly exists.'}
        $summary.adsAlternateAliasSafe=$true
        $summary.adsAlternateAliasPreimageProven=$true
        $summary.adsAlternateAliasOutcome='inside-inside-link-denied'
    }elseif($adsAliasOutcome -eq 'allowed'){
        if(-not(Test-Path -LiteralPath $adsAlias -PathType Leaf)){throw 'ADS alternate alias was not created.'}
        $adsPath=$adsAlias+':ransomguard-qualification'
        $adsPayload='RANSOMGUARD-ADS-ALIAS-QUALIFICATION'
        $adsDenied=$false
        try{[IO.File]::WriteAllText($adsPath,$adsPayload,[Text.Encoding]::UTF8)}
        catch{
            if(Test-SafeMutationRejection $_.Exception){$adsDenied=$true}else{throw}
        }

        if($adsDenied){
            $summary.adsAlternateAliasOutcome='ads-create-denied'
            $summary.adsAlternateAliasPreimageProven=$true
        }else{
            $actualAds=[IO.File]::ReadAllText($adsPath,[Text.Encoding]::UTF8)
            if($actualAds -ne $adsPayload){throw 'ADS write through alternate alias returned unexpected content.'}
            Assert-OriginallyAbsentBaseline $session $adsPath 'ADS alternate-alias create'
            $summary.adsAlternateAliasOutcome='ads-create-originally-absent-preserved'
            $summary.adsAlternateAliasPreimageProven=$true
        }
        $summary.adsAlternateAliasSafe=$true
    }else{
        throw "Unexpected ADS alternate-alias hard-link outcome '$adsAliasOutcome'."
    }

    Stop-ProcessHard $gate.Process 'ProductionGate hard-link scenario'
    Cleanup-Scenario 'active hard-link topology'

    # Scenario 6: FSCTL_SET_ZERO_DATA may mutate only after a durable full pre-image exists.
    Ensure-CleanStart
    $root=Join-Path $RootBase "fsctl-zero-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'zero-data.bin'
    New-TestFile $target
    $originalHash=(Get-FileHash $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-fsctl-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $result=Join-Path $ResultsDirectory 'fsctl-zero.result'
    & $helperExe fsctl-zero --file $target --offset 0 --length 4096 --result $result
    if($LASTEXITCODE -ne 0 -or (Get-Content $result -Raw).Trim() -ne 'allowed'){throw 'ProductionGate FSCTL_SET_ZERO_DATA did not complete after baseline.'}
    $summary.fsctlZeroAllowedWithBaseline=$true
    $afterHash=(Get-FileHash $target -Algorithm SHA256).Hash
    if([string]::Equals($afterHash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate FSCTL_SET_ZERO_DATA did not mutate target.'}
    $summary.fsctlZeroMutatedTarget=$true
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$session)
    $capture=Wait-JournalMatch (Join-Path $sessionRoot 'journal.jsonl') {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)
    } 20 'ProductionGate FSCTL full pre-image'
    if(-not [string]::Equals([string]$capture.originalSha256,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate FSCTL pre-image hash mismatch.'}
    $snapshot=Join-Path $sessionRoot ([string]$capture.snapshotRelativePath)
    if(-not(Test-Path $snapshot -PathType Leaf)){throw 'ProductionGate FSCTL pre-image snapshot missing.'}
    if(-not [string]::Equals((Get-FileHash $snapshot -Algorithm SHA256).Hash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate FSCTL snapshot hash mismatch.'}
    $summary.fsctlZeroPreimageHashMatched=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL scenario'
    Cleanup-Scenario 'FSCTL_SET_ZERO_DATA'

    # Scenario 7: FSCTL_SET_SPARSE must retain a durable full pre-image before changing sparse metadata.
    Ensure-CleanStart
    $capTarget=Join-Path $RootBase "cap-set-sparse-$stamp.bin"
    New-TestFile $capTarget 53
    $capResultPath=Join-Path $ResultsDirectory 'fsctl-set-sparse-capability.result'
    $capResult=Invoke-FsctlQualificationProbe @('set-sparse','--file',$capTarget) $capResultPath 'FSCTL_SET_SPARSE capability'
    $summary.fsctlSetSparseCapability=$capResult
    if(-not(Test-FsctlAllowedResult $capResult)){
        throw "NTFS qualification VM does not support FSCTL_SET_SPARSE as expected. result=$capResult"
    }

    $root=Join-Path $RootBase "fsctl-set-sparse-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'set-sparse.bin'
    New-TestFile $target 59
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-set-sparse-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-set-sparse-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $resultPath=Join-Path $ResultsDirectory 'fsctl-set-sparse.result'
    $protectedResult=Invoke-FsctlQualificationProbe @('set-sparse','--file',$target) $resultPath 'ProductionGate FSCTL_SET_SPARSE'
    $summary.fsctlSetSparseResult=$protectedResult
    Assert-FsctlCapabilityConsistency $capResult $protectedResult 'FSCTL_SET_SPARSE'
    $attributes=(Get-Item -LiteralPath $target -Force).Attributes
    if(($attributes -band [IO.FileAttributes]::SparseFile) -eq 0){
        throw 'ProductionGate FSCTL_SET_SPARSE returned success but the sparse attribute was not set.'
    }
    Assert-DurablePreimage $session $target $originalHash 'ProductionGate FSCTL_SET_SPARSE'
    $summary.fsctlSetSparseQualified=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL_SET_SPARSE scenario'
    Cleanup-Scenario 'FSCTL_SET_SPARSE'
    Remove-Item -LiteralPath $capTarget -Force -ErrorAction SilentlyContinue

    # Scenario 8: FSCTL_FILE_LEVEL_TRIM must preserve the original content before any supported storage trim.
    Ensure-CleanStart
    $capTarget=Join-Path $RootBase "cap-file-trim-$stamp.bin"
    New-TestFile $capTarget 61
    $capResultPath=Join-Path $ResultsDirectory 'fsctl-file-trim-capability.result'
    $capResult=Invoke-FsctlQualificationProbe @('file-trim','--file',$capTarget,'--offset','0','--length','65536') $capResultPath 'FSCTL_FILE_LEVEL_TRIM capability'
    $summary.fsctlFileLevelTrimCapability=$capResult

    $root=Join-Path $RootBase "fsctl-file-trim-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'file-trim.bin'
    New-TestFile $target 67
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-file-trim-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-file-trim-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $resultPath=Join-Path $ResultsDirectory 'fsctl-file-trim.result'
    $protectedResult=Invoke-FsctlQualificationProbe @('file-trim','--file',$target,'--offset','0','--length','65536') $resultPath 'ProductionGate FSCTL_FILE_LEVEL_TRIM'
    $summary.fsctlFileLevelTrimResult=$protectedResult
    Assert-FsctlCapabilityConsistency $capResult $protectedResult 'FSCTL_FILE_LEVEL_TRIM'
    if((Test-FsctlAllowedResult $capResult) -and $protectedResult -notmatch '^allowed:[1-9][0-9]*$'){
        throw "FSCTL_FILE_LEVEL_TRIM reported success without a processed range. result=$protectedResult"
    }
    Assert-DurablePreimage $session $target $originalHash 'ProductionGate FSCTL_FILE_LEVEL_TRIM'
    $summary.fsctlFileLevelTrimQualified=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL_FILE_LEVEL_TRIM scenario'
    Cleanup-Scenario 'FSCTL_FILE_LEVEL_TRIM'
    Remove-Item -LiteralPath $capTarget -Force -ErrorAction SilentlyContinue

    # Scenario 9: FSCTL_DUPLICATE_EXTENTS_TO_FILE is either qualified with preservation or recorded as unavailable on this NTFS target.
    Ensure-CleanStart
    $capSource=Join-Path $RootBase "cap-dup-source-$stamp.bin"
    $capTarget=Join-Path $RootBase "cap-dup-target-$stamp.bin"
    New-TestFile $capSource 71
    New-TestFile $capTarget 79
    $capSourceHash=(Get-FileHash -LiteralPath $capSource -Algorithm SHA256).Hash
    $capTargetBefore=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
    $capResultPath=Join-Path $ResultsDirectory 'fsctl-duplicate-extents-capability.result'
    $capResult=Invoke-FsctlQualificationProbe @('duplicate-extents','--source',$capSource,'--target',$capTarget,'--length','65536') $capResultPath 'FSCTL_DUPLICATE_EXTENTS_TO_FILE capability'
    $summary.fsctlDuplicateExtentsCapability=$capResult
    if(Test-FsctlAllowedResult $capResult){
        $capTargetAfter=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
        if(-not [string]::Equals($capTargetAfter,$capSourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'FSCTL_DUPLICATE_EXTENTS_TO_FILE capability probe returned success without cloning the requested bytes.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash,$capTargetBefore,[StringComparison]::OrdinalIgnoreCase)){
        throw 'FSCTL_DUPLICATE_EXTENTS_TO_FILE capability probe failed but still changed the target.'
    }

    $root=Join-Path $RootBase "fsctl-duplicate-extents-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $source=Join-Path $RootBase "dup-source-$stamp.bin"
    $target=Join-Path $root 'dup-target.bin'
    New-TestFile $source 83
    New-TestFile $target 89
    $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-dup-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-duplicate-extents-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $resultPath=Join-Path $ResultsDirectory 'fsctl-duplicate-extents.result'
    $protectedResult=Invoke-FsctlQualificationProbe @('duplicate-extents','--source',$source,'--target',$target,'--length','65536') $resultPath 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE'
    $summary.fsctlDuplicateExtentsResult=$protectedResult
    Assert-FsctlCapabilityConsistency $capResult $protectedResult 'FSCTL_DUPLICATE_EXTENTS_TO_FILE'
    if(Test-FsctlAllowedResult $capResult){
        if(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$sourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE returned success without mutating the target to source content.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Unsupported FSCTL_DUPLICATE_EXTENTS_TO_FILE changed protected target content.'
    }
    Assert-DurablePreimage $session $target $originalHash 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE'
    $summary.fsctlDuplicateExtentsQualified=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE scenario'
    Cleanup-Scenario 'FSCTL_DUPLICATE_EXTENTS_TO_FILE'
    Remove-Item -LiteralPath $capSource,$capTarget,$source -Force -ErrorAction SilentlyContinue

    # Scenario 10: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX follows the same preservation/capability contract.
    Ensure-CleanStart
    $capSource=Join-Path $RootBase "cap-dup-ex-source-$stamp.bin"
    $capTarget=Join-Path $RootBase "cap-dup-ex-target-$stamp.bin"
    New-TestFile $capSource 97
    New-TestFile $capTarget 101
    $capSourceHash=(Get-FileHash -LiteralPath $capSource -Algorithm SHA256).Hash
    $capTargetBefore=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
    $capResultPath=Join-Path $ResultsDirectory 'fsctl-duplicate-extents-ex-capability.result'
    $capResult=Invoke-FsctlQualificationProbe @('duplicate-extents-ex','--source',$capSource,'--target',$capTarget,'--length','65536') $capResultPath 'FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX capability'
    $summary.fsctlDuplicateExtentsExCapability=$capResult
    if(Test-FsctlAllowedResult $capResult){
        $capTargetAfter=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
        if(-not [string]::Equals($capTargetAfter,$capSourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX capability probe returned success without cloning the requested bytes.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash,$capTargetBefore,[StringComparison]::OrdinalIgnoreCase)){
        throw 'FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX capability probe failed but still changed the target.'
    }

    $root=Join-Path $RootBase "fsctl-duplicate-extents-ex-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $source=Join-Path $RootBase "dup-ex-source-$stamp.bin"
    $target=Join-Path $root 'dup-ex-target.bin'
    New-TestFile $source 103
    New-TestFile $target 107
    $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-dup-ex-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-duplicate-extents-ex-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $resultPath=Join-Path $ResultsDirectory 'fsctl-duplicate-extents-ex.result'
    $protectedResult=Invoke-FsctlQualificationProbe @('duplicate-extents-ex','--source',$source,'--target',$target,'--length','65536') $resultPath 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX'
    $summary.fsctlDuplicateExtentsExResult=$protectedResult
    Assert-FsctlCapabilityConsistency $capResult $protectedResult 'FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX'
    if(Test-FsctlAllowedResult $capResult){
        if(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$sourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX returned success without mutating the target to source content.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Unsupported FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX changed protected target content.'
    }
    Assert-DurablePreimage $session $target $originalHash 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX'
    $summary.fsctlDuplicateExtentsExQualified=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX scenario'
    Cleanup-Scenario 'FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX'
    Remove-Item -LiteralPath $capSource,$capTarget,$source -Force -ErrorAction SilentlyContinue

    # Scenario 11: FSCTL_OFFLOAD_WRITE is capability-bound to the current NTFS/storage stack and still requires target preservation.
    Ensure-CleanStart
    $capSource=Join-Path $RootBase "cap-offload-source-$stamp.bin"
    $capTarget=Join-Path $RootBase "cap-offload-target-$stamp.bin"
    New-TestFile $capSource 109
    New-TestFile $capTarget 113
    $capSourceHash=(Get-FileHash -LiteralPath $capSource -Algorithm SHA256).Hash
    $capTargetBefore=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
    $capResultPath=Join-Path $ResultsDirectory 'fsctl-offload-write-capability.result'
    $capResult=Invoke-FsctlQualificationProbe @('offload-copy','--source',$capSource,'--target',$capTarget,'--length','65536') $capResultPath 'FSCTL_OFFLOAD_WRITE capability'
    $summary.fsctlOffloadWriteCapability=$capResult
    if(Test-FsctlAllowedResult $capResult){
        $capTargetAfter=(Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash
        if(-not [string]::Equals($capTargetAfter,$capSourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'FSCTL_OFFLOAD_WRITE capability probe returned success without copying the requested bytes.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $capTarget -Algorithm SHA256).Hash,$capTargetBefore,[StringComparison]::OrdinalIgnoreCase)){
        throw 'FSCTL_OFFLOAD_WRITE capability probe failed but still changed the target.'
    }

    $root=Join-Path $RootBase "fsctl-offload-write-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $source=Join-Path $RootBase "offload-source-$stamp.bin"
    $target=Join-Path $root 'offload-target.bin'
    New-TestFile $source 127
    New-TestFile $target 131
    $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-offload-$stamp"
    $gate=Start-ProductionGate $root $session 'fsctl-offload-write-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    $resultPath=Join-Path $ResultsDirectory 'fsctl-offload-write.result'
    $protectedResult=Invoke-FsctlQualificationProbe @('offload-copy','--source',$source,'--target',$target,'--length','65536') $resultPath 'ProductionGate FSCTL_OFFLOAD_WRITE'
    $summary.fsctlOffloadWriteResult=$protectedResult
    Assert-FsctlCapabilityConsistency $capResult $protectedResult 'FSCTL_OFFLOAD_WRITE'
    if(Test-FsctlAllowedResult $capResult){
        if(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$sourceHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'ProductionGate FSCTL_OFFLOAD_WRITE returned success without mutating the target to source content.'
        }
    }elseif(-not [string]::Equals((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Unavailable FSCTL_OFFLOAD_WRITE changed protected target content.'
    }
    Assert-DurablePreimage $session $target $originalHash 'ProductionGate FSCTL_OFFLOAD_WRITE'
    $summary.fsctlOffloadWriteQualified=$true
    Stop-ProcessHard $gate.Process 'ProductionGate FSCTL_OFFLOAD_WRITE scenario'
    Cleanup-Scenario 'FSCTL_OFFLOAD_WRITE'
    Remove-Item -LiteralPath $capSource,$capTarget,$source -Force -ErrorAction SilentlyContinue

    # Scenario 12: post-activation mapped write must retain the original full pre-image.
    Ensure-CleanStart
    $root=Join-Path $RootBase "mapped-write-$stamp"
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'mapped.bin'
    New-TestFile $target
    $originalHash=(Get-FileHash $target -Algorithm SHA256).Hash
    Install-ScenarioDriver
    $session="prod-mut-map-$stamp"
    $gate=Start-ProductionGate $root $session 'mapped-write-production-gate'
    Wait-LogPattern $gate.StdOut 'kernel gate ACTIVE' $gate.Process 45
    & $helperExe map-write --file $target
    if($LASTEXITCODE -ne 0){throw "ProductionGate mapped-write helper failed, exit=$LASTEXITCODE"}
    $afterHash=(Get-FileHash $target -Algorithm SHA256).Hash
    if([string]::Equals($afterHash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate mapped write did not mutate target.'}
    $summary.postActivationMappedWriteMutatedTarget=$true
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$session)
    [void](Wait-JournalMatch (Join-Path $sessionRoot 'section-state\writable-section-journal.jsonl') {
        param($x)
        [int]$x.state -eq 1 -and [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),$target,[StringComparison]::OrdinalIgnoreCase)
    } 30 'ProductionGate writable-section baseline evidence')
    $capture=Wait-JournalMatch (Join-Path $sessionRoot 'journal.jsonl') {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)
    } 20 'ProductionGate mapped-write full pre-image'
    if(-not [string]::Equals([string]$capture.originalSha256,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate mapped-write pre-image hash mismatch.'}
    $snapshot=Join-Path $sessionRoot ([string]$capture.snapshotRelativePath)
    if(-not(Test-Path $snapshot -PathType Leaf)){throw 'ProductionGate mapped-write snapshot missing.'}
    if(-not [string]::Equals((Get-FileHash $snapshot -Algorithm SHA256).Hash,$originalHash,[StringComparison]::OrdinalIgnoreCase)){throw 'ProductionGate mapped-write snapshot hash mismatch.'}
    $summary.postActivationMappedWritePreimageHashMatched=$true
    Stop-ProcessHard $gate.Process 'ProductionGate mapped-write scenario'
    Cleanup-Scenario 'post-activation mapped write'

    $summary.cleanupPassed=$true
    $summary.passed=$true
}
catch{
    $runtimeFailure=$_
}
finally{
    try{
        foreach($p in @($activeProcesses)){
            if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
        }
        foreach($p in @($holderProcesses)){
            if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
        }
        if($installed){
            & $unloadScript -Volume $volume -RemovePackage
            $script:installed=$false
        }
        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            throw 'RansomGuardMinifilter remained loaded after production mutation qualification.'
        }
        Reset-QualificationStateRoot $stateRoot
    }catch{
        $cleanupFailure=$_
        $summary.cleanupPassed=$false
        $summary.cleanupError=$_.Exception.Message
        $summary.passed=$false
    }

    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-mutation-matrix-result.json') -Encoding utf8
}

if($runtimeFailure){
    if($cleanupFailure){throw "Production mutation scenario failed: $($runtimeFailure.Exception.Message) Cleanup also failed: $($cleanupFailure.Exception.Message)"}
    throw $runtimeFailure
}
if($cleanupFailure){throw $cleanupFailure}
if(-not $summary.passed){throw 'Production mutation qualification did not pass.'}

Write-Host "FROZEN PRODUCTION MUTATION MATRIX PASSED: $ResultsDirectory" -ForegroundColor Green
