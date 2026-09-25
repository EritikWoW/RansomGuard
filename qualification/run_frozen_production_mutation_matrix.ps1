[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CandidateRoot,
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
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

function New-TestFile([string]$Path){
    $parent=Split-Path -Parent $Path
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*17+41) -band 0xFF)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

Assert-Administrator
$vm=Assert-DisposableVm

if($ExpectedSha -notmatch '^[0-9A-Fa-f]{40}$'){throw 'ExpectedSha must be exactly 40 hexadecimal characters.'}
$ExpectedSha=$ExpectedSha.ToLowerInvariant()
$CandidateRoot=[IO.Path]::GetFullPath($CandidateRoot)
$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
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
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript,$driverSys,$driverInf,$driverCat,$driverProvenancePath)){
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

$summary=[ordered]@{
    schema=1
    frozenCandidateSha=$ExpectedSha
    driverSysSha256=$actualSys
    driverInfSha256=$actualInf
    driverCatSha256=$actualCat
    vm=$vm
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
    fsctlZeroAllowedWithBaseline=$false
    fsctlZeroMutatedTarget=$false
    fsctlZeroPreimageHashMatched=$false
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
        $win32=([int]$_.Exception.HResult) -band 0xFFFF
        if($_.Exception -isnot [UnauthorizedAccessException] -and $win32 -ne 5){
            throw "Post-activation junction creation failed for an unexpected reason. HResult=0x$('{0:X8}' -f ([uint32]$_.Exception.HResult)); $($_.Exception.Message)"
        }
        $reparseDenied=$true
    }

    if(-not $reparseDenied){throw 'Post-activation reparse mutation denial was not observed.'}
    if(Test-Path -LiteralPath $junction){
        $createdItem=Get-Item -LiteralPath $junction -Force
        if(($createdItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            & $env:ComSpec /d /c rmdir "$junction"
            throw 'Post-activation reparse mutation returned an error but still created a reparse point.'
        }
        Remove-Item -LiteralPath $junction -Recurse -Force
    }
    $summary.postActivationReparseMutationDenied=$true
    Stop-ProcessHard $gate.Process 'ProductionGate post-activation reparse scenario'
    Cleanup-Scenario 'post-activation reparse mutation'

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

    # Scenario 7: post-activation mapped write must retain the original full pre-image.
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
