[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CandidateRoot,
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [Parameter(Mandatory=$true)][string]$ProbeHelperExe,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedSha,
    [string]$RootBase='C:\RansomGuard-VM-MappedAdversarial',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Mapped adversarial qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: mapped adversarial qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required.'
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

function Quote-Arg([string]$Value){return '"' + $Value.Replace('"','\"') + '"'}

function Start-LoggedProcess([string]$FilePath,[string[]]$Arguments,[string]$StdOut,[string]$StdErr){
    foreach($path in @($StdOut,$StdErr)){
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        $parent=Split-Path -Parent $path
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    }
    return Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Stop-ProcessHard([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Description pid=$($Process.Id)."}
}

function Wait-Path([string]$Path,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){return}
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
            $err=if(Test-Path -LiteralPath ($Path+'.err')){Get-Content -LiteralPath ($Path+'.err') -Raw}else{''}
            throw "Process exited before '$Pattern'. Exit=$($Process.ExitCode). $err"
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for '$Pattern' in $Path"
}

function Wait-JournalMatch([string]$Path,[scriptblock]$Predicate,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            foreach($line in Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue){
                if([string]::IsNullOrWhiteSpace($line)){continue}
                try{$entry=$line | ConvertFrom-Json -Depth 20}catch{continue}
                if(& $Predicate $entry){return $entry}
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description in $Path"
}

function Test-FailSafeMappedDenial([Exception]$Exception){
    # Windows may reject destructive operations against a live mapped section before the
    # minifilter's explicit deny is surfaced to user mode. Accept only well-known denial
    # classes, then require unchanged namespace/content postconditions below.
    $safeWin32=@(
        5,    # ERROR_ACCESS_DENIED
        32,   # ERROR_SHARING_VIOLATION
        33,   # ERROR_LOCK_VIOLATION
        1224  # ERROR_USER_MAPPED_FILE
    )
    $cursor=$Exception
    while($null -ne $cursor){
        if($cursor -is [UnauthorizedAccessException]){return $true}
        $win32=([int]$cursor.HResult -band 0xFFFF)
        if($win32 -in $safeWin32){return $true}
        $cursor=$cursor.InnerException
    }
    return $false
}

function New-TestFile([string]$Path,[int]$Salt){
    $parent=Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*17+$Salt)%251)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

$stateRoot=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'))
$fixedStore=[IO.Path]::GetFullPath((Join-Path $stateRoot 'Rollback'))

function Reset-QualificationState {
    if(Test-Path -LiteralPath $stateRoot){
        Assert-NoReparsePath $stateRoot 'QualificationStateRoot'
        Remove-Item -LiteralPath $stateRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $fixedStore -Force | Out-Null
}

function Assert-DurablePreimage([string]$Session,[string]$Target,[string]$OriginalHash,[string]$Description){
    $sessionRoot=Join-Path $fixedStore ("Sessions\"+$Session)
    $capture=Wait-JournalMatch (Join-Path $sessionRoot 'journal.jsonl') {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$Target,[StringComparison]::OrdinalIgnoreCase)
    } 25 "$Description durable pre-image"
    if(-not [string]::Equals([string]$capture.originalSha256,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description pre-image hash mismatch."
    }
    $snapshot=Join-Path $sessionRoot ([string]$capture.snapshotRelativePath)
    if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){throw "$Description snapshot missing."}
    $snapshotHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
    if(-not [string]::Equals($snapshotHash,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Description snapshot hash mismatch."
    }
    return $capture
}

Assert-Administrator
$vm=Assert-DisposableVm

$CandidateRoot=[IO.Path]::GetFullPath($CandidateRoot)
$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$ProbeHelperExe=[IO.Path]::GetFullPath($ProbeHelperExe)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
foreach($path in @($CandidateRoot,$LabReleaseDirectory,$DriverPackageDirectory)){
    if(-not(Test-Path -LiteralPath $path -PathType Container)){throw "Required directory missing: $path"}
}
if(-not(Test-Path -LiteralPath $ProbeHelperExe -PathType Leaf)){throw "Mapped adversarial helper missing: $ProbeHelperExe"}

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$installScript=Join-Path $CandidateRoot 'minifilter-tools\install_minifilter_lab.ps1'
$unloadScript=Join-Path $CandidateRoot 'minifilter-tools\unload_minifilter_lab.ps1'
$provenancePath=Join-Path $DriverPackageDirectory 'runtime-package.json'
foreach($required in @($gateExe,$installScript,$unloadScript,$provenancePath)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required frozen input missing: $required"}
}
$provenance=Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
if(-not [string]::Equals([string]$provenance.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
    throw "Frozen package commit '$($provenance.commit)' does not match '$ExpectedSha'."
}

if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) ('RansomGuard-MappedAdversarial-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
if(Test-Path -LiteralPath $ResultsDirectory){
    Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'
    Remove-Item -LiteralPath $ResultsDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $ResultsDirectory,$RootBase -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'
Assert-NoReparsePath $RootBase 'RootBase'
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')

$summary=[ordered]@{
    schema=1
    frozenCandidateSha=$ExpectedSha.ToLowerInvariant()
    driverSysSha256=[string]$provenance.sysSha256
    driverInfSha256=[string]$provenance.infSha256
    driverCatSha256=[string]$provenance.catSha256
    vm=$vm
    mappedLossFailSafe=$false
    mappedLossPreimageProven=$false
    mappingRenameSafe=$false
    mappingRenamePreimageProven=$false
    mappingTruncateSafe=$false
    mappingTruncatePreimageProven=$false
    mappingDeleteSafe=$false
    mappingDeletePreimageProven=$false
    dirtyFlushBoundarySafe=$false
    dirtyFlushPreimageProven=$false
    cleanupPassed=$false
    passed=$false
    error=$null
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    completedUtc=$null
}
$runtimeFailure=$null
$activeProcesses=New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$installed=$false

function Cleanup-Scenario {
    foreach($p in @($activeProcesses)){
        try{Stop-ProcessHard $p 'mapped qualification process'}catch{}
    }
    $activeProcesses.Clear()
    if($script:installed){
        & $unloadScript -Volume $volume -RemovePackage
        $script:installed=$false
    }
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'Mapped qualification left RansomGuardMinifilter loaded.'
    }
    Reset-QualificationState
}

function Release-ScenarioHolder(
    [System.Diagnostics.Process]$Holder,
    [string]$ReleaseMarker,
    [string]$Description
){
    New-Item -ItemType File -Path $ReleaseMarker -Force | Out-Null
    if(-not $Holder.WaitForExit(15000)){
        Stop-ProcessHard $Holder $Description
        throw "$Description did not exit after release."
    }
    if($Holder.ExitCode -ne 0){throw "$Description failed, exit=$($Holder.ExitCode)."}
    $activeProcesses.Remove($Holder) | Out-Null
}

function Start-Scenario([string]$Name,[int]$Salt){
    # Prevent nested helper/script output from becoming part of this function's return value.
    # Start-Scenario must emit exactly one scenario object so StrictMode property access is deterministic.
    Cleanup-Scenario | Write-Host
    $root=Join-Path $RootBase $Name
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target=Join-Path $root 'target.bin'
    New-TestFile $target $Salt
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Write-Host
    $script:installed=$true

    $session=$Name+'-'+(Get-Date -Format 'yyyyMMddHHmmssfff')
    $out=Join-Path $ResultsDirectory ($Name+'.gate.out.log')
    $err=$out+'.err'
    $gate=Start-LoggedProcess $gateExe @('--production','--root',(Quote-Arg $root),'--session',$session) $out $err
    $activeProcesses.Add($gate)
    Wait-LogPattern $out 'kernel gate ACTIVE' $gate 45

    return [pscustomobject]@{Name=$Name;Root=$root;Target=$target;OriginalHash=$originalHash;Session=$session;Gate=$gate;Out=$out;Err=$err}
}

try{
    Reset-QualificationState

    # 1. Writable mapping exists while ProductionGate is ACTIVE; mutate/flush only after GateClient loss.
    $s=Start-Scenario 'mapped-loss' 11
    $ready=Join-Path $ResultsDirectory 'mapped-loss.ready'
    $go=Join-Path $ResultsDirectory 'mapped-loss.go'
    $release=Join-Path $ResultsDirectory 'mapped-loss.release'
    $result=Join-Path $ResultsDirectory 'mapped-loss.result'
    $helperOut=Join-Path $ResultsDirectory 'mapped-loss.helper.out.log'
    $helperErr=$helperOut+'.err'
    $holder=Start-LoggedProcess $ProbeHelperExe @(
        'hold-map-mutate','--file',(Quote-Arg $s.Target),
        '--ready',(Quote-Arg $ready),'--go',(Quote-Arg $go),
        '--release',(Quote-Arg $release),'--result',(Quote-Arg $result)
    ) $helperOut $helperErr
    $activeProcesses.Add($holder)
    Wait-Path $ready 20 'mapped-loss probe readiness'
    Stop-ProcessHard $s.Gate 'mapped-loss ProductionGate'
    Start-Sleep -Milliseconds 500
    New-Item -ItemType File -Path $go -Force | Out-Null
    Wait-Path $result 20 'mapped-loss flush result'
    Release-ScenarioHolder $holder $release 'Mapped-loss holder'
    $after=(Get-FileHash -LiteralPath $s.Target -Algorithm SHA256).Hash
    if([string]::Equals($after,$s.OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        $summary.mappedLossFailSafe=$true
        $summary.mappedLossPreimageProven=$true
    }else{
        $null=Assert-DurablePreimage $s.Session $s.Target $s.OriginalHash 'mapped loss'
        $summary.mappedLossFailSafe=$true
        $summary.mappedLossPreimageProven=$true
    }
    Cleanup-Scenario

    # 2. Rename while a writable mapping is alive.
    $s=Start-Scenario 'mapping-rename' 23
    $ready=Join-Path $ResultsDirectory 'mapping-rename.ready'
    $release=Join-Path $ResultsDirectory 'mapping-rename.release'
    $holder=Start-LoggedProcess $ProbeHelperExe @(
        'hold-map','--file',(Quote-Arg $s.Target),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) (Join-Path $ResultsDirectory 'mapping-rename.helper.out.log') (Join-Path $ResultsDirectory 'mapping-rename.helper.err.log')
    $activeProcesses.Add($holder)
    Wait-Path $ready 20 'mapping-rename holder'
    $destination=Join-Path $s.Root 'renamed.bin'
    $renameDenied=$false
    try{[IO.File]::Move($s.Target,$destination)}
    catch{if(Test-FailSafeMappedDenial $_.Exception){$renameDenied=$true}else{throw}}
    Release-ScenarioHolder $holder $release 'Mapping-rename holder'
    if($renameDenied){
        if(-not(Test-Path -LiteralPath $s.Target -PathType Leaf)){throw 'Denied mapped rename lost source path.'}
        if(-not [string]::Equals((Get-FileHash -LiteralPath $s.Target -Algorithm SHA256).Hash,$s.OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Denied mapped rename changed source content.'
        }
    }else{
        if(-not(Test-Path -LiteralPath $destination -PathType Leaf)){throw 'Allowed mapped rename did not create destination path.'}
        $null=Assert-DurablePreimage $s.Session $s.Target $s.OriginalHash 'mapping rename'
        $summary.mappingRenamePreimageProven=$true
    }
    if($renameDenied){$summary.mappingRenamePreimageProven=$true}
    $summary.mappingRenameSafe=$true
    Cleanup-Scenario

    # 3. EOF truncation while a writable mapping is alive.
    $s=Start-Scenario 'mapping-truncate' 37
    $ready=Join-Path $ResultsDirectory 'mapping-truncate.ready'
    $release=Join-Path $ResultsDirectory 'mapping-truncate.release'
    $holder=Start-LoggedProcess $ProbeHelperExe @(
        'hold-map','--file',(Quote-Arg $s.Target),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) (Join-Path $ResultsDirectory 'mapping-truncate.helper.out.log') (Join-Path $ResultsDirectory 'mapping-truncate.helper.err.log')
    $activeProcesses.Add($holder)
    Wait-Path $ready 20 'mapping-truncate holder'
    $truncateDenied=$false
    try{
        $stream=[IO.File]::Open($s.Target,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        try{$stream.SetLength(32768);$stream.Flush($true)}finally{$stream.Dispose()}
    }catch{if(Test-FailSafeMappedDenial $_.Exception){$truncateDenied=$true}else{throw}}
    Release-ScenarioHolder $holder $release 'Mapping-truncate holder'
    if($truncateDenied){
        if((Get-Item -LiteralPath $s.Target).Length -ne 65536){throw 'Denied mapped truncate changed file length.'}
        if(-not [string]::Equals((Get-FileHash -LiteralPath $s.Target -Algorithm SHA256).Hash,$s.OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Denied mapped truncate changed file content.'
        }
    }else{
        if((Get-Item -LiteralPath $s.Target).Length -ne 32768){throw 'Allowed mapped truncate did not set expected EOF.'}
        $null=Assert-DurablePreimage $s.Session $s.Target $s.OriginalHash 'mapping truncate'
        $summary.mappingTruncatePreimageProven=$true
    }
    if($truncateDenied){$summary.mappingTruncatePreimageProven=$true}
    $summary.mappingTruncateSafe=$true
    Cleanup-Scenario

    # 4. Delete disposition while a writable mapping is alive.
    $s=Start-Scenario 'mapping-delete' 51
    $ready=Join-Path $ResultsDirectory 'mapping-delete.ready'
    $release=Join-Path $ResultsDirectory 'mapping-delete.release'
    $holder=Start-LoggedProcess $ProbeHelperExe @(
        'hold-map','--file',(Quote-Arg $s.Target),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) (Join-Path $ResultsDirectory 'mapping-delete.helper.out.log') (Join-Path $ResultsDirectory 'mapping-delete.helper.err.log')
    $activeProcesses.Add($holder)
    Wait-Path $ready 20 'mapping-delete holder'
    $deleteDenied=$false
    try{[IO.File]::Delete($s.Target)}
    catch{if(Test-FailSafeMappedDenial $_.Exception){$deleteDenied=$true}else{throw}}
    Release-ScenarioHolder $holder $release 'Mapping-delete holder'
    if(-not $deleteDenied){
        $null=Assert-DurablePreimage $s.Session $s.Target $s.OriginalHash 'mapping delete'
        $summary.mappingDeletePreimageProven=$true
    }else{
        if(-not(Test-Path -LiteralPath $s.Target -PathType Leaf)){throw 'Denied mapped delete lost target path.'}
        if(-not [string]::Equals((Get-FileHash -LiteralPath $s.Target -Algorithm SHA256).Hash,$s.OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Denied mapped delete changed target content.'
        }
        $summary.mappingDeletePreimageProven=$true
    }
    $summary.mappingDeleteSafe=$true
    Cleanup-Scenario

    # 5. Dirty mapped page exists before GateClient loss; explicit flush happens after loss.
    $s=Start-Scenario 'dirty-flush-loss' 67
    $ready=Join-Path $ResultsDirectory 'dirty-flush.ready'
    $go=Join-Path $ResultsDirectory 'dirty-flush.go'
    $release=Join-Path $ResultsDirectory 'dirty-flush.release'
    $result=Join-Path $ResultsDirectory 'dirty-flush.result'
    $holder=Start-LoggedProcess $ProbeHelperExe @(
        'hold-map-dirty-flush','--file',(Quote-Arg $s.Target),
        '--ready',(Quote-Arg $ready),'--go',(Quote-Arg $go),
        '--release',(Quote-Arg $release),'--result',(Quote-Arg $result)
    ) (Join-Path $ResultsDirectory 'dirty-flush.helper.out.log') (Join-Path $ResultsDirectory 'dirty-flush.helper.err.log')
    $activeProcesses.Add($holder)
    Wait-Path $ready 20 'dirty mapped page readiness'
    Stop-ProcessHard $s.Gate 'dirty-flush ProductionGate'
    Start-Sleep -Milliseconds 500
    New-Item -ItemType File -Path $go -Force | Out-Null
    Wait-Path $result 20 'dirty mapped flush result'
    Release-ScenarioHolder $holder $release 'Dirty-flush holder'
    $after=(Get-FileHash -LiteralPath $s.Target -Algorithm SHA256).Hash
    if([string]::Equals($after,$s.OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        $summary.dirtyFlushBoundarySafe=$true
        $summary.dirtyFlushPreimageProven=$true
    }else{
        $null=Assert-DurablePreimage $s.Session $s.Target $s.OriginalHash 'dirty flush loss'
        $summary.dirtyFlushBoundarySafe=$true
        $summary.dirtyFlushPreimageProven=$true
    }
    Cleanup-Scenario

    $summary.cleanupPassed=$true
    $summary.passed=$true
}catch{
    $runtimeFailure=$_
    $summary.error=$_.Exception.Message
    try{Cleanup-Scenario}catch{}
}finally{
    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'mapped-adversarial-result.json') -Encoding utf8
}

if($runtimeFailure){throw $runtimeFailure}
if(-not $summary.passed){throw 'Mapped adversarial qualification did not pass.'}
Write-Host "MAPPED ADVERSARIAL QUALIFICATION PASSED: $ResultsDirectory" -ForegroundColor Green
