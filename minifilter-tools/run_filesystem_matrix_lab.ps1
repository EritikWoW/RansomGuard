[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$ScratchDirectory='',
    [string]$ResultsDirectory='',
    [ValidateRange(512,4096)][int]$VhdSizeMiB=1024
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Filesystem matrix harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: filesystem matrix requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
    }
    return $vmText
}

function Assert-SafeScratchPath([string]$Path,[string]$Label){
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

function Stop-LabProcess([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    if(-not $Process.WaitForExit(10000)){
        throw "Timed out stopping $($Description) process pid=$($Process.Id)."
    }
}

function Wait-Path([string]$Path,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $($Description): $Path"
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
                try{$obj=$line | ConvertFrom-Json -Depth 30}catch{continue}
                if(& $Predicate $obj){return $obj}
            }
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for $Description in $Path"
}

function New-TestFile([string]$Path,[int]$Length=65536){
    $parent=Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes=New-Object byte[] $Length
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*29+17)%251)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $prepareOutput=@(& $GateExe --root $Root --prepare-root 2>&1)
    $prepareExit=$LASTEXITCODE
    foreach($line in $prepareOutput){Write-Host $line}
    if($prepareExit -ne 0){
        throw "Gate root preparation failed for $Root, exit=$prepareExit. Output: $($prepareOutput -join [Environment]::NewLine)"
    }
}

function Get-FreeDriveLetter {
    $used=@([IO.DriveInfo]::GetDrives() | ForEach-Object {$_.Name.Substring(0,1).ToUpperInvariant()})
    foreach($letter in @('R','S','T','U','V','W','X','Y','Z','Q','P')){
        if($used -notcontains $letter){return $letter}
    }
    throw 'No free drive letter is available for the disposable filesystem matrix VHD.'
}

function Invoke-DiskPartScript([string[]]$Lines,[string]$Description,[bool]$AllowFailure=$false){
    $scriptPath=Join-Path $ScratchDirectory ("diskpart-{0}.txt" -f [Guid]::NewGuid().ToString('N'))
    $stdout=Join-Path $ScratchDirectory ("diskpart-{0}.out.txt" -f [Guid]::NewGuid().ToString('N'))
    $stderr=Join-Path $ScratchDirectory ("diskpart-{0}.err.txt" -f [Guid]::NewGuid().ToString('N'))
    try{
        $Lines | Set-Content -LiteralPath $scriptPath -Encoding ASCII
        $proc=Start-Process -FilePath 'diskpart.exe' -ArgumentList @('/s',(Quote-Arg $scriptPath)) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if(-not $proc.WaitForExit(60000)){
            try{$proc.Kill($true)}catch{}
            throw "DiskPart timeout during $Description."
        }
        $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
        $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
        $combined=($out+[Environment]::NewLine+$err).Trim()
        $failed=$proc.ExitCode -ne 0 -or
            $combined -match '(?im)DiskPart has encountered an error|Virtual Disk Service error|The arguments specified for this command are not valid'
        if($failed -and -not $AllowFailure){
            throw "DiskPart failed during $Description. exit=$($proc.ExitCode). Output: $combined"
        }
        return [pscustomobject]@{Succeeded=(-not $failed);ExitCode=$proc.ExitCode;Output=$combined}
    }
    finally{
        Remove-Item -LiteralPath $scriptPath,$stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

function New-ScratchVhd([string]$FileSystem){
    $letter=Get-FreeDriveLetter
    $vhdPath=Join-Path $ScratchDirectory ("RansomGuard-{0}-{1}.vhd" -f $FileSystem.ToLowerInvariant(),[Guid]::NewGuid().ToString('N'))
    $volume=("{0}:" -f $letter)
    if(Test-Path -LiteralPath $vhdPath){throw "Refusing to overwrite existing VHD: $vhdPath"}

    $create=Invoke-DiskPartScript @(
        "create vdisk file=""$vhdPath"" maximum=$VhdSizeMiB type=expandable",
        "select vdisk file=""$vhdPath""",
        'attach vdisk',
        'create partition primary',
        "assign letter=$letter"
    ) "create isolated $FileSystem VHD" $true

    if(-not $create.Succeeded){
        return [pscustomobject]@{
            FileSystem=$FileSystem
            DriveLetter=$letter
            Volume=$volume
            VhdPath=$vhdPath
            Provisioned=$false
            Supported=$false
            Reason=("VHD provisioning failed: " + $create.Output)
        }
    }

    try{
        $null=Format-Volume -DriveLetter $letter -FileSystem $FileSystem -NewFileSystemLabel ("RGFS{0}" -f $FileSystem.ToUpperInvariant()) -Confirm:$false -Force -ErrorAction Stop
        $volumeInfo=Get-Volume -DriveLetter $letter -ErrorAction Stop
        if(-not [string]::Equals([string]$volumeInfo.FileSystem,$FileSystem,[StringComparison]::OrdinalIgnoreCase)){
            throw "Formatted filesystem mismatch. expected=$FileSystem actual=$($volumeInfo.FileSystem)"
        }

        return [pscustomobject]@{
            FileSystem=$FileSystem
            DriveLetter=$letter
            Volume=$volume
            VhdPath=$vhdPath
            Provisioned=$true
            Supported=$true
            Reason=''
        }
    }
    catch{
        return [pscustomobject]@{
            FileSystem=$FileSystem
            DriveLetter=$letter
            Volume=$volume
            VhdPath=$vhdPath
            Provisioned=$true
            Supported=$false
            Reason=$_.Exception.Message
        }
    }
}

function Remove-ScratchVhd($Vhd){
    if($null -eq $Vhd){return}
    if(-not $Vhd.VhdPath){return}
    if(-not(Test-Path -LiteralPath $Vhd.VhdPath)){return}

    $detach=Invoke-DiskPartScript @(
        "select vdisk file=""$($Vhd.VhdPath)""",
        'detach vdisk'
    ) "detach isolated $($Vhd.FileSystem) VHD" $true
    if(-not $detach.Succeeded){
        throw "REFUSED: scratch VHD detach was not confirmed; leaving the VHD file intact for VM checkpoint recovery. Output: $($detach.Output)"
    }

    Remove-Item -LiteralPath $Vhd.VhdPath -Force -ErrorAction Stop
}

function Run-FileSystemScenario($Vhd){
    $fs=[string]$Vhd.FileSystem
    $volume=[string]$Vhd.Volume
    $stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
    $root=Join-Path ($volume+'\') ("RansomGuard-FS-Matrix-{0}-{1}" -f $fs,$stamp)
    $store=Join-Path $ResultsDirectory ("{0}-store" -f $fs.ToLowerInvariant())
    $session=("fs-{0}" -f $fs.ToLowerInvariant())
    $gateOut=Join-Path $ResultsDirectory ("{0}-gate.out.log" -f $fs.ToLowerInvariant())
    $gateErr=$gateOut+'.err'
    $gate=$null

    $createTarget=Join-Path $root 'created.bin'
    $renameSource=Join-Path $root 'rename-source.bin'
    $renameDestination=Join-Path $root 'rename-destination.bin'
    $truncateTarget=Join-Path $root 'truncate.bin'
    $deleteTarget=Join-Path $root 'delete.bin'
    $mappedTarget=Join-Path $root 'mapped.bin'
    $truncateReady=Join-Path $ResultsDirectory ("{0}-truncate.ready" -f $fs.ToLowerInvariant())
    $truncateGo=Join-Path $ResultsDirectory ("{0}-truncate.go" -f $fs.ToLowerInvariant())
    $deleteReady=Join-Path $ResultsDirectory ("{0}-delete.ready" -f $fs.ToLowerInvariant())
    $deleteGo=Join-Path $ResultsDirectory ("{0}-delete.go" -f $fs.ToLowerInvariant())

    try{
        Prepare-GateRoot $gateExe $root
        New-TestFile $renameSource 8192
        New-TestFile $truncateTarget 8192
        New-TestFile $deleteTarget 8192
        New-TestFile $mappedTarget 65536
        $mappedOriginalHash=(Get-FileHash -LiteralPath $mappedTarget -Algorithm SHA256).Hash

        & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Out-Host

        $gate=Start-LoggedProcess $gateExe @(
            '--root',(Quote-Arg $root),
            '--store',(Quote-Arg $store),
            '--session',$session
        ) $gateOut $gateErr
        Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

        & $helperExe create-new --file $createTarget | Out-Host
        if($LASTEXITCODE -ne 0){throw "$fs CREATE_NEW helper failed, exit=$LASTEXITCODE"}
        if(-not(Test-Path -LiteralPath $createTarget -PathType Leaf)){throw "$fs CREATE_NEW target missing."}

        & $helperExe rename-file --source $renameSource --destination $renameDestination | Out-Host
        if($LASTEXITCODE -ne 0){throw "$fs RENAME helper failed, exit=$LASTEXITCODE"}
        if((Test-Path -LiteralPath $renameSource) -or -not(Test-Path -LiteralPath $renameDestination -PathType Leaf)){
            throw "$fs RENAME topology mismatch."
        }

        $truncateProc=Start-LoggedProcess $helperExe @(
            'truncate-eof','--file',(Quote-Arg $truncateTarget),'--length','1024',
            '--ready',(Quote-Arg $truncateReady),'--go',(Quote-Arg $truncateGo)
        ) (Join-Path $ResultsDirectory ("{0}-truncate.out.log" -f $fs.ToLowerInvariant())) (Join-Path $ResultsDirectory ("{0}-truncate.err.log" -f $fs.ToLowerInvariant()))
        Wait-Path $truncateReady 30 "$fs truncate helper readiness"
        Wait-LogPattern $gateOut ("CreateResult.*" + [regex]::Escape($truncateTarget)) $gate 30
        Set-Content -LiteralPath $truncateGo -Value 'go' -Encoding ASCII
        if(-not $truncateProc.WaitForExit(45000)){Stop-Process -Id $truncateProc.Id -Force -ErrorAction SilentlyContinue; throw "$fs TRUNCATE helper timeout."}
        if($truncateProc.ExitCode -ne 0){throw "$fs TRUNCATE helper failed, exit=$($truncateProc.ExitCode)"}
        if((Get-Item -LiteralPath $truncateTarget).Length -ne 1024){throw "$fs TRUNCATE length mismatch."}

        $deleteProc=Start-LoggedProcess $helperExe @(
            'delete-file','--file',(Quote-Arg $deleteTarget),
            '--ready',(Quote-Arg $deleteReady),'--go',(Quote-Arg $deleteGo)
        ) (Join-Path $ResultsDirectory ("{0}-delete.out.log" -f $fs.ToLowerInvariant())) (Join-Path $ResultsDirectory ("{0}-delete.err.log" -f $fs.ToLowerInvariant()))
        Wait-Path $deleteReady 30 "$fs delete helper readiness"
        Wait-LogPattern $gateOut ("CreateResult.*" + [regex]::Escape($deleteTarget)) $gate 30
        Set-Content -LiteralPath $deleteGo -Value 'go' -Encoding ASCII
        if(-not $deleteProc.WaitForExit(45000)){Stop-Process -Id $deleteProc.Id -Force -ErrorAction SilentlyContinue; throw "$fs DELETE helper timeout."}
        if($deleteProc.ExitCode -ne 0){throw "$fs DELETE helper failed, exit=$($deleteProc.ExitCode)"}
        $deleteDeadline=(Get-Date).AddSeconds(10)
        while((Get-Date) -lt $deleteDeadline -and (Test-Path -LiteralPath $deleteTarget)){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $deleteTarget){throw "$fs DELETE pathname still exists after exact handle cleanup."}

        & $helperExe map-write --file $mappedTarget | Out-Host
        if($LASTEXITCODE -ne 0){throw "$fs mapped-write helper failed, exit=$LASTEXITCODE"}

        $sessionRoot=Join-Path $store "Sessions\$session"
        $createCompletion=Join-Path $sessionRoot 'create-state\create-completion-journal.jsonl'
        $renameCompletion=Join-Path $sessionRoot 'rename-state\rename-completion-journal.jsonl'
        $truncateCompletion=Join-Path $sessionRoot 'truncate-state\truncate-completion-journal.jsonl'
        $deleteCompletion=Join-Path $sessionRoot 'delete-state\delete-completion-journal.jsonl'
        $deleteFinalization=Join-Path $sessionRoot 'delete-state\delete-finalization-journal.jsonl'
        $sectionJournal=Join-Path $sessionRoot 'section-state\writable-section-journal.jsonl'
        $pagingJournal=Join-Path $sessionRoot 'paging-state\paging-write-journal.jsonl'
        $rollbackJournal=Join-Path $sessionRoot 'journal.jsonl'

        $null=Wait-JournalMatch $createCompletion {
            param($x)
            [string]::Equals([IO.Path]::GetFullPath([string]$x.finalPath),$createTarget,[StringComparison]::OrdinalIgnoreCase) -and
            [int]$x.state -ne 5
        } 30 "$fs authoritative CREATE completion"

        $null=Wait-JournalMatch $renameCompletion {
            param($x)
            [string]::Equals([IO.Path]::GetFullPath([string]$x.finalDestinationPath),$renameDestination,[StringComparison]::OrdinalIgnoreCase) -and
            [int]$x.state -ne 5
        } 30 "$fs authoritative RENAME completion"

        $null=Wait-JournalMatch $truncateCompletion {
            param($x)
            [int64]$x.observedLength -eq 1024 -and [int]$x.state -ne 5
        } 30 "$fs authoritative TRUNCATE completion"

        $deleteCompletionRecord=Wait-JournalMatch $deleteCompletion {
            param($x)
            [int]$x.state -ne 1
        } 30 "$fs authoritative DELETE disposition completion"

        $null=Wait-JournalMatch $deleteFinalization {
            param($x)
            [uint64]$x.requestSequence -eq [uint64]$deleteCompletionRecord.requestSequence -and
            [int]$x.state -eq 1
        } 30 "$fs DELETE pathname finalization"

        $null=Wait-JournalMatch $sectionJournal {
            param($x)
            [int]$x.state -eq 1 -and
            [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),$mappedTarget,[StringComparison]::OrdinalIgnoreCase)
        } 30 "$fs writable-section evidence"

        $null=Wait-JournalMatch $pagingJournal {
            param($x)
            [uint64]$x.length -gt 0 -and
            [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),$mappedTarget,[StringComparison]::OrdinalIgnoreCase)
        } 30 "$fs paging-write evidence"

        $mappedCapture=Wait-JournalMatch $rollbackJournal {
            param($x)
            [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$mappedTarget,[StringComparison]::OrdinalIgnoreCase)
        } 30 "$fs mapped-write full pre-image"
        if(-not [string]::Equals([string]$mappedCapture.originalSha256,$mappedOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
            throw "$fs mapped-write pre-image hash mismatch."
        }

        return [pscustomobject][ordered]@{
            fileSystem=$fs
            supported=$true
            passed=$true
            volume=$volume
            root=$root
            createPassed=$true
            renamePassed=$true
            truncatePassed=$true
            deletePassed=$true
            mappedWritePassed=$true
            deleteDispositionState=[int]$deleteCompletionRecord.state
            cleanupPassed=$false
            error=$null
        }
    }
    catch{
        return [pscustomobject][ordered]@{
            fileSystem=$fs
            supported=$true
            passed=$false
            volume=$volume
            root=$root
            createPassed=$false
            renamePassed=$false
            truncatePassed=$false
            deletePassed=$false
            mappedWritePassed=$false
            deleteDispositionState=0
            cleanupPassed=$false
            error=$_.Exception.Message
        }
    }
    finally{
        try{Stop-LabProcess $gate "$fs GateClient"}catch{}
    }
}

Assert-Administrator
$vm=Assert-DisposableVm

if(-not(Get-Command Format-Volume -ErrorAction SilentlyContinue)){
    throw 'Required Storage cmdlet Format-Volume is unavailable on the runtime VM.'
}
if(-not(Get-Command Get-Volume -ErrorAction SilentlyContinue)){
    throw 'Required Storage cmdlet Get-Volume is unavailable on the runtime VM.'
}
if(-not(Get-Command diskpart.exe -ErrorAction SilentlyContinue)){
    throw 'diskpart.exe is required for isolated VHD creation.'
}

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
if(-not $ScratchDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ScratchDirectory=Join-Path $base 'RansomGuard-Filesystem-Matrix-Scratch'
}
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-Filesystem-Matrix-Results'
}
$ScratchDirectory=Assert-SafeScratchPath $ScratchDirectory 'ScratchDirectory'
$ResultsDirectory=Assert-SafeScratchPath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ScratchDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$staleVhds=@(Get-ChildItem -LiteralPath $ScratchDirectory -Filter 'RansomGuard-*.vhd' -File -ErrorAction SilentlyContinue)
if($staleVhds.Count -gt 0){
    throw "STALE MATRIX STATE: scratch VHD file(s) remain from an earlier run: $($staleVhds.Name -join ', '). Revert the disposable VM checkpoint before retrying."
}
$staleVolumes=@(Get-Volume -ErrorAction SilentlyContinue | Where-Object {
    [string]$_.FileSystemLabel -in @('RGFSNTFS','RGFSREFS')
})
if($staleVolumes.Count -gt 0){
    throw "STALE MATRIX STATE: an RGFSNTFS/RGFSREFS scratch volume is still mounted. Revert the disposable VM checkpoint before retrying."
}

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Filesystem matrix dependency missing: $required"}
}

$summary=[ordered]@{
    schema=1
    version=(Get-Item -LiteralPath $gateExe).VersionInfo.FileVersion
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    vhdSizeMiB=$VhdSizeMiB
    ntfsAttempted=$false
    ntfsSupported=$false
    ntfsPassed=$false
    refsAttempted=$false
    refsSupported=$false
    refsPassed=$false
    refsUnsupportedReason=$null
    cleanupPassed=$true
    passed=$false
    scenarios=@()
    finishedUtc=$null
}

$activeVhd=$null
$runtimeFailure=$null
try{
    foreach($fs in @('NTFS','ReFS')){
        $attemptKey=$fs.ToLowerInvariant()+'Attempted'
        $supportedKey=$fs.ToLowerInvariant()+'Supported'
        $passedKey=$fs.ToLowerInvariant()+'Passed'
        $summary[$attemptKey]=$true

        $activeVhd=New-ScratchVhd $fs
        if(-not $activeVhd.Provisioned){
            throw "$fs scratch VHD provisioning failed: $($activeVhd.Reason)"
        }
        if(-not $activeVhd.Supported){
            $summary[$supportedKey]=$false
            if($fs -eq 'ReFS'){
                $summary.refsUnsupportedReason=[string]$activeVhd.Reason
                $summary.scenarios+=@([ordered]@{
                    fileSystem='ReFS'
                    supported=$false
                    passed=$false
                    volume=[string]$activeVhd.Volume
                    root=''
                    error=[string]$activeVhd.Reason
                })
                Remove-ScratchVhd $activeVhd
                $activeVhd=$null
                continue
            }
            throw "$fs scratch filesystem is required but could not be formatted: $($activeVhd.Reason)"
        }

        $summary[$supportedKey]=$true
        $scenario=$null
        $scenarioFailure=$null
        try{
            $scenario=Run-FileSystemScenario $activeVhd
            if($null -eq $scenario -or $scenario -is [Array] -or
               $scenario.PSObject.Properties.Name -notcontains 'passed'){
                throw "$fs filesystem matrix scenario must return exactly one structured result object."
            }
            $summary.scenarios+=@($scenario)
            $summary[$passedKey]=[bool]$scenario.passed
            if(-not $scenario.passed){
                throw "$fs filesystem matrix scenario failed: $($scenario.error)"
            }
        }
        catch{
            $scenarioFailure=$_
        }
        finally{
            try{
                & $unloadScript -Volume ([string]$activeVhd.Volume) | Out-Host
                if($null -ne $scenario -and $scenario -isnot [Array] -and
                   $scenario.PSObject.Properties.Name -contains 'cleanupPassed'){
                    $scenario.cleanupPassed=$true
                }
            }
            catch{
                $summary.cleanupPassed=$false
                throw "$fs minifilter unload failed before VHD detach: $($_.Exception.Message)"
            }
        }

        Remove-ScratchVhd $activeVhd
        $activeVhd=$null

        if($null -ne $scenarioFailure){
            throw $scenarioFailure
        }
    }

    $summary.passed=$summary.ntfsPassed -and
        $summary.refsAttempted -and
        ((-not $summary.refsSupported) -or $summary.refsPassed)
}
catch{
    $runtimeFailure=$_
    $summary.passed=$false
}
finally{
    if($activeVhd){
        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -ne 0){
            $summary.cleanupPassed=$false
            Write-Warning 'Filter Manager state could not be verified; leaving the scratch VHD attached for VM checkpoint recovery.'
        }
        elseif($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            $summary.cleanupPassed=$false
            Write-Warning 'RansomGuardMinifilter is still loaded; refusing to detach/delete the active scratch VHD. Revert the disposable VM checkpoint.'
        }
        else{
            try{Remove-ScratchVhd $activeVhd}catch{
                $summary.cleanupPassed=$false
                Write-Warning "VHD cleanup failed after confirmed minifilter unload: $($_.Exception.Message)"
            }
        }
    }
    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summaryPath=Join-Path $ResultsDirectory 'filesystem-matrix-result.json'
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
}

if($runtimeFailure){throw $runtimeFailure}
if(-not $summary.cleanupPassed){throw 'Filesystem matrix cleanup did not complete safely.'}
if(-not $summary.passed){throw 'Filesystem compatibility matrix did not satisfy its required invariants.'}

Write-Host "FILESYSTEM MATRIX LAB PASSED. NTFS=$($summary.ntfsPassed); ReFS supported=$($summary.refsSupported); ReFS passed=$($summary.refsPassed). Evidence: $ResultsDirectory" -ForegroundColor Green
