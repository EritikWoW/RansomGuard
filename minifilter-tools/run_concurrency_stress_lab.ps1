[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Stress',
    [string]$ResultsDirectory='',
    [ValidateRange(9,32)][int]$Parallelism=16
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Concurrency stress harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: concurrency stress requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
    }
    return $vmText
}

function Assert-SafeRoot([string]$Path,[string]$Label){
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

    $root=[IO.Path]::GetPathRoot($full)
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
        throw "Timed out stopping $Description process pid=$($Process.Id)."
    }
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
            $errPath=$Path+'.err'
            $err=if(Test-Path -LiteralPath $errPath){Get-Content -LiteralPath $errPath -Raw}else{''}
            throw "Process exited before expected log pattern '$Pattern'. Exit=$($Process.ExitCode). $err"
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for log pattern '$Pattern'."
}

function Wait-AllPaths([string[]]$Paths,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $missing=@($Paths | Where-Object {-not(Test-Path -LiteralPath $_)})
        if($missing.Count -eq 0){return}
        Start-Sleep -Milliseconds 100
    }
    $stillMissing=@($Paths | Where-Object {-not(Test-Path -LiteralPath $_)})
    throw "Timed out waiting for $Description. Missing=$($stillMissing -join ', ')"
}

function Assert-GateWorkersHealthy([string]$ErrorPath){
    if(-not(Test-Path -LiteralPath $ErrorPath -PathType Leaf)){return}
    $text=Get-Content -LiteralPath $ErrorPath -Raw -ErrorAction SilentlyContinue
    if($text -match 'Gate worker failed:'){
        throw "GateClient worker failure detected during concurrency stress: $text"
    }
}

function Wait-DeleteFinalizations(
    [string]$JournalPath,
    [string[]]$Targets,
    [System.Diagnostics.Process]$GateProcess,
    [string]$GateErrorPath,
    [int]$Seconds
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        Assert-GateWorkersHealthy $GateErrorPath
        if($GateProcess.HasExited){
            throw "GateClient exited while waiting for durable DELETE topology finalization. exit=$($GateProcess.ExitCode)"
        }

        if(Test-Path -LiteralPath $JournalPath -PathType Leaf){
            $records=@()
            try{$records=Read-JsonLines $JournalPath 'DELETE finalization'}
            catch{
                Start-Sleep -Milliseconds 100
                continue
            }

            $missing=@()
            foreach($target in $Targets){
                $key=Path-Key $target
                $found=@($records | Where-Object {
                    [int]$_.state -eq 1 -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.originalPath) -and
                    (Path-Key ([string]$_.originalPath)) -eq $key
                })
                if($found.Count -lt 1){$missing+=@($target)}
            }
            if($missing.Count -eq 0){return}
        }
        Start-Sleep -Milliseconds 100
    }

    Assert-GateWorkersHealthy $GateErrorPath
    throw "Timed out waiting for durable DeletedObserved finalization for all DELETE targets."
}

function Wait-StressGroup([object[]]$Group,[int]$Seconds,[string]$Phase){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $running=@($Group | Where-Object {-not $_.Process.HasExited})
        if($running.Count -eq 0){break}
        Start-Sleep -Milliseconds 100
    }

    $still=@($Group | Where-Object {-not $_.Process.HasExited})
    if($still.Count -gt 0){
        foreach($item in $still){
            Stop-Process -Id $item.Process.Id -Force -ErrorAction SilentlyContinue
        }
        throw "$Phase stress timed out with $($still.Count) helper process(es) still running."
    }

    $failed=@($Group | Where-Object {$_.Process.ExitCode -ne 0})
    if($failed.Count -gt 0){
        $details=@()
        foreach($item in $failed){
            $err=if(Test-Path -LiteralPath $item.Err){Get-Content -LiteralPath $item.Err -Raw}else{''}
            $details+=("$($item.Name):exit=$($item.Process.ExitCode):$err")
        }
        throw "$Phase stress helper failures: $($details -join ' | ')"
    }
}

function Wait-StressGroupAllowAccessDenied([object[]]$Group,[int]$Seconds,[string]$Phase){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $running=@($Group | Where-Object {-not $_.Process.HasExited})
        if($running.Count -eq 0){break}
        Start-Sleep -Milliseconds 100
    }

    $still=@($Group | Where-Object {-not $_.Process.HasExited})
    if($still.Count -gt 0){
        foreach($item in $still){
            Stop-Process -Id $item.Process.Id -Force -ErrorAction SilentlyContinue
        }
        throw "$Phase admission probe timed out with $($still.Count) helper process(es) still running."
    }

    $allowed=@()
    $denied=@()
    $unexpected=@()
    foreach($item in $Group){
        if($item.Process.ExitCode -eq 0){
            $allowed+=@($item)
            continue
        }

        $err=if(Test-Path -LiteralPath $item.Err){Get-Content -LiteralPath $item.Err -Raw}else{''}
        if($item.Process.ExitCode -eq 20 -and
           $err -match 'Win32Error:\s*5' -and
           $err -match 'CreateFileW\(CREATE_NEW\) failed'){
            $denied+=@($item)
            continue
        }

        $unexpected+=("$($item.Name):exit=$($item.Process.ExitCode):$err")
    }

    if($unexpected.Count -gt 0){
        throw "$Phase admission probe had unexpected helper failures: $($unexpected -join ' | ')"
    }

    return [pscustomobject]@{
        Allowed=@($allowed)
        Denied=@($denied)
    }
}

function Start-Helper([string]$Name,[string[]]$Arguments){
    $safeName=$Name -replace '[^A-Za-z0-9_.-]','_'
    $out=Join-Path $ResultsDirectory ("helper-$safeName.out.log")
    $err=Join-Path $ResultsDirectory ("helper-$safeName.err.log")
    $process=Start-LoggedProcess $helperExe $Arguments $out $err
    return [pscustomobject]@{Name=$Name;Process=$process;Out=$out;Err=$err}
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $output=@(& $GateExe --root $Root --prepare-root 2>&1)
    $exit=$LASTEXITCODE
    foreach($line in $output){Write-Host $line}
    if($exit -ne 0){
        throw "Gate root preparation failed for $Root, exit=$exit. Output: $($output -join [Environment]::NewLine)"
    }
}

function New-TestFile([string]$Path,[int]$Length=65536,[int]$Salt=0){
    $parent=Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes=New-Object byte[] $Length
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*31+17+$Salt)%251)}
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Read-JsonLines([string]$Path,[string]$Description){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){
        throw "Missing $Description journal: $Path"
    }
    $items=@()
    foreach($line in Get-Content -LiteralPath $Path){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{$items+=@($line | ConvertFrom-Json -Depth 40)}
        catch{throw "Invalid JSON in $Description journal '$Path': $($_.Exception.Message)"}
    }
    return @($items)
}

function Path-Key([string]$Path){
    return [IO.Path]::GetFullPath($Path).ToUpperInvariant()
}

function Nt-Success($Status){
    $value=[uint64]$Status
    return (($value -band 0x80000000L) -eq 0)
}

function Assert-RequestUnique([object[]]$Records,[string]$Description){
    $ids=@($Records | ForEach-Object {[uint64]$_.requestSequence})
    if($ids.Count -ne @($ids | Sort-Object -Unique).Count){
        throw "$Description contains duplicate requestSequence values."
    }
}

function Assert-NoPendingTransactions(
    [object[]]$Intents,
    [object[]]$Completions,
    [string]$Description
){
    $completionIds=@($Completions | ForEach-Object {[uint64]$_.requestSequence})
    foreach($intent in $Intents){
        $request=[uint64]$intent.requestSequence
        if(@($completionIds | Where-Object {$_ -eq $request}).Count -ne 1){
            throw "$Description has an intent without exactly one authoritative completion: request=$request"
        }
    }
    foreach($completion in $Completions){
        $request=[uint64]$completion.requestSequence
        if(@($Intents | Where-Object {[uint64]$_.requestSequence -eq $request}).Count -ne 1){
            throw "$Description has an orphan completion without exactly one durable intent: request=$request"
        }
    }
}

function Assert-CreateEvidence([string[]]$Targets,[object[]]$Intents,[object[]]$Completions){
    foreach($target in $Targets){
        $key=Path-Key $target
        $intent=@($Intents | Where-Object {(Path-Key ([string]$_.originalPath)) -eq $key})
        if($intent.Count -ne 1){throw "CREATE stress target must have exactly one intent: $target; found=$($intent.Count)"}
        $request=[uint64]$intent[0].requestSequence
        $completion=@($Completions | Where-Object {
            [uint64]$_.requestSequence -eq $request -and
            -not [string]::IsNullOrWhiteSpace([string]$_.finalPath) -and
            (Path-Key ([string]$_.finalPath)) -eq $key
        })
        if($completion.Count -ne 1 -or -not(Nt-Success $completion[0].completionStatus)){
            throw "CREATE stress completion is missing/failed for $target request=$request"
        }
    }
}

function Assert-OverflowDeniedEvidence(
    [string[]]$Targets,
    [object[]]$Intents,
    [object[]]$Completions
){
    foreach($target in $Targets){
        if(Test-Path -LiteralPath $target){
            throw "Admission-overflow target must remain absent after fail-closed denial: $target"
        }
        $key=Path-Key $target
        $intent=@($Intents | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.originalPath) -and
            (Path-Key ([string]$_.originalPath)) -eq $key
        })
        if($intent.Count -ne 0){
            throw "Admission-overflow denial unexpectedly reached durable CREATE intent handling: $target"
        }
        $completion=@($Completions | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.finalPath) -and
            (Path-Key ([string]$_.finalPath)) -eq $key
        })
        if($completion.Count -ne 0){
            throw "Admission-overflow denial unexpectedly produced CREATE completion evidence: $target"
        }
    }
}

function Assert-RenameEvidence(
    [string[]]$Sources,
    [string[]]$Destinations,
    [object[]]$Intents,
    [object[]]$Completions
){
    for($i=0;$i -lt $Sources.Count;$i++){
        $sourceKey=Path-Key $Sources[$i]
        $destinationKey=Path-Key $Destinations[$i]
        $intent=@($Intents | Where-Object {
            (Path-Key ([string]$_.sourcePath)) -eq $sourceKey -and
            (Path-Key ([string]$_.destinationPath)) -eq $destinationKey
        })
        if($intent.Count -ne 1){throw "RENAME stress pair must have exactly one intent: $($Sources[$i]) -> $($Destinations[$i]); found=$($intent.Count)"}
        $request=[uint64]$intent[0].requestSequence
        $completion=@($Completions | Where-Object {
            [uint64]$_.requestSequence -eq $request -and
            -not [string]::IsNullOrWhiteSpace([string]$_.finalDestinationPath) -and
            (Path-Key ([string]$_.finalDestinationPath)) -eq $destinationKey
        })
        if($completion.Count -ne 1 -or -not(Nt-Success $completion[0].completionStatus)){
            throw "RENAME stress completion is missing/failed for request=$request"
        }
    }
}

function Assert-TruncateEvidence([string[]]$Targets,[object[]]$Intents,[object[]]$Completions){
    foreach($target in $Targets){
        $key=Path-Key $target
        $intent=@($Intents | Where-Object {
            (Path-Key ([string]$_.originalPath)) -eq $key -and
            [int64]$_.requestedLength -eq 1024
        })
        if($intent.Count -ne 1){throw "TRUNCATE stress target must have exactly one matching intent: $target; found=$($intent.Count)"}
        $request=[uint64]$intent[0].requestSequence
        $completion=@($Completions | Where-Object {[uint64]$_.requestSequence -eq $request})
        if($completion.Count -ne 1 -or -not(Nt-Success $completion[0].completionStatus) -or
           [int64]$completion[0].observedLength -ne 1024){
            throw "TRUNCATE stress completion is missing/failed for $target request=$request"
        }
    }
}

function Assert-DeleteEvidence(
    [string[]]$Targets,
    [object[]]$Intents,
    [object[]]$Completions,
    [object[]]$Finalizations
){
    foreach($target in $Targets){
        $key=Path-Key $target
        $intent=@($Intents | Where-Object {
            (Path-Key ([string]$_.originalPath)) -eq $key -and $_.requestDelete -eq $true
        })
        if($intent.Count -ne 1){throw "DELETE stress target must have exactly one delete intent: $target; found=$($intent.Count)"}
        $request=[uint64]$intent[0].requestSequence
        $completion=@($Completions | Where-Object {[uint64]$_.requestSequence -eq $request})
        if($completion.Count -ne 1 -or -not(Nt-Success $completion[0].completionStatus) -or
           [int]$completion[0].state -eq 1){
            throw "DELETE stress disposition completion is missing/failed for $target request=$request"
        }
        $deleted=@($Finalizations | Where-Object {
            [uint64]$_.requestSequence -eq $request -and [int]$_.state -eq 1
        })
        if($deleted.Count -lt 1){
            throw "DELETE stress target has no durable DeletedObserved finalization: $target request=$request"
        }
    }
}

function Assert-MappedEvidence(
    [string[]]$Targets,
    [object[]]$Rollback,
    [object[]]$Sections,
    [object[]]$Paging,
    [string]$SessionRoot
){
    foreach($target in $Targets){
        $key=Path-Key $target
        $capture=@($Rollback | Where-Object {(Path-Key ([string]$_.originalPath)) -eq $key})
        if($capture.Count -ne 1){throw "Mapped stress target must have exactly one full pre-image record: $target; found=$($capture.Count)"}

        $snapshot=Join-Path $SessionRoot ([string]$capture[0].snapshotRelativePath)
        if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){
            throw "Mapped stress pre-image object is missing: $snapshot"
        }
        $actualHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
        if(-not [string]::Equals($actualHash,[string]$capture[0].originalSha256,[StringComparison]::OrdinalIgnoreCase)){
            throw "Mapped stress pre-image SHA-256 mismatch for $target"
        }

        $section=@($Sections | Where-Object {
            (Path-Key ([string]$_.trackedPath)) -eq $key -and [int]$_.state -eq 1
        })
        if($section.Count -lt 1){throw "Mapped stress target has no BaselineVerified writable-section evidence: $target"}

        $page=@($Paging | Where-Object {
            (Path-Key ([string]$_.trackedPath)) -eq $key -and [uint64]$_.length -gt 0
        })
        if($page.Count -lt 1){throw "Mapped stress target has no paging-write evidence: $target"}
    }
}

Assert-Administrator
$vm=Assert-DisposableVm

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=Assert-SafeRoot $RootBase 'RootBase'
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-Concurrency-Stress-Results'
}
$ResultsDirectory=Assert-SafeRoot $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Stress dependency missing: $required"}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$root=Join-Path $RootBase ("stress-$stamp")
$store=Join-Path $ResultsDirectory 'stress-store'
$session='concurrency-stress'
$sessionRoot=Join-Path $store "Sessions\$session"
$gateOut=Join-Path $ResultsDirectory 'gate.out.log'
$gateErr=$gateOut+'.err'
$drive=[IO.Path]::GetPathRoot($root).TrimEnd('\')
$gate=$null
$installed=$false
$allHelpers=New-Object System.Collections.Generic.List[object]

$summary=[ordered]@{
    schema=1
    version=(Get-Item -LiteralPath $gateExe).VersionInfo.FileVersion
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    parallelism=$Parallelism
    gateWorkers=8
    kernelGateCap=8
    qualificationParallelism=8
    admissionOverflowPassed=$false
    overflowRounds=0
    overflowAllowed=0
    overflowDenied=0
    createPassed=$false
    renamePassed=$false
    truncatePassed=$false
    deletePassed=$false
    mappedWritePassed=$false
    transactionCorrelationPassed=$false
    noPendingTransactionsPassed=$false
    preimageHashPassed=$false
    gateStayedAlive=$false
    gateWorkersHealthyPassed=$false
    cleanupPassed=$false
    passed=$false
    error=$null
    cleanupError=$null
    root=$root
    store=$store
    finishedUtc=$null
}

try{
    if(Test-Path -LiteralPath $store){
        Remove-Item -LiteralPath $store -Recurse -Force
    }
    New-Item -ItemType Directory -Path $root,$store -Force | Out-Null
    Prepare-GateRoot $gateExe $root

    $overflowAllowedTargets=@()
    $overflowDeniedTargets=@()
    $createTargets=@()
    $renameSources=@()
    $renameDestinations=@()
    $truncateTargets=@()
    $deleteTargets=@()
    $mappedTargets=@()
    $qualificationParallelism=8

    for($i=0;$i -lt $qualificationParallelism;$i++){
        $createTargets+=Join-Path $root ("create-{0:D2}.bin" -f $i)

        $renameSource=Join-Path $root ("rename-source-{0:D2}.bin" -f $i)
        $renameDestination=Join-Path $root ("rename-destination-{0:D2}.bin" -f $i)
        New-TestFile $renameSource 65536 (100+$i)
        $renameSources+=$renameSource
        $renameDestinations+=$renameDestination

        $truncate=Join-Path $root ("truncate-{0:D2}.bin" -f $i)
        New-TestFile $truncate 65536 (200+$i)
        $truncateTargets+=$truncate

        $delete=Join-Path $root ("delete-{0:D2}.bin" -f $i)
        New-TestFile $delete 65536 (300+$i)
        $deleteTargets+=$delete

        $mapped=Join-Path $root ("mapped-{0:D2}.bin" -f $i)
        New-TestFile $mapped 65536 (400+$i)
        $mappedTargets+=$mapped
    }

    & $installScript -Volume $drive -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Out-Host
    $installed=$true

    $gate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--session',$session,
        '--gate-workers','8',
        '--max-store-mib','1024',
        '--min-free-mib','64'
    ) $gateOut $gateErr
    Wait-LogPattern $gateOut 'Bounded gate workers\s*:\s*8' $gate 45
    Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

    $overflowRound=0
    while($overflowRound -lt 3 -and $overflowDeniedTargets.Count -eq 0){
        $overflowRound++
        $group=@()
        $roundTargets=@()
        $ready=@()
        $goPath=Join-Path $ResultsDirectory ("overflow-r{0:D2}.go" -f $overflowRound)
        Remove-Item -LiteralPath $goPath -Force -ErrorAction SilentlyContinue
        for($i=0;$i -lt $Parallelism;$i++){
            $target=Join-Path $root ("overflow-r{0:D2}-{1:D2}.bin" -f $overflowRound,$i)
            $readyPath=Join-Path $ResultsDirectory ("overflow-r{0:D2}-{1:D2}.ready" -f $overflowRound,$i)
            $roundTargets+=@($target)
            $ready+=@($readyPath)
            $item=Start-Helper ("overflow-r{0:D2}-{1:D2}" -f $overflowRound,$i) @(
                'create-new','--file',(Quote-Arg $target),
                '--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
            $group+=@($item)
            $allHelpers.Add($item)
        }

        Wait-AllPaths $ready 45 'all CREATE overflow helpers to reach the shared start barrier'
        Set-Content -LiteralPath $goPath -Value 'go' -Encoding ASCII
        $probe=Wait-StressGroupAllowAccessDenied $group 60 'CREATE overflow'
        for($i=0;$i -lt $group.Count;$i++){
            $item=$group[$i]
            $target=$roundTargets[$i]
            if($item.Process.ExitCode -eq 0){
                if(-not(Test-Path -LiteralPath $target -PathType Leaf)){
                    throw "Admission probe helper succeeded but CREATE target is missing: $target"
                }
                $overflowAllowedTargets+=@($target)
            }else{
                if(Test-Path -LiteralPath $target){
                    throw "Admission probe helper was denied but target exists: $target"
                }
                $overflowDeniedTargets+=@($target)
            }
        }
        $summary.overflowRounds=$overflowRound
    }

    if($overflowDeniedTargets.Count -lt 1){
        throw "Admission overflow probe did not observe a fail-closed denial after $($summary.overflowRounds) round(s) at parallelism=$Parallelism."
    }
    $summary.overflowAllowed=$overflowAllowedTargets.Count
    $summary.overflowDenied=$overflowDeniedTargets.Count
    $summary.admissionOverflowPassed=$true

    $group=@()
    $ready=@()
    $goPath=Join-Path $ResultsDirectory 'create-qualification.go'
    Remove-Item -LiteralPath $goPath -Force -ErrorAction SilentlyContinue
    for($i=0;$i -lt $qualificationParallelism;$i++){
        $readyPath=Join-Path $ResultsDirectory ("create-{0:D2}.ready" -f $i)
        $ready+=@($readyPath)
        $item=Start-Helper ("create-{0:D2}" -f $i) @(
            'create-new','--file',(Quote-Arg $createTargets[$i]),
            '--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
        $group+=$item
        $allHelpers.Add($item)
    }
    Wait-AllPaths $ready 45 'all CREATE qualification helpers to reach the shared start barrier'
    Set-Content -LiteralPath $goPath -Value 'go' -Encoding ASCII
    Wait-StressGroup $group 60 'CREATE qualification'
    foreach($path in $createTargets){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "CREATE qualification target missing after helper success: $path"}
    }
    $summary.createPassed=$true

    $group=@()
    $ready=@()
    $goPath=Join-Path $ResultsDirectory 'rename-qualification.go'
    Remove-Item -LiteralPath $goPath -Force -ErrorAction SilentlyContinue
    for($i=0;$i -lt $qualificationParallelism;$i++){
        $readyPath=Join-Path $ResultsDirectory ("rename-{0:D2}.ready" -f $i)
        $ready+=@($readyPath)
        $item=Start-Helper ("rename-{0:D2}" -f $i) @(
            'rename-file','--source',(Quote-Arg $renameSources[$i]),
            '--destination',(Quote-Arg $renameDestinations[$i]),
            '--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
        $group+=$item
        $allHelpers.Add($item)
    }
    Wait-AllPaths $ready 45 'all RENAME qualification helpers to reach the shared start barrier'
    Set-Content -LiteralPath $goPath -Value 'go' -Encoding ASCII
    Wait-StressGroup $group 60 'RENAME'
    for($i=0;$i -lt $qualificationParallelism;$i++){
        if((Test-Path -LiteralPath $renameSources[$i]) -or
           -not(Test-Path -LiteralPath $renameDestinations[$i] -PathType Leaf)){
            throw "RENAME stress topology mismatch at index $i."
        }
    }
    $summary.renamePassed=$true

    $group=@()
    $ready=@()
    $go=@()
    for($i=0;$i -lt $qualificationParallelism;$i++){
        $readyPath=Join-Path $ResultsDirectory ("truncate-{0:D2}.ready" -f $i)
        $goPath=Join-Path $ResultsDirectory ("truncate-{0:D2}.go" -f $i)
        $ready+=$readyPath
        $go+=$goPath
        $item=Start-Helper ("truncate-{0:D2}" -f $i) @(
            'truncate-eof','--file',(Quote-Arg $truncateTargets[$i]),
            '--length','1024','--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
        $group+=$item
        $allHelpers.Add($item)
    }
    Wait-AllPaths $ready 30 'all TRUNCATE helpers to reach the barrier'
    foreach($marker in $go){Set-Content -LiteralPath $marker -Value 'go' -Encoding ASCII}
    Wait-StressGroup $group 60 'TRUNCATE'
    foreach($path in $truncateTargets){
        if((Get-Item -LiteralPath $path).Length -ne 1024){throw "TRUNCATE stress length mismatch: $path"}
    }
    $summary.truncatePassed=$true

    $group=@()
    $ready=@()
    $go=@()
    for($i=0;$i -lt $qualificationParallelism;$i++){
        $readyPath=Join-Path $ResultsDirectory ("delete-{0:D2}.ready" -f $i)
        $goPath=Join-Path $ResultsDirectory ("delete-{0:D2}.go" -f $i)
        $ready+=$readyPath
        $go+=$goPath
        $item=Start-Helper ("delete-{0:D2}" -f $i) @(
            'delete-file','--file',(Quote-Arg $deleteTargets[$i]),
            '--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
        $group+=$item
        $allHelpers.Add($item)
    }
    Wait-AllPaths $ready 30 'all DELETE helpers to reach the barrier'
    foreach($marker in $go){Set-Content -LiteralPath $marker -Value 'go' -Encoding ASCII}
    Wait-StressGroup $group 60 'DELETE'
    $deleteDeadline=(Get-Date).AddSeconds(15)
    while((Get-Date) -lt $deleteDeadline -and
          @($deleteTargets | Where-Object {Test-Path -LiteralPath $_}).Count -gt 0){
        Start-Sleep -Milliseconds 100
    }
    $remaining=@($deleteTargets | Where-Object {Test-Path -LiteralPath $_})
    if($remaining.Count -gt 0){throw "DELETE stress left pathname(s) present: $($remaining -join ', ')"}
    $deleteFinalizationJournal=Join-Path $sessionRoot 'delete-state\delete-finalization-journal.jsonl'
    Wait-DeleteFinalizations $deleteFinalizationJournal $deleteTargets $gate $gateErr 20
    $summary.deletePassed=$true

    $group=@()
    $ready=@()
    $goPath=Join-Path $ResultsDirectory 'mapped-qualification.go'
    Remove-Item -LiteralPath $goPath -Force -ErrorAction SilentlyContinue
    for($i=0;$i -lt $qualificationParallelism;$i++){
        $readyPath=Join-Path $ResultsDirectory ("mapped-{0:D2}.ready" -f $i)
        $ready+=@($readyPath)
        $item=Start-Helper ("mapped-{0:D2}" -f $i) @(
            'map-write','--file',(Quote-Arg $mappedTargets[$i]),
            '--ready',(Quote-Arg $readyPath),'--go',(Quote-Arg $goPath))
        $group+=$item
        $allHelpers.Add($item)
    }
    Wait-AllPaths $ready 45 'all MAPPED-WRITE qualification helpers to reach the shared start barrier'
    Set-Content -LiteralPath $goPath -Value 'go' -Encoding ASCII
    Wait-StressGroup $group 90 'MAPPED-WRITE'
    $summary.mappedWritePassed=$true

    if($gate.HasExited){throw "GateClient exited unexpectedly during concurrency stress. exit=$($gate.ExitCode)"}
    $summary.gateStayedAlive=$true
    Assert-GateWorkersHealthy $gateErr
    $summary.gateWorkersHealthyPassed=$true

    Start-Sleep -Milliseconds 1500

    $createIntents=Read-JsonLines (Join-Path $sessionRoot 'create-state\create-intent-journal.jsonl') 'CREATE intent'
    $createCompletions=Read-JsonLines (Join-Path $sessionRoot 'create-state\create-completion-journal.jsonl') 'CREATE completion'
    $renameIntents=Read-JsonLines (Join-Path $sessionRoot 'rename-state\rename-journal.jsonl') 'RENAME intent'
    $renameCompletions=Read-JsonLines (Join-Path $sessionRoot 'rename-state\rename-completion-journal.jsonl') 'RENAME completion'
    $truncateIntents=Read-JsonLines (Join-Path $sessionRoot 'truncate-state\truncate-intent-journal.jsonl') 'TRUNCATE intent'
    $truncateCompletions=Read-JsonLines (Join-Path $sessionRoot 'truncate-state\truncate-completion-journal.jsonl') 'TRUNCATE completion'
    $deleteIntents=Read-JsonLines (Join-Path $sessionRoot 'delete-state\delete-intent-journal.jsonl') 'DELETE intent'
    $deleteCompletions=Read-JsonLines (Join-Path $sessionRoot 'delete-state\delete-completion-journal.jsonl') 'DELETE completion'
    $deleteFinalizations=Read-JsonLines (Join-Path $sessionRoot 'delete-state\delete-finalization-journal.jsonl') 'DELETE finalization'
    $rollback=Read-JsonLines (Join-Path $sessionRoot 'journal.jsonl') 'rollback'
    $sections=Read-JsonLines (Join-Path $sessionRoot 'section-state\writable-section-journal.jsonl') 'writable-section'
    $paging=Read-JsonLines (Join-Path $sessionRoot 'paging-state\paging-write-journal.jsonl') 'paging-write'

    Assert-RequestUnique $createIntents 'CREATE intents'
    Assert-RequestUnique $createCompletions 'CREATE completions'
    Assert-RequestUnique $renameIntents 'RENAME intents'
    Assert-RequestUnique $renameCompletions 'RENAME completions'
    Assert-RequestUnique $truncateIntents 'TRUNCATE intents'
    Assert-RequestUnique $truncateCompletions 'TRUNCATE completions'
    Assert-RequestUnique $deleteIntents 'DELETE intents'
    Assert-RequestUnique $deleteCompletions 'DELETE completions'

    Assert-NoPendingTransactions $createIntents $createCompletions 'CREATE store'
    Assert-NoPendingTransactions $renameIntents $renameCompletions 'RENAME store'
    Assert-NoPendingTransactions $truncateIntents $truncateCompletions 'TRUNCATE store'
    Assert-NoPendingTransactions $deleteIntents $deleteCompletions 'DELETE disposition store'
    $summary.noPendingTransactionsPassed=$true

    $allSuccessfulCreateTargets=@($overflowAllowedTargets)+@($createTargets)
    Assert-CreateEvidence $allSuccessfulCreateTargets $createIntents $createCompletions
    Assert-OverflowDeniedEvidence $overflowDeniedTargets $createIntents $createCompletions
    Assert-RenameEvidence $renameSources $renameDestinations $renameIntents $renameCompletions
    Assert-TruncateEvidence $truncateTargets $truncateIntents $truncateCompletions
    Assert-DeleteEvidence $deleteTargets $deleteIntents $deleteCompletions $deleteFinalizations
    Assert-MappedEvidence $mappedTargets $rollback $sections $paging $sessionRoot

    $summary.transactionCorrelationPassed=$true
    $summary.preimageHashPassed=$true
    $summary.passed=$summary.admissionOverflowPassed -and
        $summary.createPassed -and $summary.renamePassed -and
        $summary.truncatePassed -and $summary.deletePassed -and
        $summary.mappedWritePassed -and $summary.transactionCorrelationPassed -and
        $summary.noPendingTransactionsPassed -and $summary.preimageHashPassed -and
        $summary.gateStayedAlive -and $summary.gateWorkersHealthyPassed
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    foreach($item in $allHelpers){
        try{Stop-LabProcess $item.Process $item.Name}catch{}
    }
    try{Stop-LabProcess $gate 'GateClient'}catch{}

    if($installed){
        try{
            & $unloadScript -Volume $drive | Out-Host
            $summary.cleanupPassed=$true
        }catch{
            $summary.cleanupPassed=$false
            $summary.cleanupError=$_.Exception.Message
        }
    }else{
        $summary.cleanupPassed=$true
    }

    if(-not $summary.cleanupPassed){$summary.passed=$false}
    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summaryPath=Join-Path $ResultsDirectory 'concurrency-stress-result.json'
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
}

if(-not $summary.passed){
    throw "Concurrency stress failed. error='$($summary.error)' cleanup='$($summary.cleanupError)' Evidence: $ResultsDirectory"
}

Write-Host "CONCURRENCY STRESS LAB PASSED. overflow-width=$Parallelism denied=$($summary.overflowDenied) allowed=$($summary.overflowAllowed); qualification-parallelism=8; gate-workers=8 kernel-cap=8. Evidence: $ResultsDirectory" -ForegroundColor Green
