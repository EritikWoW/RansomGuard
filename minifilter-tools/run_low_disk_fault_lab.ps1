[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Fault',
    [string]$ScratchDirectory='',
    [string]$ResultsDirectory='',
    [ValidateRange(512,2048)][int]$VhdSizeMiB=512,
    [ValidateRange(64,256)][int]$MinFreeMiB=64
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Low-disk fault harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: low-disk fault campaign requires an obvious disposable VM. Detected: $vmText"
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

function Stop-LabProcess([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Description process pid=$($Process.Id)."}
}

function Wait-LogPattern([string]$Path,[string]$Pattern,[System.Diagnostics.Process]$Process,[int]$Seconds){
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

function Get-FreeDriveLetter {
    $used=@([IO.DriveInfo]::GetDrives() | ForEach-Object {$_.Name.Substring(0,1).ToUpperInvariant()})
    foreach($letter in @('R','S','T','U','V','W','X','Y','Z','Q','P')){
        if($used -notcontains $letter){return $letter}
    }
    throw 'No free drive letter is available for the isolated low-disk VHD.'
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
        if($failed -and -not $AllowFailure){throw "DiskPart failed during $Description. exit=$($proc.ExitCode). Output: $combined"}
        return [pscustomobject]@{Succeeded=(-not $failed);ExitCode=$proc.ExitCode;Output=$combined}
    }
    finally{
        Remove-Item -LiteralPath $scriptPath,$stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

function New-LowDiskVhd {
    $letter=Get-FreeDriveLetter
    $vhdPath=Join-Path $ScratchDirectory ("RansomGuard-low-disk-{0}.vhd" -f [Guid]::NewGuid().ToString('N'))
    if(Test-Path -LiteralPath $vhdPath){throw "Refusing to overwrite existing VHD: $vhdPath"}

    $created=Invoke-DiskPartScript @(
        "create vdisk file=""$vhdPath"" maximum=$VhdSizeMiB type=expandable",
        "select vdisk file=""$vhdPath""",
        'attach vdisk',
        'create partition primary',
        "assign letter=$letter"
    ) 'create isolated low-disk VHD'

    if(-not $created.Succeeded){throw "Unable to provision isolated low-disk VHD: $($created.Output)"}
    $null=Format-Volume -DriveLetter $letter -FileSystem NTFS -NewFileSystemLabel 'RGLOWDISK' -Confirm:$false -Force -ErrorAction Stop
    $volumeInfo=Get-Volume -DriveLetter $letter -ErrorAction Stop
    if(-not [string]::Equals([string]$volumeInfo.FileSystem,'NTFS',[StringComparison]::OrdinalIgnoreCase)){
        throw "Low-disk VHD filesystem mismatch. actual=$($volumeInfo.FileSystem)"
    }

    return [pscustomobject]@{
        DriveLetter=$letter
        Volume=($letter + ':')
        Root=($letter + ':\')
        VhdPath=$vhdPath
    }
}

function Remove-LowDiskVhd($Vhd){
    if($null -eq $Vhd -or [string]::IsNullOrWhiteSpace([string]$Vhd.VhdPath)){return}
    if(-not(Test-Path -LiteralPath $Vhd.VhdPath)){return}
    $detach=Invoke-DiskPartScript @(
        "select vdisk file=""$($Vhd.VhdPath)""",
        'detach vdisk'
    ) 'detach isolated low-disk VHD' $true
    if(-not $detach.Succeeded){
        throw "REFUSED: low-disk VHD detach was not confirmed; leaving the VHD file intact for VM checkpoint recovery. Output: $($detach.Output)"
    }
    Remove-Item -LiteralPath $Vhd.VhdPath -Force -ErrorAction Stop
}

function Get-AvailableFree([string]$VolumeRoot){
    return ([IO.DriveInfo]::new($VolumeRoot)).AvailableFreeSpace
}

function Fill-ToLowFreeSpace([string]$VolumeRoot,[string]$FillerPath,[long]$TargetFreeBytes){
    $chunkSize=4MB
    $buffer=New-Object byte[] $chunkSize
    for($i=0;$i -lt $buffer.Length;$i+=4096){$buffer[$i]=[byte](($i/4096)%251)}
    $stream=[IO.FileStream]::new(
        $FillerPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read,
        $chunkSize,
        [IO.FileOptions]::WriteThrough)
    try{
        while((Get-AvailableFree $VolumeRoot) -gt ($TargetFreeBytes+$chunkSize)){
            $stream.Write($buffer,0,$buffer.Length)
        }
        $stream.Flush($true)
    }
    finally{$stream.Dispose()}
    return (Get-AvailableFree $VolumeRoot)
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

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $output=@(& $GateExe --root $Root --prepare-root 2>&1)
    $exit=$LASTEXITCODE
    foreach($line in $output){Write-Host $line}
    if($exit -ne 0){throw "Gate root preparation failed for $Root, exit=$exit. Output: $($output -join [Environment]::NewLine)"}
}

Assert-Administrator
$vm=Assert-DisposableVm

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ScratchDirectory){$ScratchDirectory=Join-Path ([IO.Path]::GetTempPath()) 'RansomGuard-LowDisk-Scratch'}
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) 'RansomGuard-LowDisk-Results'}
$ScratchDirectory=Assert-SafePath $ScratchDirectory 'ScratchDirectory'
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ScratchDirectory,$ResultsDirectory,$RootBase -Force | Out-Null

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Low-disk dependency missing: $required"}
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$root=Join-Path $RootBase "low-disk-$stamp"
$source=Join-Path $root 'rename-source.bin'
$destination=Join-Path $root 'rename-destination.bin'
$gateOut=Join-Path $ResultsDirectory 'gate.out.log'
$gateErr=$gateOut+'.err'
$denyOut=Join-Path $ResultsDirectory 'rename-denied.out.log'
$denyErr=Join-Path $ResultsDirectory 'rename-denied.err.log'
$retryOut=Join-Path $ResultsDirectory 'rename-retry.out.log'
$retryErr=Join-Path $ResultsDirectory 'rename-retry.err.log'
$vhd=$null
$gate=$null
$installed=$false
$filler=$null

$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    vhdSizeMiB=$VhdSizeMiB
    minFreeMiB=$MinFreeMiB
    freeBeforePressure=0
    freeUnderPressure=0
    freeAfterPressure=0
    failClosedObserved=$false
    sourcePreservedOnDenial=$false
    destinationAbsentOnDenial=$false
    budgetDenialObserved=$false
    gateStayedAlive=$false
    retryPassed=$false
    preimageHashMatched=$false
    cleanupPassed=$false
    passed=$false
    error=$null
    cleanupError=$null
}

try{
    $existing=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager before low-disk lab, exit=$LASTEXITCODE"}
    if($existing -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the disposable VM before low-disk testing.'
    }

    $vhd=New-LowDiskVhd
    $store=Join-Path $vhd.Root 'RansomGuard-LowDisk-Store'
    $session='low-disk'
    $sessionRoot=Join-Path $store "Sessions\$session"
    $filler=Join-Path $vhd.Root 'RansomGuard-low-disk-filler.bin'
    New-Item -ItemType Directory -Path $store -Force | Out-Null
    $summary.freeBeforePressure=Get-AvailableFree $vhd.Root

    Prepare-GateRoot $gateExe $root
    $bytes=New-Object byte[] (8MB)
    for($i=0;$i -lt $bytes.Length;$i+=4096){$bytes[$i]=[byte](($i/4096+37)%251)}
    [IO.File]::WriteAllBytes($source,$bytes)
    $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if(Test-Path -LiteralPath $destination){throw "Low-disk destination must start absent: $destination"}

    $installed=$true
    $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Out-Host

    $gate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--session',$session,
        '--gate-workers','4',
        '--max-store-mib','256',
        '--min-free-mib',([string]$MinFreeMiB)
    ) $gateOut $gateErr
    Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

    $targetFree=[long](($MinFreeMiB-16)*1MB)
    $summary.freeUnderPressure=Fill-ToLowFreeSpace $vhd.Root $filler $targetFree
    if($summary.freeUnderPressure -ge ([long]$MinFreeMiB*1MB)){
        throw "Unable to create low-disk condition. free=$($summary.freeUnderPressure) minFree=$([long]$MinFreeMiB*1MB)"
    }

    $denied=Start-LoggedProcess $helperExe @(
        'rename-file','--source',(Quote-Arg $source),'--destination',(Quote-Arg $destination)
    ) $denyOut $denyErr
    if(-not $denied.WaitForExit(45000)){
        Stop-Process -Id $denied.Id -Force -ErrorAction SilentlyContinue
        throw 'Low-disk rename probe timed out.'
    }
    if($denied.ExitCode -eq 0){throw 'Low-disk destructive rename unexpectedly succeeded.'}
    $summary.failClosedObserved=$true

    if(-not(Test-Path -LiteralPath $source -PathType Leaf)){
        throw 'Low-disk denial failed closed but source pathname disappeared.'
    }
    $summary.sourcePreservedOnDenial=$true
    if(Test-Path -LiteralPath $destination){throw 'Low-disk denial unexpectedly created rename destination.'}
    $summary.destinationAbsentOnDenial=$true

    $gateErrorText=if(Test-Path -LiteralPath $gateErr){Get-Content -LiteralPath $gateErr -Raw}else{''}
    if($gateErrorText -notmatch 'Rollback storage budget denied rename-source-preimage'){
        throw "GateClient did not attribute the fail-closed denial to rollback storage pressure. Error log: $gateErrorText"
    }
    $summary.budgetDenialObserved=$true

    if($gate.HasExited){throw "GateClient exited during low-disk denial. exit=$($gate.ExitCode)"}
    $summary.gateStayedAlive=$true

    Remove-Item -LiteralPath $filler -Force -ErrorAction Stop
    $filler=$null
    $summary.freeAfterPressure=Get-AvailableFree $vhd.Root
    if($summary.freeAfterPressure -le ([long]($MinFreeMiB+32)*1MB)){
        throw "Low-disk pressure did not recover enough free space for retry. free=$($summary.freeAfterPressure)"
    }

    $retry=Start-LoggedProcess $helperExe @(
        'rename-file','--source',(Quote-Arg $source),'--destination',(Quote-Arg $destination)
    ) $retryOut $retryErr
    if(-not $retry.WaitForExit(45000)){
        Stop-Process -Id $retry.Id -Force -ErrorAction SilentlyContinue
        throw 'Post-pressure rename retry timed out.'
    }
    if($retry.ExitCode -ne 0){
        $err=if(Test-Path -LiteralPath $retryErr){Get-Content -LiteralPath $retryErr -Raw}else{''}
        throw "Post-pressure rename retry failed, exit=$($retry.ExitCode). $err"
    }
    if((Test-Path -LiteralPath $source) -or -not(Test-Path -LiteralPath $destination -PathType Leaf)){
        throw 'Post-pressure rename topology mismatch.'
    }
    $summary.retryPassed=$true

    $deadline=(Get-Date).AddSeconds(20)
    $capture=$null
    while((Get-Date) -lt $deadline -and $null -eq $capture){
        $journal=Join-Path $sessionRoot 'journal.jsonl'
        foreach($record in @(Read-JsonLines $journal)){
            if(-not [string]::IsNullOrWhiteSpace([string]$record.originalPath) -and
               [string]::Equals([IO.Path]::GetFullPath([string]$record.originalPath),$source,[StringComparison]::OrdinalIgnoreCase)){
                $capture=$record
                break
            }
        }
        if($null -eq $capture){Start-Sleep -Milliseconds 150}
    }
    if($null -eq $capture){throw 'Post-pressure retry did not commit the source full pre-image.'}
    if(-not [string]::Equals([string]$capture.originalSha256,$sourceHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "Post-pressure source pre-image SHA-256 mismatch. expected=$sourceHash actual=$($capture.originalSha256)"
    }
    $summary.preimageHashMatched=$true

    $evidenceCopy=Join-Path $ResultsDirectory 'store-evidence'
    if(Test-Path -LiteralPath $evidenceCopy){Remove-Item -LiteralPath $evidenceCopy -Recurse -Force}
    Copy-Item -LiteralPath $sessionRoot -Destination $evidenceCopy -Recurse -Force

    $summary.passed=$summary.failClosedObserved -and
        $summary.sourcePreservedOnDenial -and
        $summary.destinationAbsentOnDenial -and
        $summary.budgetDenialObserved -and
        $summary.gateStayedAlive -and
        $summary.retryPassed -and
        $summary.preimageHashMatched
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    try{Stop-LabProcess $gate 'GateClient'}catch{}
    if($filler -and (Test-Path -LiteralPath $filler)){
        Remove-Item -LiteralPath $filler -Force -ErrorAction SilentlyContinue
    }
    if($installed){
        try{
            $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
            & $unloadScript -Volume $volume | Out-Host
        }catch{
            $summary.cleanupError=$_.Exception.Message
        }
    }
    try{
        Remove-LowDiskVhd $vhd
    }catch{
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){$summary.cleanupError=$_.Exception.Message}
        else{$summary.cleanupError+=' | '+$_.Exception.Message}
    }
    $summary.cleanupPassed=[string]::IsNullOrWhiteSpace([string]$summary.cleanupError)
    if(-not $summary.cleanupPassed){$summary.passed=$false}
    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'low-disk-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Low-disk fault campaign failed. error='$($summary.error)' cleanup='$($summary.cleanupError)' Evidence: $ResultsDirectory"
}

Write-Host "LOW-DISK FAULT LAB PASSED. denied under reserve, source preserved, retry succeeded with hash-verified pre-image. Evidence: $ResultsDirectory" -ForegroundColor Green
