[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Reboot',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Reboot ARM harness must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: reboot campaign requires an obvious disposable VM. Detected: $vmText"
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

function Wait-Path([string]$Path,[System.Diagnostics.Process]$Process,[int]$Seconds,[string]$Description){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){return}
        if($Process.HasExited){throw "$Description process exited early. exit=$($Process.ExitCode)"}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description: $Path"
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

function Stop-LabProcess([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Description process pid=$($Process.Id)."}
}

function Prepare-GateRoot([string]$GateExe,[string]$Root){
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $output=@(& $GateExe --root $Root --prepare-root 2>&1)
    $exit=$LASTEXITCODE
    foreach($line in $output){Write-Host $line}
    if($exit -ne 0){throw "Gate root preparation failed for $Root, exit=$exit. Output: $($output -join [Environment]::NewLine)"}
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

function Write-DurableJson([string]$Path,$Value){
    $json=$Value | ConvertTo-Json -Depth 30
    $tmp=$Path+'.tmp'
    [IO.File]::WriteAllText($tmp,$json,[Text.UTF8Encoding]::new($false))
    $fs=[IO.FileStream]::new($tmp,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try{$fs.Flush($true)}finally{$fs.Dispose()}
    Move-Item -LiteralPath $tmp -Destination $Path -Force
    $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($Path+'.sha256',$hash,[Text.Encoding]::ASCII)
    $hf=[IO.FileStream]::new($Path+'.sha256',[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try{$hf.Flush($true)}finally{$hf.Dispose()}
    return $hash
}

Assert-Administrator
$vm=Assert-DisposableVm
if([string]::IsNullOrWhiteSpace($env:RG_WORKFLOW_SHA)){throw 'RG_WORKFLOW_SHA is required for exact reboot campaign binding.'}

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) 'RansomGuard-Reboot-Arm-Results'}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $RootBase,$ResultsDirectory -Force | Out-Null

$active=Join-Path $RootBase 'Active'
if(Test-Path -LiteralPath $active){
    throw "REFUSED: an existing reboot campaign is already armed or awaiting cleanup: $active"
}
New-Item -ItemType Directory -Path $active -Force | Out-Null

$root=Join-Path $active 'protected'
$store=Join-Path $active 'rollback-store'
$session='reboot-truncate'
$target=Join-Path $root 'truncate-across-reboot.bin'
$statePath=Join-Path $active 'reboot-arm-state.json'
$gateOut=Join-Path $ResultsDirectory 'reboot-arm-gate.out.log'
$gateErr=$gateOut+'.err'
$triggerOut=Join-Path $ResultsDirectory 'reboot-arm-trigger.out.log'
$triggerErr=$triggerOut+'.err'
$ready=Join-Path $ResultsDirectory 'truncate.ready'
$go=Join-Path $ResultsDirectory 'truncate.go'
$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$helperExe=Join-Path $LabReleaseDirectory 'MinifilterLab\RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.exe'
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
foreach($required in @($gateExe,$helperExe,$installScript,$unloadScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Reboot ARM dependency missing: $required"}
}

$originalLength=8192
$requestedLength=1024
$gate=$null
$trigger=$null
$installed=$false
$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    workflowSha=$env:RG_WORKFLOW_SHA
    bootUpUtc=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')
    completionLossObserved=$false
    truncateIntentDurable=$false
    truncateCompletionAbsent=$false
    truncateLengthChanged=$false
    preimageHashMatched=$false
    stateDurable=$false
    filterLeftLoadedForReboot=$false
    rebootRequired=$false
    passed=$false
    error=$null
}

try{
    $existing=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager before reboot ARM, exit=$LASTEXITCODE"}
    if($existing -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the disposable VM before arming reboot proof.'
    }

    Prepare-GateRoot $gateExe $root
    $bytes=New-Object byte[] $originalLength
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*19+71)%251)}
    [IO.File]::WriteAllBytes($target,$bytes)
    $originalHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    $installed=$true
    $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Out-Host

    $gate=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),
        '--store',(Quote-Arg $store),
        '--session',$session,
        '--drop-first-truncate-completion'
    ) $gateOut $gateErr
    Wait-LogPattern $gateOut 'LAB completion-loss injection\s+: ARMED for the first authoritative TRUNCATE result' $gate 45
    Wait-LogPattern $gateOut 'kernel gate ACTIVE' $gate 45

    $trigger=Start-LoggedProcess $helperExe @(
        'truncate-eof',
        '--file',(Quote-Arg $target),
        '--length',([string]$requestedLength),
        '--ready',(Quote-Arg $ready),
        '--go',(Quote-Arg $go)
    ) $triggerOut $triggerErr

    Wait-Path $ready $trigger 30 'TRUNCATE reboot trigger readiness'
    Wait-LogPattern $gateOut 'CreateResult\s+request=' $gate 30
    Set-Content -LiteralPath $go -Value 'go' -Encoding ASCII

    if(-not $trigger.WaitForExit(45000)){
        Stop-Process -Id $trigger.Id -Force -ErrorAction SilentlyContinue
        throw 'TRUNCATE reboot trigger did not return.'
    }
    if($trigger.ExitCode -ne 0){
        $err=if(Test-Path -LiteralPath $triggerErr){Get-Content -LiteralPath $triggerErr -Raw}else{''}
        throw "TRUNCATE must complete before result loss. exit=$($trigger.ExitCode). $err"
    }
    if(-not $gate.WaitForExit(30000)){
        Stop-Process -Id $gate.Id -Force -ErrorAction SilentlyContinue
        throw 'GateClient did not exit after dropping TRUNCATE completion.'
    }
    if($gate.ExitCode -ne 0){throw "GateClient completion-loss injection failed. exit=$($gate.ExitCode)"}

    $combined=(Get-Content -LiteralPath $gateOut -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+
        (Get-Content -LiteralPath $gateErr -Raw -ErrorAction SilentlyContinue)
    if($combined -notmatch 'LAB COMPLETION LOSS: intentionally dropping authoritative TRUNCATE result'){
        throw "GateClient did not prove the intended TRUNCATE result-loss point. Output: $combined"
    }
    $summary.completionLossObserved=$true

    if((Get-Item -LiteralPath $target).Length -ne $requestedLength){
        throw "TRUNCATE did not persist requested length $requestedLength before reboot."
    }
    $summary.truncateLengthChanged=$true

    $sessionRoot=Join-Path $store "Sessions\$session"
    $intentJournal=Join-Path $sessionRoot 'truncate-state\truncate-intent-journal.jsonl'
    $completionJournal=Join-Path $sessionRoot 'truncate-state\truncate-completion-journal.jsonl'
    $intents=@(Read-JsonLines $intentJournal)
    if($intents.Count -ne 1){throw "Expected exactly one durable TRUNCATE intent. Found $($intents.Count)."}
    $intent=$intents[0]
    if([uint64]$intent.requestSequence -eq 0 -or
       [uint32]$intent.fileInformationClass -ne 20 -or
       [int64]$intent.requestedLength -ne $requestedLength -or
       [int64]$intent.originalObservedLength -ne $originalLength -or
       -not [string]::Equals([IO.Path]::GetFullPath([string]$intent.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)){
        throw "Durable TRUNCATE intent mismatch: $($intent | ConvertTo-Json -Compress -Depth 20)"
    }
    $summary.truncateIntentDurable=$true

    $completions=@(Read-JsonLines $completionJournal)
    if($completions.Count -ne 0){throw "Authoritative TRUNCATE completion must be absent before reboot. Found $($completions.Count)."}
    $summary.truncateCompletionAbsent=$true

    $rollback=@(Read-JsonLines (Join-Path $sessionRoot 'journal.jsonl'))
    $capture=@($rollback | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.originalPath) -and
        [string]::Equals([IO.Path]::GetFullPath([string]$_.originalPath),$target,[StringComparison]::OrdinalIgnoreCase)
    })
    if($capture.Count -ne 1){throw "Expected exactly one durable full pre-image for reboot target. Found $($capture.Count)."}
    if(-not [string]::Equals([string]$capture[0].originalSha256,$originalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Reboot target pre-image SHA-256 mismatch before reboot.'
    }
    $summary.preimageHashMatched=$true

    $state=[ordered]@{
        schema=1
        phase='armed'
        workflowSha=$env:RG_WORKFLOW_SHA
        armedUtc=[DateTime]::UtcNow.ToString('o')
        bootUpUtc=$summary.bootUpUtc
        root=$root
        store=$store
        session=$session
        target=$target
        originalLength=$originalLength
        requestedLength=$requestedLength
        originalSha256=$originalHash
        requestSequence=[uint64]$intent.requestSequence
        originalFileIdHex=[string]$intent.originalFileIdHex
        preservationRecordSha256=[string]$intent.preservationRecordSha256
    }
    $stateHash=Write-DurableJson $statePath $state
    Copy-Item -LiteralPath $statePath,$($statePath+'.sha256') -Destination $ResultsDirectory -Force
    $summary.stateSha256=$stateHash
    $summary.stateDurable=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'Reboot ARM expected the LAB minifilter to remain loaded until the VM reboot.'
    }
    $summary.filterLeftLoadedForReboot=$true
    $summary.rebootRequired=$true
    $summary.passed=$summary.completionLossObserved -and
        $summary.truncateIntentDurable -and
        $summary.truncateCompletionAbsent -and
        $summary.truncateLengthChanged -and
        $summary.preimageHashMatched -and
        $summary.stateDurable -and
        $summary.filterLeftLoadedForReboot
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    try{Stop-LabProcess $trigger 'TRUNCATE helper'}catch{}
    try{Stop-LabProcess $gate 'GateClient'}catch{}

    if(-not $summary.passed -and $installed){
        try{
            $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
            & $unloadScript -Volume $volume | Out-Host
        }catch{
            $summary.cleanupError=$_.Exception.Message
        }
    }

    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'reboot-arm-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Reboot ARM failed. error='$($summary.error)' cleanup='$($summary.cleanupError)' Evidence: $ResultsDirectory"
}

Write-Warning 'REBOOT REQUIRED: this successful ARM phase intentionally leaves RansomGuardMinifilter loaded. Reboot the disposable VM now, restart the self-hosted runner if needed, then run the VERIFY phase on the exact same commit. Do not use Re-run jobs for VERIFY.'
