[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Verifier',
    [string]$StressRootBase='C:\RansomGuard-VM-Verifier-Stress',
    [string]$ResultsDirectory='',
    [ValidateRange(9,32)][int]$Parallelism=16
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$TargetDriver='RansomGuardMinifilter.sys'
$StandardMask=[uint32]0x000209BB
$VerifierRegistry='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Driver Verifier runtime phase must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: Driver Verifier qualification requires an obvious disposable VM. Detected: $vmText"
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
    foreach($segment in $full.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
        $cursor=Join-Path $cursor $segment
        if(-not(Test-Path -LiteralPath $cursor)){break}
        if(((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point: $cursor"
        }
    }
    return $full
}

function Invoke-Verifier([string[]]$Arguments,[string]$Name){
    $stdout=Join-Path $ResultsDirectory ("verifier-{0}.out.txt" -f $Name)
    $stderr=Join-Path $ResultsDirectory ("verifier-{0}.err.txt" -f $Name)
    Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    $p=Start-Process -FilePath "$env:SystemRoot\System32\verifier.exe" -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if(-not $p.WaitForExit(60000)){
        try{$p.Kill($true)}catch{}
        throw "verifier.exe timed out during $Name."
    }
    $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
    $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
    return [pscustomobject]@{ExitCode=$p.ExitCode;Output=($out+[Environment]::NewLine+$err).Trim()}
}

function Get-VerifierRegistryState {
    $p=Get-ItemProperty -LiteralPath $VerifierRegistry -ErrorAction Stop
    $drivers=''
    $level=[uint32]0
    if($p.PSObject.Properties['VerifyDrivers']){$drivers=[string]$p.VerifyDrivers}
    if($p.PSObject.Properties['VerifyDriverLevel']){$level=[uint32]$p.VerifyDriverLevel}
    $tokens=@([regex]::Matches($drivers,'[^\s,;]+') | ForEach-Object {$_.Value})
    return [pscustomobject]@{Drivers=$drivers;DriverTokens=$tokens;Level=$level}
}

function Write-DurableJson([string]$Path,$Value){
    $tmp=$Path+'.tmp'
    $json=$Value | ConvertTo-Json -Depth 30
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

function Read-And-VerifyState([string]$StatePath){
    $hashPath=$StatePath+'.sha256'
    if(-not(Test-Path -LiteralPath $StatePath -PathType Leaf)){throw "Driver Verifier ARM state is missing: $StatePath"}
    if(-not(Test-Path -LiteralPath $hashPath -PathType Leaf)){throw "Driver Verifier ARM state hash is missing: $hashPath"}
    $expected=(Get-Content -LiteralPath $hashPath -Raw).Trim()
    $actual=(Get-FileHash -LiteralPath $StatePath -Algorithm SHA256).Hash
    if(-not [string]::Equals($expected,$actual,[StringComparison]::OrdinalIgnoreCase)){
        throw "Driver Verifier state SHA-256 mismatch. expected=$expected actual=$actual"
    }
    return [pscustomobject]@{State=(Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -Depth 30);Hash=$actual}
}

function Get-BugCheckEvents([DateTime]$SinceUtc){
    try{
        return @(
            Get-WinEvent -FilterHashtable @{
                LogName='System'
                ProviderName='Microsoft-Windows-WER-SystemErrorReporting'
                Id=1001
                StartTime=$SinceUtc.ToLocalTime()
            } -ErrorAction Stop
        )
    }catch{
        if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){return @()}
        if($_.Exception.Message -match '(?i)no events were found'){return @()}
        throw
    }
}

Assert-Administrator
$vm=Assert-DisposableVm
if([string]::IsNullOrWhiteSpace($env:RG_WORKFLOW_SHA)){throw 'RG_WORKFLOW_SHA is required for exact Driver Verifier commit binding.'}

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=Assert-SafePath $RootBase 'RootBase'
$StressRootBase=Assert-SafePath $StressRootBase 'StressRootBase'
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-Driver-Verifier-Runtime-Results'
}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ResultsDirectory,$StressRootBase -Force | Out-Null

$active=Join-Path $RootBase 'Active'
$statePath=Join-Path $active 'driver-verifier-state.json'
$verified=Read-And-VerifyState $statePath
$state=$verified.State
if([int]$state.schema -ne 1 -or [string]$state.phase -ne 'armed'){
    throw "Driver Verifier runtime requires an ARM state with phase=armed. Found schema='$($state.schema)' phase='$($state.phase)'."
}
if(-not [string]::Equals([string]$state.workflowSha,$env:RG_WORKFLOW_SHA,[StringComparison]::OrdinalIgnoreCase)){
    throw "Runtime commit '$env:RG_WORKFLOW_SHA' does not match ARM commit '$($state.workflowSha)'."
}
if(-not [string]::Equals([string]$state.targetDriver,$TargetDriver,[StringComparison]::OrdinalIgnoreCase)){
    throw "ARM target driver '$($state.targetDriver)' does not match '$TargetDriver'."
}

$armBoot=[DateTime]::Parse([string]$state.bootUpUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
$currentBoot=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime()
if($currentBoot -le $armBoot.AddSeconds(1)){
    throw "No reboot was observed between Driver Verifier ARM and runtime. armBoot=$($armBoot.ToString('o')) currentBoot=$($currentBoot.ToString('o'))"
}

$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'
$stressScript=Join-Path $PSScriptRoot 'run_concurrency_stress_lab.ps1'
foreach($required in @($installScript,$unloadScript,$stressScript)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Driver Verifier runtime dependency missing: $required"}
}

$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    workflowSha=$env:RG_WORKFLOW_SHA
    armStateSha256=$verified.Hash
    targetDriver=$TargetDriver
    armBootUtc=$armBoot.ToString('o')
    currentBootUtc=$currentBoot.ToString('o')
    bootChanged=$true
    standardSettingsPersisted=$false
    verifierObservedTargetLoaded=$false
    noBugcheckBeforeStress=$false
    stressPassed=$false
    noBugcheckAfterStress=$false
    resetCommandSucceeded=$false
    persistentSettingsCleared=$false
    resetStateDurable=$false
    rebootRequired=$false
    passed=$false
    error=$null
    cleanupError=$null
}

$probeLoaded=$false
$resetAttempted=$false
$stressResults=Join-Path $ResultsDirectory 'stress'
try{
    $reg=Get-VerifierRegistryState
    if($reg.DriverTokens.Count -ne 1 -or
       -not [string]::Equals([string]$reg.DriverTokens[0],$TargetDriver,[StringComparison]::OrdinalIgnoreCase)){
        throw "Driver Verifier target after reboot is not exactly '$TargetDriver'. VerifyDrivers='$($reg.Drivers)'."
    }
    if(($reg.Level -band $StandardMask) -ne $StandardMask){
        throw "Driver Verifier standard mask is incomplete after reboot. level=0x$('{0:X8}' -f $reg.Level)"
    }
    $summary.standardSettingsPersisted=$true

    $armedUtc=[DateTime]::Parse([string]$state.armedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $beforeBugchecks=@(Get-BugCheckEvents $armedUtc)
    if($beforeBugchecks.Count -ne 0){
        $beforeBugchecks | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'bugchecks-before-stress.json') -Encoding UTF8
        throw "A Windows bugcheck was recorded after Driver Verifier ARM and before stress. count=$($beforeBugchecks.Count)"
    }
    $summary.noBugcheckBeforeStress=$true

    $probeRoot=Join-Path $StressRootBase 'probe'
    New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
    $volume=[IO.Path]::GetPathRoot($probeRoot).TrimEnd('\')
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' | Out-Host
    $probeLoaded=$true

    $query=Invoke-Verifier @('/query') 'query-active-driver'
    if($query.ExitCode -ne 0){throw "verifier /query failed while target driver was loaded. exit=$($query.ExitCode). Output: $($query.Output)"}
    if($query.Output -notmatch [regex]::Escape($TargetDriver)){
        throw "Driver Verifier current activity did not name loaded target '$TargetDriver'. Output: $($query.Output)"
    }
    $summary.verifierObservedTargetLoaded=$true

    & $unloadScript -Volume $volume | Out-Host
    $probeLoaded=$false

    if(Test-Path -LiteralPath $stressResults){Remove-Item -LiteralPath $stressResults -Recurse -Force}
    New-Item -ItemType Directory -Path $stressResults -Force | Out-Null
    & $stressScript -LabReleaseDirectory $LabReleaseDirectory -DriverPackageDirectory $DriverPackageDirectory -RootBase $StressRootBase -ResultsDirectory $stressResults -Parallelism $Parallelism
    $stressSummary=Get-Content -LiteralPath (Join-Path $stressResults 'concurrency-stress-result.json') -Raw | ConvertFrom-Json
    foreach($name in @(
        'admissionOverflowPassed','createPassed','renamePassed','truncatePassed','deletePassed','mappedWritePassed',
        'transactionCorrelationPassed','noPendingTransactionsPassed','preimageHashPassed',
        'gateStayedAlive','gateWorkersHealthyPassed','cleanupPassed','passed'
    )){
        if($stressSummary.$name -ne $true){throw "Driver Verifier stress invariant '$name' was not true."}
    }
    if([int]$stressSummary.qualificationParallelism -ne 8 -or [int]$stressSummary.gateWorkers -ne 8 -or [int]$stressSummary.kernelGateCap -ne 8){
        throw 'Driver Verifier stress did not exercise the intended 8-worker/8-request qualification ceiling.'
    }
    if([int]$stressSummary.overflowDenied -lt 1){throw 'Driver Verifier stress did not observe fail-closed admission overflow.'}
    $summary.stressPassed=$true

    $afterBugchecks=@(Get-BugCheckEvents $armedUtc)
    if($afterBugchecks.Count -ne 0){
        $afterBugchecks | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'bugchecks-after-stress.json') -Encoding UTF8
        throw "A Windows bugcheck was recorded during the Driver Verifier qualification window. count=$($afterBugchecks.Count)"
    }
    $summary.noBugcheckAfterStress=$true
}
catch{
    $summary.error=$_.Exception.Message
}
finally{
    if($probeLoaded){
        try{
            $probeRoot=Join-Path $StressRootBase 'probe'
            $volume=[IO.Path]::GetPathRoot($probeRoot).TrimEnd('\')
            & $unloadScript -Volume $volume | Out-Host
        }catch{
            $summary.cleanupError=$_.Exception.Message
        }
    }

    try{
        $reset=Invoke-Verifier @('/reset') 'reset-after-runtime'
        $resetAttempted=$true
        if($reset.ExitCode -ne 0){throw "verifier /reset failed. exit=$($reset.ExitCode). Output: $($reset.Output)"}
        $summary.resetCommandSucceeded=$true

        $postReset=Get-VerifierRegistryState
        if($postReset.DriverTokens.Count -ne 0 -or $postReset.Level -ne 0){
            throw "Persistent Driver Verifier settings remain after /reset. VerifyDrivers='$($postReset.Drivers)' level=0x$('{0:X8}' -f $postReset.Level)."
        }
        $summary.persistentSettingsCleared=$true

        $querySettings=Invoke-Verifier @('/querysettings') 'querysettings-after-reset'
        if($querySettings.ExitCode -ne 0){throw "verifier /querysettings failed after reset. exit=$($querySettings.ExitCode). Output: $($querySettings.Output)"}
        if($querySettings.Output -match [regex]::Escape($TargetDriver)){
            throw "Scheduled Driver Verifier settings still name '$TargetDriver' after reset."
        }

        $newState=[ordered]@{
            schema=1
            phase=if($summary.stressPassed -and $summary.noBugcheckAfterStress){'runtime-reset'}else{'runtime-failed-reset'}
            workflowSha=$env:RG_WORKFLOW_SHA
            targetDriver=$TargetDriver
            standardMask=('0x{0:X8}' -f $StandardMask)
            armStateSha256=$verified.Hash
            armedUtc=[string]$state.armedUtc
            armBootUtc=$armBoot.ToString('o')
            runtimeBootUtc=$currentBoot.ToString('o')
            runtimeCompletedUtc=[DateTime]::UtcNow.ToString('o')
            stressPassed=[bool]$summary.stressPassed
            noBugcheckAfterStress=[bool]$summary.noBugcheckAfterStress
            resetScheduled=$true
        }
        $newHash=Write-DurableJson $statePath $newState
        Copy-Item -LiteralPath $statePath,$($statePath+'.sha256') -Destination $ResultsDirectory -Force
        $summary.resetStateSha256=$newHash
        $summary.resetStateDurable=$true
        $summary.rebootRequired=$true
    }catch{
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){$summary.cleanupError=$_.Exception.Message}
        else{$summary.cleanupError+=' | '+$_.Exception.Message}
    }

    $summary.passed=[string]::IsNullOrWhiteSpace([string]$summary.error) -and
        [string]::IsNullOrWhiteSpace([string]$summary.cleanupError) -and
        $summary.bootChanged -and
        $summary.standardSettingsPersisted -and
        $summary.verifierObservedTargetLoaded -and
        $summary.noBugcheckBeforeStress -and
        $summary.stressPassed -and
        $summary.noBugcheckAfterStress -and
        $summary.resetCommandSucceeded -and
        $summary.persistentSettingsCleared -and
        $summary.resetStateDurable

    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'driver-verifier-runtime-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Driver Verifier runtime failed. error='$($summary.error)' cleanup='$($summary.cleanupError)' resetAttempted=$resetAttempted Evidence: $ResultsDirectory"
}

Write-Warning "DRIVER VERIFIER RUNTIME PASSED under standard verification for $TargetDriver. verifier /reset is scheduled; reboot the disposable VM once more, then run the CLEAR phase to prove verification is disabled."
