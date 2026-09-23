[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-Verifier',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$TargetDriver='RansomGuardMinifilter.sys'
$StandardMask=[uint32]0x000209BB
$stageScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$VerifierRegistry='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Driver Verifier ARM must run as Administrator.'
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

function Assert-OnlyTargetDriver($State,[string]$Context){
    if($State.DriverTokens.Count -ne 1 -or
       -not [string]::Equals([string]$State.DriverTokens[0],$TargetDriver,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Context Driver Verifier target set is not exactly '$TargetDriver'. Raw VerifyDrivers='$($State.Drivers)'."
    }
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

Assert-Administrator
$vm=Assert-DisposableVm
if([string]::IsNullOrWhiteSpace($env:RG_WORKFLOW_SHA)){throw 'RG_WORKFLOW_SHA is required for exact Driver Verifier commit binding.'}
if(-not(Test-Path -LiteralPath "$env:SystemRoot\System32\verifier.exe" -PathType Leaf)){throw 'verifier.exe is not available.'}
if(-not(Test-Path -LiteralPath $stageScript -PathType Leaf)){throw "Driver staging helper missing: $stageScript"}
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
foreach($required in @('RansomGuardMinifilter.inf','RansomGuardMinifilter.sys','RansomGuardMinifilter.cat')){
    if(-not(Test-Path -LiteralPath (Join-Path $DriverPackageDirectory $required) -PathType Leaf)){
        throw "Driver Verifier ARM package file missing: $required"
    }
}

$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-Driver-Verifier-Arm-Results'
}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $RootBase,$ResultsDirectory -Force | Out-Null

$active=Join-Path $RootBase 'Active'
if(Test-Path -LiteralPath $active){
    throw "REFUSED: an existing Driver Verifier campaign is already active or awaiting cleanup: $active"
}

$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    workflowSha=$env:RG_WORKFLOW_SHA
    targetDriver=$TargetDriver
    standardMask=('0x{0:X8}' -f $StandardMask)
    cleanVerifierState=$false
    driverPackageRegistered=$false
    targetOnlyConfigured=$false
    standardFlagsConfigured=$false
    querySettingsConfirmed=$false
    oneBootCommandSucceeded=$false
    stateDurable=$false
    rebootRequired=$false
    passed=$false
    error=$null
    cleanupError=$null
}

$settingsModified=$false
try{
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager before Driver Verifier ARM, exit=$LASTEXITCODE"}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is loaded before Driver Verifier ARM. Unload it or revert the disposable VM checkpoint.'
    }

    $before=Get-VerifierRegistryState
    if($before.DriverTokens.Count -ne 0 -or $before.Level -ne 0){
        throw "REFUSED: Driver Verifier already has persistent settings. VerifyDrivers='$($before.Drivers)' VerifyDriverLevel=0x$('{0:X8}' -f $before.Level). Revert/clean the disposable VM instead of overwriting unrelated verifier state."
    }
    $summary.cleanVerifierState=$true

    New-Item -ItemType Directory -Path $active -Force | Out-Null
    $queryBefore=Invoke-Verifier @('/querysettings') 'querysettings-before'
    if($queryBefore.ExitCode -ne 0){throw "verifier /querysettings failed before ARM. exit=$($queryBefore.ExitCode). Output: $($queryBefore.Output)"}
    $preExistingDriverNames=@([regex]::Matches($queryBefore.Output,'(?i)\b[A-Za-z0-9_.-]+\.sys\b') | ForEach-Object {$_.Value} | Select-Object -Unique)
    if($preExistingDriverNames.Count -gt 0){
        throw "REFUSED: verifier /querysettings already names driver target(s): $($preExistingDriverNames -join ', '). Revert/clean the disposable VM instead of overwriting verifier state."
    }

    & $stageScript -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER' -StageOnly | Out-Host
    $filtersAfterStage=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager after Driver Verifier staging, exit=$LASTEXITCODE"}
    if($filtersAfterStage -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'StageOnly unexpectedly loaded RansomGuardMinifilter before Driver Verifier reboot.'
    }
    $summary.driverPackageRegistered=$true

    $configure=Invoke-Verifier @('/standard','/driver',$TargetDriver) 'configure-standard'
    if($configure.ExitCode -ne 0){throw "verifier /standard /driver $TargetDriver failed. exit=$($configure.ExitCode). Output: $($configure.Output)"}
    $settingsModified=$true

    $oneBoot=Invoke-Verifier @('/bootmode','oneboot') 'configure-oneboot'
    if($oneBoot.ExitCode -ne 0){throw "verifier /bootmode oneboot failed. exit=$($oneBoot.ExitCode). Output: $($oneBoot.Output)"}
    $summary.oneBootCommandSucceeded=$true

    $after=Get-VerifierRegistryState
    Assert-OnlyTargetDriver $after 'ARM'
    $summary.targetOnlyConfigured=$true
    if(($after.Level -band $StandardMask) -ne $StandardMask){
        throw "Driver Verifier standard mask is incomplete. level=0x$('{0:X8}' -f $after.Level) required=0x$('{0:X8}' -f $StandardMask)"
    }
    $summary.standardFlagsConfigured=$true
    $summary.verifyDriverLevel=('0x{0:X8}' -f $after.Level)

    $queryAfter=Invoke-Verifier @('/querysettings') 'querysettings-after'
    if($queryAfter.ExitCode -ne 0){throw "verifier /querysettings failed after ARM. exit=$($queryAfter.ExitCode). Output: $($queryAfter.Output)"}
    if($queryAfter.Output -notmatch [regex]::Escape($TargetDriver)){
        throw "verifier /querysettings did not name the exact target driver '$TargetDriver'. Output: $($queryAfter.Output)"
    }
    $summary.querySettingsConfirmed=$true

    $bootUtc=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime()
    $state=[ordered]@{
        schema=1
        phase='armed'
        workflowSha=$env:RG_WORKFLOW_SHA
        targetDriver=$TargetDriver
        standardMask=('0x{0:X8}' -f $StandardMask)
        verifyDriverLevel=('0x{0:X8}' -f $after.Level)
        armedUtc=[DateTime]::UtcNow.ToString('o')
        bootUpUtc=$bootUtc.ToString('o')
        bootMode='oneboot'
    }
    $statePath=Join-Path $active 'driver-verifier-state.json'
    $stateHash=Write-DurableJson $statePath $state
    Copy-Item -LiteralPath $statePath,$($statePath+'.sha256') -Destination $ResultsDirectory -Force
    $summary.stateSha256=$stateHash
    $summary.stateDurable=$true
    $summary.rebootRequired=$true
    $summary.passed=$summary.cleanVerifierState -and
        $summary.driverPackageRegistered -and
        $summary.targetOnlyConfigured -and
        $summary.standardFlagsConfigured -and
        $summary.querySettingsConfirmed -and
        $summary.oneBootCommandSucceeded -and
        $summary.stateDurable
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    if(-not $summary.passed -and $settingsModified){
        try{
            $reset=Invoke-Verifier @('/reset') 'failure-reset'
            if($reset.ExitCode -ne 0){throw "verifier /reset failed after ARM failure. exit=$($reset.ExitCode). Output: $($reset.Output)"}
            $postReset=Get-VerifierRegistryState
            if($postReset.DriverTokens.Count -ne 0 -or $postReset.Level -ne 0){
                throw "Driver Verifier persistent settings remain after failure reset. VerifyDrivers='$($postReset.Drivers)' level=0x$('{0:X8}' -f $postReset.Level)."
            }
        }catch{
            $summary.cleanupError=$_.Exception.Message
        }
    }

    if(-not $summary.passed -and [string]::IsNullOrWhiteSpace([string]$summary.cleanupError) -and (Test-Path -LiteralPath $active)){
        Remove-Item -LiteralPath $active -Recurse -Force -ErrorAction SilentlyContinue
    }

    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'driver-verifier-arm-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Driver Verifier ARM failed. error='$($summary.error)' cleanup='$($summary.cleanupError)' Evidence: $ResultsDirectory"
}

Write-Warning "DRIVER VERIFIER ARM PASSED for $TargetDriver with standard settings and bootmode=oneboot. Reboot the disposable VM now; if Verifier finds a violation the VM may bugcheck. The oneboot mode limits verification to that next boot."
