[CmdletBinding()]
param(
    [string]$RootBase='C:\RansomGuard-VM-Verifier',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$TargetDriver='RansomGuardMinifilter.sys'
$VerifierRegistry='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Driver Verifier CLEAR must run as Administrator.'
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

function Read-And-VerifyState([string]$StatePath){
    $hashPath=$StatePath+'.sha256'
    if(-not(Test-Path -LiteralPath $StatePath -PathType Leaf)){throw "Driver Verifier runtime state is missing: $StatePath"}
    if(-not(Test-Path -LiteralPath $hashPath -PathType Leaf)){throw "Driver Verifier runtime state hash is missing: $hashPath"}
    $expected=(Get-Content -LiteralPath $hashPath -Raw).Trim()
    $actual=(Get-FileHash -LiteralPath $StatePath -Algorithm SHA256).Hash
    if(-not [string]::Equals($expected,$actual,[StringComparison]::OrdinalIgnoreCase)){
        throw "Driver Verifier state SHA-256 mismatch. expected=$expected actual=$actual"
    }
    $raw=Get-Content -LiteralPath $StatePath -Raw
    return [pscustomobject]@{State=($raw | ConvertFrom-Json -Depth 30);Hash=$actual;RawJson=$raw}
}

function Get-JsonStringProperty([string]$RawJson,[string]$PropertyName){
    $doc=[Text.Json.JsonDocument]::Parse($RawJson)
    try{
        $element=$doc.RootElement.GetProperty($PropertyName)
        if($element.ValueKind -ne [Text.Json.JsonValueKind]::String){
            throw "Driver Verifier state property '$PropertyName' must be a JSON string."
        }
        $value=$element.GetString()
        if([string]::IsNullOrWhiteSpace($value)){
            throw "Driver Verifier state property '$PropertyName' is empty."
        }
        return $value
    }finally{
        $doc.Dispose()
    }
}

function Get-JsonUtcTimestamp([string]$RawJson,[string]$PropertyName){
    $value=Get-JsonStringProperty $RawJson $PropertyName
    if($value -notmatch '(?i)(?:Z|[+-][0-9]{2}:[0-9]{2})$'){
        throw "Driver Verifier state timestamp '$PropertyName' must contain an explicit UTC/offset designator. Found '$value'."
    }
    $dto=[DateTimeOffset]::Parse(
        $value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None)
    return $dto.UtcDateTime
}

Assert-Administrator
$vm=Assert-DisposableVm
if([string]::IsNullOrWhiteSpace($env:RG_WORKFLOW_SHA)){throw 'RG_WORKFLOW_SHA is required for exact Driver Verifier commit binding.'}

$RootBase=Assert-SafePath $RootBase 'RootBase'
if(-not $ResultsDirectory){
    $base=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
    $ResultsDirectory=Join-Path $base 'RansomGuard-Driver-Verifier-Clear-Results'
}
$ResultsDirectory=Assert-SafePath $ResultsDirectory 'ResultsDirectory'
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

$active=Join-Path $RootBase 'Active'
$statePath=Join-Path $active 'driver-verifier-state.json'
$verified=Read-And-VerifyState $statePath
$state=$verified.State
if([int]$state.schema -ne 1 -or [string]$state.phase -ne 'runtime-reset'){
    throw "Driver Verifier CLEAR requires a successful runtime-reset state. Found schema='$($state.schema)' phase='$($state.phase)'."
}
if(-not [string]::Equals([string]$state.workflowSha,$env:RG_WORKFLOW_SHA,[StringComparison]::OrdinalIgnoreCase)){
    throw "CLEAR commit '$env:RG_WORKFLOW_SHA' does not match runtime commit '$($state.workflowSha)'."
}
if(-not [bool]$state.stressPassed -or -not [bool]$state.noBugcheckAfterStress -or -not [bool]$state.resetScheduled){
    throw 'Driver Verifier CLEAR state does not prove a successful runtime qualification with reset scheduled.'
}

$runtimeBoot=Get-JsonUtcTimestamp $verified.RawJson 'runtimeBootUtc'
$currentBoot=([datetime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime()
if($currentBoot -le $runtimeBoot.AddSeconds(1)){
    throw "No reboot was observed after verifier /reset. runtimeBoot=$($runtimeBoot.ToString('o')) currentBoot=$($currentBoot.ToString('o'))"
}

$summary=[ordered]@{
    schema=1
    startedUtc=[DateTime]::UtcNow.ToString('o')
    vm=$vm
    workflowSha=$env:RG_WORKFLOW_SHA
    runtimeStateSha256=$verified.Hash
    targetDriver=$TargetDriver
    runtimeBootUtc=$runtimeBoot.ToString('o')
    currentBootUtc=$currentBoot.ToString('o')
    bootChanged=$true
    persistentSettingsAbsent=$false
    querySettingsClear=$false
    currentActivityClear=$false
    filterNotLoaded=$false
    activeCampaignArchived=$false
    passed=$false
    error=$null
}

try{
    $reg=Get-VerifierRegistryState
    if($reg.DriverTokens.Count -ne 0 -or $reg.Level -ne 0){
        throw "Driver Verifier persistent settings remain after reset reboot. VerifyDrivers='$($reg.Drivers)' level=0x$('{0:X8}' -f $reg.Level)."
    }
    $summary.persistentSettingsAbsent=$true

    $settings=Invoke-Verifier @('/querysettings') 'querysettings-clear'
    if($settings.ExitCode -ne 0){throw "verifier /querysettings failed during CLEAR. exit=$($settings.ExitCode). Output: $($settings.Output)"}
    if($settings.Output -match [regex]::Escape($TargetDriver)){
        throw "Driver Verifier scheduled settings still name '$TargetDriver' after reset reboot."
    }
    $summary.querySettingsClear=$true

    $activity=Invoke-Verifier @('/query') 'query-current-clear'
    if($activity.ExitCode -ne 0){throw "verifier /query failed during CLEAR. exit=$($activity.ExitCode). Output: $($activity.Output)"}
    if($activity.Output -match [regex]::Escape($TargetDriver)){
        throw "Driver Verifier current activity still names '$TargetDriver' after reset reboot."
    }
    $summary.currentActivityClear=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager during Driver Verifier CLEAR, exit=$LASTEXITCODE"}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter is unexpectedly still loaded during Driver Verifier CLEAR.'
    }
    $summary.filterNotLoaded=$true

    Copy-Item -LiteralPath $statePath,$($statePath+'.sha256') -Destination $ResultsDirectory -Force
    $completed=Join-Path $RootBase ("Completed-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if(Test-Path -LiteralPath $completed){throw "Driver Verifier completed archive already exists: $completed"}
    Move-Item -LiteralPath $active -Destination $completed
    $summary.completedCampaignPath=$completed
    $summary.activeCampaignArchived=$true

    $summary.passed=$summary.bootChanged -and
        $summary.persistentSettingsAbsent -and
        $summary.querySettingsClear -and
        $summary.currentActivityClear -and
        $summary.filterNotLoaded -and
        $summary.activeCampaignArchived
}
catch{
    $summary.error=$_.Exception.Message
    $summary.passed=$false
}
finally{
    $summary.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'driver-verifier-clear-result.json') -Encoding UTF8
}

if(-not $summary.passed){
    throw "Driver Verifier CLEAR failed. error='$($summary.error)' Evidence: $ResultsDirectory"
}

Write-Host "DRIVER VERIFIER CLEAR PASSED. A second reboot was observed, persistent/current verification for $TargetDriver is absent, the filter is unloaded, and the completed campaign was archived." -ForegroundColor Green
