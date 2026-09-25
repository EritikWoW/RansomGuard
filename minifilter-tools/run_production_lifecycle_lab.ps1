[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$QualificationDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionLifecycle',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production lifecycle qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production lifecycle qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: set RANSOMGUARD_LAB_VM=I_UNDERSTAND only inside the disposable snapshot VM.'
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

function Get-RansomGuardPublishedInfNames {
    $windowsInf=Join-Path $env:SystemRoot 'INF'
    if(-not(Test-Path -LiteralPath $windowsInf -PathType Container)){return @()}
    return @(
        Get-ChildItem -LiteralPath $windowsInf -Filter 'oem*.inf' -File -ErrorAction Stop |
            Where-Object {
                try{
                    $text=Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
                    $text -match '(?im)^\s*ServiceName\s*=\s*"RansomGuardMinifilter"\s*$' -and
                    $text -match '(?im)^\s*CatalogFile\s*=\s*RansomGuardMinifilter\.cat\s*$'
                }catch{$false}
            } |
            Select-Object -ExpandProperty Name
    )
}

function Remove-RansomGuardDriverRegistration {
    $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager before lifecycle qualification.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is loaded before lifecycle qualification. Revert/clean the disposable VM first.'
    }

    $published=@(Get-RansomGuardPublishedInfNames)
    if(Test-Path -LiteralPath $serviceKey){
        $delete=(& sc.exe delete RansomGuardMinifilter 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060){
            throw "Unable to delete stale RansomGuardMinifilter registration. $delete"
        }
        for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $serviceKey);$i++){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $serviceKey){throw 'Stale RansomGuardMinifilter service registration did not disappear.'}
    }

    foreach($publishedInf in $published){
        $delete=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0){throw "Unable to remove stale RansomGuard driver package '$publishedInf'. $delete"}
    }
    $remaining=@(Get-RansomGuardPublishedInfNames)
    if($remaining.Count -gt 0){throw "Stale RansomGuard driver package(s) remain: $($remaining -join ', ')"}
}

function Remove-QualificationServiceIfOwned {
    $serviceName='RansomGuardV03'
    $serviceKey="HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if(-not(Test-Path -LiteralPath $serviceKey)){return}
    $props=Get-ItemProperty -LiteralPath $serviceKey
    $image=[string]$props.ImagePath
    if($image -notmatch '(?i)RansomGuard-ProductionLifecycle-Qualification'){
        throw "REFUSED: existing $serviceName service is not an obvious prior qualification instance: $image"
    }
    $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if($svc -and $svc.Status -ne 'Stopped'){
        throw "REFUSED: prior qualification service $serviceName is still $($svc.Status). Revert the disposable VM checkpoint."
    }
    $delete=(& sc.exe delete $serviceName 2>&1 | Out-String)
    if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060){throw "Unable to delete stale qualification service. $delete"}
    for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $serviceKey);$i++){Start-Sleep -Milliseconds 100}
    if(Test-Path -LiteralPath $serviceKey){throw 'Stale qualification service registration did not disappear.'}
}

function Invoke-Sc([string[]]$Arguments,[switch]$AllowNonZero){
    $output=(& sc.exe @Arguments 2>&1 | Out-String)
    $exit=$LASTEXITCODE
    if(-not $AllowNonZero -and $exit -ne 0){throw "sc.exe $($Arguments -join ' ') failed exit=$exit. $output"}
    return [pscustomobject]@{ExitCode=$exit;Output=$output}
}

function Wait-ServiceState([string]$Name,[string]$State,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
        if($svc -and [string]$svc.Status -eq $State){return}
        Start-Sleep -Milliseconds 200
    }
    $current=Get-Service -Name $Name -ErrorAction SilentlyContinue
    throw "Timed out waiting for service '$Name' state '$State'. Current=$(if($current){$current.Status}else{'missing'})"
}

function Test-AccessDeniedException([Exception]$Exception){
    $cursor=$Exception
    while($null -ne $cursor){
        if($cursor -is [UnauthorizedAccessException]){return $true}
        $win32=([int]$cursor.HResult -band 0xFFFF)
        if($win32 -eq 5){return $true}
        $cursor=$cursor.InnerException
    }
    return $false
}

function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $audit=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\audit.jsonl'
    if(-not(Test-Path -LiteralPath $audit -PathType Leaf)){return @()}
    $entries=New-Object System.Collections.Generic.List[object]
    foreach($line in Get-Content -LiteralPath $audit -ErrorAction SilentlyContinue){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{
            $item=$line | ConvertFrom-Json
            if($null -eq $item.Utc){continue}
            $utc=[DateTimeOffset]::Parse([string]$item.Utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
            if($utc -ge $SinceUtc){$entries.Add($item)}
        }catch{}
    }
    return @($entries)
}

function Wait-AuditType([string]$Type,[DateTimeOffset]$SinceUtc,[int]$Seconds,[string]$DifferentSession=''){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-AuditEntries $SinceUtc | Where-Object {
            [string]$_.Type -eq $Type -and
            ([string]::IsNullOrWhiteSpace($DifferentSession) -or [string]$_.Session -ne $DifferentSession)
        })
        if($matches.Count -gt 0){return $matches[-1]}
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for audit event Type='$Type'."
}

Assert-Administrator
$vm=Assert-DisposableVm

$QualificationDirectory=[IO.Path]::GetFullPath($QualificationDirectory)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
$rootDrive=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
if($RootBase -eq $rootDrive){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $QualificationDirectory 'QualificationDirectory'
Assert-NoReparsePath $RootBase 'RootBase'

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionLifecycle-$stamp"}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

$packageSummaryPath=Join-Path $QualificationDirectory 'qualification-package.json'
$serviceExe=Join-Path $QualificationDirectory 'RansomGuard.Service.exe'
$appSettings=Join-Path $QualificationDirectory 'appsettings.json'
foreach($required in @($packageSummaryPath,$serviceExe,$appSettings)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Qualification input missing: $required"}
}
$package=Get-Content -LiteralPath $packageSummaryPath -Raw | ConvertFrom-Json
if([int]$package.schema -ne 1 -or $package.qualificationOnly -ne $true){throw 'Qualification package provenance is invalid.'}
if(-not [string]::Equals([string]$package.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Qualification package commit '$($package.commit)' does not match expected '$ExpectedCommit'."
}

$root=Join-Path $RootBase "service-lifecycle-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Assert-NoReparsePath $root 'ProtectedRoot'
$target=Join-Path $root 'lifecycle-target.bin'
[IO.File]::WriteAllText($target,'production-lifecycle-initial',[Text.UTF8Encoding]::new($false))

$config=Get-Content -LiteralPath $appSettings -Raw | ConvertFrom-Json
$config.Mode='Enforce'
$config.ProtectedRoots=@($root)
$config.CanaryFiles=@()
$config.Enforce.RequireSignedDriver=$true
$config.Enforce.AutomaticContainment=$false
$config.Enforce.StartupTimeoutSeconds=45
$config.Enforce.GateWorkers=4
$config.Enforce.RollbackMaxStoreMiB=8192
$config.Enforce.RollbackMinFreeMiB=256
$config.Enforce.ReconnectDelaySeconds=5
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $appSettings -Encoding utf8

$serviceName='RansomGuardV03'
$startedUtc=[DateTimeOffset]::UtcNow
$summary=[ordered]@{
    schema=1
    version=[string]$package.productVersion
    commit=[string]$package.commit
    startedUtc=$startedUtc.ToString('o')
    vm=$vm
    qualificationAltitude=[string]$package.qualificationAltitude
    serviceStarted=$false
    admittedAndProtected=$false
    productionMutationAllowed=$false
    gateClientLossObserved=$false
    degradedDeniedMutation=$false
    degradedPreservedHash=$false
    reconnectProtected=$false
    reconnectReplacementObserved=$false
    reconnectPidReused=$false
    reconnectMutationAllowed=$false
    serviceCrashObserved=$false
    serviceCrashGateExited=$false
    serviceCrashDeniedMutation=$false
    serviceCrashPreservedHash=$false
    serviceRestartProtected=$false
    serviceRestartMutationAllowed=$false
    maintenanceStopObserved=$false
    driverUnloadedAfterMaintenance=$false
    serviceStopped=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}
$runtimeFailure=$null
$cleanupFailure=$null
$firstActivation=$null
$secondActivation=$null
$thirdActivation=$null
$serviceCreated=$false

try{
    Remove-QualificationServiceIfOwned
    Remove-RansomGuardDriverRegistration

    $binPath='"'+$serviceExe+'"'
    Invoke-Sc @('create',$serviceName,"binPath= $binPath",'start= demand','obj= LocalSystem') | Out-Null
    $serviceCreated=$true
    Invoke-Sc @('start',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Running' 30
    $summary.serviceStarted=$true

    $firstActivation=Wait-AuditType 'ProductionProtectionActivated' $startedUtc 75
    if([string]$firstActivation.Root -ne $root){throw "First activation root mismatch: $($firstActivation.Root)"}
    if([int]$firstActivation.GateClientPid -le 0){throw 'First activation did not record a GateClient PID.'}
    if([string]$firstActivation.Protection.State -ne 'Protected' -or $firstActivation.Protection.KernelEnforcementActive -ne $true){
        throw 'First activation audit did not publish Protected/kernel-enforcement truth.'
    }
    $summary.admittedAndProtected=$true

    [IO.File]::WriteAllText($target,'production-lifecycle-before-loss',[Text.UTF8Encoding]::new($false))
    if((Get-Content -LiteralPath $target -Raw) -ne 'production-lifecycle-before-loss'){
        throw 'Protected Production lifecycle mutation did not complete.'
    }
    $summary.productionMutationAllowed=$true
    $protectedHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    $firstGatePid=[int]$firstActivation.GateClientPid
    Stop-Process -Id $firstGatePid -Force -ErrorAction Stop
    for($i=0;$i -lt 50 -and (Get-Process -Id $firstGatePid -ErrorAction SilentlyContinue);$i++){
        Start-Sleep -Milliseconds 100
    }
    if(Get-Process -Id $firstGatePid -ErrorAction SilentlyContinue){
        throw "Original ProductionGate pid=$firstGatePid did not exit after the forced-loss probe."
    }
    $summary.reconnectReplacementObserved=$true
    $lost=Wait-AuditType 'ProductionGateLost' $startedUtc 30
    if([string]$lost.Session -ne [string]$firstActivation.Session){throw 'GateClient-loss audit session does not match the first activation.'}
    if([string]$lost.Protection.State -ne 'DegradedProtected' -or $lost.Protection.KernelEnforcementActive -ne $true){
        throw 'Unexpected GateClient loss did not publish DegradedProtected with kernel enforcement retained.'
    }
    $summary.gateClientLossObserved=$true

    if((Get-Content -LiteralPath $target -Raw) -ne 'production-lifecycle-before-loss'){
        throw 'Read-only access failed in DegradedProtected.'
    }

    $denied=$false
    try{[IO.File]::WriteAllText($target,'must-be-denied-while-degraded',[Text.UTF8Encoding]::new($false))}
    catch{
        if(Test-AccessDeniedException $_.Exception){$denied=$true}else{throw}
    }
    if(-not $denied){throw 'Resolved protected-root mutation was not denied during service-supervised DegradedProtected.'}
    $summary.degradedDeniedMutation=$true
    $afterDenied=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if(-not [string]::Equals($protectedHash,$afterDenied,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Protected target changed while DegradedProtected mutation was denied.'
    }
    $summary.degradedPreservedHash=$true

    $secondActivation=Wait-AuditType 'ProductionProtectionActivated' $lost.Utc 75 ([string]$firstActivation.Session)
    if([string]$secondActivation.Root -ne $root){throw 'Reconnect activation root mismatch.'}
    if([string]$secondActivation.Protection.State -ne 'Protected' -or
       $secondActivation.Protection.KernelEnforcementActive -ne $true -or
       $secondActivation.Protection.KernelChannelConnected -ne $true){
        throw 'Reconnect did not return to Protected with a connected kernel channel.'
    }
    $summary.reconnectProtected=$true
    $summary.reconnectPidReused=([int]$secondActivation.GateClientPid -eq $firstGatePid)
    # PID reuse is explicitly allowed here: the security boundary is the new kernel PEPROCESS
    # plus a new ProductionGate session after the original process has been proved exited.

    [IO.File]::WriteAllText($target,'production-lifecycle-after-reconnect',[Text.UTF8Encoding]::new($false))
    if((Get-Content -LiteralPath $target -Raw) -ne 'production-lifecycle-after-reconnect'){
        throw 'Mutation did not resume after ProductionGate reconnect.'
    }
    $summary.reconnectMutationAllowed=$true

    # Crash the supervising service itself. Control-pipe loss must never authorize
    # DeactivateGate; the ProductionGate must exit and leave the kernel fail-safe latch active.
    $secondGatePid=[int]$secondActivation.GateClientPid
    $secondGateProcess=Get-Process -Id $secondGatePid -ErrorAction Stop
    $serviceCim=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if($null -eq $serviceCim){throw "Unable to resolve owned qualification service '$serviceName'."}
    $servicePid=[int]$serviceCim.ProcessId
    if($servicePid -le 0 -or $servicePid -eq $secondGatePid){
        throw "Qualification service process identity is invalid. servicePid=$servicePid gatePid=$secondGatePid"
    }
    $serviceCrashHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Stop-Process -Id $servicePid -Force -ErrorAction Stop
    Wait-ServiceState $serviceName 'Stopped' 30
    $summary.serviceCrashObserved=$true

    if(-not $secondGateProcess.WaitForExit(15000)){
        throw "ProductionGate pid=$secondGatePid did not exit after supervising service control-channel loss."
    }
    $summary.serviceCrashGateExited=$true
    Start-Sleep -Milliseconds 250

    $serviceCrashDenied=$false
    try{[IO.File]::WriteAllText($target,'must-be-denied-after-service-crash',[Text.UTF8Encoding]::new($false))}
    catch{
        if(Test-AccessDeniedException $_.Exception){$serviceCrashDenied=$true}else{throw}
    }
    if(-not $serviceCrashDenied){
        throw 'Protected-root mutation was not denied after service crash and ProductionGate fail-safe disconnect.'
    }
    $summary.serviceCrashDeniedMutation=$true
    $afterServiceCrash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if(-not [string]::Equals($serviceCrashHash,$afterServiceCrash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Protected target changed after service crash while the kernel should remain fail-safe.'
    }
    $summary.serviceCrashPreservedHash=$true

    $restartUtc=[DateTimeOffset]::UtcNow
    Invoke-Sc @('start',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Running' 30
    $thirdActivation=Wait-AuditType 'ProductionProtectionActivated' $restartUtc 75 ([string]$secondActivation.Session)
    if([string]$thirdActivation.Root -ne $root){throw 'Service-restart activation root mismatch.'}
    if([int]$thirdActivation.GateClientPid -le 0){throw 'Service restart did not record a replacement ProductionGate PID.'}
    if([string]$thirdActivation.Protection.State -ne 'Protected' -or
       $thirdActivation.Protection.KernelEnforcementActive -ne $true -or
       $thirdActivation.Protection.KernelChannelConnected -ne $true){
        throw 'Service restart did not reconnect the retained ProductionGate session into Protected.'
    }
    $summary.serviceRestartProtected=$true

    [IO.File]::WriteAllText($target,'production-lifecycle-after-service-restart',[Text.UTF8Encoding]::new($false))
    if((Get-Content -LiteralPath $target -Raw) -ne 'production-lifecycle-after-service-restart'){
        throw 'Mutation did not resume after service restart and ProductionGate preflight.'
    }
    $summary.serviceRestartMutationAllowed=$true

    Invoke-Sc @('stop',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Stopped' 60
    $summary.serviceStopped=$true

    $maintenance=Wait-AuditType 'ProductionProtectionMaintenanceStop' $restartUtc 15
    if([string]$maintenance.Root -ne $root -or [string]$maintenance.Protection.State -ne 'Maintenance'){
        throw 'Clean service stop did not publish the expected Maintenance audit state.'
    }
    $summary.maintenanceStopObserved=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager after production maintenance stop.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter remained loaded after confirmed production maintenance stop.'
    }
    $summary.driverUnloadedAfterMaintenance=$true
    $summary.passed=$true
}catch{
    $runtimeFailure=$_
}finally{
    try{
        $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -ne 'Stopped'){
            try{Invoke-Sc @('stop',$serviceName) -AllowNonZero | Out-Null}catch{}
            try{Wait-ServiceState $serviceName 'Stopped' 30}catch{}
        }

        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -eq 0 -and $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
            & (Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1') -Volume $volume
        }

        if($serviceCreated -or (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName")){
            $delete=(& sc.exe delete $serviceName 2>&1 | Out-String)
            if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060){throw "Unable to delete qualification service. $delete"}
        }

        $driverServiceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
        if(Test-Path -LiteralPath $driverServiceKey){
            $delete=(& sc.exe delete RansomGuardMinifilter 2>&1 | Out-String)
            if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060){throw "Unable to delete qualification driver service. $delete"}
            for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $driverServiceKey);$i++){Start-Sleep -Milliseconds 100}
        }
        foreach($publishedInf in @(Get-RansomGuardPublishedInfNames)){
            $delete=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
            if($LASTEXITCODE -ne 0){throw "Unable to remove qualification Driver Store package '$publishedInf'. $delete"}
        }

        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            throw 'RansomGuardMinifilter remained loaded after lifecycle qualification cleanup.'
        }
        $summary.cleanupPassed=$true
    }catch{
        $cleanupFailure=$_
        $summary.cleanupPassed=$false
        $summary.cleanupError=$_.Exception.Message
        $summary.passed=$false
    }

    $summary.completedUtc=(Get-Date).ToUniversalTime().ToString('o')
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-lifecycle-result.json') -Encoding utf8
}

if($runtimeFailure){throw $runtimeFailure}
if($cleanupFailure){throw $cleanupFailure}
if(-not $summary.passed){throw 'Production lifecycle qualification did not pass.'}
Write-Host "Production Enforce service lifecycle qualification PASSED. Evidence: $ResultsDirectory" -ForegroundColor Green
