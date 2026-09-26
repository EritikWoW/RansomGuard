[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$QualificationDirectory,
    [Parameter(Mandatory=$true)][string]$FixtureExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionContainmentRecovery',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production containment crash-recovery qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production containment crash-recovery qualification requires an obvious disposable VM. Detected: $vmText"
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
        Start-Sleep -Milliseconds 100
    }
    $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
    throw "Timed out waiting for service '$Name' state '$State'. Current=$(if($svc){$svc.Status}else{'missing'})"
}

function Wait-ProcessGone([int]$ProcessId,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(-not(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Process $ProcessId did not exit within the bounded timeout."
}

function Convert-AuditUtc($Value){
    if($Value -is [DateTimeOffset]){return [DateTimeOffset]$Value}
    if($Value -is [DateTime]){
        $date=[DateTime]$Value
        if($date.Kind -eq [DateTimeKind]::Unspecified){$date=[DateTime]::SpecifyKind($date,[DateTimeKind]::Utc)}
        return [DateTimeOffset]$date
    }
    return [DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
}

function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $audit=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\audit.jsonl'
    if(-not(Test-Path -LiteralPath $audit -PathType Leaf)){return @()}
    $entries=@()
    foreach($line in Get-Content -LiteralPath $audit -ErrorAction SilentlyContinue){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{
            $item=$line | ConvertFrom-Json
            $utcProperty=$item.PSObject.Properties['Utc']
            if($null -eq $utcProperty){continue}
            if((Convert-AuditUtc $utcProperty.Value) -ge $SinceUtc){$entries += $item}
        }catch{}
    }
    return $entries
}

function Wait-Audit([string]$Property,[string]$Value,[DateTimeOffset]$SinceUtc,[int]$Seconds,[switch]$AllowStopped){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-AuditEntries $SinceUtc | Where-Object {
            $p=$_.PSObject.Properties[$Property]
            $null -ne $p -and [string]$p.Value -eq $Value
        })
        if($matches.Count -gt 0){return $matches[-1]}
        if(-not $AllowStopped){
            $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
            if($null -eq $svc -or [string]$svc.Status -ne 'Running'){
                throw "Service left the Running state while waiting for audit $Property='$Value'."
            }
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for audit $Property='$Value'."
}

function Wait-JsonFile([string]$Path,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            try{return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100}catch{}
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for JSON file: $Path"
}

function Find-IncidentForProcess([int]$ProcessId,[long]$CreationFileTimeUtc,[string[]]$BaselineCases,[int]$Seconds){
    $cases=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\Incidents'
    $baseline=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($path in $BaselineCases){[void]$baseline.Add([IO.Path]::GetFullPath($path))}
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        foreach($dir in @(Get-ChildItem -LiteralPath $cases -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)){
            if($baseline.Contains($dir.FullName)){continue}
            $incidentPath=Join-Path $dir.FullName 'incident.json'
            if(-not(Test-Path -LiteralPath $incidentPath -PathType Leaf)){continue}
            try{
                $incident=Get-Content -LiteralPath $incidentPath -Raw | ConvertFrom-Json -Depth 100
                if([int]$incident.Risk.Process.Pid -eq $ProcessId -and
                   [long]$incident.Risk.Process.CreationFileTimeUtc -eq $CreationFileTimeUtc){
                    return [pscustomobject]@{Directory=$dir.FullName;Incident=$incident}
                }
            }catch{}
        }
        Start-Sleep -Milliseconds 150
    }
    return $null
}

function Get-JournalRecordsForProcess([string]$Path,[int]$ProcessId,[long]$CreationFileTimeUtc){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    return @(
        Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue |
            Where-Object {-not [string]::IsNullOrWhiteSpace($_)} |
            ForEach-Object {try{$_ | ConvertFrom-Json}catch{$null}} |
            Where-Object {
                $null -ne $_ -and
                [int]$_.processId -eq $ProcessId -and
                [long]$_.processCreationFileTimeUtc -eq $CreationFileTimeUtc
            }
    )
}

function Wait-JournalPhaseForProcess(
    [string]$Path,
    [int]$ProcessId,
    [long]$CreationFileTimeUtc,
    [int]$Phase,
    [int]$Seconds
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $match=@(Get-JournalRecordsForProcess $Path $ProcessId $CreationFileTimeUtc | Where-Object {[int]$_.phase -eq $Phase})
        if($match.Count -gt 0){return $match[-1]}
        $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
        if($null -eq $svc -or [string]$svc.Status -ne 'Running'){
            throw "Service left Running before state-change journal phase $Phase was observed."
        }
        Start-Sleep -Milliseconds 50
    }
    throw "Timed out waiting for state-change journal phase $Phase for pid=$ProcessId creation=$CreationFileTimeUtc."
}

function Wait-HeartbeatAdvance([string]$Path,[string]$Before,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            try{
                $now=Get-Content -LiteralPath $Path -Raw
                if(-not [string]::Equals($now,$Before,[StringComparison]::Ordinal)){return $now}
            }catch{}
        }
        Start-Sleep -Milliseconds 50
    }
    throw 'Target heartbeat did not recover after hard service termination.'
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

function Remove-StaleQualificationState {
    $serviceName='RansomGuardV03'
    $serviceKey="HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if(Test-Path -LiteralPath $serviceKey){
        $props=Get-ItemProperty -LiteralPath $serviceKey
        $image=[string]$props.ImagePath
        if($image -notmatch '(?i)RansomGuard-(ProductionLifecycle|ProductionContainment)'){
            throw "REFUSED: existing $serviceName is not an obvious qualification service: $image"
        }
        $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -ne 'Stopped'){
            throw "REFUSED: prior qualification service is still $($svc.Status). Revert the disposable VM snapshot."
        }
        Invoke-Sc @('delete',$serviceName) -AllowNonZero | Out-Null
        for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $serviceKey);$i++){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $serviceKey){throw 'Stale qualification service registration did not disappear.'}
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager before crash-recovery qualification.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded before crash-recovery qualification.'
    }

    $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
    if(Test-Path -LiteralPath $driverKey){
        Invoke-Sc @('delete','RansomGuardMinifilter') -AllowNonZero | Out-Null
        for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $driverKey);$i++){Start-Sleep -Milliseconds 100}
    }
    foreach($publishedInf in @(Get-RansomGuardPublishedInfNames)){
        $out=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0){throw "Unable to remove stale driver package '$publishedInf'. $out"}
    }
}

function Quarantine-ExistingQualificationState([string]$StateRoot,[string]$Purpose){
    if(-not(Test-Path -LiteralPath $StateRoot)){return $null}
    $item=Get-Item -LiteralPath $StateRoot -Force
    if(-not $item.PSIsContainer){throw "REFUSED: qualification state path is not a directory: $StateRoot"}
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw "REFUSED: qualification state root is a reparse point: $StateRoot"
    }
    $running=@(Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" -ErrorAction SilentlyContinue)
    if($running.Count -gt 0){throw "REFUSED: RansomGuard.Service.exe is still running. pids=$($running.ProcessId -join ',')"}

    $parent=Split-Path -Parent $StateRoot
    $leaf=Split-Path -Leaf $StateRoot
    $quarantine=Join-Path $parent ("{0}.{1}.{2}.{3}" -f $leaf,$Purpose,(Get-Date -Format 'yyyyMMdd-HHmmss'),[Guid]::NewGuid().ToString('N').Substring(0,8))
    Move-Item -LiteralPath $StateRoot -Destination $quarantine
    if(Test-Path -LiteralPath $StateRoot){throw 'Qualification state root still exists after quarantine rename.'}
    return $quarantine
}

function Get-ExactServicePid([string]$ServiceName,[string]$ExpectedExecutable){
    $svc=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if(-not $svc -or [int]$svc.ProcessId -le 4){throw 'SCM did not expose a valid service process id.'}
    $serviceProcessId=[int]$svc.ProcessId
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$serviceProcessId" -ErrorAction Stop
    if(-not $process){throw "Unable to inspect service process $serviceProcessId."}
    $actual=[IO.Path]::GetFullPath([string]$process.ExecutablePath)
    if(-not [string]::Equals($actual,[IO.Path]::GetFullPath($ExpectedExecutable),[StringComparison]::OrdinalIgnoreCase)){
        throw "REFUSED: SCM service pid $serviceProcessId points to unexpected image '$actual'."
    }
    return $serviceProcessId
}

Assert-Administrator
$vm=Assert-DisposableVm

$QualificationDirectory=[IO.Path]::GetFullPath($QualificationDirectory)
$FixtureExecutable=[IO.Path]::GetFullPath($FixtureExecutable)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
foreach($pair in @(@($QualificationDirectory,'QualificationDirectory'),@($FixtureExecutable,'FixtureExecutable'))){
    if(-not(Test-Path -LiteralPath $pair[0])){throw "$($pair[1]) missing: $($pair[0])"}
    Assert-NoReparsePath $pair[0] $pair[1]
}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionContainment-Recovery-$stamp"}
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

$root=Join-Path $RootBase "containment-recovery-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Assert-NoReparsePath $root 'ProtectedRoot'
$crashCanary=Join-Path $root 'crash-canary.bin'
$blockedCanary=Join-Path $root 'post-restart-canary.bin'
[IO.File]::WriteAllText($crashCanary,'ransomguard-crash-canary-original',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($blockedCanary,'ransomguard-restart-canary-original',[Text.UTF8Encoding]::new($false))

$config=Get-Content -LiteralPath $appSettings -Raw | ConvertFrom-Json
$config.Mode='Enforce'
$config.ProtectedRoots=@($root)
$config.CanaryFiles=@($crashCanary,$blockedCanary)
$config.Enforce.RequireSignedDriver=$true
$config.Enforce.AutomaticContainment=$true
$config.Enforce.ContainmentHoldMilliseconds=10000
$config.Enforce.StartupTimeoutSeconds=45
$config.Enforce.GateWorkers=4
$config.Enforce.RollbackMaxStoreMiB=8192
$config.Enforce.RollbackMinFreeMiB=256
$config.Enforce.ReconnectDelaySeconds=2
$config.RiskThreshold=85
$config.QueueCapacity=8192
$config.MaxEventsPerProcess=512
$config.MaxIncidents=200
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $appSettings -Encoding utf8

$programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$stateRoot=Join-Path $programData 'RansomGuardV03'
$casesRoot=Join-Path $stateRoot 'Incidents'
$journalPath=Join-Path $stateRoot 'ContainmentStateChange\containment-state-change-journal.jsonl'
$serviceName='RansomGuardV03'
$startedUtc=[DateTimeOffset]::UtcNow

$summary=[ordered]@{
    schema=1
    commit=[string]$package.commit
    version=[string]$package.productVersion
    startedUtc=$startedUtc.ToString('o')
    vm=$vm
    protectedRoot=$root
    priorStateQuarantine=$null
    stateGenerationMarkerReady=$false
    initialProtectionReady=$false
    crashFixturePid=0
    crashFixtureCreationFileTimeUtc=0
    crashRequestId=$null
    suspendAppliedBeforeCrash=$false
    serviceHardKilled=$false
    servicePid=0
    gatePid=0
    gateExitedAfterServiceCrash=$false
    kernelFailSafeRetained=$false
    crashReleaseHeartbeatObserved=$false
    crashReleaseLatencyMs=0.0
    crashFixtureCompleted=$false
    incompleteJournalPreserved=$false
    restartedService=$false
    restartedProtection=$false
    automaticContainmentBlockedAfterRestart=$false
    automaticContainmentReadyAbsentAfterRestart=$false
    postRestartPid=0
    postRestartCreationFileTimeUtc=0
    postRestartIncidentPersisted=$false
    postRestartAuthorizationDenied=$false
    postRestartNoContainment=$false
    cleanMaintenanceStop=$false
    driverUnloaded=$false
    cleanupPassed=$false
    cleanupError=$null
    stateEvidenceQuarantine=$null
    passed=$false
}

$runtimeFailure=$null
$cleanupFailure=$null
$serviceCreated=$false

try{
    Remove-StaleQualificationState
    $summary.priorStateQuarantine=Quarantine-ExistingQualificationState $stateRoot 'QUALIFICATION-QUARANTINE'

    $binPath='"'+$serviceExe+'"'
    Invoke-Sc @('create',$serviceName,'binPath=',$binPath,'start=','demand','obj=','LocalSystem') | Out-Null
    $serviceCreated=$true
    Invoke-Sc @('start',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Running' 30

    $generationMarker=Join-Path $stateRoot '.ransomguard-state-v1'
    $markerDeadline=(Get-Date).AddSeconds(10)
    while((Get-Date) -lt $markerDeadline -and -not(Test-Path -LiteralPath $generationMarker -PathType Leaf)){
        $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if($null -eq $svc -or [string]$svc.Status -ne 'Running'){
            throw 'Service left Running before creating the trusted state generation marker.'
        }
        Start-Sleep -Milliseconds 100
    }
    if(-not(Test-Path -LiteralPath $generationMarker -PathType Leaf)){throw 'Trusted state generation marker was not created.'}
    $summary.stateGenerationMarkerReady=$true

    $rollbackReady=Wait-Audit 'Type' 'RollbackStoreReady' $startedUtc 75
    if([string]$rollbackReady.RequestedMode -ne 'Enforce' -or $rollbackReady.ProtectionPackage.ReadyForLifecycle -ne $true){
        throw 'Production package was not admitted in Enforce mode.'
    }
    $activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $startedUtc 75
    $ready=Wait-Audit 'Type' 'AutomaticContainmentReady' $startedUtc 30
    if($ready.Protection.AutomaticContainmentActive -ne $true){throw 'Initial automatic containment did not become active.'}
    $summary.initialProtectionReady=$true
    $summary.gatePid=[int]$activation.GateClientPid

    $fixtureRoot=Join-Path $ResultsDirectory 'fixture'
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $crashHeartbeat=Join-Path $fixtureRoot 'crash-heartbeat.txt'
    $crashReadyPath=Join-Path $fixtureRoot 'crash-ready.json'
    $crashResult=Join-Path $fixtureRoot 'crash-result.json'
    $crashFixture=Start-Process -FilePath $FixtureExecutable -ArgumentList @(
        '--malicious',$crashCanary,$crashHeartbeat,$crashReadyPath,$crashResult
    ) -PassThru -WindowStyle Hidden
    $crashReady=Wait-JsonFile $crashReadyPath 10
    if([int]$crashReady.pid -ne $crashFixture.Id -or [long]$crashReady.creationFileTimeUtc -le 0){
        throw 'Crash fixture ready identity mismatch.'
    }
    $summary.crashFixturePid=[int]$crashReady.pid
    $summary.crashFixtureCreationFileTimeUtc=[long]$crashReady.creationFileTimeUtc

    $suspendRecord=Wait-JournalPhaseForProcess $journalPath ([int]$crashReady.pid) ([long]$crashReady.creationFileTimeUtc) 2 20
    $summary.suspendAppliedBeforeCrash=$true
    $summary.crashRequestId=[string]$suspendRecord.requestId

    $beforeHeartbeat=''
    if(Test-Path -LiteralPath $crashHeartbeat -PathType Leaf){
        try{$beforeHeartbeat=Get-Content -LiteralPath $crashHeartbeat -Raw}catch{}
    }

    $servicePid=Get-ExactServicePid $serviceName $serviceExe
    $summary.servicePid=$servicePid
    $killStarted=[DateTimeOffset]::UtcNow
    Stop-Process -Id $servicePid -Force -ErrorAction Stop
    $summary.serviceHardKilled=$true
    Wait-ServiceState $serviceName 'Stopped' 20
    Wait-ProcessGone ([int]$summary.gatePid) 15
    $summary.gateExitedAfterServiceCrash=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'Kernel minifilter fail-safe was not retained after hard service/gate loss.'
    }
    $summary.kernelFailSafeRetained=$true

    [void](Wait-HeartbeatAdvance $crashHeartbeat $beforeHeartbeat 8)
    $summary.crashReleaseLatencyMs=([DateTimeOffset]::UtcNow-$killStarted).TotalMilliseconds
    if([double]$summary.crashReleaseLatencyMs -gt 5000){
        throw "Crash-release heartbeat recovery exceeded the 5s bound: $($summary.crashReleaseLatencyMs) ms."
    }
    $summary.crashReleaseHeartbeatObserved=$true

    if(-not $crashFixture.WaitForExit(20000)){
        try{$crashFixture.Kill($true)}catch{}
        throw 'Crash fixture did not finish after service loss released the state-change handle.'
    }
    if($crashFixture.ExitCode -ne 0){throw "Crash fixture failed exit=$($crashFixture.ExitCode)."}
    [void](Wait-JsonFile $crashResult 3)
    $summary.crashFixtureCompleted=$true

    $crashRecords=@(Get-JournalRecordsForProcess $journalPath ([int]$crashReady.pid) ([long]$crashReady.creationFileTimeUtc))
    $crashPhases=@($crashRecords | ForEach-Object {[int]$_.phase})
    if($crashPhases -notcontains 1 -or $crashPhases -notcontains 2){
        throw 'Crash request did not preserve Prepared + SuspendApplied journal evidence.'
    }
    foreach($forbidden in @(3,4,5)){
        if($crashPhases -contains $forbidden){throw "Crash request unexpectedly contains terminal/recovery phase $forbidden."}
    }
    $summary.incompleteJournalPreserved=$true

    $restartUtc=[DateTimeOffset]::UtcNow
    Invoke-Sc @('start',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Running' 30
    $summary.restartedService=$true

    $blocked=Wait-Audit 'Type' 'AutomaticContainmentUnavailable' $restartUtc 90
    if([string]$blocked.Reason -ne 'IncompleteStateChangeSessionsRequireReview' -or [int]$blocked.IncompleteSessions -lt 1){
        throw "Restart did not fail closed on incomplete containment journal. reason=$($blocked.Reason) incomplete=$($blocked.IncompleteSessions)"
    }
    if($blocked.Protection.AutomaticContainmentActive -eq $true){
        throw 'Restart recovery incorrectly left automatic containment active.'
    }
    $summary.automaticContainmentBlockedAfterRestart=$true

    $activation2=Wait-Audit 'Type' 'ProductionProtectionActivated' $restartUtc 90
    if([string]$activation2.Protection.State -ne 'Protected' -or
       $activation2.Protection.KernelEnforcementActive -ne $true -or
       $activation2.Protection.KernelChannelConnected -ne $true -or
       $activation2.Protection.AutomaticContainmentActive -eq $true){
        throw 'Restarted protection state did not remain kernel-Protected with automatic containment disabled.'
    }
    $summary.restartedProtection=$true

    $readyAfter=@(Get-AuditEntries $restartUtc | Where-Object {
        $_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'AutomaticContainmentReady'
    })
    if($readyAfter.Count -ne 0){throw 'AutomaticContainmentReady was published after restart despite an incomplete state-change session.'}
    $summary.automaticContainmentReadyAbsentAfterRestart=$true

    $baselineCases=@(Get-ChildItem -LiteralPath $casesRoot -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $postHeartbeat=Join-Path $fixtureRoot 'post-restart-heartbeat.txt'
    $postReadyPath=Join-Path $fixtureRoot 'post-restart-ready.json'
    $postResult=Join-Path $fixtureRoot 'post-restart-result.json'
    $post=Start-Process -FilePath $FixtureExecutable -ArgumentList @(
        '--malicious',$blockedCanary,$postHeartbeat,$postReadyPath,$postResult
    ) -PassThru -WindowStyle Hidden
    $postReady=Wait-JsonFile $postReadyPath 10
    if([int]$postReady.pid -ne $post.Id -or [long]$postReady.creationFileTimeUtc -le 0){
        throw 'Post-restart fixture ready identity mismatch.'
    }
    $summary.postRestartPid=[int]$postReady.pid
    $summary.postRestartCreationFileTimeUtc=[long]$postReady.creationFileTimeUtc

    if(-not $post.WaitForExit(20000)){
        try{$post.Kill($true)}catch{}
        throw 'Post-restart fixture did not exit within the bounded timeout.'
    }
    if($post.ExitCode -ne 0){throw "Post-restart fixture failed exit=$($post.ExitCode)."}
    $postOutput=Wait-JsonFile $postResult 3
    if([double]$postOutput.maxHeartbeatGapMs -ge 700){
        throw "Post-restart fixture observed an unexpected containment-sized heartbeat gap: $($postOutput.maxHeartbeatGapMs) ms."
    }

    $postCase=Find-IncidentForProcess ([int]$postReady.pid) ([long]$postReady.creationFileTimeUtc) $baselineCases 12
    if($null -eq $postCase){throw 'Post-restart canary mutation did not persist a risk incident.'}
    $summary.postRestartIncidentPersisted=$true

    $postAuthorization=Wait-JsonFile (Join-Path $postCase.Directory 'authorization.json') 5
    if($postAuthorization.Decision.Eligible -eq $true -or
       @($postAuthorization.Decision.Reasons) -notcontains 'AutomaticContainmentNotActive'){
        throw "Post-restart authorization did not deny automatic containment for the incomplete-session gate."
    }
    $summary.postRestartAuthorizationDenied=$true

    $postResponse=Wait-JsonFile (Join-Path $postCase.Directory 'response.json') 5
    if([string]$postResponse.Action -ne 'AuditOnly' -or $postResponse.ActuationAttempted -ne $false){
        throw 'Post-restart incident was not held at AuditOnly with no actuation.'
    }

    $postJournal=@(Get-JournalRecordsForProcess $journalPath ([int]$postReady.pid) ([long]$postReady.creationFileTimeUtc))
    if($postJournal.Count -ne 0){throw 'Post-restart denied process unexpectedly reached the containment state-change journal.'}
    $summary.postRestartNoContainment=$true

    Invoke-Sc @('stop',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Stopped' 60
    $maintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $restartUtc 20 -AllowStopped
    if([string]$maintenance.Protection.State -ne 'Maintenance'){
        throw 'Clean restart-service stop did not publish Maintenance state.'
    }
    $summary.cleanMaintenanceStop=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter remained loaded after clean recovery-campaign shutdown.'
    }
    $summary.driverUnloaded=$true
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

        $gateProcesses=@(Get-CimInstance Win32_Process -Filter "Name='RansomGuard.GateClient.exe'" -ErrorAction SilentlyContinue)
        foreach($gateProcess in $gateProcesses){
            $path=[string]$gateProcess.ExecutablePath
            if($path -and $path.StartsWith($QualificationDirectory,[StringComparison]::OrdinalIgnoreCase)){
                try{Stop-Process -Id ([int]$gateProcess.ProcessId) -Force -ErrorAction SilentlyContinue}catch{}
            }
        }

        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -eq 0 -and $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            $volume=[IO.Path]::GetPathRoot($root).TrimEnd('\')
            & (Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1') -Volume $volume
        }

        if($serviceCreated -or (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName")){
            Invoke-Sc @('delete',$serviceName) -AllowNonZero | Out-Null
        }

        $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
        if(Test-Path -LiteralPath $driverKey){
            Invoke-Sc @('delete','RansomGuardMinifilter') -AllowNonZero | Out-Null
            for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $driverKey);$i++){Start-Sleep -Milliseconds 100}
        }
        foreach($publishedInf in @(Get-RansomGuardPublishedInfNames)){
            $out=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
            if($LASTEXITCODE -ne 0){throw "Unable to remove qualification Driver Store package '$publishedInf'. $out"}
        }

        $filtersAfter=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -ne 0 -or $filtersAfter -match '(?m)^\s*RansomGuardMinifilter\b'){
            throw 'RansomGuardMinifilter remained loaded after crash-recovery cleanup.'
        }
        $summary.cleanupPassed=$true
    }catch{
        $cleanupFailure=$_
        $summary.cleanupPassed=$false
        $summary.cleanupError=$_.Exception.Message
        $summary.passed=$false
    }

    try{
        $audit=@(Get-AuditEntries $startedUtc)
        ConvertTo-Json -InputObject $audit -Depth 20 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-containment-recovery-audit.json') -Encoding utf8
        if(Test-Path -LiteralPath $journalPath -PathType Leaf){
            Copy-Item -LiteralPath $journalPath -Destination (Join-Path $ResultsDirectory 'containment-state-change-journal.jsonl') -Force
            $head=Join-Path (Split-Path -Parent $journalPath) 'containment-state-change-journal.head.json'
            if(Test-Path -LiteralPath $head -PathType Leaf){
                Copy-Item -LiteralPath $head -Destination (Join-Path $ResultsDirectory 'containment-state-change-journal.head.json') -Force
            }
        }
        if(Test-Path -LiteralPath $casesRoot -PathType Container){
            $caseEvidence=Join-Path $ResultsDirectory 'incidents'
            New-Item -ItemType Directory -Path $caseEvidence -Force | Out-Null
            foreach($dir in @(Get-ChildItem -LiteralPath $casesRoot -Directory -ErrorAction SilentlyContinue)){
                Copy-Item -LiteralPath $dir.FullName -Destination (Join-Path $caseEvidence $dir.Name) -Recurse -Force
            }
        }
        if(Test-Path -LiteralPath $stateRoot -PathType Container){
            $summary.stateEvidenceQuarantine=Quarantine-ExistingQualificationState $stateRoot 'CRASH-RECOVERY-EVIDENCE'
        }
    }catch{
        $summary.passed=$false
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){$summary.cleanupError='EvidenceCopy: '+$_.Exception.Message}
    }

    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-containment-recovery-result.json') -Encoding utf8
}

if($runtimeFailure){throw $runtimeFailure}
if($cleanupFailure){throw $cleanupFailure}
if(-not $summary.passed){throw 'Production containment crash-recovery qualification did not pass.'}
Write-Host "Production automatic-containment crash/restart recovery qualification PASSED. Evidence: $ResultsDirectory" -ForegroundColor Green
