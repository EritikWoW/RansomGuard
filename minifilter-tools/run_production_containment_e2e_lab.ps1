[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$QualificationDirectory,
    [Parameter(Mandatory=$true)][string]$FixtureExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionContainmentE2E',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production containment E2E qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production containment E2E qualification requires an obvious disposable VM. Detected: $vmText"
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
        Start-Sleep -Milliseconds 200
    }
    $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
    throw "Timed out waiting for service '$Name' state '$State'. Current=$(if($svc){$svc.Status}else{'missing'})"
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

function Wait-Audit([string]$Property,[string]$Value,[DateTimeOffset]$SinceUtc,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-AuditEntries $SinceUtc | Where-Object {
            $p=$_.PSObject.Properties[$Property]
            $null -ne $p -and [string]$p.Value -eq $Value
        })
        if($matches.Count -gt 0){return $matches[-1]}
        $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
        if($null -eq $svc -or [string]$svc.Status -ne 'Running'){
            throw "Service left Running while waiting for audit $Property='$Value'."
        }
        Start-Sleep -Milliseconds 200
    }
    $recent=@(Get-AuditEntries $SinceUtc | Select-Object -Last 16 | ForEach-Object {
        if($_.PSObject.Properties['Type']){"Type=$($_.Type)"}
        elseif($_.PSObject.Properties['Event']){"Event=$($_.Event)"}
        else{'<untyped>'}
    })
    throw "Timed out waiting for audit $Property='$Value'. Recent=$($recent -join ' -> ')"
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

function Find-IncidentForPid([int]$ProcessId,[string[]]$BaselineCases,[int]$Seconds){
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
                if([int]$incident.Risk.Process.Pid -eq $ProcessId){
                    return [pscustomobject]@{Directory=$dir.FullName;Incident=$incident}
                }
            }catch{}
        }
        Start-Sleep -Milliseconds 150
    }
    return $null
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
        if($image -notmatch '(?i)RansomGuard-(ProductionLifecycle|ProductionContainment-E2E)-Qualification'){
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
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager before E2E qualification.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the disposable VM first.'
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
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionContainment-E2E-$stamp"}
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

$root=Join-Path $RootBase "containment-e2e-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Assert-NoReparsePath $root 'ProtectedRoot'
$canary=Join-Path $root 'containment-canary.txt'
$benignTarget=Join-Path $root 'benign-high-io.bin'
[IO.File]::WriteAllText($canary,'ransomguard-e2e-canary-original',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($benignTarget,'ransomguard-benign-original',[Text.UTF8Encoding]::new($false))
$canaryOriginalSha=(Get-FileHash -LiteralPath $canary -Algorithm SHA256).Hash

$config=Get-Content -LiteralPath $appSettings -Raw | ConvertFrom-Json
$config.Mode='Enforce'
$config.ProtectedRoots=@($root)
$config.CanaryFiles=@($canary)
$config.Enforce.RequireSignedDriver=$true
$config.Enforce.AutomaticContainment=$true
$config.Enforce.ContainmentHoldMilliseconds=1200
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
$baselineCases=if(Test-Path -LiteralPath $casesRoot){@(Get-ChildItem -LiteralPath $casesRoot -Directory | Select-Object -ExpandProperty FullName)}else{@()}

$serviceName='RansomGuardV03'
$startedUtc=[DateTimeOffset]::UtcNow
$summary=[ordered]@{
    schema=1
    commit=[string]$package.commit
    version=[string]$package.productVersion
    startedUtc=$startedUtc.ToString('o')
    vm=$vm
    protectedRoot=$root
    canary=$canary
    productionSession=$null
    maliciousPid=0
    maliciousProcessCreationFileTimeUtc=0
    maliciousCaseId=$null
    maliciousMaxHeartbeatGapMs=0.0
    benignPid=0
    benignProcessCreationFileTimeUtc=0
    benignMaxHeartbeatGapMs=0.0
    serviceStarted=$false
    productionProtected=$false
    automaticContainmentReady=$false
    monitorRunning=$false
    maliciousIncidentPersisted=$false
    authorizationEligible=$false
    containmentCompleted=$false
    containmentHeartbeatGapObserved=$false
    stateChangeJournalCompleted=$false
    rollbackEvidenceObserved=$false
    benignHighIoCompleted=$false
    benignNoIncident=$false
    benignNoContainment=$false
    serviceStopped=$false
    driverUnloaded=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}
$runtimeFailure=$null
$cleanupFailure=$null
$serviceCreated=$false

try{
    Remove-StaleQualificationState

    $binPath='"'+$serviceExe+'"'
    Invoke-Sc @('create',$serviceName,'binPath=',$binPath,'start=','demand','obj=','LocalSystem') | Out-Null
    $serviceCreated=$true
    Invoke-Sc @('start',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Running' 30
    $summary.serviceStarted=$true

    $rollbackReady=Wait-Audit 'Type' 'RollbackStoreReady' $startedUtc 75
    if([string]$rollbackReady.RequestedMode -ne 'Enforce' -or $rollbackReady.ProtectionPackage.ReadyForLifecycle -ne $true){
        throw 'Production package was not admitted in Enforce mode.'
    }

    $activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $startedUtc 75
    if([string]$activation.Root -ne $root -or
       [string]$activation.Protection.State -ne 'Protected' -or
       $activation.Protection.KernelEnforcementActive -ne $true -or
       $activation.Protection.KernelChannelConnected -ne $true){
        throw 'Production lifecycle did not reach exact-root Protected state.'
    }
    $summary.productionProtected=$true
    $summary.productionSession=[string]$activation.Session

    $containmentReady=Wait-Audit 'Type' 'AutomaticContainmentReady' $startedUtc 30
    if($containmentReady.Protection.AutomaticContainmentActive -ne $true){
        throw 'Automatic containment readiness audit did not publish active containment.'
    }
    $summary.automaticContainmentReady=$true

    $startup=Wait-Audit 'Event' 'Startup' $startedUtc 30
    if([string]$startup.Protection.State -notin @('Protected','Preflight')){
        throw "Unexpected GuardWorker startup protection state '$($startup.Protection.State)'."
    }
    $summary.monitorRunning=$true

    $fixtureRoot=Join-Path $ResultsDirectory 'fixture'
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $maliciousHeartbeat=Join-Path $fixtureRoot 'malicious-heartbeat.txt'
    $maliciousReady=Join-Path $fixtureRoot 'malicious-ready.json'
    $maliciousResult=Join-Path $fixtureRoot 'malicious-result.json'

    $malicious=Start-Process -FilePath $FixtureExecutable -ArgumentList @(
        '--malicious',$canary,$maliciousHeartbeat,$maliciousReady,$maliciousResult
    ) -PassThru -WindowStyle Hidden
    $ready=Wait-JsonFile $maliciousReady 10
    if([int]$ready.pid -ne $malicious.Id -or [long]$ready.creationFileTimeUtc -le 0){
        throw 'Malicious fixture ready identity mismatch.'
    }
    $summary.maliciousPid=[int]$ready.pid
    $summary.maliciousProcessCreationFileTimeUtc=[long]$ready.creationFileTimeUtc

    if(-not $malicious.WaitForExit(20000)){
        try{$malicious.Kill($true)}catch{}
        throw 'Malicious fixture did not exit within the bounded E2E timeout.'
    }
    if($malicious.ExitCode -ne 0){throw "Malicious fixture failed exit=$($malicious.ExitCode)."}
    $maliciousOutput=Wait-JsonFile $maliciousResult 3
    $summary.maliciousMaxHeartbeatGapMs=[double]$maliciousOutput.maxHeartbeatGapMs
    if([double]$maliciousOutput.maxHeartbeatGapMs -lt 700){
        throw "Malicious fixture did not observe the expected production containment heartbeat gap. maxGapMs=$($maliciousOutput.maxHeartbeatGapMs)"
    }
    $summary.containmentHeartbeatGapObserved=$true

    $case=Find-IncidentForPid -ProcessId $malicious.Id -BaselineCases $baselineCases -Seconds 10
    if($null -eq $case){throw 'No persisted incident was found for the malicious fixture process.'}
    $summary.maliciousIncidentPersisted=$true
    $summary.maliciousCaseId=Split-Path -Leaf $case.Directory
    if([long]$case.Incident.Risk.Process.CreationFileTimeUtc -ne [long]$ready.creationFileTimeUtc){
        throw 'Persisted incident is not bound to the exact malicious process instance.'
    }

    $authorization=Wait-JsonFile (Join-Path $case.Directory 'authorization.json') 5
    if($authorization.Decision.Eligible -ne $true -or [string]$authorization.Decision.State -ne 'Eligible'){
        throw "Production containment authorization was not Eligible. reasons=$($authorization.Decision.Reasons -join ',')"
    }
    $summary.authorizationEligible=$true

    $response=Wait-JsonFile (Join-Path $case.Directory 'response.json') 5
    if($response.ProductionContainment.Completed -ne $true -or
       $response.ProductionContainment.Suspended -ne $true -or
       $response.ProductionContainment.ExplicitResumeApplied -ne $true -or
       [string]$response.ProductionContainment.Action -ne 'StateChangeContained'){
        throw 'Production containment response did not prove suspend + explicit resume completion.'
    }
    $summary.containmentCompleted=$true

    foreach($name in @('containment-actuation-pre.json','containment-actuation-suspended.json','containment-actuation-result.json')){
        if(-not(Test-Path -LiteralPath (Join-Path $case.Directory $name) -PathType Leaf)){
            throw "Production containment case evidence missing: $name"
        }
    }

    if(-not(Test-Path -LiteralPath $journalPath -PathType Leaf)){throw 'Containment state-change journal is missing.'}
    $requestId=[string]$response.ProductionContainment.RequestId
    $journalRecords=@(
        Get-Content -LiteralPath $journalPath |
            Where-Object {-not [string]::IsNullOrWhiteSpace($_)} |
            ForEach-Object {$_ | ConvertFrom-Json} |
            Where-Object {[string]$_.requestId -eq $requestId}
    )
    $phases=@($journalRecords | ForEach-Object {[string]$_.phase})
    foreach($requiredPhase in @('Prepared','SuspendApplied','ExplicitResumeApplied','Completed')){
        if($phases -notcontains $requiredPhase){throw "State-change journal missing phase '$requiredPhase' for request '$requestId'."}
    }
    if($phases -contains 'Abnormal'){throw 'State-change journal unexpectedly recorded an Abnormal terminal phase.'}
    $summary.stateChangeJournalCompleted=$true

    $rangeJournal=Join-Path $stateRoot "Rollback\Sessions\$($summary.productionSession)\write-cow\range-journal.jsonl"
    if(-not(Test-Path -LiteralPath $rangeJournal -PathType Leaf)){throw 'ProductionGate range-COW journal is missing.'}
    $canaryEvidence=@(
        Get-Content -LiteralPath $rangeJournal |
            Where-Object {-not [string]::IsNullOrWhiteSpace($_)} |
            ForEach-Object {$_ | ConvertFrom-Json} |
            Where-Object {[string]::Equals([string]$_.originalPath,$canary,[StringComparison]::OrdinalIgnoreCase)}
    )
    if($canaryEvidence.Count -eq 0){throw 'No ProductionGate rollback evidence was recorded for the malicious canary mutation.'}
    $summary.rollbackEvidenceObserved=$true

    $canaryChangedSha=(Get-FileHash -LiteralPath $canary -Algorithm SHA256).Hash
    if([string]::Equals($canaryOriginalSha,$canaryChangedSha,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Malicious canary fixture did not actually mutate the protected file.'
    }

    $casesBeforeBenign=@(Get-ChildItem -LiteralPath $casesRoot -Directory | Select-Object -ExpandProperty FullName)
    $journalBeforeBenign=@(Get-Content -LiteralPath $journalPath -ErrorAction SilentlyContinue).Count
    $benignHeartbeat=Join-Path $fixtureRoot 'benign-heartbeat.txt'
    $benignReady=Join-Path $fixtureRoot 'benign-ready.json'
    $benignResult=Join-Path $fixtureRoot 'benign-result.json'

    $benign=Start-Process -FilePath $FixtureExecutable -ArgumentList @(
        '--benign',$benignTarget,$benignHeartbeat,$benignReady,$benignResult
    ) -PassThru -WindowStyle Hidden
    $benignReadyObject=Wait-JsonFile $benignReady 10
    if([int]$benignReadyObject.pid -ne $benign.Id -or [long]$benignReadyObject.creationFileTimeUtc -le 0){
        throw 'Benign fixture ready identity mismatch.'
    }
    $summary.benignPid=[int]$benignReadyObject.pid
    $summary.benignProcessCreationFileTimeUtc=[long]$benignReadyObject.creationFileTimeUtc

    if(-not $benign.WaitForExit(15000)){
        try{$benign.Kill($true)}catch{}
        throw 'Benign high-I/O fixture did not exit within the bounded E2E timeout.'
    }
    if($benign.ExitCode -ne 0){throw "Benign fixture failed exit=$($benign.ExitCode)."}
    $benignOutput=Wait-JsonFile $benignResult 3
    $summary.benignMaxHeartbeatGapMs=[double]$benignOutput.maxHeartbeatGapMs
    if([int]$benignOutput.protectedWrites -lt 100){throw 'Benign fixture did not perform the intended high-I/O workload.'}
    $summary.benignHighIoCompleted=$true

    Start-Sleep -Seconds 2
    $benignCase=Find-IncidentForPid -ProcessId $benign.Id -BaselineCases $casesBeforeBenign -Seconds 1
    if($null -ne $benignCase){throw 'Benign high-I/O fixture unexpectedly produced a risk incident.'}
    $summary.benignNoIncident=$true

    $benignJournalRecords=@(
        Get-Content -LiteralPath $journalPath -ErrorAction SilentlyContinue |
            Where-Object {-not [string]::IsNullOrWhiteSpace($_)} |
            ForEach-Object {$_ | ConvertFrom-Json} |
            Where-Object {
                [int]$_.processId -eq [int]$benignReadyObject.pid -and
                [long]$_.processCreationFileTimeUtc -eq [long]$benignReadyObject.creationFileTimeUtc
            }
    )
    if($benignJournalRecords.Count -ne 0){throw 'Benign high-I/O fixture unexpectedly reached production containment actuation.'}
    if(@(Get-Content -LiteralPath $journalPath -ErrorAction SilentlyContinue).Count -lt $journalBeforeBenign){
        throw 'Containment journal record count moved backwards.'
    }
    $summary.benignNoContainment=$true

    Invoke-Sc @('stop',$serviceName) | Out-Null
    Wait-ServiceState $serviceName 'Stopped' 60
    $summary.serviceStopped=$true

    $maintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $startedUtc 15
    if([string]$maintenance.Root -ne $root -or [string]$maintenance.Protection.State -ne 'Maintenance'){
        throw 'Clean service stop did not publish Maintenance state.'
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager after service stop.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter remained loaded after clean E2E service stop.'
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
            throw 'RansomGuardMinifilter remained loaded after E2E cleanup.'
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
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-containment-e2e-audit.json') -Encoding utf8
        if(Test-Path -LiteralPath $journalPath -PathType Leaf){
            Copy-Item -LiteralPath $journalPath -Destination (Join-Path $ResultsDirectory 'containment-state-change-journal.jsonl') -Force
        }
        if($summary.maliciousCaseId){
            $casePath=Join-Path $casesRoot ([string]$summary.maliciousCaseId)
            if(Test-Path -LiteralPath $casePath -PathType Container){
                Copy-Item -LiteralPath $casePath -Destination (Join-Path $ResultsDirectory 'malicious-case') -Recurse -Force
            }
        }
    }catch{
        $summary.passed=$false
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){$summary.cleanupError='EvidenceCopy: '+$_.Exception.Message}
    }

    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-containment-e2e-result.json') -Encoding utf8
}

if($runtimeFailure){throw $runtimeFailure}
if($cleanupFailure){throw $cleanupFailure}
if(-not $summary.passed){throw 'Production containment E2E qualification did not pass.'}
Write-Host "Production automatic containment E2E qualification PASSED. Evidence: $ResultsDirectory" -ForegroundColor Green
