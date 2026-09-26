[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('arm','resume','verify')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionContainmentRebootRecovery'
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production containment reboot-recovery qualification must run as Administrator.'
    }
}
function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: containment reboot recovery requires an obvious disposable VM. Detected: $text"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required.'
    }
    return $text
}
function Assert-NoReparsePath([string]$Path,[string]$Label){
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){throw "$Label has no filesystem root: $full"}
    $cursor=$root.TrimEnd('\')
    foreach($segment in $full.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)){
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
function Write-Utf8Durable([string]$Path,[string]$Text){
    $parent=Split-Path -Parent $Path
    if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $tmp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        $fs=[IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
            $fs.Write($bytes,0,$bytes.Length)
            $fs.Flush($true)
        }finally{$fs.Dispose()}
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }finally{
        if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}
    }
}
function Write-State([hashtable]$State,[string]$Path){
    Write-Utf8Durable $Path ($State | ConvertTo-Json -Depth 80)
    $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Write-Utf8Durable ($Path+'.sha256') ($hash+[Environment]::NewLine)
}
function Read-State([string]$Path,[string]$ExpectedSha){
    foreach($p in @($Path,$Path+'.sha256')){
        if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Campaign state missing: $p"}
        Assert-NoReparsePath $p 'Campaign state'
    }
    $expected=(Get-Content -LiteralPath ($Path+'.sha256') -Raw).Trim()
    $actual=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if(-not [string]::Equals($expected,$actual,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Campaign state SHA-256 mismatch.'
    }
    $state=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100 -AsHashtable
    if([int]$state.schema -ne 1){throw 'Campaign state schema must be 1.'}
    if(-not [string]::Equals([string]$state.commit,$ExpectedSha,[StringComparison]::OrdinalIgnoreCase)){
        throw "Campaign state commit '$($state.commit)' does not match '$ExpectedSha'."
    }
    return $state
}
function Save-Summary([hashtable]$State,[string]$EvidenceRoot){
    New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
    Write-Utf8Durable (Join-Path $EvidenceRoot 'production-containment-reboot-recovery-result.json') ($State | ConvertTo-Json -Depth 80)
}
function Get-BootUtc {
    $boot=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    if($boot -isnot [DateTime]){$boot=[Management.ManagementDateTimeConverter]::ToDateTime([string]$boot)}
    return ([DateTimeOffset]$boot.ToUniversalTime())
}
function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
    $items=@()
    foreach($path in @(
        (Join-Path $root 'audit.jsonl'),
        (Join-Path $root 'audit.1.jsonl'),
        (Join-Path $root 'audit.2.jsonl'),
        (Join-Path $root 'audit.3.jsonl')
    )){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        Assert-NoReparsePath $path 'Audit evidence'
        foreach($line in Get-Content -LiteralPath $path -ErrorAction SilentlyContinue){
            if([string]::IsNullOrWhiteSpace($line)){continue}
            try{
                $item=$line | ConvertFrom-Json
                if($item.PSObject.Properties['Utc'] -and [DateTimeOffset]::Parse([string]$item.Utc) -ge $SinceUtc){
                    $items += $item
                }
            }catch{}
        }
    }
    return @($items | Sort-Object {[DateTimeOffset]::Parse([string]$_.Utc)})
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
                throw "Service left Running while waiting for audit $Property='$Value'."
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
function Get-JournalRecordsForProcess([string]$Path,[int]$ProcessId,[long]$CreationFileTimeUtc){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
    return @(
        Get-Content -LiteralPath $Path -ErrorAction Stop |
            Where-Object {-not [string]::IsNullOrWhiteSpace($_)} |
            ForEach-Object {try{$_ | ConvertFrom-Json}catch{$null}} |
            Where-Object {
                $null -ne $_ -and
                [int]$_.processId -eq $ProcessId -and
                [long]$_.processCreationFileTimeUtc -eq $CreationFileTimeUtc
            }
    )
}
function Wait-JournalPhaseForProcess([string]$Path,[int]$ProcessId,[long]$CreationFileTimeUtc,[int]$PhaseNumber,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-JournalRecordsForProcess $Path $ProcessId $CreationFileTimeUtc | Where-Object {[int]$_.phase -eq $PhaseNumber})
        if($matches.Count -gt 0){return $matches[-1]}
        $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
        if($null -eq $svc -or [string]$svc.Status -ne 'Running'){
            throw "Service left Running before journal phase $PhaseNumber was observed."
        }
        Start-Sleep -Milliseconds 50
    }
    throw "Timed out waiting for journal phase $PhaseNumber for pid=$ProcessId creation=$CreationFileTimeUtc."
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
            } | Select-Object -ExpandProperty Name
    )
}
function Get-ExactServicePid([string]$ExpectedExecutable){
    $svc=Get-CimInstance Win32_Service -Filter "Name='RansomGuardV03'" -ErrorAction Stop
    if(-not $svc -or [int]$svc.ProcessId -le 4){throw 'SCM did not expose a valid service process id.'}
    $serviceProcessId=[int]$svc.ProcessId
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$serviceProcessId" -ErrorAction Stop
    $actual=[IO.Path]::GetFullPath([string]$process.ExecutablePath)
    if(-not [string]::Equals($actual,[IO.Path]::GetFullPath($ExpectedExecutable),[StringComparison]::OrdinalIgnoreCase)){
        throw "REFUSED: service pid $serviceProcessId points to unexpected image '$actual'."
    }
    return $serviceProcessId
}
function Assert-ServiceRegistration([string]$ExpectedExecutable){
    $svc=Get-CimInstance Win32_Service -Filter "Name='RansomGuardV03'" -ErrorAction Stop
    if(-not $svc){throw 'RansomGuardV03 service registration is missing.'}
    $raw=[string]$svc.PathName
    $actual=$raw.Trim().Trim('"')
    if(-not [string]::Equals([IO.Path]::GetFullPath($actual),[IO.Path]::GetFullPath($ExpectedExecutable),[StringComparison]::OrdinalIgnoreCase)){
        throw "Service ImagePath drifted across reboot. expected='$ExpectedExecutable' actual='$actual'"
    }
}
function Assert-FilterAbsent([string]$Context){
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager during $Context."}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){throw "RansomGuardMinifilter unexpectedly loaded during $Context."}
}
function Assert-FilterPresent([string]$Context){
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
        throw "RansomGuardMinifilter is not loaded during $Context."
    }
}
function Quarantine-State([string]$StateRoot,[string]$Purpose){
    if(-not(Test-Path -LiteralPath $StateRoot)){return $null}
    $item=Get-Item -LiteralPath $StateRoot -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw "REFUSED: unsafe qualification state root: $StateRoot"
    }
    $running=@(Get-CimInstance Win32_Process -Filter "Name='RansomGuard.Service.exe'" -ErrorAction SilentlyContinue)
    if($running.Count -gt 0){throw "REFUSED: RansomGuard.Service.exe is still running. pids=$($running.ProcessId -join ',')"}
    $parent=Split-Path -Parent $StateRoot
    $leaf=Split-Path -Leaf $StateRoot
    $dest=Join-Path $parent ("{0}.{1}.{2}.{3}" -f $leaf,$Purpose,(Get-Date -Format 'yyyyMMdd-HHmmss'),[Guid]::NewGuid().ToString('N').Substring(0,8))
    Move-Item -LiteralPath $StateRoot -Destination $dest
    return $dest
}
function Cleanup-Qualification([string]$Volume){
    $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
    if($svc -and $svc.Status -ne 'Stopped'){
        [void](Invoke-Sc @('stop','RansomGuardV03') -AllowNonZero)
        try{Wait-ServiceState 'RansomGuardV03' 'Stopped' 30}catch{}
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -eq 0 -and $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        & (Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1') -Volume $Volume
        if($LASTEXITCODE -ne 0){throw 'Unable to unload RansomGuardMinifilter during campaign cleanup.'}
    }

    $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardV03'
    if(Test-Path -LiteralPath $serviceKey){
        [void](Invoke-Sc @('delete','RansomGuardV03') -AllowNonZero)
        for($i=0;$i -lt 50 -and (Test-Path -LiteralPath $serviceKey);$i++){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $serviceKey){throw 'RansomGuardV03 registration remained after cleanup.'}
    }

    $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
    if(Test-Path -LiteralPath $driverKey){
        [void](Invoke-Sc @('delete','RansomGuardMinifilter') -AllowNonZero)
        for($i=0;$i -lt 50 -and (Test-Path -LiteralPath $driverKey);$i++){Start-Sleep -Milliseconds 100}
    }
    foreach($publishedInf in @(Get-RansomGuardPublishedInfNames)){
        $out=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0){throw "Unable to remove qualification driver package '$publishedInf'. $out"}
    }
}
function Assert-IncompleteJournal([string]$Journal,[int]$Pid,[long]$Creation,[string]$RequestId){
    $records=@(Get-JournalRecordsForProcess $Journal $Pid $Creation)
    if($records.Count -lt 2){throw 'Incomplete containment request lost its durable journal records.'}
    $phases=@($records | ForEach-Object {[int]$_.phase})
    if($phases -notcontains 1 -or $phases -notcontains 2){throw 'Incomplete containment request lost Prepared or SuspendApplied.'}
    foreach($terminal in @(3,4,5)){
        if($phases -contains $terminal){throw "Incomplete containment request unexpectedly gained terminal phase $terminal."}
    }
    $requests=@($records | ForEach-Object {[string]$_.requestId} | Select-Object -Unique)
    if($requests.Count -ne 1 -or -not [string]::Equals($requests[0],$RequestId,[StringComparison]::Ordinal)){
        throw 'Incomplete containment request identity changed across reboot.'
    }
}
function Invoke-DeniedFixture(
    [string]$Fixture,
    [string]$Canary,
    [string]$FixtureRoot,
    [string]$Journal,
    [DateTimeOffset]$SinceUtc,
    [string]$Label
){
    $casesRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\Incidents'
    $baseline=@(Get-ChildItem -LiteralPath $casesRoot -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $heartbeat=Join-Path $FixtureRoot ($Label+'-heartbeat.txt')
    $readyPath=Join-Path $FixtureRoot ($Label+'-ready.json')
    $resultPath=Join-Path $FixtureRoot ($Label+'-result.json')
    $p=Start-Process -FilePath $Fixture -ArgumentList @('--malicious',$Canary,$heartbeat,$readyPath,$resultPath) -PassThru -WindowStyle Hidden
    $ready=Wait-JsonFile $readyPath 10
    if([int]$ready.pid -ne $p.Id -or [long]$ready.creationFileTimeUtc -le 0){throw "$Label fixture identity mismatch."}
    if(-not $p.WaitForExit(20000)){
        try{$p.Kill($true)}catch{}
        throw "$Label fixture did not exit."
    }
    if($p.ExitCode -ne 0){throw "$Label fixture failed exit=$($p.ExitCode)."}
    $result=Wait-JsonFile $resultPath 3
    if([double]$result.maxHeartbeatGapMs -ge 700){throw "$Label fixture observed a containment-sized heartbeat gap."}

    $incident=Find-IncidentForProcess ([int]$ready.pid) ([long]$ready.creationFileTimeUtc) $baseline 12
    if($null -eq $incident){throw "$Label fixture did not persist an incident."}
    $authorization=Wait-JsonFile (Join-Path $incident.Directory 'authorization.json') 5
    if($authorization.Decision.Eligible -eq $true -or @($authorization.Decision.Reasons) -notcontains 'AutomaticContainmentNotActive'){
        throw "$Label authorization did not fail closed on AutomaticContainmentNotActive."
    }
    $response=Wait-JsonFile (Join-Path $incident.Directory 'response.json') 5
    if([string]$response.Action -ne 'AuditOnly' -or $response.ActuationAttempted -ne $false){
        throw "$Label response was not AuditOnly/no-actuation."
    }
    if(@(Get-JournalRecordsForProcess $Journal ([int]$ready.pid) ([long]$ready.creationFileTimeUtc)).Count -ne 0){
        throw "$Label denied process unexpectedly reached state-change journal."
    }
    return [ordered]@{
        pid=[int]$ready.pid
        creationFileTimeUtc=[long]$ready.creationFileTimeUtc
        incident=$incident.Directory
        auditOnly=$true
    }
}

Assert-Administrator
$vm=Assert-DisposableVm
$ExpectedCommit=$ExpectedCommit.ToLowerInvariant()
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$active=Join-Path $RootBase 'Active'
$qualification=Join-Path $active 'qualification'
$fixture=Join-Path $active 'fixture\RansomGuard.ProductionContainmentE2EFixture.exe'
$statePath=Join-Path $active 'containment-reboot-recovery-campaign.json'
$evidenceRoot=Join-Path (Join-Path $RootBase 'Evidence') $ExpectedCommit
$packageSummary=Join-Path $qualification 'qualification-package.json'
$serviceExe=Join-Path $qualification 'RansomGuard.Service.exe'
$appSettings=Join-Path $qualification 'appsettings.json'
$programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$stateRoot=Join-Path $programData 'RansomGuardV03'
$casesRoot=Join-Path $stateRoot 'Incidents'
$journal=Join-Path $stateRoot 'ContainmentStateChange\containment-state-change-journal.jsonl'
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')

foreach($path in @($qualification,$fixture,$packageSummary,$serviceExe,$appSettings)){
    if(-not(Test-Path -LiteralPath $path)){throw "Persistent campaign input missing: $path"}
    Assert-NoReparsePath $path 'Persistent campaign input'
}
$package=Get-Content -LiteralPath $packageSummary -Raw | ConvertFrom-Json
if([int]$package.schema -ne 1 -or $package.qualificationOnly -ne $true){throw 'Qualification package provenance is invalid.'}
if(-not [string]::Equals([string]$package.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Qualification package commit '$($package.commit)' does not match '$ExpectedCommit'."
}
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

if($Phase -eq 'arm'){
    if(Test-Path -LiteralPath $statePath){throw 'A containment reboot-recovery campaign is already armed.'}
    $existing=Get-CimInstance Win32_Service -Filter "Name='RansomGuardV03'" -ErrorAction SilentlyContinue
    if($existing){throw "REFUSED: RansomGuardV03 already exists before ARM. ImagePath=$($existing.PathName)"}
    Assert-FilterAbsent 'ARM preflight'

    $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
    if(Test-Path -LiteralPath $driverKey -or @(Get-RansomGuardPublishedInfNames).Count -gt 0){
        Cleanup-Qualification $volume
    }
    $priorState=Quarantine-State $stateRoot 'CONTAINMENT-REBOOT-PRIOR'

    $protectedRoot=Join-Path $RootBase ('Protected-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    $armCanary=Join-Path $protectedRoot 'arm-canary.bin'
    $resumeCanary=Join-Path $protectedRoot 'resume-canary.bin'
    $verifyCanary=Join-Path $protectedRoot 'verify-canary.bin'
    [IO.File]::WriteAllText($armCanary,'ransomguard-reboot-arm-original',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($resumeCanary,'ransomguard-reboot-resume-original',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($verifyCanary,'ransomguard-reboot-verify-original',[Text.UTF8Encoding]::new($false))

    $config=Get-Content -LiteralPath $appSettings -Raw | ConvertFrom-Json
    $config.Mode='Enforce'
    $config.ProtectedRoots=@($protectedRoot)
    $config.CanaryFiles=@($armCanary,$resumeCanary,$verifyCanary)
    $config.Enforce.RequireSignedDriver=$true
    $config.Enforce.AutomaticContainment=$true
    $config.Enforce.ContainmentHoldMilliseconds=5000
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

    $started=[DateTimeOffset]::UtcNow
    $binPath='"'+$serviceExe+'"'
    Invoke-Sc @('create','RansomGuardV03','binPath=',$binPath,'start=','demand','obj=','LocalSystem') | Out-Null
    try{
        Invoke-Sc @('start','RansomGuardV03') | Out-Null
        Wait-ServiceState 'RansomGuardV03' 'Running' 30
        [void](Wait-Audit 'Type' 'RollbackStoreReady' $started 75)
        $activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $started 75
        $ready=Wait-Audit 'Type' 'AutomaticContainmentReady' $started 30
        if($ready.Protection.AutomaticContainmentActive -ne $true){throw 'ARM automatic containment did not become active.'}

        $fixtureRoot=Join-Path $evidenceRoot 'arm-fixture'
        New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
        $heartbeat=Join-Path $fixtureRoot 'heartbeat.txt'
        $readyPath=Join-Path $fixtureRoot 'ready.json'
        $resultPath=Join-Path $fixtureRoot 'result.json'
        $target=Start-Process -FilePath $fixture -ArgumentList @('--malicious',$armCanary,$heartbeat,$readyPath,$resultPath) -PassThru -WindowStyle Hidden
        $targetReady=Wait-JsonFile $readyPath 10
        if([int]$targetReady.pid -ne $target.Id -or [long]$targetReady.creationFileTimeUtc -le 0){throw 'ARM fixture identity mismatch.'}

        $suspend=Wait-JournalPhaseForProcess $journal ([int]$targetReady.pid) ([long]$targetReady.creationFileTimeUtc) 2 20
        $beforeHeartbeat=''
        if(Test-Path -LiteralPath $heartbeat -PathType Leaf){$beforeHeartbeat=Get-Content -LiteralPath $heartbeat -Raw}

        $servicePid=Get-ExactServicePid $serviceExe
        Stop-Process -Id $servicePid -Force -ErrorAction Stop
        Wait-ServiceState 'RansomGuardV03' 'Stopped' 20
        Wait-ProcessGone ([int]$activation.GateClientPid) 15
        Assert-FilterPresent 'post-crash ARM fail-safe'

        [void](Wait-HeartbeatAdvance $heartbeat $beforeHeartbeat 8)
        if(-not $target.WaitForExit(20000)){try{$target.Kill($true)}catch{};throw 'ARM fixture did not finish after service crash.'}
        if($target.ExitCode -ne 0){throw "ARM fixture failed exit=$($target.ExitCode)."}
        [void](Wait-JsonFile $resultPath 3)

        Assert-IncompleteJournal $journal ([int]$targetReady.pid) ([long]$targetReady.creationFileTimeUtc) ([string]$suspend.requestId)

        $state=[ordered]@{
            schema=1
            commit=$ExpectedCommit
            phase='armed'
            vm=$vm
            protectedRoot=$protectedRoot
            armCanary=$armCanary
            resumeCanary=$resumeCanary
            verifyCanary=$verifyCanary
            serviceImage=$serviceExe
            journal=$journal
            requestId=[string]$suspend.requestId
            processId=[int]$targetReady.pid
            processCreationFileTimeUtc=[long]$targetReady.creationFileTimeUtc
            armBootUtc=(Get-BootUtc).ToString('o')
            armCompletedUtc=[DateTimeOffset]::UtcNow.ToString('o')
            priorStateQuarantine=$priorState
            failSafeRetainedBeforeReboot=$true
            firstRebootObserved=$false
            firstBootFailClosed=$false
            firstBootAuditOnly=$false
            secondRebootObserved=$false
            idempotentFailClosed=$false
            secondBootAuditOnly=$false
            cleanupPassed=$false
            stateEvidenceQuarantine=$null
            passed=$false
        }
        Write-State $state $statePath
        Save-Summary $state $evidenceRoot
        Write-Host "PRODUCTION-CONTAINMENT-REBOOT-RECOVERY ARM PASS request=$($state.requestId) commit=$ExpectedCommit"
        exit 0
    }catch{
        try{Cleanup-Qualification $volume}catch{}
        throw
    }
}

$state=Read-State $statePath $ExpectedCommit
Assert-ServiceRegistration ([string]$state.serviceImage)
Assert-NoReparsePath ([string]$state.journal) 'Containment state-change journal'

if($Phase -eq 'resume'){
    if([string]$state.phase -ne 'armed'){throw "RESUME requires armed state; found '$($state.phase)'."}
    $currentBoot=Get-BootUtc
    $armBoot=[DateTimeOffset]::Parse([string]$state.armBootUtc)
    if($currentBoot -le $armBoot){throw 'No real VM reboot was observed between ARM and RESUME.'}
    $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction Stop
    if([string]$svc.Status -ne 'Stopped'){throw "Service must be Stopped after reboot; found $($svc.Status)."}
    Assert-FilterAbsent 'RESUME post-reboot pre-start'
    Assert-IncompleteJournal ([string]$state.journal) ([int]$state.processId) ([long]$state.processCreationFileTimeUtc) ([string]$state.requestId)

    $phaseStarted=[DateTimeOffset]::UtcNow
    Invoke-Sc @('start','RansomGuardV03') | Out-Null
    Wait-ServiceState 'RansomGuardV03' 'Running' 30
    $blocked=Wait-Audit 'Type' 'AutomaticContainmentUnavailable' $phaseStarted 90
    if([string]$blocked.Reason -ne 'IncompleteStateChangeSessionsRequireReview' -or
       [int]$blocked.IncompleteSessions -lt 1 -or $blocked.Protection.AutomaticContainmentActive -eq $true){
        throw 'First reboot did not restore incomplete-session fail-closed containment readiness.'
    }
    $activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $phaseStarted 90
    if([string]$activation.Protection.State -ne 'Protected' -or
       $activation.Protection.KernelEnforcementActive -ne $true -or
       $activation.Protection.KernelChannelConnected -ne $true -or
       $activation.Protection.AutomaticContainmentActive -eq $true){
        throw 'First reboot did not restore kernel protection with automatic containment disabled.'
    }
    if(@(Get-AuditEntries $phaseStarted | Where-Object {$_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'AutomaticContainmentReady'}).Count -ne 0){
        throw 'AutomaticContainmentReady was published after first reboot despite incomplete state-change evidence.'
    }

    $fixtureRoot=Join-Path $evidenceRoot 'resume-fixture'
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $denied=Invoke-DeniedFixture $fixture ([string]$state.resumeCanary) $fixtureRoot ([string]$state.journal) $phaseStarted 'resume'

    Invoke-Sc @('stop','RansomGuardV03') | Out-Null
    Wait-ServiceState 'RansomGuardV03' 'Stopped' 60
    $maintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $phaseStarted 20 -AllowStopped
    if([string]$maintenance.Protection.State -ne 'Maintenance'){throw 'RESUME clean stop did not publish Maintenance.'}
    Assert-FilterAbsent 'RESUME clean stop'
    Assert-IncompleteJournal ([string]$state.journal) ([int]$state.processId) ([long]$state.processCreationFileTimeUtc) ([string]$state.requestId)

    $state.phase='recovered'
    $state.firstRebootObserved=$true
    $state.firstBootFailClosed=$true
    $state.firstBootAuditOnly=$true
    $state.resumeFixture=$denied
    $state.resumeBootUtc=$currentBoot.ToString('o')
    $state.resumeCompletedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    Write-State $state $statePath
    Save-Summary $state $evidenceRoot
    Write-Host "PRODUCTION-CONTAINMENT-REBOOT-RECOVERY RESUME PASS request=$($state.requestId) commit=$ExpectedCommit"
    exit 0
}

if([string]$state.phase -ne 'recovered'){throw "VERIFY requires recovered state; found '$($state.phase)'."}
$currentBoot=Get-BootUtc
$resumeBoot=[DateTimeOffset]::Parse([string]$state.resumeBootUtc)
if($currentBoot -le $resumeBoot){throw 'No second real VM reboot was observed between RESUME and VERIFY.'}
$svc=Get-Service -Name 'RansomGuardV03' -ErrorAction Stop
if([string]$svc.Status -ne 'Stopped'){throw "Service must be Stopped after second reboot; found $($svc.Status)."}
Assert-FilterAbsent 'VERIFY post-reboot pre-start'
Assert-IncompleteJournal ([string]$state.journal) ([int]$state.processId) ([long]$state.processCreationFileTimeUtc) ([string]$state.requestId)

$phaseStarted=[DateTimeOffset]::UtcNow
Invoke-Sc @('start','RansomGuardV03') | Out-Null
Wait-ServiceState 'RansomGuardV03' 'Running' 30
$blocked=Wait-Audit 'Type' 'AutomaticContainmentUnavailable' $phaseStarted 90
if([string]$blocked.Reason -ne 'IncompleteStateChangeSessionsRequireReview' -or
   [int]$blocked.IncompleteSessions -lt 1 -or $blocked.Protection.AutomaticContainmentActive -eq $true){
    throw 'Second reboot did not preserve incomplete-session fail-closed containment readiness.'
}
$activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $phaseStarted 90
if([string]$activation.Protection.State -ne 'Protected' -or
   $activation.Protection.KernelEnforcementActive -ne $true -or
   $activation.Protection.KernelChannelConnected -ne $true -or
   $activation.Protection.AutomaticContainmentActive -eq $true){
    throw 'Second reboot did not preserve kernel protection with automatic containment disabled.'
}
if(@(Get-AuditEntries $phaseStarted | Where-Object {$_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'AutomaticContainmentReady'}).Count -ne 0){
    throw 'AutomaticContainmentReady was published after second reboot despite incomplete state-change evidence.'
}

$fixtureRoot=Join-Path $evidenceRoot 'verify-fixture'
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$denied=Invoke-DeniedFixture $fixture ([string]$state.verifyCanary) $fixtureRoot ([string]$state.journal) $phaseStarted 'verify'

Invoke-Sc @('stop','RansomGuardV03') | Out-Null
Wait-ServiceState 'RansomGuardV03' 'Stopped' 60
$maintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $phaseStarted 20 -AllowStopped
if([string]$maintenance.Protection.State -ne 'Maintenance'){throw 'VERIFY clean stop did not publish Maintenance.'}
Assert-FilterAbsent 'VERIFY clean stop'
Assert-IncompleteJournal ([string]$state.journal) ([int]$state.processId) ([long]$state.processCreationFileTimeUtc) ([string]$state.requestId)

$state.phase='complete'
$state.secondRebootObserved=$true
$state.idempotentFailClosed=$true
$state.secondBootAuditOnly=$true
$state.verifyFixture=$denied
$state.verifyBootUtc=$currentBoot.ToString('o')
$state.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')

# Preserve exact journal/head and audit before final qualification cleanup.
Copy-Item -LiteralPath ([string]$state.journal) -Destination (Join-Path $evidenceRoot 'containment-state-change-journal.final.jsonl') -Force
$journalHead=Join-Path (Split-Path -Parent ([string]$state.journal)) 'containment-state-change-journal.head.json'
if(Test-Path -LiteralPath $journalHead -PathType Leaf){
    Copy-Item -LiteralPath $journalHead -Destination (Join-Path $evidenceRoot 'containment-state-change-journal.head.final.json') -Force
}
Get-AuditEntries ([DateTimeOffset]::Parse([string]$state.armCompletedUtc).AddMinutes(-5)) |
    ConvertTo-Json -Depth 30 |
    Set-Content -LiteralPath (Join-Path $evidenceRoot 'production-containment-reboot-recovery-audit.json') -Encoding utf8

Cleanup-Qualification $volume
$state.stateEvidenceQuarantine=Quarantine-State $stateRoot 'CONTAINMENT-REBOOT-EVIDENCE'
$state.cleanupPassed=$true
$state.passed=$true
Write-State $state $statePath
Save-Summary $state $evidenceRoot
Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceRoot 'campaign-state-final.json') -Force
Copy-Item -LiteralPath ($statePath+'.sha256') -Destination (Join-Path $evidenceRoot 'campaign-state-final.json.sha256') -Force

foreach($path in @($qualification,(Split-Path -Parent $fixture))){
    if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}
}
Remove-Item -LiteralPath $statePath -Force
Remove-Item -LiteralPath ($statePath+'.sha256') -Force

Write-Host "PRODUCTION-CONTAINMENT-REBOOT-RECOVERY VERIFY PASS request=$($state.requestId) commit=$ExpectedCommit evidence=$evidenceRoot"
