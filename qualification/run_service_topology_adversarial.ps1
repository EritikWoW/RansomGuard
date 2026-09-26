param(
    [Parameter(Mandatory=$true)][string]$QualificationDirectory,
    [Parameter(Mandatory=$true)][string]$RuntimeHelperExe,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ServiceTopology',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Service topology qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: service topology qualification requires an obvious disposable VM. Detected: $vmText"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required.'
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

function Quote-Arg([string]$Value){return '"' + $Value.Replace('"','\"') + '"'}

function Start-LoggedProcess([string]$FilePath,[string[]]$Arguments,[string]$StdOut,[string]$StdErr){
    foreach($path in @($StdOut,$StdErr)){
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        $parent=Split-Path -Parent $path
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    }
    return Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Stop-ProcessHard([System.Diagnostics.Process]$Process,[string]$Label){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Label pid=$($Process.Id)."}
}

function Wait-Path([string]$Path,[int]$Seconds,[string]$Label){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){return}
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Label at $Path"
}


function Test-SafeMutationRejection([Exception]$Exception){
    $cursor=$Exception
    while($null -ne $cursor){
        if($cursor -is [UnauthorizedAccessException]){return $true}
        $code=([int]$cursor.HResult -band 0xFFFF)
        if($code -in @(5,32,1224)){return $true}
        $cursor=$cursor.InnerException
    }
    return $false
}

function Wait-JournalMatch(
    [string]$Path,
    [scriptblock]$Predicate,
    [int]$Seconds,
    [string]$Label
){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            foreach($line in Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue){
                if([string]::IsNullOrWhiteSpace($line)){continue}
                try{$obj=$line | ConvertFrom-Json -Depth 30}catch{continue}
                if(& $Predicate $obj){return $obj}
            }
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for $Label in $Path"
}

function New-ControlledWritableMap([string]$Path){
    $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,$share)
    try{
        $mmf=[IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
            $stream,$null,0,
            [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
            [IO.HandleInheritability]::None,
            $true)
        try{
            $view=$mmf.CreateViewAccessor(0,0,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
            return [pscustomobject]@{Stream=$stream;Mapping=$mmf;View=$view}
        }catch{
            $mmf.Dispose()
            throw
        }
    }catch{
        $stream.Dispose()
        throw
    }
}

function Close-ControlledWritableMap($Mapping){
    if($null -eq $Mapping){return}
    try{if($Mapping.View){$Mapping.View.Dispose()}}catch{}
    try{if($Mapping.Mapping){$Mapping.Mapping.Dispose()}}catch{}
    try{if($Mapping.Stream){$Mapping.Stream.Dispose()}}catch{}
}

function Assert-MappedBaseline(
    [string]$Session,
    [string]$File,
    [string]$OriginalHash,
    [string]$Label
){
    $sessionRoot=Join-Path (Join-Path $stateRoot 'Rollback\Sessions') $Session
    $sectionJournal=Join-Path $sessionRoot 'section-state\writable-section-journal.jsonl'
    $null=Wait-JournalMatch $sectionJournal {
        param($x)
        [int]$x.state -eq 1 -and
        [string]::Equals([IO.Path]::GetFullPath([string]$x.trackedPath),[IO.Path]::GetFullPath($File),[StringComparison]::OrdinalIgnoreCase)
    } 30 "$Label BaselineVerified writable-section evidence"

    $rollbackJournal=Join-Path $sessionRoot 'journal.jsonl'
    $capture=Wait-JournalMatch $rollbackJournal {
        param($x)
        [string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),[IO.Path]::GetFullPath($File),[StringComparison]::OrdinalIgnoreCase)
    } 30 "$Label full pre-image evidence"

    if(-not [string]::Equals([string]$capture.originalSha256,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Label pre-image hash mismatch. expected=$OriginalHash actual=$($capture.originalSha256)"
    }
    $snapshot=Join-Path $sessionRoot ([string]$capture.snapshotRelativePath)
    if(-not(Test-Path -LiteralPath $snapshot -PathType Leaf)){throw "$Label pre-image object is missing: $snapshot"}
    $snapshotHash=(Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
    if(-not [string]::Equals($snapshotHash,$OriginalHash,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Label snapshot hash mismatch. expected=$OriginalHash actual=$snapshotHash"
    }
    return [pscustomobject]@{SessionRoot=$sessionRoot;Capture=$capture;Snapshot=$snapshot;SnapshotHash=$snapshotHash}
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

$stateRoot=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'))
$auditPath=Join-Path $stateRoot 'audit.jsonl'

function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    if(-not(Test-Path -LiteralPath $auditPath -PathType Leaf)){return @()}
    $entries=@()
    foreach($line in Get-Content -LiteralPath $auditPath -ErrorAction SilentlyContinue){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{
            $item=$line | ConvertFrom-Json -Depth 20
            if($null -eq $item.Utc){continue}
            if((Convert-AuditUtc $item.Utc) -ge $SinceUtc){$entries += $item}
        }catch{}
    }
    return $entries
}

function Wait-AuditType([string]$Type,[DateTimeOffset]$SinceUtc,[int]$Seconds,[string]$ExpectedSession=''){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-AuditEntries $SinceUtc | Where-Object {
            $typeProp=$_.PSObject.Properties['Type']
            if($null -eq $typeProp -or [string]$typeProp.Value -ne $Type){return $false}
            if([string]::IsNullOrWhiteSpace($ExpectedSession)){return $true}
            $sessionProp=$_.PSObject.Properties['Session']
            return $null -ne $sessionProp -and [string]$sessionProp.Value -eq $ExpectedSession
        })
        if($matches.Count -gt 0){return $matches[-1]}
        Start-Sleep -Milliseconds 200
    }
    $recent=@(Get-AuditEntries $SinceUtc | Select-Object -Last 10 | ForEach-Object {
        if($_.PSObject.Properties['Type']){[string]$_.Type}else{'<untyped>'}
    })
    throw "Timed out waiting for audit Type='$Type'. Recent=$($recent -join ' -> ')"
}

function Wait-ServiceState([string]$State,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
        if($svc -and [string]$svc.Status -eq $State){return}
        Start-Sleep -Milliseconds 200
    }
    $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
    throw "Timed out waiting for RansomGuardV03 state '$State'. Current=$(if($svc){$svc.Status}else{'missing'})"
}

function Invoke-Sc([string[]]$Arguments,[switch]$AllowNonZero){
    $output=(& sc.exe @Arguments 2>&1 | Out-String)
    $exit=$LASTEXITCODE
    if(-not $AllowNonZero -and $exit -ne 0){throw "sc.exe $($Arguments -join ' ') failed exit=$exit. $output"}
    return [pscustomobject]@{ExitCode=$exit;Output=$output}
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

function Reset-StateRoot {
    if(Test-Path -LiteralPath $stateRoot){
        Assert-NoReparsePath $stateRoot 'StateRoot'
        Remove-Item -LiteralPath $stateRoot -Recurse -Force
    }
}

function Cleanup-OwnedState([string]$ProtectedRoot){
    $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardV03'
    if(Test-Path -LiteralPath $serviceKey){
        $props=Get-ItemProperty -LiteralPath $serviceKey
        $image=[string]$props.ImagePath
        $expected=[IO.Path]::GetFullPath($serviceExe)
        $normalized=$image.Trim().Trim('"')
        if(-not [string]::Equals($normalized,$expected,[StringComparison]::OrdinalIgnoreCase)){
            throw "REFUSED: existing RansomGuardV03 service is not owned by this qualification package. image='$image' expected='$expected'"
        }
    }

    $svc=Get-Service -Name 'RansomGuardV03' -ErrorAction SilentlyContinue
    if($svc -and $svc.Status -ne 'Stopped'){
        try{Invoke-Sc @('stop','RansomGuardV03') -AllowNonZero | Out-Null}catch{}
        try{Wait-ServiceState 'Stopped' 30}catch{}
    }
    if(Test-Path -LiteralPath $serviceKey){
        Invoke-Sc @('delete','RansomGuardV03') -AllowNonZero | Out-Null
        for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $serviceKey);$i++){Start-Sleep -Milliseconds 100}
    }

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -eq 0 -and $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        & fltmc unload RansomGuardMinifilter 2>$null | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Unable to unload RansomGuardMinifilter during qualification cleanup.'}
    }
    if(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'){
        Invoke-Sc @('delete','RansomGuardMinifilter') -AllowNonZero | Out-Null
        for($i=0;$i -lt 30 -and (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter');$i++){Start-Sleep -Milliseconds 100}
    }
    foreach($publishedInf in @(Get-RansomGuardPublishedInfNames)){
        $out=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0){throw "Unable to remove qualification driver package '$publishedInf'. $out"}
    }

    $filtersAfter=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filtersAfter -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter remained loaded after qualification cleanup.'
    }

    if($ProtectedRoot -and (Test-Path -LiteralPath $ProtectedRoot -PathType Container)){
        Remove-Item -LiteralPath $ProtectedRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Reset-StateRoot
}

function Configure-Package([string]$Root){
    $config=Get-Content -LiteralPath $appSettings -Raw | ConvertFrom-Json
    $config.Mode='Enforce'
    $config.ProtectedRoots=@($Root)
    $config.CanaryFiles=@()
    $config.Enforce.RequireSignedDriver=$true
    $config.Enforce.AutomaticContainment=$false
    $config.Enforce.StartupTimeoutSeconds=45
    $config.Enforce.GateWorkers=4
    $config.Enforce.RollbackMaxStoreMiB=8192
    $config.Enforce.RollbackMinFreeMiB=256
    $config.Enforce.ReconnectDelaySeconds=5
    $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $appSettings -Encoding utf8
}

function Start-OwnedService {
    $binPath='"'+$serviceExe+'"'
    Invoke-Sc @('create','RansomGuardV03','binPath=',$binPath,'start=','demand','obj=','LocalSystem') | Out-Null
    Invoke-Sc @('start','RansomGuardV03') | Out-Null
}

function Assert-NoActivation([DateTimeOffset]$SinceUtc,[string]$Label){
    $activated=@(Get-AuditEntries $SinceUtc | Where-Object {
        $_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'ProductionProtectionActivated'
    })
    if($activated.Count -gt 0){throw "$Label unexpectedly published ProductionProtectionActivated."}
}

function Run-StartupRejectionScenario([string]$Kind,[string]$Root,[string]$File){
    Cleanup-OwnedState $Root
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    [IO.File]::WriteAllBytes($File,(0..255 | ForEach-Object {[byte]$_}))
    Configure-Package $Root

    $ready=Join-Path $ResultsDirectory "$Kind.ready"
    $release=Join-Path $ResultsDirectory "$Kind.release"
    $out=Join-Path $ResultsDirectory "$Kind-holder.out.log"
    $err=Join-Path $ResultsDirectory "$Kind-holder.err.log"
    $command=if($Kind -eq 'preexisting-handle'){'hold-write-handle'}else{'hold-map'}
    $holder=Start-LoggedProcess $RuntimeHelperExe @(
        $command,'--file',(Quote-Arg $File),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) $out $err
    try{
        Wait-Path $ready 20 "$Kind holder readiness"
        $started=[DateTimeOffset]::UtcNow
        Start-OwnedService
        $failure=Wait-AuditType 'ProductionLifecycleStartupFailed' $started 75
        if([string]::IsNullOrWhiteSpace([string]$failure.Session)){throw "$Kind startup failure did not retain a session id."}
        Assert-NoActivation $started $Kind
        Wait-ServiceState 'Stopped' 30
    }finally{
        New-Item -ItemType File -Path $release -Force | Out-Null
        if(-not $holder.WaitForExit(15000)){Stop-ProcessHard $holder "$Kind holder"}
        if($holder.HasExited -and $holder.ExitCode -ne 0){throw "$Kind holder failed exit=$($holder.ExitCode)."}
        Cleanup-OwnedState $Root
    }
}

Assert-Administrator
$vm=Assert-DisposableVm

$QualificationDirectory=[IO.Path]::GetFullPath($QualificationDirectory)
$RuntimeHelperExe=[IO.Path]::GetFullPath($RuntimeHelperExe)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
if(-not(Test-Path -LiteralPath $RuntimeHelperExe -PathType Leaf)){throw "Runtime helper missing: $RuntimeHelperExe"}
$packageSummary=Join-Path $QualificationDirectory 'qualification-package.json'
$serviceExe=Join-Path $QualificationDirectory 'RansomGuard.Service.exe'
$appSettings=Join-Path $QualificationDirectory 'appsettings.json'
foreach($required in @($packageSummary,$serviceExe,$appSettings)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Qualification input missing: $required"}
}
$package=Get-Content -LiteralPath $packageSummary -Raw | ConvertFrom-Json
if([int]$package.schema -ne 1 -or $package.qualificationOnly -ne $true){throw 'Qualification package provenance is invalid.'}
if(-not [string]::Equals([string]$package.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Qualification package commit '$($package.commit)' does not match expected '$ExpectedCommit'."
}

if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) ('RansomGuard-ServiceTopology-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'
Assert-NoReparsePath $RootBase 'RootBase'

$summary=[ordered]@{
    schema=1
    frozenCandidateSha=$ExpectedCommit.ToLowerInvariant()
    vm=$vm
    preexistingWritableHandleLifecycleRejected=$false
    preexistingWritableMappingLifecycleRejected=$false
    reconnectMappingPreflightRejected=$false
    degradedMutationDeniedWhileReconnectBlocked=$false
    degradedMutationPreservedHash=$false
    reconnectAfterMappingReleaseProtected=$false
    reconnectSessionPreserved=$false
    mappedLossBaselineVerified=$false
    mappedLossFailSafe=$false
    mappedLossReconnectBlocked=$false
    mappedLossReconnectProtected=$false
    mappedLossSessionPreserved=$false
    mappingRenameFailSafe=$false
    mappingTruncateFailSafe=$false
    mappingDeleteFailSafe=$false
    cleanupPassed=$false
    passed=$false
    startedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    completedUtc=$null
    error=$null
}

$runtimeFailure=$null
try{
    $handleRoot=Join-Path $RootBase 'preexisting-handle'
    $handleFile=Join-Path $handleRoot 'target.bin'
    Run-StartupRejectionScenario 'preexisting-handle' $handleRoot $handleFile
    $summary.preexistingWritableHandleLifecycleRejected=$true

    $mappingRoot=Join-Path $RootBase 'preexisting-mapping'
    $mappingFile=Join-Path $mappingRoot 'target.bin'
    Run-StartupRejectionScenario 'preexisting-mapping' $mappingRoot $mappingFile
    $summary.preexistingWritableMappingLifecycleRejected=$true

    $reconnectRoot=Join-Path $RootBase 'reconnect-mapping'
    Cleanup-OwnedState $reconnectRoot
    New-Item -ItemType Directory -Path $reconnectRoot -Force | Out-Null
    $reconnectFile=Join-Path $reconnectRoot 'target.bin'
    $bytes=New-Object byte[] 65536
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*29+7)%251)}
    [IO.File]::WriteAllBytes($reconnectFile,$bytes)
    Configure-Package $reconnectRoot

    $started=[DateTimeOffset]::UtcNow
    Start-OwnedService
    Wait-ServiceState 'Running' 30
    $first=Wait-AuditType 'ProductionProtectionActivated' $started 75
    if([string]$first.Root -ne $reconnectRoot){throw 'Initial reconnect scenario activation root mismatch.'}
    if([int]$first.GateClientPid -le 0){throw 'Initial reconnect scenario activation did not report GateClient PID.'}
    $session=[string]$first.Session

    Stop-Process -Id ([int]$first.GateClientPid) -Force -ErrorAction Stop
    $lost=Wait-AuditType 'ProductionGateLost' $started 30 $session

    $ready=Join-Path $ResultsDirectory 'reconnect-map.ready'
    $release=Join-Path $ResultsDirectory 'reconnect-map.release'
    $holderOut=Join-Path $ResultsDirectory 'reconnect-map-holder.out.log'
    $holderErr=Join-Path $ResultsDirectory 'reconnect-map-holder.err.log'
    $holder=Start-LoggedProcess $RuntimeHelperExe @(
        'hold-map','--file',(Quote-Arg $reconnectFile),'--ready',(Quote-Arg $ready),'--release',(Quote-Arg $release)
    ) $holderOut $holderErr
    try{
        Wait-Path $ready 20 'reconnect writable mapping'
        $failure=Wait-AuditType 'ProductionLifecycleStartupFailed' (Convert-AuditUtc $lost.Utc) 45 $session
        $summary.reconnectMappingPreflightRejected=$true

        $before=(Get-FileHash -LiteralPath $reconnectFile -Algorithm SHA256).Hash
        $denied=$false
        try{
            $fs=[IO.File]::Open($reconnectFile,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
            try{$fs.WriteByte(0x5A);$fs.Flush($true)}finally{$fs.Dispose()}
        }catch{
            $cursor=$_.Exception
            while($null -ne $cursor){
                if($cursor -is [UnauthorizedAccessException] -or (([int]$cursor.HResult -band 0xFFFF) -eq 5)){$denied=$true;break}
                $cursor=$cursor.InnerException
            }
            if(-not $denied){throw}
        }
        if(-not $denied){throw 'Mutation unexpectedly succeeded while reconnect preflight was blocked by writable mapping.'}
        $summary.degradedMutationDeniedWhileReconnectBlocked=$true
        $after=(Get-FileHash -LiteralPath $reconnectFile -Algorithm SHA256).Hash
        if(-not [string]::Equals($before,$after,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Protected content changed while reconnect remained blocked in DegradedProtected.'
        }
        $summary.degradedMutationPreservedHash=$true
    }finally{
        New-Item -ItemType File -Path $release -Force | Out-Null
        if(-not $holder.WaitForExit(15000)){Stop-ProcessHard $holder 'reconnect map holder'}
        if($holder.HasExited -and $holder.ExitCode -ne 0){throw "Reconnect map holder failed exit=$($holder.ExitCode)."}
    }

    $second=Wait-AuditType 'ProductionProtectionActivated' (Convert-AuditUtc $lost.Utc) 75 $session
    if([string]$second.Session -ne $session){throw 'Reconnect after mapping release changed rollback session.'}
    if([string]$second.Root -ne $reconnectRoot){throw 'Reconnect after mapping release changed protected root.'}
    if([string]$second.Protection.State -ne 'Protected' -or $second.Protection.KernelEnforcementActive -ne $true -or $second.Protection.KernelChannelConnected -ne $true){
        throw 'Reconnect after mapping release did not return to Protected with connected kernel enforcement.'
    }
    $summary.reconnectSessionPreserved=$true
    $summary.reconnectAfterMappingReleaseProtected=$true

    # Scenario: create a writable mapping while fully protected, then lose GateClient,
    # dirty+flush that already-authorized section while the kernel is degraded, prove the
    # durable full pre-image remains valid, and require reconnect preflight to stay blocked
    # until the writable mapping is released.
    $lossFile=Join-Path $reconnectRoot 'mapped-loss.bin'
    $lossBytes=New-Object byte[] 65536
    for($i=0;$i -lt $lossBytes.Length;$i++){$lossBytes[$i]=[byte](($i*41+13)%251)}
    [IO.File]::WriteAllBytes($lossFile,$lossBytes)
    $lossOriginalHash=(Get-FileHash -LiteralPath $lossFile -Algorithm SHA256).Hash
    $lossMap=$null
    try{
        $lossMap=New-ControlledWritableMap $lossFile
        $null=Assert-MappedBaseline $session $lossFile $lossOriginalHash 'mapped-loss'
        $summary.mappedLossBaselineVerified=$true

        $activeBeforeLoss=@(Get-AuditEntries ([DateTimeOffset]::UtcNow.AddMinutes(-2)) | Where-Object {
            $_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'ProductionProtectionActivated' -and
            $_.PSObject.Properties['Session'] -and [string]$_.Session -eq $session
        } | Select-Object -Last 1)
        if($activeBeforeLoss.Count -ne 1 -or [int]$activeBeforeLoss[0].GateClientPid -le 0){
            throw 'Unable to resolve active GateClient PID for mapped-loss scenario.'
        }

        $lossStarted=[DateTimeOffset]::UtcNow
        Stop-Process -Id ([int]$activeBeforeLoss[0].GateClientPid) -Force -ErrorAction Stop
        $lossEvent=Wait-AuditType 'ProductionGateLost' $lossStarted 30 $session

        $payload=[Text.Encoding]::ASCII.GetBytes('RANSOMGUARD-MAPPED-LOSS-FLUSH-V1')
        $writeRejected=$false
        try{
            $lossMap.View.WriteArray(0,$payload,0,$payload.Length)
            $lossMap.View.Flush()
            $lossMap.Stream.Flush($true)
        }catch{
            if(Test-SafeMutationRejection $_.Exception){$writeRejected=$true}else{throw}
        }

        # Reconnect must not re-activate while this writable section remains mapped.
        $null=Wait-AuditType 'ProductionLifecycleStartupFailed' (Convert-AuditUtc $lossEvent.Utc) 45 $session
        $summary.mappedLossReconnectBlocked=$true

        $lossAfterHash=(Get-FileHash -LiteralPath $lossFile -Algorithm SHA256).Hash
        $null=Assert-MappedBaseline $session $lossFile $lossOriginalHash 'mapped-loss-postflush'
        if($writeRejected){
            if(-not [string]::Equals($lossAfterHash,$lossOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Mapped-loss write was rejected but protected content changed.'
            }
        }
        $summary.mappedLossFailSafe=$true
    }finally{
        Close-ControlledWritableMap $lossMap
    }

    $lossReconnect=Wait-AuditType 'ProductionProtectionActivated' ([DateTimeOffset]::UtcNow.AddMinutes(-2)) 75 $session
    if([string]$lossReconnect.Session -ne $session){throw 'Mapped-loss reconnect changed rollback session.'}
    if([string]$lossReconnect.Root -ne $reconnectRoot){throw 'Mapped-loss reconnect changed protected root.'}
    if([string]$lossReconnect.Protection.State -ne 'Protected' -or
       $lossReconnect.Protection.KernelEnforcementActive -ne $true -or
       $lossReconnect.Protection.KernelChannelConnected -ne $true){
        throw 'Mapped-loss reconnect did not return to Protected with kernel enforcement connected.'
    }
    $summary.mappedLossSessionPreserved=$true
    $summary.mappedLossReconnectProtected=$true

    # Mapping + rename. Either the operation is safely rejected with the original path/hash
    # intact, or it succeeds only after the already-mapped file has a durable full pre-image.
    $renameFile=Join-Path $reconnectRoot 'mapped-rename.bin'
    $renameDest=Join-Path $reconnectRoot 'mapped-rename-destination.bin'
    [IO.File]::WriteAllBytes($renameFile,$lossBytes)
    $renameOriginalHash=(Get-FileHash -LiteralPath $renameFile -Algorithm SHA256).Hash
    $renameMap=$null
    try{
        $renameMap=New-ControlledWritableMap $renameFile
        $null=Assert-MappedBaseline $session $renameFile $renameOriginalHash 'mapping-rename'
        $renameRejected=$false
        try{[IO.File]::Move($renameFile,$renameDest,$false)}
        catch{
            if(Test-SafeMutationRejection $_.Exception){$renameRejected=$true}else{throw}
        }
        if($renameRejected){
            if(-not(Test-Path -LiteralPath $renameFile -PathType Leaf) -or (Test-Path -LiteralPath $renameDest)){
                throw 'Rejected mapping+rename changed namespace state.'
            }
            if(-not [string]::Equals((Get-FileHash -LiteralPath $renameFile -Algorithm SHA256).Hash,$renameOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Rejected mapping+rename changed protected content.'
            }
        }else{
            if(Test-Path -LiteralPath $renameFile){throw 'Successful mapping+rename left the source path present.'}
            if(-not(Test-Path -LiteralPath $renameDest -PathType Leaf)){throw 'Successful mapping+rename did not create destination path.'}
            if(-not [string]::Equals((Get-FileHash -LiteralPath $renameDest -Algorithm SHA256).Hash,$renameOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Successful mapping+rename changed file content unexpectedly.'
            }
        }
        $summary.mappingRenameFailSafe=$true
    }finally{
        Close-ControlledWritableMap $renameMap
    }

    # Mapping + truncate/EOF. The platform may reject truncation of a user-mapped file
    # (ERROR_USER_MAPPED_FILE); otherwise a durable pre-image must already exist.
    $truncateFile=Join-Path $reconnectRoot 'mapped-truncate.bin'
    [IO.File]::WriteAllBytes($truncateFile,$lossBytes)
    $truncateOriginalHash=(Get-FileHash -LiteralPath $truncateFile -Algorithm SHA256).Hash
    $truncateOriginalLength=(Get-Item -LiteralPath $truncateFile).Length
    $truncateMap=$null
    try{
        $truncateMap=New-ControlledWritableMap $truncateFile
        $null=Assert-MappedBaseline $session $truncateFile $truncateOriginalHash 'mapping-truncate'
        $truncateRejected=$false
        try{
            $truncateMap.Stream.SetLength([int64]($truncateOriginalLength/2))
            $truncateMap.Stream.Flush($true)
        }catch{
            if(Test-SafeMutationRejection $_.Exception){$truncateRejected=$true}else{throw}
        }
        if($truncateRejected){
            if((Get-Item -LiteralPath $truncateFile).Length -ne $truncateOriginalLength){
                throw 'Rejected mapping+truncate changed file length.'
            }
            if(-not [string]::Equals((Get-FileHash -LiteralPath $truncateFile -Algorithm SHA256).Hash,$truncateOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Rejected mapping+truncate changed protected content.'
            }
        }else{
            if((Get-Item -LiteralPath $truncateFile).Length -ne [int64]($truncateOriginalLength/2)){
                throw 'Successful mapping+truncate did not produce the requested EOF.'
            }
        }
        $summary.mappingTruncateFailSafe=$true
    }finally{
        Close-ControlledWritableMap $truncateMap
    }

    # Mapping + delete disposition. If deletion is accepted, the full pre-image must already
    # be durable; if Windows/filter rejects it, the original path/hash must remain intact.
    $deleteFile=Join-Path $reconnectRoot 'mapped-delete.bin'
    [IO.File]::WriteAllBytes($deleteFile,$lossBytes)
    $deleteOriginalHash=(Get-FileHash -LiteralPath $deleteFile -Algorithm SHA256).Hash
    $deleteMap=$null
    $deleteRejected=$false
    try{
        $deleteMap=New-ControlledWritableMap $deleteFile
        $null=Assert-MappedBaseline $session $deleteFile $deleteOriginalHash 'mapping-delete'
        try{[IO.File]::Delete($deleteFile)}
        catch{
            if(Test-SafeMutationRejection $_.Exception){$deleteRejected=$true}else{throw}
        }
        if($deleteRejected){
            if(-not(Test-Path -LiteralPath $deleteFile -PathType Leaf)){
                throw 'Rejected mapping+delete removed the protected pathname.'
            }
            if(-not [string]::Equals((Get-FileHash -LiteralPath $deleteFile -Algorithm SHA256).Hash,$deleteOriginalHash,[StringComparison]::OrdinalIgnoreCase)){
                throw 'Rejected mapping+delete changed protected content.'
            }
        }
    }finally{
        Close-ControlledWritableMap $deleteMap
    }
    if(-not $deleteRejected -and (Test-Path -LiteralPath $deleteFile)){
        # Delete may be pending until the mapped section is released; give cleanup a bounded window.
        for($i=0;$i -lt 50 -and (Test-Path -LiteralPath $deleteFile);$i++){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $deleteFile){throw 'Successful mapping+delete remained present after mapped-section release.'}
    }
    $summary.mappingDeleteFailSafe=$true

    Invoke-Sc @('stop','RansomGuardV03') | Out-Null
    Wait-ServiceState 'Stopped' 60
    Cleanup-OwnedState $reconnectRoot
    $summary.cleanupPassed=$true
    $summary.passed=$true
}catch{
    $runtimeFailure=$_
    $summary.error=$_.Exception.Message
    try{Cleanup-OwnedState ''}catch{}
}finally{
    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'service-topology-result.json') -Encoding utf8
}

if($runtimeFailure){throw $runtimeFailure}
if(-not $summary.passed){throw 'Service topology qualification did not pass.'}
Write-Host "SERVICE TOPOLOGY QUALIFICATION PASSED: $ResultsDirectory" -ForegroundColor Green
