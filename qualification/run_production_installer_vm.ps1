[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AdminHelper,
    [Parameter(Mandatory=$true)][string]$QualificationDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionInstaller',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production installer qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production installer qualification requires an obvious disposable VM. Detected: $text"
    }
    if($env:RANSOMGUARD_LAB_VM -cne 'I_UNDERSTAND'){
        throw 'REFUSED: RANSOMGUARD_LAB_VM=I_UNDERSTAND is required inside the disposable VM.'
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
            throw "$Label must not traverse a reparse point: $cursor"
        }
    }
}

function Invoke-Helper([string[]]$Arguments){
    $output=(& $AdminHelper @Arguments 2>&1 | Out-String).Trim()
    $exit=$LASTEXITCODE
    if($exit -ne 0){throw "Administration helper failed exit=$exit args='$($Arguments -join ' ')'. $output"}
    if([string]::IsNullOrWhiteSpace($output)){return $null}
    try{return $output | ConvertFrom-Json -Depth 100}
    catch{throw "Administration helper returned non-JSON output. $output"}
}

function Convert-AuditUtc($Value){
    if($Value -is [DateTimeOffset]){return [DateTimeOffset]$Value}
    if($Value -is [DateTime]){
        $date=[DateTime]$Value
        if($date.Kind -eq [DateTimeKind]::Unspecified){$date=[DateTime]::SpecifyKind($date,[DateTimeKind]::Utc)}
        return [DateTimeOffset]$date
    }
    return [DateTimeOffset]::Parse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind)
}

function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $state=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
    $paths=@(
        (Join-Path $state 'audit.jsonl'),
        (Join-Path $state 'audit.1.jsonl'),
        (Join-Path $state 'audit.2.jsonl'),
        (Join-Path $state 'audit.3.jsonl')
    )
    $items=@()
    foreach($path in $paths){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        Assert-NoReparsePath $path 'Audit evidence'
        foreach($line in Get-Content -LiteralPath $path -ErrorAction SilentlyContinue){
            if([string]::IsNullOrWhiteSpace($line)){continue}
            try{
                $item=$line | ConvertFrom-Json
                if($item.PSObject.Properties['Utc'] -and (Convert-AuditUtc $item.Utc) -ge $SinceUtc){$items += $item}
            }catch{}
        }
    }
    return @($items | Sort-Object {Convert-AuditUtc $_.Utc})
}

function Wait-Audit([string]$Property,[string]$Value,[DateTimeOffset]$SinceUtc,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        $matches=@(Get-AuditEntries $SinceUtc | Where-Object {
            $p=$_.PSObject.Properties[$Property]
            $null -ne $p -and [string]$p.Value -eq $Value
        })
        if($matches.Count -gt 0){return $matches[-1]}
        Start-Sleep -Milliseconds 250
    }
    throw "Timed out waiting for audit $Property='$Value'."
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

function Remove-StaleDriverQualification {
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the disposable VM.'
    }

    $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'
    if(Test-Path -LiteralPath $driverKey){
        & sc.exe delete RansomGuardMinifilter | Out-Null
        for($i=0;$i -lt 40 -and (Test-Path -LiteralPath $driverKey);$i++){Start-Sleep -Milliseconds 100}
        if(Test-Path -LiteralPath $driverKey){throw 'Stale RansomGuardMinifilter registration could not be removed.'}
    }

    foreach($inf in @(Get-RansomGuardPublishedInfNames)){
        $out=(& pnputil.exe /delete-driver $inf /uninstall /force 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0){throw "Unable to remove stale qualification driver package '$inf'. $out"}
    }
}

function Quarantine-State([string]$StateRoot){
    if(-not(Test-Path -LiteralPath $StateRoot)){return $null}
    $item=Get-Item -LiteralPath $StateRoot -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw "REFUSED: prior state is not a plain directory: $StateRoot"
    }
    $q="$StateRoot.QUALIFICATION-QUARANTINE.$(Get-Date -Format 'yyyyMMdd-HHmmss').$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    Move-Item -LiteralPath $StateRoot -Destination $q
    if(Test-Path -LiteralPath $StateRoot){throw 'Prior state remained at the production state path after quarantine.'}
    return $q
}

function Assert-InstalledPackage([string]$Image,[string]$SourceRoot){
    $installedRoot=Split-Path -Parent ([IO.Path]::GetFullPath($Image))
    $expected=@(
        'Protection\protection-package.json',
        'Protection\GateClient\RansomGuard.GateClient.exe',
        'Protection\Driver\RansomGuardMinifilter.sys',
        'Protection\Driver\RansomGuardMinifilter.inf',
        'Protection\Driver\RansomGuardMinifilter.cat'
    )
    foreach($relative in $expected){
        $src=Join-Path $SourceRoot $relative
        $dst=Join-Path $installedRoot $relative
        foreach($pair in @(@($src,'source'),@($dst,'installed'))){
            if(-not(Test-Path -LiteralPath $pair[0] -PathType Leaf)){
                throw "Missing $($pair[1]) Protection file: $($pair[0])"
            }
            Assert-NoReparsePath $pair[0] "$($pair[1]) Protection file"
        }
        $sourceHash=(Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
        $installedHash=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
        if(-not [string]::Equals($sourceHash,$installedHash,[StringComparison]::OrdinalIgnoreCase)){
            throw "Installed Protection bytes differ from reviewed package: $relative"
        }
    }

    $config=Get-Content -LiteralPath (Join-Path $installedRoot 'appsettings.json') -Raw | ConvertFrom-Json
    if([string]$config.Mode -ne 'Enforce' -or $config.Enforce.AutomaticContainment -ne $true){
        throw 'Installed configuration did not persist Enforce + AutomaticContainment.'
    }
    return $installedRoot
}

Assert-Administrator
$vm=Assert-DisposableVm
$AdminHelper=[IO.Path]::GetFullPath($AdminHelper)
$QualificationDirectory=[IO.Path]::GetFullPath($QualificationDirectory)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}

foreach($pair in @(@($AdminHelper,'AdminHelper'),@($QualificationDirectory,'QualificationDirectory'))){
    if(-not(Test-Path -LiteralPath $pair[0])){throw "$($pair[1]) missing: $($pair[0])"}
    Assert-NoReparsePath $pair[0] $pair[1]
}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$packageSummaryPath=Join-Path $QualificationDirectory 'qualification-package.json'
if(-not(Test-Path -LiteralPath $packageSummaryPath -PathType Leaf)){throw 'qualification-package.json missing.'}
$package=Get-Content -LiteralPath $packageSummaryPath -Raw | ConvertFrom-Json
if([int]$package.schema -ne 1 -or $package.qualificationOnly -ne $true){throw 'Qualification package provenance is invalid.'}
if(-not [string]::Equals([string]$package.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Qualification package commit '$($package.commit)' does not match '$ExpectedCommit'."
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$root=Join-Path $RootBase "protected-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Assert-NoReparsePath $root 'ProtectedRoot'

if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionInstaller-$stamp"}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

$stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
$startedUtc=[DateTimeOffset]::UtcNow
$summary=[ordered]@{
    schema=1
    commit=$ExpectedCommit.ToLowerInvariant()
    version=[string]$package.productVersion
    vm=$vm
    protectedRoot=$root
    priorStateQuarantine=$null
    initialServiceAbsent=$false
    installReviewEnforce=$false
    productionPackageStaged=$false
    installAuditBound=$false
    serviceStarted=$false
    productionProtected=$false
    automaticContainmentReady=$false
    cleanMaintenanceStop=$false
    driverUnloaded=$false
    serviceUnregistered=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}
$failure=$null

try{
    $initial=Invoke-Helper @('query')
    if($initial.Installed -eq $true){
        throw "REFUSED: RansomGuardV03 already installed at '$($initial.ImagePath)'."
    }
    $summary.initialServiceAbsent=$true

    Remove-StaleDriverQualification
    $summary.priorStateQuarantine=Quarantine-State $stateRoot

    $install=Invoke-Helper @('install-production',$QualificationDirectory,$root)
    if([string]$install.Mode -ne 'Enforce' -or $install.ProductionProtection -ne $true -or
       [string]::IsNullOrWhiteSpace([string]$install.Altitude)){
        throw 'Production installation review evidence was not returned by the administration boundary.'
    }
    $summary.installReviewEnforce=$true

    [void](Assert-InstalledPackage ([string]$install.image) $QualificationDirectory)
    $summary.productionPackageStaged=$true

    $prepared=Wait-Audit 'Event' 'ServiceInstallPrepared' $startedUtc 15
    if([string]$prepared.Mode -ne 'Enforce' -or $prepared.ProductionProtection -ne $true -or
       -not [string]::Equals([string]$prepared.ProtectionAltitude,[string]$install.Altitude,[StringComparison]::Ordinal)){
        throw 'ServiceInstallPrepared audit is not bound to the reviewed Enforce Protection package.'
    }
    $summary.installAuditBound=$true

    $started=Invoke-Helper @('start')
    if($started.Installed -ne $true -or [string]$started.State -ne 'Running'){
        throw "Administration start did not reach SCM Running. state=$($started.State)"
    }
    $summary.serviceStarted=$true

    $activation=Wait-Audit 'Type' 'ProductionProtectionActivated' $startedUtc 90
    if([string]$activation.Root -ne $root -or [string]$activation.Protection.State -ne 'Protected' -or
       $activation.Protection.KernelEnforcementActive -ne $true){
        throw 'ProductionProtectionActivated did not prove Protected kernel enforcement for the installed root.'
    }
    $summary.productionProtected=$true

    $ready=Wait-Audit 'Type' 'AutomaticContainmentReady' $startedUtc 30
    if($ready.Protection.AutomaticContainmentActive -ne $true){
        throw 'AutomaticContainmentReady audit did not prove the automatic containment backend ready.'
    }
    $summary.automaticContainmentReady=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter is not loaded after production installer startup.'
    }

    $stopped=Invoke-Helper @('stop')
    if($stopped.Installed -ne $true -or [string]$stopped.State -ne 'Stopped'){
        throw 'Administration stop did not leave the production service Stopped.'
    }
    $maintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $startedUtc 30
    if([string]$maintenance.Root -ne $root -or [string]$maintenance.Protection.State -ne 'Maintenance'){
        throw 'Clean production stop did not prove Maintenance.'
    }
    $summary.cleanMaintenanceStop=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'RansomGuardMinifilter remained loaded after clean production stop.'
    }
    $summary.driverUnloaded=$true

    [void](Invoke-Helper @('uninstall'))
    $after=Invoke-Helper @('query')
    if($after.Installed -eq $true){throw 'RansomGuardV03 remained registered after administration uninstall.'}
    $summary.serviceUnregistered=$true
    $summary.passed=$true
}catch{
    $failure=$_.Exception
}finally{
    try{
        $status=Invoke-Helper @('query')
        if($status.Installed -eq $true){
            if([string]$status.State -ne 'Stopped'){[void](Invoke-Helper @('stop'))}
            [void](Invoke-Helper @('uninstall'))
        }

        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -eq 0 -and $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            throw 'Cleanup refused to force-unload an active production filter; inspect the failed run or revert the VM snapshot.'
        }
        Remove-StaleDriverQualification
        $summary.cleanupPassed=$true
    }catch{
        $summary.cleanupPassed=$false
        $summary.cleanupError=$_.Exception.Message
        $summary.passed=$false
    }

    try{
        $audit=@(Get-AuditEntries $startedUtc)
        $audit | ConvertTo-Json -Depth 30 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-installer-audit.json') -Encoding utf8
        $package | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'qualification-package.json') -Encoding utf8
    }catch{
        $summary.passed=$false
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){
            $summary.cleanupError='Evidence: '+$_.Exception.Message
        }
    }

    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-installer-result.json') -Encoding utf8
}

if($null -ne $failure){throw $failure}
if(-not $summary.cleanupPassed){throw "Production installer cleanup failed: $($summary.cleanupError)"}
if(-not $summary.passed){throw 'Production installer qualification did not reach PASS.'}
Write-Host "PRODUCTION-INSTALLER-EVIDENCE PASS commit=$ExpectedCommit results=$ResultsDirectory"
