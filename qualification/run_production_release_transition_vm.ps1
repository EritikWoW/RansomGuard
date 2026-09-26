[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OldAdminHelper,
    [Parameter(Mandatory=$true)][string]$CurrentAdminHelper,
    [Parameter(Mandatory=$true)][string]$FutureAdminHelper,
    [Parameter(Mandatory=$true)][string]$OldPackage,
    [Parameter(Mandatory=$true)][string]$CurrentPackage,
    [Parameter(Mandatory=$true)][string]$FailurePackage,
    [Parameter(Mandatory=$true)][string]$PackageSummary,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedCommit,
    [string]$RootBase='C:\RansomGuard-VM-ProductionReleaseTransition',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=[Security.Principal.WindowsPrincipal]::new($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Production release-transition qualification must run as Administrator.'
    }
}
function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $text="$($cs.Manufacturer) $($cs.Model)"
    if($text -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: production release-transition qualification requires a disposable VM. Detected: $text"
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
function Invoke-Helper([string]$Exe,[string[]]$Arguments){
    $output=(& $Exe @Arguments 2>&1 | Out-String).Trim()
    $exit=$LASTEXITCODE
    if($exit -ne 0){throw "Qualification helper failed exit=$exit args='$($Arguments -join ' ')'. $output"}
    if([string]::IsNullOrWhiteSpace($output)){return $null}
    try{return $output | ConvertFrom-Json -Depth 100}
    catch{throw "Qualification helper returned non-JSON output. $output"}
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
function Get-AuditPaths {
    $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
    return @(
        (Join-Path $root 'audit.jsonl'),
        (Join-Path $root 'audit.1.jsonl'),
        (Join-Path $root 'audit.2.jsonl'),
        (Join-Path $root 'audit.3.jsonl')
    )
}
function Get-AuditEntries([DateTimeOffset]$SinceUtc){
    $items=@()
    foreach($path in @(Get-AuditPaths)){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        Assert-NoReparsePath $path 'Audit evidence'
        foreach($line in Get-Content -LiteralPath $path -ErrorAction Stop){
            if([string]::IsNullOrWhiteSpace($line)){continue}
            try{
                $item=$line | ConvertFrom-Json -Depth 50
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
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for audit $Property='$Value'."
}
function Get-ExactAuditEvidence(
    [Parameter(Mandatory=$true)][string]$Event,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{32}$')][string]$TransactionId,
    [Parameter(Mandatory=$true)][string]$EvidenceLabel
){
    $rawMatches=@()
    $parsedMatches=@()
    foreach($path in @(Get-AuditPaths)){
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        Assert-NoReparsePath $path 'Exact update audit evidence'
        $lineNumber=0
        foreach($line in Get-Content -LiteralPath $path -ErrorAction Stop){
            $lineNumber++
            if([string]::IsNullOrWhiteSpace($line)){continue}
            if($line.IndexOf($TransactionId,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
            $rawMatches += [pscustomobject]@{
                file=[IO.Path]::GetFileName($path)
                line=$lineNumber
                text=$line
            }
            try{$item=$line | ConvertFrom-Json -Depth 50}catch{continue}
            if(-not $item.PSObject.Properties['Event'] -or -not $item.PSObject.Properties['Transaction']){continue}
            if([string]$item.Event -ne $Event){continue}
            if(-not [string]::Equals([string]$item.Transaction,$TransactionId,[StringComparison]::OrdinalIgnoreCase)){continue}
            if(-not $item.PSObject.Properties['Utc']){throw "Exact $Event audit entry has no Utc field."}
            [void](Convert-AuditUtc $item.Utc)
            $parsedMatches += $item
        }
    }
    @($rawMatches) | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory ($EvidenceLabel+'-raw-lines.json')) -Encoding utf8
    return @($parsedMatches)
}
function Get-UpdateRecords {
    $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\ServiceUpdates'
    if(-not(Test-Path -LiteralPath $root -PathType Container)){return @()}
    Assert-NoReparsePath $root 'ServiceUpdates'
    $records=@()
    foreach($file in Get-ChildItem -LiteralPath $root -Filter '*.json' -File -ErrorAction Stop){
        try{
            $item=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -Depth 50
            if([string]$item.TransactionId -match '^[A-Fa-f0-9]{32}$'){$records += $item}
        }catch{}
    }
    return $records
}
function Get-UpdateRecord([string]$TransactionId){
    $matches=@(Get-UpdateRecords | Where-Object {
        [string]::Equals([string]$_.TransactionId,$TransactionId,[StringComparison]::OrdinalIgnoreCase)
    })
    if($matches.Count -ne 1){
        throw "Expected exactly one durable update transaction '$TransactionId'; found $($matches.Count)."
    }
    return $matches[0]
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
function Assert-FilterAbsent([string]$Context){
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw "Unable to query Filter Manager during $Context."}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw "RansomGuardMinifilter remained loaded during $Context."
    }
}
function Assert-FilterPresent([string]$Context){
    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0 -or $filters -notmatch '(?m)^\s*RansomGuardMinifilter\b'){
        throw "RansomGuardMinifilter is not loaded during $Context."
    }
}
function Remove-StaleDriverQualification {
    Assert-FilterAbsent 'driver cleanup preflight'
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
function Assert-InstalledProtectionPackage(
    [string]$Image,
    [string]$SourceRoot,
    [string]$ExpectedVersion
){
    $installedRoot=Split-Path -Parent ([IO.Path]::GetFullPath($Image))
    $serviceVersion=(Get-Item -LiteralPath $Image).VersionInfo.FileVersion
    if(-not [string]::Equals($serviceVersion,$ExpectedVersion,[StringComparison]::Ordinal)){
        throw "Installed service version mismatch. expected=$ExpectedVersion actual=$serviceVersion"
    }
    $installRecord=Get-Content -LiteralPath (Join-Path $installedRoot 'install.json') -Raw | ConvertFrom-Json
    if(-not [string]::Equals([string]$installRecord.Version,$ExpectedVersion,[StringComparison]::Ordinal)){
        throw "Installed immutable record version mismatch. expected=$ExpectedVersion actual=$($installRecord.Version)"
    }

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
    $descriptor=Get-Content -LiteralPath (Join-Path $installedRoot 'Protection\protection-package.json') -Raw | ConvertFrom-Json
    if(-not [string]::Equals([string]$descriptor.Version,$ExpectedVersion,[StringComparison]::Ordinal)){
        throw "Installed Protection descriptor version mismatch. expected=$ExpectedVersion actual=$($descriptor.Version)"
    }
    $config=Get-Content -LiteralPath (Join-Path $installedRoot 'appsettings.json') -Raw | ConvertFrom-Json
    if([string]$config.Mode -ne 'Enforce' -or $config.Enforce.AutomaticContainment -ne $true){
        throw 'Installed configuration did not preserve Enforce + AutomaticContainment.'
    }
    return $installedRoot
}

Assert-Administrator
$vm=Assert-DisposableVm

foreach($name in @('OldAdminHelper','CurrentAdminHelper','FutureAdminHelper','OldPackage','CurrentPackage','FailurePackage','PackageSummary')){
    $value=[IO.Path]::GetFullPath([string](Get-Variable -Name $name -ValueOnly))
    Set-Variable -Name $name -Value $value
    if(-not(Test-Path -LiteralPath $value)){throw "$name missing: $value"}
    Assert-NoReparsePath $value $name
}

$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
if($RootBase -eq [IO.Path]::GetPathRoot($RootBase).TrimEnd('\')){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$packages=Get-Content -LiteralPath $PackageSummary -Raw | ConvertFrom-Json -Depth 50
if([int]$packages.schema -ne 1 -or $packages.qualificationOnly -ne $true){throw 'Release-transition package summary is invalid.'}
if(-not [string]::Equals([string]$packages.commit,$ExpectedCommit,[StringComparison]::OrdinalIgnoreCase)){
    throw "Release-transition package commit '$($packages.commit)' does not match '$ExpectedCommit'."
}
$oldVersion=[string]$packages.oldVersion
$currentVersion=[string]$packages.currentVersion
$futureVersion=[string]$packages.futureFailureVersion
if(([Version]$oldVersion) -ge ([Version]$currentVersion) -or ([Version]$currentVersion) -ge ([Version]$futureVersion)){
    throw "Release-transition versions are not strictly forward: $oldVersion -> $currentVersion -> $futureVersion"
}
foreach($record in @($packages.old,$packages.current,$packages.future)){
    if(-not [string]::Equals([string]$record.driverSysSha256,[string]$packages.driverSysSha256,[StringComparison]::OrdinalIgnoreCase) -or
       -not [string]::Equals([string]$record.altitude,[string]$packages.qualificationAltitude,[StringComparison]::Ordinal)){
        throw 'Release-transition package changed production filter SYS identity or altitude.'
    }
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$protectedRoot=Join-Path $RootBase "protected-$stamp"
New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
Assert-NoReparsePath $protectedRoot 'ProtectedRoot'
if([string]::IsNullOrWhiteSpace($ResultsDirectory)){
    $ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionReleaseTransition-$stamp"
}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

$stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03'
$startedUtc=[DateTimeOffset]::UtcNow
$summary=[ordered]@{
    schema=1
    commit=$ExpectedCommit.ToLowerInvariant()
    oldVersion=$oldVersion
    currentVersion=$currentVersion
    futureFailureVersion=$futureVersion
    vm=$vm
    protectedRoot=$protectedRoot
    priorStateQuarantine=$null
    initialServiceAbsent=$false
    oldInstallEnforce=$false
    oldProtectionReady=$false
    oldCleanStop=$false
    forwardReviewPassed=$false
    forwardUpdateCompleted=$false
    forwardTransactionId=$null
    forwardCurrentImage=$null
    forwardProtectionTransitionVerified=$false
    completedJournalTerminal=$false
    completionAuditObserved=$false
    postCommitFailureObserved=$false
    rollbackTransactionId=$null
    previousImageRestored=$false
    rollbackJournalTerminal=$false
    rollbackAuditObserved=$false
    rollbackProtectionRestored=$false
    finalUninstallPassed=$false
    driverCleanupPassed=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}
$failure=$null

try{
    $initial=Invoke-Helper $CurrentAdminHelper @('query')
    if($initial.QuerySucceeded -ne $true){throw "Initial service query failed: $($initial.Error)"}
    if($initial.Installed -eq $true){throw "REFUSED: RansomGuardV03 is already installed at '$($initial.ImagePath)'."}
    $summary.initialServiceAbsent=$true

    Remove-StaleDriverQualification
    $summary.priorStateQuarantine=Quarantine-State $stateRoot

    $install=Invoke-Helper $OldAdminHelper @('install-production',$OldPackage,$protectedRoot)
    if([string]$install.Mode -ne 'Enforce' -or $install.ProductionProtection -ne $true){
        throw 'Old production installation did not bind Enforce to a verified Protection package.'
    }
    $oldImage=[IO.Path]::GetFullPath([string]$install.image)
    [void](Assert-InstalledProtectionPackage $oldImage $OldPackage $oldVersion)
    $summary.oldInstallEnforce=$true

    $oldStartUtc=[DateTimeOffset]::UtcNow
    $started=Invoke-Helper $OldAdminHelper @('start')
    if($started.Installed -ne $true -or [string]$started.State -ne 'Running'){
        throw 'Old production service did not reach Running.'
    }
    $oldActivation=Wait-Audit 'Type' 'ProductionProtectionActivated' $oldStartUtc 90
    if([string]$oldActivation.Root -ne $protectedRoot -or
       [string]$oldActivation.Protection.State -ne 'Protected' -or
       $oldActivation.Protection.KernelEnforcementActive -ne $true){
        throw 'Old production service did not reach Protected kernel enforcement.'
    }
    $oldReady=Wait-Audit 'Type' 'AutomaticContainmentReady' $oldStartUtc 30
    if($oldReady.Protection.AutomaticContainmentActive -ne $true){
        throw 'Old production service did not reach AutomaticContainmentReady.'
    }
    Assert-FilterPresent 'old production start'
    $summary.oldProtectionReady=$true

    $oldStopUtc=[DateTimeOffset]::UtcNow
    $stopped=Invoke-Helper $OldAdminHelper @('stop')
    if($stopped.Installed -ne $true -or [string]$stopped.State -ne 'Stopped'){
        throw 'Old production service did not stop cleanly.'
    }
    $oldMaintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $oldStopUtc 30
    if([string]$oldMaintenance.Protection.State -ne 'Maintenance'){
        throw 'Old production service did not publish Maintenance on clean stop.'
    }
    Assert-FilterAbsent 'old production clean stop'
    $summary.oldCleanStop=$true

    $review=Invoke-Helper $CurrentAdminHelper @('review-update',$CurrentPackage)
    if(-not [string]::Equals([string]$review.version,$currentVersion,[StringComparison]::Ordinal)){
        throw "Current update review version mismatch: $($review.version)"
    }
    $summary.forwardReviewPassed=$true

    $forwardStartedUtc=[DateTimeOffset]::UtcNow
    $updated=Invoke-Helper $CurrentAdminHelper @('update',$CurrentPackage)
    if([string]$updated.Outcome -ne 'Completed'){throw "Forward update outcome was '$($updated.Outcome)'."}
    $summary.forwardUpdateCompleted=$true
    $summary.forwardTransactionId=[string]$updated.TransactionId
    $forwardRecord=Get-UpdateRecord ([string]$updated.TransactionId)
    if([string]$forwardRecord.Phase -ne 'Completed'){throw 'Forward update durable transaction is not terminal Completed.'}
    $summary.completedJournalTerminal=$true
    $forwardRecord | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'forward-completed-transaction.json') -Encoding utf8

    $forwardAudit=@(
        Get-ExactAuditEvidence -Event 'ServiceUpdateCompleted' -TransactionId ([string]$summary.forwardTransactionId) -EvidenceLabel 'forward-completed-audit'
    )
    if($forwardAudit.Count -lt 1){throw 'Exact ServiceUpdateCompleted audit evidence missing.'}
    $summary.completionAuditObserved=$true
    $forwardAudit | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'forward-completed-audit.json') -Encoding utf8

    $afterForward=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterForward.QuerySucceeded -ne $true -or $afterForward.Installed -ne $true -or [string]$afterForward.State -ne 'Stopped'){
        throw 'Forward update did not leave the current service installed and Stopped.'
    }
    $currentImage=[IO.Path]::GetFullPath([string]$afterForward.ImagePath)
    if([string]::Equals($currentImage,$oldImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Forward update did not select a new immutable current image.'
    }
    [void](Assert-InstalledProtectionPackage $currentImage $CurrentPackage $currentVersion)
    $summary.forwardCurrentImage=$currentImage

    $forwardActivation=Wait-Audit 'Type' 'ProductionProtectionActivated' $forwardStartedUtc 90
    if([string]$forwardActivation.Root -ne $protectedRoot -or
       [string]$forwardActivation.Protection.State -ne 'Protected' -or
       $forwardActivation.Protection.KernelEnforcementActive -ne $true){
        throw 'Forward-updated production service did not prove Protected startup verification.'
    }
    $forwardReady=Wait-Audit 'Type' 'AutomaticContainmentReady' $forwardStartedUtc 30
    if($forwardReady.Protection.AutomaticContainmentActive -ne $true){
        throw 'Forward-updated production service did not reach AutomaticContainmentReady during updater verification.'
    }
    $forwardMaintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $forwardStartedUtc 30
    if([string]$forwardMaintenance.Protection.State -ne 'Maintenance'){
        throw 'Forward-updated service did not cleanly enter Maintenance after updater verification.'
    }
    Assert-FilterAbsent 'forward update verification stop'
    $summary.forwardProtectionTransitionVerified=$true

    $baselineBeforeRollback=@(Get-UpdateRecords | ForEach-Object {[string]$_.TransactionId})
    $rollbackStartedUtc=[DateTimeOffset]::UtcNow
    [void](Invoke-Helper $FutureAdminHelper @('expect-update-failure',$FailurePackage,'rolled back to the previous verified image'))
    $summary.postCommitFailureObserved=$true

    $afterRollback=Invoke-Helper $CurrentAdminHelper @('query')
    if($afterRollback.QuerySucceeded -ne $true -or $afterRollback.Installed -ne $true -or [string]$afterRollback.State -ne 'Stopped'){
        throw 'Deterministic rollback did not leave the current service installed and Stopped.'
    }
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$afterRollback.ImagePath),$currentImage,[StringComparison]::OrdinalIgnoreCase)){
        throw "Rollback selected '$($afterRollback.ImagePath)' instead of exact current image '$currentImage'."
    }
    $summary.previousImageRestored=$true
    [void](Assert-InstalledProtectionPackage $currentImage $CurrentPackage $currentVersion)
    $summary.rollbackProtectionRestored=$true

    $records=@(Get-UpdateRecords)
    $newRollback=@($records | Where-Object {
        $id=[string]$_.TransactionId
        $baselineBeforeRollback -notcontains $id -and [string]$_.Phase -eq 'RolledBack'
    })
    if($newRollback.Count -ne 1){
        throw "Expected exactly one new terminal RolledBack transaction; found $($newRollback.Count)."
    }
    $rollbackRecord=$newRollback[0]
    $summary.rollbackTransactionId=[string]$rollbackRecord.TransactionId
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$rollbackRecord.PreviousImage),$currentImage,[StringComparison]::OrdinalIgnoreCase)){
        throw 'RolledBack transaction is not bound to the exact current immutable image.'
    }
    $summary.rollbackJournalTerminal=$true
    $records | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'release-transition-transactions.json') -Encoding utf8

    $rollbackAudit=@(
        Get-ExactAuditEvidence -Event 'ServiceUpdateRolledBack' -TransactionId ([string]$summary.rollbackTransactionId) -EvidenceLabel 'rollback-audit'
    )
    if($rollbackAudit.Count -lt 1){throw 'Exact ServiceUpdateRolledBack audit evidence missing.'}
    $summary.rollbackAuditObserved=$true
    @($forwardAudit + $rollbackAudit) | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'release-transition-update-audit.json') -Encoding utf8

    $rollbackActivation=Wait-Audit 'Type' 'ProductionProtectionActivated' $rollbackStartedUtc 90
    if([string]$rollbackActivation.Root -ne $protectedRoot -or
       [string]$rollbackActivation.Protection.State -ne 'Protected' -or
       $rollbackActivation.Protection.KernelEnforcementActive -ne $true){
        throw 'Rollback verification did not restart the restored current production service in Protected state.'
    }
    $rollbackMaintenance=Wait-Audit 'Type' 'ProductionProtectionMaintenanceStop' $rollbackStartedUtc 30
    if([string]$rollbackMaintenance.Protection.State -ne 'Maintenance'){
        throw 'Rollback verification did not cleanly stop the restored current production service.'
    }
    Assert-FilterAbsent 'rollback verification stop'

    [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
    $final=Invoke-Helper $CurrentAdminHelper @('query')
    if($final.QuerySucceeded -ne $true -or $final.Installed -eq $true){
        throw 'Final administration uninstall did not remove RansomGuardV03.'
    }
    $summary.finalUninstallPassed=$true

    Remove-StaleDriverQualification
    $summary.driverCleanupPassed=$true
    $summary.cleanupPassed=$true
    $summary.passed=$true
}catch{
    $failure=$_.Exception
}finally{
    try{
        $status=Invoke-Helper $CurrentAdminHelper @('query')
        if($status.QuerySucceeded -eq $true -and $status.Installed -eq $true){
            if([string]$status.State -ne 'Stopped'){[void](Invoke-Helper $CurrentAdminHelper @('stop'))}
            [void](Invoke-Helper $CurrentAdminHelper @('uninstall'))
        }
        Assert-FilterAbsent 'release-transition final cleanup'
        Remove-StaleDriverQualification
        $summary.driverCleanupPassed=$true
        if($summary.finalUninstallPassed -or $null -ne $failure){$summary.cleanupPassed=$true}
    }catch{
        $summary.cleanupPassed=$false
        $summary.cleanupError=$_.Exception.Message
        $summary.passed=$false
    }

    try{
        $audit=@(Get-AuditEntries $startedUtc)
        $audit | ConvertTo-Json -Depth 40 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-release-transition-audit.json') -Encoding utf8
        $packages | ConvertTo-Json -Depth 40 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-release-transition-packages.json') -Encoding utf8
    }catch{
        $summary.passed=$false
        if([string]::IsNullOrWhiteSpace([string]$summary.cleanupError)){
            $summary.cleanupError='Evidence: '+$_.Exception.Message
        }
    }

    $summary.completedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-release-transition-result.json') -Encoding utf8
}

if($null -ne $failure){throw $failure}
if(-not $summary.cleanupPassed){throw "Production release-transition cleanup failed: $($summary.cleanupError)"}
if(-not $summary.passed){throw 'Production release-transition qualification did not reach PASS.'}
Write-Host "PRODUCTION-RELEASE-TRANSITION-EVIDENCE PASS commit=$ExpectedCommit results=$ResultsDirectory"
