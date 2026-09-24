[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$DriverPackageDirectory,
    [string]$RootBase='C:\RansomGuard-VM-ProductionGate',
    [string]$ResultsDirectory=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'ProductionGate qualification must run as Administrator.'
    }
}

function Assert-DisposableVm {
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText="$($cs.Manufacturer) $($cs.Model)"
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: ProductionGate qualification requires an obvious disposable VM. Detected: $vmText"
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
        if(-not (Test-Path -LiteralPath $cursor)){break}
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
            throw "$Label must not traverse a reparse point/junction: $cursor"
        }
    }
}

function Quote-Arg([string]$Value){return '"' + $Value.Replace('"','\"') + '"'}

function Start-LoggedProcess([string]$FilePath,[string[]]$Arguments,[string]$StdOut,[string]$StdErr){
    foreach($p in @($StdOut,$StdErr)){
        $parent=Split-Path -Parent $p
        if($parent){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
    Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
}

function Wait-LogPattern([string]$Path,[string]$Pattern,[System.Diagnostics.Process]$Process,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $deadline){
        if(Test-Path -LiteralPath $Path){
            $text=Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if($text -match $Pattern){return}
        }
        if($Process.HasExited){
            $err=if(Test-Path -LiteralPath ($Path+'.err')){Get-Content -LiteralPath ($Path+'.err') -Raw}else{''}
            throw "Process exited before expected pattern '$Pattern'. Exit=$($Process.ExitCode). $err"
        }
        Start-Sleep -Milliseconds 150
    }
    throw "Timed out waiting for '$Pattern' in $Path"
}

function Stop-ProcessHard([System.Diagnostics.Process]$Process,[string]$Description){
    if($null -eq $Process -or $Process.HasExited){return}
    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    if(-not $Process.WaitForExit(10000)){throw "Timed out stopping $Description pid=$($Process.Id)."}
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

Assert-Administrator
$vm=Assert-DisposableVm

$LabReleaseDirectory=[IO.Path]::GetFullPath($LabReleaseDirectory)
$DriverPackageDirectory=[IO.Path]::GetFullPath($DriverPackageDirectory)
$RootBase=[IO.Path]::GetFullPath($RootBase).TrimEnd('\')
if($RootBase -notmatch '(?i)RansomGuard'){throw 'RootBase must contain RansomGuard.'}
$rootDrive=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
if($RootBase -eq $rootDrive){throw 'RootBase cannot be an entire drive.'}
New-Item -ItemType Directory -Path $RootBase -Force | Out-Null
Assert-NoReparsePath $RootBase 'RootBase'

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
if(-not $ResultsDirectory){$ResultsDirectory=Join-Path ([IO.Path]::GetTempPath()) "RansomGuard-ProductionGate-$stamp"}
$ResultsDirectory=[IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
Assert-NoReparsePath $ResultsDirectory 'ResultsDirectory'

$gateExe=Join-Path $LabReleaseDirectory 'MinifilterLab\GateClient\RansomGuard.GateClient.exe'
$driverSys=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.sys'
$driverInf=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.inf'
$driverCat=Join-Path $DriverPackageDirectory 'RansomGuardMinifilter.cat'
$driverProvenancePath=Join-Path $DriverPackageDirectory 'runtime-package.json'
foreach($required in @($gateExe,$driverSys,$driverInf,$driverCat,$driverProvenancePath)){
    if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required runtime artifact missing: $required"}
}

$gateVersion=(Get-Item -LiteralPath $gateExe).VersionInfo.FileVersion
$driverProvenance=Get-Content -LiteralPath $driverProvenancePath -Raw | ConvertFrom-Json
if([int]$driverProvenance.schema -ne 2){throw 'Runtime package provenance schema must be 2.'}
if([string]$driverProvenance.commit -notmatch '^[A-Fa-f0-9]{40}$'){throw 'Runtime package provenance commit is invalid.'}
if([string]$driverProvenance.productVersion -ne $gateVersion){throw 'Driver package version does not match GateClient.'}
$actualSysSha256=(Get-FileHash -LiteralPath $driverSys -Algorithm SHA256).Hash
$actualInfSha256=(Get-FileHash -LiteralPath $driverInf -Algorithm SHA256).Hash
$actualCatSha256=(Get-FileHash -LiteralPath $driverCat -Algorithm SHA256).Hash
foreach($pair in @(
    @('SYS',[string]$driverProvenance.sysSha256,$actualSysSha256),
    @('INF',[string]$driverProvenance.infSha256,$actualInfSha256),
    @('CAT',[string]$driverProvenance.catSha256,$actualCatSha256)
)){
    if(-not [string]::Equals($pair[1],$pair[2],[StringComparison]::OrdinalIgnoreCase)){
        throw "Runtime package $($pair[0]) hash does not match provenance."
    }
}

$root=Join-Path $RootBase "production-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Assert-NoReparsePath $root 'ProductionRoot'
# The marker exists only so the negative reconnect probe reaches the kernel as a valid LabGate.
[IO.File]::WriteAllText((Join-Path $root '.ransomguard-gate-lab-root'),'RANSOMGUARD-LAB-GATE-V1',[Text.Encoding]::ASCII)
$target=Join-Path $root 'production-target.bin'
[IO.File]::WriteAllText($target,'production-initial')

$fixedStore=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RansomGuardV03\Rollback'))
New-Item -ItemType Directory -Path $fixedStore -Force | Out-Null
Assert-NoReparsePath $fixedStore 'ProductionRollbackStore'

$initialSession="prod18-a-$stamp"
$reconnectSession="prod18-b-$stamp"
$labMismatchStore=Join-Path $ResultsDirectory 'lab-mismatch-store'
$volume=[IO.Path]::GetPathRoot($RootBase).TrimEnd('\')
$installScript=Join-Path $PSScriptRoot 'install_minifilter_lab.ps1'
$unloadScript=Join-Path $PSScriptRoot 'unload_minifilter_lab.ps1'

$summary=[ordered]@{
    schema=1
    version=$gateVersion
    startedUtc=(Get-Date).ToUniversalTime().ToString('o')
    vm=$vm
    driverCommit=[string]$driverProvenance.commit
    driverSysSha256=$actualSysSha256
    driverInfSha256=$actualInfSha256
    driverCatSha256=$actualCatSha256
    productionCliRejectedLabOption=$false
    productionActivated=$false
    productionMutationAllowed=$false
    degradedReadAllowed=$false
    degradedDeniedMutation=$false
    degradedPreservedHash=$false
    labProfileReconnectRejected=$false
    productionReconnectActivated=$false
    productionReconnectMutationAllowed=$false
    cleanupPassed=$false
    cleanupError=$null
    passed=$false
}

$installed=$false
$gate=$null
$labWrong=$null
$gateReconnect=$null
$runtimeFailure=$null
$cleanupFailure=$null
try{
    # User-mode profile separation must reject LAB-only controls before any port connection.
    $rejectOut=Join-Path $ResultsDirectory 'production-reject.out.log'
    $rejectErr=$rejectOut+'.err'
    $reject=Start-LoggedProcess $gateExe @(
        '--production','--root',(Quote-Arg $root),'--contain-pid','12345'
    ) $rejectOut $rejectErr
    if(-not $reject.WaitForExit(15000)){
        Stop-Process -Id $reject.Id -Force -ErrorAction SilentlyContinue
        throw 'ProductionGate LAB-option rejection probe timed out.'
    }
    $rejectErrText=if(Test-Path -LiteralPath $rejectErr){Get-Content -LiteralPath $rejectErr -Raw}else{''}
    $rejectOutText=if(Test-Path -LiteralPath $rejectOut){Get-Content -LiteralPath $rejectOut -Raw}else{''}
    $rejectText=$rejectErrText+$rejectOutText
    if($reject.ExitCode -eq 0 -or $rejectText -notmatch 'ProductionGate forbids LAB prepare/fault/reconciliation/shutdown/containment options'){
        throw 'ProductionGate did not reject a LAB-only containment option.'
    }
    $summary.productionCliRejectedLabOption=$true

    $filters=(& fltmc filters 2>$null | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Unable to query Filter Manager before ProductionGate qualification.'}
    if($filters -match '(?m)^\s*RansomGuardMinifilter\b'){
        throw 'REFUSED: RansomGuardMinifilter is already loaded. Revert/clean the VM first.'
    }

    $installed=$true
    & $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation 'LAB-MINIFILTER'

    $out=Join-Path $ResultsDirectory 'production-gate.out.log'
    $err=$out+'.err'
    $gate=Start-LoggedProcess $gateExe @(
        '--production','--root',(Quote-Arg $root),'--session',$initialSession
    ) $out $err
    Wait-LogPattern $out 'RansomGuard PRODUCTION pre-write gate' $gate 45
    Wait-LogPattern $out 'Production containment: disabled by profile' $gate 45
    Wait-LogPattern $out 'kernel gate ACTIVE' $gate 45
    $summary.productionActivated=$true

    [IO.File]::WriteAllText($target,'production-write-before-loss')
    if((Get-Content -LiteralPath $target -Raw) -ne 'production-write-before-loss'){
        throw 'ProductionGate mutation did not succeed after activation.'
    }
    $summary.productionMutationAllowed=$true
    $protectedHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    Stop-ProcessHard $gate 'ProductionGate'
    $gate=$null
    Start-Sleep -Milliseconds 500

    if((Get-Content -LiteralPath $target -Raw) -ne 'production-write-before-loss'){
        throw 'Read-only access failed after ProductionGate loss.'
    }
    $summary.degradedReadAllowed=$true

    $denied=$false
    try{[IO.File]::WriteAllText($target,'must-be-denied-after-production-loss')}
    catch{
        if(Test-AccessDeniedException $_.Exception){$denied=$true}else{throw}
    }
    if(-not $denied){throw 'Resolved in-root mutation was not denied after ProductionGate loss.'}
    $summary.degradedDeniedMutation=$true
    $afterDenied=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if(-not [string]::Equals($afterDenied,$protectedHash,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Protected target changed despite degraded ProductionGate denial.'
    }
    $summary.degradedPreservedHash=$true

    # A valid LabGate on the exact same root must still be rejected by the retained kernel profile.
    $labOut=Join-Path $ResultsDirectory 'lab-profile-reconnect.out.log'
    $labErr=$labOut+'.err'
    $labWrong=Start-LoggedProcess $gateExe @(
        '--root',(Quote-Arg $root),'--store',(Quote-Arg $labMismatchStore),'--session',"lab-mismatch-$stamp"
    ) $labOut $labErr
    if(-not $labWrong.WaitForExit(15000)){
        Stop-Process -Id $labWrong.Id -Force -ErrorAction SilentlyContinue
        throw 'LabGate unexpectedly stayed connected to retained ProductionGate state.'
    }
    $labOutText=if(Test-Path -LiteralPath $labOut){Get-Content -LiteralPath $labOut -Raw}else{''}
    $labErrText=if(Test-Path -LiteralPath $labErr){Get-Content -LiteralPath $labErr -Raw}else{''}
    $labText=$labOutText+$labErrText
    if($labWrong.ExitCode -eq 0 -or $labText -match 'kernel gate ACTIVE'){
        throw 'LabGate unexpectedly replaced retained ProductionGate state.'
    }
    if($labText -notmatch 'FilterConnectCommunicationPort failed'){
        throw 'LabGate profile-mismatch probe failed before proving the kernel rejected the connection.'
    }
    $labWrong=$null
    $summary.labProfileReconnectRejected=$true

    # Exact ProductionGate profile/root reconnect must rerun preflight and return Protected.
    $reOut=Join-Path $ResultsDirectory 'production-reconnect.out.log'
    $reErr=$reOut+'.err'
    $gateReconnect=Start-LoggedProcess $gateExe @(
        '--production','--root',(Quote-Arg $root),'--session',$reconnectSession
    ) $reOut $reErr
    Wait-LogPattern $reOut 'kernel gate ACTIVE' $gateReconnect 45
    $summary.productionReconnectActivated=$true

    [IO.File]::WriteAllText($target,'production-write-after-reconnect')
    if((Get-Content -LiteralPath $target -Raw) -ne 'production-write-after-reconnect'){
        throw 'ProductionGate mutation did not succeed after exact-profile reconnect.'
    }
    $summary.productionReconnectMutationAllowed=$true

    $summary.passed=$true
}
catch{
    $runtimeFailure=$_
}
finally{
    foreach($p in @($gate,$labWrong,$gateReconnect)){
        try{Stop-ProcessHard $p 'qualification GateClient'}catch{
            if($null -eq $cleanupFailure){$cleanupFailure=$_}
        }
    }
    if($installed){
        try{& $unloadScript -Volume $volume}catch{
            if($null -eq $cleanupFailure){$cleanupFailure=$_}
        }
    }

    try{
        $filters=(& fltmc filters 2>$null | Out-String)
        if($LASTEXITCODE -ne 0 -or $filters -match '(?m)^\s*RansomGuardMinifilter\b'){
            throw 'RansomGuardMinifilter remained loaded after ProductionGate qualification.'
        }
        $summary.cleanupPassed=$true
    }catch{
        if($null -eq $cleanupFailure){$cleanupFailure=$_}
    }

    if($cleanupFailure){
        $summary.cleanupPassed=$false
        $summary.cleanupError=$cleanupFailure.Exception.Message
        $summary.passed=$false
    }
    $summary.completedUtc=(Get-Date).ToUniversalTime().ToString('o')
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'production-gate-result.json') -Encoding UTF8
}

if($runtimeFailure){throw $runtimeFailure}
if($cleanupFailure){throw $cleanupFailure}
if(-not $summary.passed){throw 'ProductionGate qualification did not pass.'}
Write-Host "ProductionGate protocol-v18 qualification PASSED. Evidence: $ResultsDirectory" -ForegroundColor Green
