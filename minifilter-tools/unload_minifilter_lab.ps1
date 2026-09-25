[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]:

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

function Invoke-FltmcBounded {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $stdout=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.out" -f $PID,[Guid]::NewGuid().ToString('N'))
    $stderr=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.err" -f $PID,[Guid]::NewGuid().ToString('N'))
    try{
        $proc=Start-Process -FilePath 'fltmc.exe' -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if(-not $proc.WaitForExit($NativeTimeoutSeconds*1000)){
            try{$proc.Kill($true)}catch{}
            throw "TIMEOUT: $Description did not return within $NativeTimeoutSeconds seconds. The loaded LAB driver may be stuck in a kernel callback/unload path. Do not keep retrying unload; revert the disposable VM checkpoint."
        }
        $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
        $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
        return [pscustomobject]@{
            ExitCode=$proc.ExitCode
            Output=($out+[Environment]::NewLine+$err).Trim()
        }
    }
    finally{
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
$detach=Invoke-FltmcBounded -Arguments @('detach','RansomGuardMinifilter',$Volume) -Description "fltmc detach RansomGuardMinifilter $Volume"
if($detach.ExitCode -ne 0){
    Write-Warning "fltmc detach returned $($detach.ExitCode). Continuing with unload and final-state verification. Output: $($detach.Output)"
}

Write-Host 'Unloading RansomGuardMinifilter ...'
$unload=Invoke-FltmcBounded -Arguments @('unload','RansomGuardMinifilter') -Description 'fltmc unload RansomGuardMinifilter'
if($unload.ExitCode -ne 0){
    Write-Warning "fltmc unload returned $($unload.ExitCode). Verifying whether the filter is still present. Output: $($unload.Output)"
}

$query=Invoke-FltmcBounded -Arguments @('filters') -Description 'fltmc filters cleanup verification'
if($query.ExitCode -ne 0){
    throw "Could not verify Filter Manager state after cleanup. fltmc filters exit=$($query.ExitCode). Output: $($query.Output)"
}
if($query.Output -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw "RansomGuardMinifilter is still loaded after cleanup. detachExit=$($detach.ExitCode) unloadExit=$($unload.ExitCode). Revert the disposable VM checkpoint before another crash/fault run."
}

if($RemovePackage){
    $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardMinifilter'

    function Get-RansomGuardPublishedInfNames {
        $windowsInf=Join-Path $env:SystemRoot 'INF'
        if(-not (Test-Path -LiteralPath $windowsInf -PathType Container)){return @()}
        return @(
            Get-ChildItem -LiteralPath $windowsInf -Filter 'oem*.inf' -File -ErrorAction Stop |
                Where-Object {
                    try{
                        $text=Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
                        $text -match '(?im)^\s*ServiceName\s*=\s*"RansomGuardMinifilter"\s*
)][string]$Volume='C:',
    [ValidateRange(5,120)][int]$NativeTimeoutSeconds=20,
    [switch]$RemovePackage
)

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

function Invoke-FltmcBounded {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $stdout=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.out" -f $PID,[Guid]::NewGuid().ToString('N'))
    $stderr=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.err" -f $PID,[Guid]::NewGuid().ToString('N'))
    try{
        $proc=Start-Process -FilePath 'fltmc.exe' -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if(-not $proc.WaitForExit($NativeTimeoutSeconds*1000)){
            try{$proc.Kill($true)}catch{}
            throw "TIMEOUT: $Description did not return within $NativeTimeoutSeconds seconds. The loaded LAB driver may be stuck in a kernel callback/unload path. Do not keep retrying unload; revert the disposable VM checkpoint."
        }
        $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
        $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
        return [pscustomobject]@{
            ExitCode=$proc.ExitCode
            Output=($out+[Environment]::NewLine+$err).Trim()
        }
    }
    finally{
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
$detach=Invoke-FltmcBounded -Arguments @('detach','RansomGuardMinifilter',$Volume) -Description "fltmc detach RansomGuardMinifilter $Volume"
if($detach.ExitCode -ne 0){
    Write-Warning "fltmc detach returned $($detach.ExitCode). Continuing with unload and final-state verification. Output: $($detach.Output)"
}

Write-Host 'Unloading RansomGuardMinifilter ...'
$unload=Invoke-FltmcBounded -Arguments @('unload','RansomGuardMinifilter') -Description 'fltmc unload RansomGuardMinifilter'
if($unload.ExitCode -ne 0){
    Write-Warning "fltmc unload returned $($unload.ExitCode). Verifying whether the filter is still present. Output: $($unload.Output)"
}

$query=Invoke-FltmcBounded -Arguments @('filters') -Description 'fltmc filters cleanup verification'
if($query.ExitCode -ne 0){
    throw "Could not verify Filter Manager state after cleanup. fltmc filters exit=$($query.ExitCode). Output: $($query.Output)"
}
if($query.Output -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw "RansomGuardMinifilter is still loaded after cleanup. detachExit=$($detach.ExitCode) unloadExit=$($unload.ExitCode). Revert the disposable VM checkpoint before another crash/fault run."
}

Write-Host 'Done. RansomGuardMinifilter is not loaded. The package may remain in Driver Store; revert the VM snapshot after lab testing.' -ForegroundColor Green
 -and
                        $text -match '(?im)^\s*CatalogFile\s*=\s*RansomGuardMinifilter\.cat\s*
)][string]$Volume='C:',
    [ValidateRange(5,120)][int]$NativeTimeoutSeconds=20,
    [switch]$RemovePackage
)

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

function Invoke-FltmcBounded {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $stdout=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.out" -f $PID,[Guid]::NewGuid().ToString('N'))
    $stderr=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.err" -f $PID,[Guid]::NewGuid().ToString('N'))
    try{
        $proc=Start-Process -FilePath 'fltmc.exe' -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if(-not $proc.WaitForExit($NativeTimeoutSeconds*1000)){
            try{$proc.Kill($true)}catch{}
            throw "TIMEOUT: $Description did not return within $NativeTimeoutSeconds seconds. The loaded LAB driver may be stuck in a kernel callback/unload path. Do not keep retrying unload; revert the disposable VM checkpoint."
        }
        $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
        $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
        return [pscustomobject]@{
            ExitCode=$proc.ExitCode
            Output=($out+[Environment]::NewLine+$err).Trim()
        }
    }
    finally{
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
$detach=Invoke-FltmcBounded -Arguments @('detach','RansomGuardMinifilter',$Volume) -Description "fltmc detach RansomGuardMinifilter $Volume"
if($detach.ExitCode -ne 0){
    Write-Warning "fltmc detach returned $($detach.ExitCode). Continuing with unload and final-state verification. Output: $($detach.Output)"
}

Write-Host 'Unloading RansomGuardMinifilter ...'
$unload=Invoke-FltmcBounded -Arguments @('unload','RansomGuardMinifilter') -Description 'fltmc unload RansomGuardMinifilter'
if($unload.ExitCode -ne 0){
    Write-Warning "fltmc unload returned $($unload.ExitCode). Verifying whether the filter is still present. Output: $($unload.Output)"
}

$query=Invoke-FltmcBounded -Arguments @('filters') -Description 'fltmc filters cleanup verification'
if($query.ExitCode -ne 0){
    throw "Could not verify Filter Manager state after cleanup. fltmc filters exit=$($query.ExitCode). Output: $($query.Output)"
}
if($query.Output -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw "RansomGuardMinifilter is still loaded after cleanup. detachExit=$($detach.ExitCode) unloadExit=$($unload.ExitCode). Revert the disposable VM checkpoint before another crash/fault run."
}

Write-Host 'Done. RansomGuardMinifilter is not loaded. The package may remain in Driver Store; revert the VM snapshot after lab testing.' -ForegroundColor Green

                    }catch{$false}
                } |
                Select-Object -ExpandProperty Name
        )
    }

    if(Test-Path -LiteralPath $serviceKey){
        $deleteService=(& sc.exe delete RansomGuardMinifilter 2>&1 | Out-String)
        $deleteServiceExit=$LASTEXITCODE
        if($deleteServiceExit -ne 0 -and $deleteServiceExit -ne 1060){
            throw "Could not delete RansomGuardMinifilter LAB service registration. exit=$deleteServiceExit. Output: $deleteService"
        }
        for($attempt=0;$attempt -lt 30 -and (Test-Path -LiteralPath $serviceKey);$attempt++){
            Start-Sleep -Milliseconds 100
        }
        if(Test-Path -LiteralPath $serviceKey){
            throw 'RansomGuardMinifilter LAB service registration remained after sc.exe delete.'
        }
    }

    $published=@(Get-RansomGuardPublishedInfNames)
    foreach($publishedInf in $published){
        $deletePackage=(& pnputil.exe /delete-driver $publishedInf /uninstall /force 2>&1 | Out-String)
        $deletePackageExit=$LASTEXITCODE
        if($deletePackageExit -ne 0){
            throw "Could not delete RansomGuard LAB Driver Store package '$publishedInf'. exit=$deletePackageExit. Output: $deletePackage"
        }
    }

    $remaining=@(Get-RansomGuardPublishedInfNames)
    if($remaining.Count -gt 0){
        throw "RansomGuard LAB Driver Store package(s) remain after cleanup: $($remaining -join ', ')"
    }
    if(Test-Path -LiteralPath $serviceKey){
        throw 'RansomGuardMinifilter service registration reappeared after Driver Store cleanup.'
    }

    Write-Host 'Done. RansomGuardMinifilter is unloaded and its LAB registration/package are absent.' -ForegroundColor Green
}else{
    Write-Host 'Done. RansomGuardMinifilter is not loaded. The package may remain in Driver Store; revert the VM snapshot after lab testing.' -ForegroundColor Green
}
)][string]$Volume='C:',
    [ValidateRange(5,120)][int]$NativeTimeoutSeconds=20,
    [switch]$RemovePackage
)

$ErrorActionPreference='Stop'

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Run as Administrator.'
}

function Invoke-FltmcBounded {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $stdout=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.out" -f $PID,[Guid]::NewGuid().ToString('N'))
    $stderr=Join-Path $env:TEMP ("ransomguard-fltmc-{0}-{1}.err" -f $PID,[Guid]::NewGuid().ToString('N'))
    try{
        $proc=Start-Process -FilePath 'fltmc.exe' -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if(-not $proc.WaitForExit($NativeTimeoutSeconds*1000)){
            try{$proc.Kill($true)}catch{}
            throw "TIMEOUT: $Description did not return within $NativeTimeoutSeconds seconds. The loaded LAB driver may be stuck in a kernel callback/unload path. Do not keep retrying unload; revert the disposable VM checkpoint."
        }
        $out=if(Test-Path -LiteralPath $stdout){Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue}else{''}
        $err=if(Test-Path -LiteralPath $stderr){Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue}else{''}
        return [pscustomobject]@{
            ExitCode=$proc.ExitCode
            Output=($out+[Environment]::NewLine+$err).Trim()
        }
    }
    finally{
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Detaching RansomGuardMinifilter from $Volume ..."
$detach=Invoke-FltmcBounded -Arguments @('detach','RansomGuardMinifilter',$Volume) -Description "fltmc detach RansomGuardMinifilter $Volume"
if($detach.ExitCode -ne 0){
    Write-Warning "fltmc detach returned $($detach.ExitCode). Continuing with unload and final-state verification. Output: $($detach.Output)"
}

Write-Host 'Unloading RansomGuardMinifilter ...'
$unload=Invoke-FltmcBounded -Arguments @('unload','RansomGuardMinifilter') -Description 'fltmc unload RansomGuardMinifilter'
if($unload.ExitCode -ne 0){
    Write-Warning "fltmc unload returned $($unload.ExitCode). Verifying whether the filter is still present. Output: $($unload.Output)"
}

$query=Invoke-FltmcBounded -Arguments @('filters') -Description 'fltmc filters cleanup verification'
if($query.ExitCode -ne 0){
    throw "Could not verify Filter Manager state after cleanup. fltmc filters exit=$($query.ExitCode). Output: $($query.Output)"
}
if($query.Output -match '(?m)^\s*RansomGuardMinifilter\b'){
    throw "RansomGuardMinifilter is still loaded after cleanup. detachExit=$($detach.ExitCode) unloadExit=$($unload.ExitCode). Revert the disposable VM checkpoint before another crash/fault run."
}

Write-Host 'Done. RansomGuardMinifilter is not loaded. The package may remain in Driver Store; revert the VM snapshot after lab testing.' -ForegroundColor Green
