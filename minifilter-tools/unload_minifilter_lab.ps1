[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:',
    [ValidateRange(5,120)][int]$NativeTimeoutSeconds=20
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
