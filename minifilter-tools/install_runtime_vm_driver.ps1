[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [ValidatePattern('^[A-Za-z]:$')][string]$Volume='C:'
)

$ErrorActionPreference='Stop'

function Assert-DisposableVm {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Runtime driver installer must run elevated.'}
    if($env:RANSOMGUARD_RUNTIME_VM -cne 'YES-I-AM-DISPOSABLE'){
        throw 'REFUSED: runtime driver installation requires RANSOMGUARD_RUNTIME_VM=YES-I-AM-DISPOSABLE.'
    }
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText=("$($cs.Manufacturer) $($cs.Model)")
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: runtime driver installer requires an obvious VM. Detected: $vmText"
    }
    Write-Host "Disposable VM confirmed: $vmText"
}

function Find-WdkTool([string]$Name){
    $kits=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction Stop).KitsRoot10.TrimEnd('\')
    $matches=Get-ChildItem -LiteralPath $kits -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '(?i)\x64\' } |
        Sort-Object FullName -Descending
    $tool=$matches | Select-Object -First 1
    if(-not $tool){throw "Required x64 WDK tool not found: $Name"}
    return $tool.FullName
}

Assert-DisposableVm
$PackageDirectory=[IO.Path]::GetFullPath($PackageDirectory)
$inf=Join-Path $PackageDirectory 'RansomGuardMinifilter.inf'
$sys=Join-Path $PackageDirectory 'RansomGuardMinifilter.sys'
$cat=Join-Path $PackageDirectory 'RansomGuardMinifilter.cat'
if(-not (Test-Path -LiteralPath $inf -PathType Leaf)){throw "INF missing: $inf"}
if(-not (Test-Path -LiteralPath $sys -PathType Leaf)){throw "SYS missing: $sys"}

$thumb=($CertificateThumbprint -replace '\s','').ToUpperInvariant()
if($thumb -notmatch '^[0-9A-F]{40,64}$'){throw 'Certificate thumbprint is invalid.'}
$cert=Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $thumb -and $_.HasPrivateKey } |
    Select-Object -First 1
if(-not $cert){throw 'Test-signing certificate with private key was not found in CurrentUser/My or LocalMachine/My.'}
$machineStore=$cert.PSParentPath -match 'LocalMachine'
$storeArgs=@()
if($machineStore){$storeArgs+='/sm'}

$signtool=Find-WdkTool 'signtool.exe'
$inf2cat=Find-WdkTool 'Inf2Cat.exe'

Write-Host "Signing current SYS with lab certificate $($cert.Subject)"
& $signtool sign /v /fd SHA256 @storeArgs /sha1 $thumb $sys
if($LASTEXITCODE -ne 0){throw "signtool SYS failed: $LASTEXITCODE"}

if(Test-Path -LiteralPath $cat){Remove-Item -LiteralPath $cat -Force}
& $inf2cat /driver:$PackageDirectory /os:10_X64 /verbose
if($LASTEXITCODE -ne 0){throw "Inf2Cat failed: $LASTEXITCODE"}
if(-not (Test-Path -LiteralPath $cat -PathType Leaf)){throw 'Inf2Cat did not produce RansomGuardMinifilter.cat.'}

& $signtool sign /v /fd SHA256 @storeArgs /sha1 $thumb $cat
if($LASTEXITCODE -ne 0){throw "signtool CAT failed: $LASTEXITCODE"}

foreach($file in @($sys,$cat)){
    $sig=Get-AuthenticodeSignature -LiteralPath $file
    if($sig.Status -ne 'Valid'){throw "Signature validation failed for $file : $($sig.Status)"}
}

Get-ChildItem -LiteralPath $PackageDirectory -File |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash,$_.Name } |
    Set-Content -LiteralPath (Join-Path $PackageDirectory 'SHA256SUMS.txt') -Encoding ascii

$infText=Get-Content -LiteralPath $inf -Raw
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){throw 'INF must continue suppressing automatic attachment.'}

& pnputil.exe /add-driver $inf /install
if($LASTEXITCODE -ne 0){throw "pnputil failed: $LASTEXITCODE"}

& fltmc load RansomGuardMinifilter
if($LASTEXITCODE -ne 0){
    $filters=(& fltmc filters | Out-String)
    if($filters -notmatch 'RansomGuardMinifilter'){throw 'Driver did not load.'}
}

& fltmc attach RansomGuardMinifilter $Volume
if($LASTEXITCODE -ne 0){
    $instances=(& fltmc instances RansomGuardMinifilter | Out-String)
    if($instances -notmatch [regex]::Escape($Volume)){throw "Explicit attach to $Volume failed."}
}

& fltmc instances RansomGuardMinifilter
Write-Host 'SIGNED CURRENT-COMMIT DRIVER INSTALLED + ATTACHED IN DISPOSABLE VM.' -ForegroundColor Green
