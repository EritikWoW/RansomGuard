[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$GateClientPath,
    [string]$Root = 'C:\RansomGuard-Runtime-Lab',
    [string]$StoreRoot = 'C:\RansomGuard-Runtime-Store',
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference='Stop'

function Assert-DisposableVm {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Runtime minifilter harness must run elevated.'}
    if($env:RANSOMGUARD_RUNTIME_VM -cne 'YES-I-AM-DISPOSABLE'){
        throw 'REFUSED: set RANSOMGUARD_RUNTIME_VM=YES-I-AM-DISPOSABLE only inside the disposable snapshot VM.'
    }
    $cs=Get-CimInstance Win32_ComputerSystem
    $vmText=("$($cs.Manufacturer) $($cs.Model)")
    if($vmText -notmatch '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen'){
        throw "REFUSED: runtime harness requires an obvious VM. Detected: $vmText"
    }
    $filters=(& fltmc filters | Out-String)
    if($filters -notmatch 'RansomGuardMinifilter'){throw 'RansomGuardMinifilter is not loaded.'}
    $instances=(& fltmc instances RansomGuardMinifilter | Out-String)
    if($instances -notmatch 'RansomGuardMinifilter'){throw 'RansomGuardMinifilter has no attached instance.'}
    Write-Host "Disposable VM confirmed: $vmText"
}

function Reset-Directory([string]$Path){
    if(Test-Path -LiteralPath $Path){Remove-Item -LiteralPath $Path -Recurse -Force}
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Start-Gate([string]$LabRoot,[string]$Store,[string]$Session,[string]$Out,[string]$Err){
    $args=@('--root',$LabRoot,'--store',$Store,'--session',$Session,'--gate-workers','2')
    return Start-Process -FilePath $GateClientPath -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $Out -RedirectStandardError $Err
}

function Wait-Text([string]$Path,[string]$Needle,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    do{
        if(Test-Path -LiteralPath $Path){
            $text=Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if($text -match [regex]::Escape($Needle)){return $true}
        }
        Start-Sleep -Milliseconds 200
    }while((Get-Date) -lt $deadline)
    return $false
}

function Wait-NonEmptyFile([string]$Path,[int]$Seconds){
    $deadline=(Get-Date).AddSeconds($Seconds)
    do{
        if((Test-Path -LiteralPath $Path -PathType Leaf) -and (Get-Item -LiteralPath $Path).Length -gt 0){return $true}
        Start-Sleep -Milliseconds 200
    }while((Get-Date) -lt $deadline)
    return $false
}

function Stop-Gate([System.Diagnostics.Process]$Process){
    if($null -ne $Process -and -not $Process.HasExited){
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null=$Process.WaitForExit(5000)
    }
}

if(-not (Test-Path -LiteralPath $GateClientPath -PathType Leaf)){throw "GateClient not found: $GateClientPath"}
$GateClientPath=[IO.Path]::GetFullPath($GateClientPath)
$Root=[IO.Path]::GetFullPath($Root)
$StoreRoot=[IO.Path]::GetFullPath($StoreRoot)
if($Root -eq $StoreRoot -or $StoreRoot.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'StoreRoot must remain outside the protected LAB root.'
}

Assert-DisposableVm

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class RgRuntimeMappedView : IDisposable
{
    const uint GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000;
    const uint FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, FILE_SHARE_DELETE=4;
    const uint OPEN_EXISTING=3, PAGE_READWRITE=0x04, FILE_MAP_WRITE=0x0002;

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFileMappingW(SafeFileHandle file,IntPtr attrs,uint protect,uint maxHigh,uint maxLow,string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFile(IntPtr mapping,uint desired,uint offHigh,uint offLow,UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FlushViewOfFile(IntPtr address,UIntPtr bytes);
    [DllImport("kernel32.dll")]
    static extern bool UnmapViewOfFile(IntPtr address);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    IntPtr mapping;
    IntPtr view;
    bool disposed;

    RgRuntimeMappedView(IntPtr mapping, IntPtr view){this.mapping=mapping;this.view=view;}

    public static RgRuntimeMappedView Open(string path)
    {
        using(var file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            IntPtr.Zero,OPEN_EXISTING,0,IntPtr.Zero))
        {
            if(file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(),"CreateFileW failed");
            var map=CreateFileMappingW(file,IntPtr.Zero,PAGE_READWRITE,0,0,null);
            if(map==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(),"CreateFileMappingW failed");
            var view=MapViewOfFile(map,FILE_MAP_WRITE,0,0,UIntPtr.Zero);
            if(view==IntPtr.Zero){var e=Marshal.GetLastWin32Error();CloseHandle(map);throw new Win32Exception(e,"MapViewOfFile failed");}
            return new RgRuntimeMappedView(map,view);
        }
    }

    public void WriteByte(int offset, byte value)
    {
        if(disposed) throw new ObjectDisposedException(nameof(RgRuntimeMappedView));
        Marshal.WriteByte(view,offset,value);
    }

    public void Flush()
    {
        if(disposed) throw new ObjectDisposedException(nameof(RgRuntimeMappedView));
        if(!FlushViewOfFile(view,UIntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(),"FlushViewOfFile failed");
    }

    public void Dispose()
    {
        if(disposed) return;
        disposed=true;
        if(view!=IntPtr.Zero){UnmapViewOfFile(view);view=IntPtr.Zero;}
        if(mapping!=IntPtr.Zero){CloseHandle(mapping);mapping=IntPtr.Zero;}
    }
}
'@

$work=Join-Path $env:TEMP ('RansomGuard-Runtime-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$gateA=$null
$gateB=$null
$preMap=$null
$postMap=$null

try {
    Write-Host '[1/2] Pre-existing writable mapping must refuse activation.' -ForegroundColor Cyan
    Reset-Directory $Root
    Reset-Directory $StoreRoot
    & $GateClientPath --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "GateClient prepare-root failed: $LASTEXITCODE"}

    $preFile=Join-Path $Root 'preexisting-map.bin'
    [IO.File]::WriteAllBytes($preFile,(New-Object byte[] (64*1024)))
    $preMap=[RgRuntimeMappedView]::Open($preFile)

    $outA=Join-Path $work 'gate-preexisting.out.log'
    $errA=Join-Path $work 'gate-preexisting.err.log'
    $gateA=Start-Gate $Root $StoreRoot 'runtime_preexisting' $outA $errA

    if(-not $gateA.WaitForExit($TimeoutSeconds*1000)){
        Stop-Gate $gateA
        throw 'GateClient stayed active even though a writable mapping existed before activation.'
    }
    $combinedA=((Get-Content $outA -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+(Get-Content $errA -Raw -ErrorAction SilentlyContinue))
    if($gateA.ExitCode -eq 0){throw 'GateClient unexpectedly exited successfully in pre-existing-mapping scenario.'}
    if($combinedA -notmatch '(?i)Activation refused|writable mapped view|preflight'){
        throw "Activation failed for an unexpected reason. Output: $combinedA"
    }

    $activationJournal=Join-Path $StoreRoot 'Sessions\runtime_preexisting\activation-state\activation-preflight-journal.jsonl'
    if(-not (Wait-NonEmptyFile $activationJournal 5)){throw 'Pre-existing mapping scenario did not persist activation evidence.'}
    $activationRecord=(Get-Content -LiteralPath $activationJournal | Select-Object -Last 1 | ConvertFrom-Json)
    if(-not $activationRecord.writableViewPresent){throw 'Kernel preflight did not mark the pre-existing writable view.'}
    Write-Host 'PASS: pre-existing writable mapped view prevented LAB activation.' -ForegroundColor Green

    $preMap.Dispose(); $preMap=$null
    Stop-Gate $gateA; $gateA=$null

    Write-Host '[2/2] Clean activation then writable mapping must produce verified section + paging evidence.' -ForegroundColor Cyan
    Reset-Directory $Root
    Reset-Directory $StoreRoot
    & $GateClientPath --root $Root --prepare-root
    if($LASTEXITCODE -ne 0){throw "GateClient prepare-root failed: $LASTEXITCODE"}

    $postFile=Join-Path $Root 'post-activation-map.bin'
    $initial=New-Object byte[] (64*1024)
    for($i=0;$i -lt 64;$i++){$initial[$i]=[byte]($i -band 0xff)}
    [IO.File]::WriteAllBytes($postFile,$initial)
    $originalHash=(Get-FileHash -LiteralPath $postFile -Algorithm SHA256).Hash

    $outB=Join-Path $work 'gate-clean.out.log'
    $errB=Join-Path $work 'gate-clean.err.log'
    $gateB=Start-Gate $Root $StoreRoot 'runtime_clean' $outB $errB
    if(-not (Wait-Text $outB 'kernel gate ACTIVE' $TimeoutSeconds)){
        $combinedB=((Get-Content $outB -Raw -ErrorAction SilentlyContinue)+[Environment]::NewLine+(Get-Content $errB -Raw -ErrorAction SilentlyContinue))
        Stop-Gate $gateB
        throw "Clean activation did not become active. Output: $combinedB"
    }

    $postMap=[RgRuntimeMappedView]::Open($postFile)
    $postMap.WriteByte(7,0xA5)
    $postMap.Flush()

    $sessionRoot=Join-Path $StoreRoot 'Sessions\runtime_clean'
    $sectionJournal=Join-Path $sessionRoot 'section-state\writable-section-journal.jsonl'
    $pagingJournal=Join-Path $sessionRoot 'paging-state\paging-write-journal.jsonl'
    if(-not (Wait-NonEmptyFile $sectionJournal $TimeoutSeconds)){throw 'Writable mapping produced no section attestation journal.'}
    if(-not (Wait-NonEmptyFile $pagingJournal $TimeoutSeconds)){throw 'Flushed mapped write produced no paging-write evidence journal.'}

    $sectionRecord=(Get-Content -LiteralPath $sectionJournal | Select-Object -Last 1 | ConvertFrom-Json)
    if([int]$sectionRecord.state -ne 1){throw "Writable section was not BaselineVerified. state=$($sectionRecord.state)"}

    $objects=Join-Path $sessionRoot 'objects'
    $preimages=@(Get-ChildItem -LiteralPath $objects -Filter '*.preimage' -File -ErrorAction SilentlyContinue)
    if($preimages.Count -lt 1){throw 'Writable-open mapping scenario has no committed full pre-image.'}
    $snapshotHash=(Get-FileHash -LiteralPath $preimages[0].FullName -Algorithm SHA256).Hash
    if($snapshotHash -ne $originalHash){throw 'Committed pre-image does not match the original mapped file bytes.'}

    $postHash=(Get-FileHash -LiteralPath $postFile -Algorithm SHA256).Hash
    if($postHash -eq $originalHash){throw 'Mapped-write test did not change the live file.'}

    Write-Host 'PASS: clean activation produced BaselineVerified writable-section evidence, paging evidence, and a byte-identical pre-image.' -ForegroundColor Green
    Write-Host "Runtime evidence root: $sessionRoot"
}
finally {
    if($null -ne $postMap){$postMap.Dispose()}
    if($null -ne $preMap){$preMap.Dispose()}
    Stop-Gate $gateB
    Stop-Gate $gateA
    Write-Host "Runtime logs: $work"
}
