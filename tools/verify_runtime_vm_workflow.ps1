$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$workflow=Join-Path $root '.github\workflows\minifilter-runtime-vm.yml'
$harness=Join-Path $root 'minifilter-tools\run_runtime_vm_integration.ps1'
$installer=Join-Path $root 'minifilter-tools\install_runtime_vm_driver.ps1'

foreach($path in @($workflow,$harness,$installer)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Runtime VM source boundary missing: $path"}
}

$wf=Get-Content -LiteralPath $workflow -Raw
if($wf -notmatch '(?m)^\s*workflow_dispatch\s*:'){throw 'Runtime VM workflow must remain manual workflow_dispatch only.'}
if($wf -match '(?m)^\s*(push|pull_request|schedule)\s*:'){throw 'Runtime VM workflow must never run automatically on push/PR/schedule.'}
if($wf -notmatch [regex]::Escape('runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]')){
    throw 'Runtime VM workflow must require the dedicated self-hosted ransomguard-lab-vm runner label.'
}
if($wf -match '(?i)windows-(latest|2022|2025)|ubuntu-|macos-'){
    throw 'Runtime VM workflow must not target a GitHub-hosted runner label.'
}
foreach($required in @(
    'environment: ransomguard-runtime-lab',
    'RANSOMGUARD_RUNTIME_VM: YES-I-AM-DISPOSABLE',
    'RANSOMGUARD_TEST_CERT_THUMBPRINT',
    'build_minifilter.ps1 -Configuration Release',
    'dotnet publish .\src\RansomGuard.GateClient\RansomGuard.GateClient.csproj',
    'install_runtime_vm_driver.ps1',
    'run_runtime_vm_integration.ps1',
    'if: always()',
    'unload_minifilter_lab.ps1'
)){
    if($wf -notmatch [regex]::Escape($required)){throw "Runtime VM workflow missing invariant: $required"}
}

$h=Get-Content -LiteralPath $harness -Raw
foreach($required in @(
    'YES-I-AM-DISPOSABLE',
    'Pre-existing writable mapping must refuse activation',
    'GateClient stayed active even though a writable mapping existed before activation',
    'writableViewPresent',
    'Clean activation then writable mapping must produce verified section + paging evidence',
    'kernel gate ACTIVE',
    'writable-section-journal.jsonl',
    'paging-write-journal.jsonl',
    'Writable section was not BaselineVerified',
    'Committed pre-image does not match the original mapped file bytes',
    'FlushViewOfFile'
)){
    if($h -notmatch [regex]::Escape($required)){throw "Runtime VM harness missing invariant: $required"}
}

$i=Get-Content -LiteralPath $installer -Raw
foreach($required in @(
    'YES-I-AM-DISPOSABLE',
    'virtual|vmware|virtualbox|kvm|qemu|hyper-v|parallels|xen',
    'signtool.exe',
    'Inf2Cat.exe',
    'Get-AuthenticodeSignature',
    'pnputil.exe /add-driver',
    'fltmc load RansomGuardMinifilter',
    'fltmc attach RansomGuardMinifilter'
)){
    if($i -notmatch [regex]::Escape($required)){throw "Runtime VM installer missing invariant: $required"}
}

$combined=$wf+$h+$i
foreach($forbidden in @(
    'bcdedit /set testsigning',
    'Set-MpPreference',
    'DisableRealtimeMonitoring',
    'certutil -addstore',
    'Confirm-SecureBootUEFI'
)){
    if($combined -match [regex]::Escape($forbidden)){throw "Runtime VM tooling must not weaken host security automatically: $forbidden"}
}

Write-Host 'Runtime VM source boundary PASSED: manual-only dedicated self-hosted VM, exact-commit build/sign/install, two mapped-I/O scenarios, unconditional unload.' -ForegroundColor Green
