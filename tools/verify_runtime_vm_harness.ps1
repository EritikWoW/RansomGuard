$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

$workflowPath=Join-Path $root '.github\workflows\minifilter-runtime-vm.yml'
$runtimeScript=Join-Path $root 'minifilter-tools\run_runtime_integration_lab.ps1'
$packageScript=Join-Path $root 'minifilter-tools\prepare_runtime_driver_package.ps1'
$readinessScript=Join-Path $root 'minifilter-tools\verify_runtime_runner_readiness.ps1'
$installScript=Join-Path $root 'minifilter-tools\install_minifilter_lab.ps1'
$helperSource=Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs'
$helperProject=Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.csproj'
$build=Join-Path $root 'build_windows.ps1'
$buildWrapper=Join-Path $root 'build_windows.cmd'

foreach($path in @($workflowPath,$runtimeScript,$packageScript,$readinessScript,$installScript,$helperSource,$helperProject,$build,$buildWrapper)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Runtime VM harness required file missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'workflow_dispatch:',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'environment: ransomguard-lab-vm',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RANSOMGUARD_LAB_CERT_THUMBPRINT',
    'prepare_runtime_driver_package.ps1',
    'verify_runtime_runner_readiness.ps1',
    'run_runtime_integration_lab.ps1',
    'runtime-package.json',
    'github.sha'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Runtime VM workflow missing invariant: $required"}
}
if($workflow -match '(?m)^\s+(push|pull_request|schedule):'){
    throw 'Runtime VM workflow must remain manual workflow_dispatch only.'
}
if($workflow -match 'ransomguard-runtime-driver/\*\*'){
    throw 'Signed runtime driver package must not be uploaded as a workflow artifact.'
}

$runtime=Get-Content -LiteralPath $runtimeScript -Raw
foreach($required in @(
    'RANSOMGUARD_LAB_VM',
    'I_UNDERSTAND',
    'Win32_ComputerSystem',
    'install_minifilter_lab.ps1',
    'unload_minifilter_lab.ps1',
    'predirectory',
    'preexistingDirectoryHandleRejected',
    'hold-dir-delete',
    'preexisting-map.bin',
    'writableViewPresent',
    'postactivation-map.bin',
    'BaselineVerified writable-section evidence',
    'paging-write evidence',
    'originalSha256',
    'runtime-result.json',
    'containment',
    '--contain-pid',
    'containmentDeniedTarget',
    'containmentPreservedTargetHash',
    'containmentAllowedPeer',
    'containment-transition',
    '--contain-after-pid',
    'transitionRequested',
    'transitionKernelActive',
    'transitionDeniedNextWrite',
    'containment-journal.jsonl'
)){
    if($runtime -notmatch [regex]::Escape($required)){throw "Runtime integration script missing invariant: $required"}
}

$readiness=Get-Content -LiteralPath $readinessScript -Raw
foreach($required in @(
    'WindowsBuiltInRole]::Administrator',
    'RANSOMGUARD_LAB_VM',
    'Win32_ComputerSystem',
    'Cert:\CurrentUser\My',
    'Cert:\LocalMachine\My',
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    'fltKernel.h',
    'FltMgr.lib',
    'signtool.exe',
    'Inf2Cat.exe',
    'infverif.exe',
    'ApiValidator.exe',
    'Aitstatic.exe',
    'pwsh.exe',
    'fltmc.exe',
    'pnputil.exe'
)){
    if($readiness -notmatch [regex]::Escape($required)){throw "Runtime runner readiness check missing invariant: $required"}
}

$package=Get-Content -LiteralPath $packageScript -Raw
foreach($required in @(
    'build_minifilter.ps1',
    'signtool.exe',
    'Inf2Cat.exe',
    'RANSOMGUARD_LAB_VM',
    'runtime-package.json',
    'git -C $root rev-parse HEAD',
    'Get-AuthenticodeSignature',
    'RansomGuardMinifilter.cat'
)){
    if($package -notmatch [regex]::Escape($required)){throw "Runtime package script missing invariant: $required"}
}

$forbidden=@(
    'bcdedit',
    'Set-MpPreference',
    'Add-MpPreference',
    'Remove-MpPreference',
    'certutil -addstore',
    'Import-Certificate',
    'Set-SecureBootUEFI',
    'Disable-WindowsOptionalFeature'
)
foreach($path in @($runtimeScript,$packageScript,$readinessScript,$workflowPath)){
    $text=Get-Content -LiteralPath $path -Raw
    foreach($token in $forbidden){
        if($text -match [regex]::Escape($token)){throw "Runtime VM harness must not modify boot/security/trust policy: $token in $path"}
    }
}

$helper=Get-Content -LiteralPath $helperSource -Raw
foreach($required in @(
    'hold-map',
    'hold-dir-delete',
    'map-write',
    'containment-probe',
    'containment-transition',
    'ContainmentTransitionProbe',
    'denied-after-threshold',
    'RANSOMGUARD-CONTAINMENT-PROBE-SHOULD-NOT-WRITE',
    'DeleteAccess',
    'FileFlagBackupSemantics',
    'CreateFileMappingW',
    'MapViewOfFile',
    'FlushViewOfFile',
    'FlushFileBuffers',
    'UnmapViewOfFile'
)){
    if($helper -notmatch [regex]::Escape($required)){throw "Runtime mapping helper missing invariant: $required"}
}
$holdStart=$helper.IndexOf('static void HoldMappedView')
$holdEnd=$helper.IndexOf('static void MapAndWrite',$holdStart)
if($holdStart -lt 0 -or $holdEnd -lt 0){throw 'HoldMappedView source block missing.'}
$hold=$helper.Substring($holdStart,$holdEnd-$holdStart)
$closeMap=$hold.IndexOf('Native.CloseHandle(mapping)')
$closeFile=$hold.IndexOf('file.Dispose()')
$ready=$hold.IndexOf('File.WriteAllText(readyMarker')
if($closeMap -lt 0 -or $closeFile -lt 0 -or $ready -lt 0 -or $closeMap -gt $ready -or $closeFile -gt $ready){
    throw 'Pre-existing mapping scenario must close file/mapping handles before advertising the held mapped view.'
}

$dirHoldStart=$helper.IndexOf('static void HoldDirectoryDeleteHandle')
$dirHoldEnd=$helper.IndexOf('static void MapAndWrite',$dirHoldStart)
if($dirHoldStart -lt 0 -or $dirHoldEnd -lt 0){throw 'HoldDirectoryDeleteHandle source block missing.'}
$dirHold=$helper.Substring($dirHoldStart,$dirHoldEnd-$dirHoldStart)
foreach($required in @('DeleteAccess','ShareRead | ShareWrite | ShareDelete','FileFlagBackupSemantics','CreateFileW','readyMarker','releaseMarker')){
    if($dirHold -notmatch [regex]::Escape($required)){throw "Directory DELETE-handle runtime helper missing invariant: $required"}
}

$containStart=$helper.IndexOf('static void ContainmentProbe')
$containEnd=$helper.IndexOf('static void MapAndWrite',$containStart)
if($containStart -lt 0 -or $containEnd -lt 0){throw 'ContainmentProbe source block missing.'}
$containBlock=$helper.Substring($containStart,$containEnd-$containStart)
foreach($required in @('readyMarker','goMarker','resultMarker','File.AppendAllText','UnauthorizedAccessException','Environment.ExitCode = 9')){
    if($containBlock -notmatch [regex]::Escape($required)){throw "Containment runtime helper missing invariant: $required"}
}
if($runtime -notmatch 'LAB containment\s+: ACTIVE' -or
   $runtime -notmatch [regex]::Escape("if(`$containOutcome -ne 'denied'){") -or
   $runtime -notmatch [regex]::Escape('peerAfterHash,$peerOriginalHash')){
    throw 'Runtime containment scenario must prove target denial/hash preservation and ordinary-peer mutation.'
}

$transitionStart=$helper.IndexOf('static void ContainmentTransitionProbe')
$transitionEnd=$helper.IndexOf('static void MapAndWrite',$transitionStart)
if($transitionStart -lt 0 -or $transitionEnd -lt 0){throw 'ContainmentTransitionProbe source block missing.'}
$transitionBlock=$helper.Substring($transitionStart,$transitionEnd-$transitionStart)
foreach($required in @(
    'FileMode.Open',
    'FileAccess.Write',
    'FileOptions.WriteThrough',
    'a.Write(new byte[] { 0xA1 })',
    'b.Write(new byte[] { 0xB2 })',
    'denied-after-threshold'
)){
    if($transitionBlock -notmatch [regex]::Escape($required)){throw "Event-bound containment runtime helper missing invariant: $required"}
}
foreach($required in @(
    "'--contain-after-pid'",
    "'--contain-after-events','4'",
    "'--contain-after-paths','2'",
    '[int]$x.phase -eq 1',
    '[int]$x.evidenceCount -eq 4',
    '[int]$x.distinctPathCount -eq 2',
    '[int]$x.phase -eq 2',
    'transitionRequest.kernelSequence',
    'LAB CONTAINMENT ACTIVE'
)){
    if($runtime -notmatch [regex]::Escape($required)){throw "Event-bound containment runtime scenario missing invariant: $required"}
}

$install=Get-Content -LiteralPath $installScript -Raw
if($install -notmatch [regex]::Escape("ValidateSet('','LAB-MINIFILTER')") -or
   $install -notmatch [regex]::Escape('$Confirmation')){
    throw 'Install script must support explicit VM-only noninteractive confirmation for the runtime workflow.'
}

$buildText=Get-Content -LiteralPath $build -Raw
foreach($required in @(
    'RansomGuard.Minifilter.RuntimeHarness.csproj',
    'MinifilterLab\RuntimeHarness',
    'verify_runtime_vm_harness.ps1'
)){
    if($buildText -notmatch [regex]::Escape($required)){throw "Engineering LAB build missing runtime harness packaging invariant: $required"}
}

$buildWrapperText=Get-Content -LiteralPath $buildWrapper -Raw
foreach($required in @('where.exe pwsh.exe','set "PS_EXE=pwsh.exe"','powershell.exe')){
    if($buildWrapperText -notmatch [regex]::Escape($required)){throw "Windows build wrapper missing PowerShell host invariant: $required"}
}

Write-Host 'Runtime VM harness source gate PASSED: manual self-hosted VM only, exact-commit signed driver provenance, mapping coverage, pre-armed containment and event-bound containment transition, no boot/trust/Defender mutation.' -ForegroundColor Green
