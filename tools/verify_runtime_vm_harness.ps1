$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

$workflowPath=Join-Path $root '.github\workflows\minifilter-runtime-vm.yml'
$runtimeScript=Join-Path $root 'minifilter-tools\run_runtime_integration_lab.ps1'
$packageScript=Join-Path $root 'minifilter-tools\prepare_runtime_driver_package.ps1'
$readinessScript=Join-Path $root 'minifilter-tools\verify_runtime_runner_readiness.ps1'
$installScript=Join-Path $root 'minifilter-tools\install_minifilter_lab.ps1'
$unloadScript=Join-Path $root 'minifilter-tools\unload_minifilter_lab.ps1'
$helperSource=Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\Program.cs'
$helperProject=Join-Path $root 'tests\RansomGuard.Minifilter.RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.csproj'
$build=Join-Path $root 'build_windows.ps1'
$buildWrapper=Join-Path $root 'build_windows.cmd'
$automationAudit=Join-Path $root 'tools\verify_powershell_automation.ps1'

foreach($path in @($workflowPath,$runtimeScript,$packageScript,$readinessScript,$installScript,$unloadScript,$helperSource,$helperProject,$build,$buildWrapper,$automationAudit)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Runtime VM harness required file missing: $path"}
}

& $automationAudit -RepositoryRoot $root

foreach($scriptPath in @($runtimeScript,$packageScript,$readinessScript,$installScript,$unloadScript)){
    $tokens=$null
    $parseErrors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$parseErrors)
    if(@($parseErrors).Count -gt 0){
        $details=(@($parseErrors) | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
        throw "Runtime VM PowerShell syntax check failed for ${scriptPath}: $details"
    }
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'workflow_dispatch:',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'environment: ransomguard-lab-vm',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RANSOMGUARD_LAB_CERT_THUMBPRINT',
    'RG_WORKFLOW_SHA',
    'prepare_runtime_driver_package.ps1',
    'verify_runtime_runner_readiness.ps1',
    'run_runtime_integration_lab.ps1',
    'unload_minifilter_lab.ps1',
    'Clear stale LAB minifilter from prior failed run',
    'runtime-package.json',
    'provenance.schema',
    'provenance.productVersion',
    'Get-FileHash -LiteralPath $artifact[1] -Algorithm SHA256',
    'Remove-Item -LiteralPath $results -Recurse -Force',
    "'cleanupPassed'",
    'Runtime result invariant',
    'Runtime cleanup reported an error',
    'certificateThumbprint',
    'Ensure LAB minifilter is unloaded after run',
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
if($runtime -match [regex]::Escape("version='0.7.21.0'")){
    throw 'Runtime evidence must not hard-code the product version.'
}

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
    'concurrencyStressPassed',
    'concurrencyCreateCorrelated',
    'concurrencyRenameCorrelated',
    'concurrencyTruncateCorrelated',
    'concurrencyDeleteCorrelated',
    'concurrencyMappedEvidence',
    'concurrencyGateWorkers=4',
    '$summary.concurrencyProcessCount=$stressProcesses.Count',
    'Concurrency stress launched an unexpected helper count',
    'concurrency-stress',
    "'--gate-workers','4'",
    "'Bounded gate workers\s+: 4'",
    "'Sessions\concurrency-stress'",
    "'create-state\create-completion-journal.jsonl'",
    '$stressCount=4',
    'Wait-StressProcesses $stressProcesses 90',
    'Wait-CorrelatedJournalPair',
    'Timed out waiting for correlated $Description journals',
    'foreach($targetPath in @($truncateFiles+$deleteFiles))',
    'durable stress CREATE completion for $targetPath',
    'Assert-CorrelatedJournalPair',
    '[System.Collections.Generic.HashSet[uint64]]::new()',
    '$truncateIntent.requestSequence',
    '$deleteIntent.requestSequence',
    'Stress mapped pre-image hash mismatch',
    'Gate worker failed:',
    'containment-journal.jsonl',
    'Stop-LabProcess $gatePost',
    'Stop-LabProcess $gateContain',
    '.VersionInfo.FileVersion',
    'version=$gateVersion',
    'cleanupPassed=$false',
    'cleanupError=$null',
    '$runtimeFailure=$null',
    '$cleanupFailure=$null',
    'runtime-package.json',
    'Assert-NoReparsePath',
    'Assert-NoReparsePath -Path $RootBase -Label ''RootBase''',
    'Assert-NoReparsePath -Path $ResultsDirectory -Label ''ResultsDirectory''',
    'driverProvenance.schema',
    'driverProvenance.productVersion',
    'driverSysSha256',
    'driverInfSha256',
    'driverCatSha256'
)){
    if($runtime -notmatch [regex]::Escape($required)){throw "Runtime integration script missing invariant: $required"}
}

$stressStart=$runtime.IndexOf('# Scenario 5: mixed high-concurrency stress.')
$stressStopTransition=$runtime.IndexOf('Stop-LabProcess $gateTransition ''event-bound containment gate''',$stressStart)
$stressGateStart=$runtime.IndexOf('''--gate-workers'',''4''',$stressStopTransition)
$stressReady=$runtime.IndexOf('Wait-Path $truncateReady 30',$stressGateStart)
$stressCreateCompletion=$runtime.IndexOf('$createCompletionJournal',$stressReady)
$stressImmediate=$runtime.IndexOf('# Add 12 immediate operations',$stressCreateCompletion)
$stressRelease=$runtime.IndexOf('foreach($marker in $stressGoMarkers)',$stressImmediate)
$stressWait=$runtime.IndexOf('Wait-StressProcesses $stressProcesses 90',$stressRelease)
$stressCorrelation=$runtime.IndexOf('Wait-CorrelatedJournalPair (Join-Path $stressSession ''rename-state\rename-journal.jsonl'') $renameCompletionJournal ''stress RENAME'' 45 4 4',$stressWait)
$stressStop=$runtime.IndexOf('Stop-LabProcess $gateStress ''concurrency stress gate''',$stressCorrelation)
if($stressStart -lt 0 -or $stressStopTransition -lt 0 -or $stressGateStart -lt 0 -or
   $stressReady -lt 0 -or $stressCreateCompletion -lt 0 -or $stressImmediate -lt 0 -or
   $stressRelease -lt 0 -or $stressWait -lt 0 -or $stressCorrelation -lt 0 -or $stressStop -lt 0 -or
   $stressStart -gt $stressStopTransition -or $stressStopTransition -gt $stressGateStart -or
   $stressGateStart -gt $stressReady -or $stressReady -gt $stressCreateCompletion -or
   $stressCreateCompletion -gt $stressImmediate -or $stressImmediate -gt $stressRelease -or
   $stressRelease -gt $stressWait -or $stressWait -gt $stressCorrelation -or
   $stressCorrelation -gt $stressStop){
    throw 'Concurrency stress must stop the prior gate, fix GateClient at 4 workers, hold destructive handles until durable CREATE completion, release one mixed burst, correlate journals, then stop the stress gate.'
}

foreach($binding in @(
    '[string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$truncateFiles[$i]',
    '[uint64]$x.requestSequence -eq [uint64]$truncateIntent.requestSequence',
    '[string]::Equals([IO.Path]::GetFullPath([string]$x.originalPath),$deleteFiles[$i]',
    '[uint64]$x.requestSequence -eq [uint64]$deleteIntent.requestSequence'
)){
    if($runtime -notmatch [regex]::Escape($binding)){
        throw "Concurrency stress exact path/requestSequence binding missing: $binding"
    }
}

if($runtime -match [regex]::Escape('foreach($path in @($truncateFiles+$deleteFiles))')){
    throw 'Concurrency stress must use a dedicated targetPath variable when waiting for CREATE completion evidence.'
}

foreach($damaged in @(
    'Bounded gate workerss+: 4',
    'Sessionsconcurrency-stress',
    'create-statecreate-completion-journal.jsonl',
    'rename-staterename-completion-journal.jsonl',
    'truncate-statetruncate-completion-journal.jsonl',
    'delete-statedelete-completion-journal.jsonl',
    'section-statewritable-section-journal.jsonl',
    'paging-statepaging-write-journal.jsonl'
)){
    if($runtime.Contains($damaged)){
        throw "Concurrency stress contains an escaped-path/log corruption marker: $damaged"
    }
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
    'Confirm-SecureBootUEFI',
    'Set-AuthenticodeSignature',
    'X509EnhancedKeyUsageExtension',
    '2.5.29.37',
    'EnhancedKeyUsages',
    'TrustedPublisher',
    'testsigning',
    'fltmc filters',
    'fltmc.exe',
    'pnputil.exe'
)){
    if($readiness -notmatch [regex]::Escape($required)){throw "Runtime runner readiness check missing invariant: $required"}
}

if($readiness -match [regex]::Escape('EnhancedKeyUsageList')){
    throw 'Runtime runner readiness must decode the certificate EKU extension directly; EnhancedKeyUsageList provider projections are not stable across PowerShell hosts.'
}

$package=Get-Content -LiteralPath $packageScript -Raw
foreach($required in @(
    'build_minifilter.ps1',
    'signtool.exe',
    'Inf2Cat.exe',
    'RANSOMGUARD_LAB_VM',
    'runtime-package.json',
    'git -C $root rev-parse HEAD',
    'schema=2',
    'productVersion=$productVersion',
    'infSha256=',
    'Get-AuthenticodeSignature',
    'SignerCertificate',
    'signer thumbprint does not match requested lab certificate',
    'RansomGuardMinifilter.cat'
)){
    if($package -notmatch [regex]::Escape($required)){throw "Runtime package script missing invariant: $required"}
}

$forbidden=@(
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
    if($text -match '(?im)\bbcdedit(?:\.exe)?\b[^\r\n]*(?:/set|/deletevalue|/create|/copy|/delete|/import)\b'){
        throw "Runtime VM harness may query BCD state but must never mutate it: $path"
    }
}

$helper=Get-Content -LiteralPath $helperSource -Raw
foreach($requiredDiagnostic in @(
    'RUNTIME HARNESS ERROR',
    'HResult: 0x{ex.HResult:X8}',
    'Win32Error:',
    'Environment.ExitCode = 20'
)){
    if($helper -notmatch [regex]::Escape($requiredDiagnostic)){throw "Runtime mapping helper missing explicit crash diagnostic: $requiredDiagnostic"}
}

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
foreach($required in @('readyMarker','goMarker','resultMarker','File.AppendAllText','UnauthorizedAccessException','(ex.HResult & 0xFFFF) == 5','Environment.ExitCode = 9')){
    if($containBlock -notmatch [regex]::Escape($required)){throw "Containment runtime helper missing invariant: $required"}
}
if($runtime -notmatch [regex]::Escape("'LAB containment\s+: ACTIVE'") -or
   $runtime -notmatch [regex]::Escape("if(`$containOutcome -ne 'denied'){") -or
   $runtime -notmatch [regex]::Escape('peerAfterHash,$peerOriginalHash')){
    throw 'Runtime containment scenario must prove target denial/hash preservation and ordinary-peer mutation.'
}

$transitionStart=$helper.IndexOf('static void ContainmentTransitionProbe')
$transitionEnd=$helper.IndexOf('static void MapAndWrite',$transitionStart)
if($transitionStart -lt 0 -or $transitionEnd -lt 0){throw 'ContainmentTransitionProbe source block missing.'}
$transitionBlock=$helper.Substring($transitionStart,$transitionEnd-$transitionStart)
foreach($required in @(
    'OpenTransitionWriteHandle(fileA)',
    'OpenTransitionWriteHandle(fileB)',
    'WriteTransitionByte(a, 0, 0xA1',
    'WriteTransitionByte(b, 0, 0xB2',
    'TryWriteTransitionByte(a, 1, 0xC3',
    'FileFlagWriteThrough',
    'Native.SetFilePointerEx',
    'Native.WriteFile',
    'error == 5',
    'denied-after-threshold'
)){
    if($transitionBlock -notmatch [regex]::Escape($required)){throw "Event-bound containment runtime helper missing invariant: $required"}
}
if($transitionBlock -match 'FileStream\(' -or $transitionBlock -match '\.Flush\(true\)'){
    throw 'Event-bound containment runtime helper must use direct WriteFile operations; buffered FileStream/Flush can split one logical step into multiple gated writes.'
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
foreach($required in @(
    'ImagePath',
    'packageSysHash',
    'installedSysHash',
    'registered minifilter image is stale or mismatched',
    'already loaded before install',
    'rundll32 DefaultInstall failed',
    'Registered minifilter service StartType',
    'Registered minifilter instance contract is invalid'
)){
    if($install -notmatch [regex]::Escape($required)){throw "Install script missing exact-package image verification invariant: $required"}
}
foreach($required in @(
    'fltmc instances -f RansomGuardMinifilter',
    '$instancesExit=$LASTEXITCODE',
    '$instances -notmatch [regex]::Escape($Volume)'
)){
    if($install -notmatch [regex]::Escape($required)){throw "Install script missing attach-verification invariant: $required"}
}
if($install -match [regex]::Escape('fltmc instances -f RansomGuardMinifilter -v $Volume')){
    throw 'Install script uses an invalid fltmc instances syntax: -f and -v are mutually exclusive.'
}

$unload=Get-Content -LiteralPath $unloadScript -Raw
foreach($required in @(
    'fltmc detach RansomGuardMinifilter',
    'fltmc unload RansomGuardMinifilter',
    'fltmc filters',
    'RansomGuardMinifilter is still loaded after cleanup'
)){
    if($unload -notmatch [regex]::Escape($required)){throw "Runtime cleanup script missing final-state invariant: $required"}
}
$cleanupArmIndex=$runtime.IndexOf('$installed=$true')
$installInvokeIndex=$runtime.IndexOf('& $installScript')
if($cleanupArmIndex -lt 0 -or $installInvokeIndex -lt 0 -or $cleanupArmIndex -gt $installInvokeIndex){
    throw 'Runtime harness must arm minifilter cleanup before invoking the installer.'
}

$buildText=Get-Content -LiteralPath $build -Raw
foreach($required in @(
    'RansomGuard.Minifilter.RuntimeHarness.csproj',
    'MinifilterLab\RuntimeHarness',
    'verify_runtime_vm_harness.ps1',
    'verify_powershell_automation.ps1'
)){
    if($buildText -notmatch [regex]::Escape($required)){throw "Engineering LAB build missing runtime harness packaging invariant: $required"}
}

$buildWrapperText=Get-Content -LiteralPath $buildWrapper -Raw
foreach($required in @('where.exe pwsh.exe','set "PS_EXE=pwsh.exe"','powershell.exe','if /I not "%GITHUB_ACTIONS%"=="true" pause')){
    if($buildWrapperText -notmatch [regex]::Escape($required)){throw "Windows build wrapper missing PowerShell host invariant: $required"}
}

Write-Host 'Runtime VM harness source gate PASSED: manual self-hosted VM only, exact-commit signed driver provenance, mapping coverage, bounded 20-process concurrency stress, containment transitions, no boot/trust/Defender mutation.' -ForegroundColor Green
