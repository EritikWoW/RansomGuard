[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $RepositoryRoot '.github\workflows\minifilter-gateclient-loss-vm.yml'
$harnessPath=Join-Path $RepositoryRoot 'minifilter-tools\run_gateclient_loss_lab.ps1'
$gateClientPath=Join-Path $RepositoryRoot 'src\RansomGuard.GateClient\Program.cs'
$driverPath=Join-Path $RepositoryRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
foreach($path in @($workflowPath,$harnessPath,$gateClientPath,$driverPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "GateClient-loss VM source missing: $path"}
}

$tokens=$null
$parseErrors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile($harnessPath,[ref]$tokens,[ref]$parseErrors)
if(@($parseErrors).Count -gt 0){
    $details=(@($parseErrors) | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
    throw "GateClient-loss harness PowerShell syntax failed: $details"
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'workflow_dispatch:',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'environment: ransomguard-lab-vm',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RANSOMGUARD_LAB_CERT_THUMBPRINT',
    'RG_WORKFLOW_SHA',
    '.\tools\verify_threat_model.ps1',
    '.\tools\verify_gateclient_loss_vm_harness.ps1',
    'verify_runtime_runner_readiness.ps1',
    'prepare_runtime_driver_package.ps1',
    'runtime-package.json',
    'run_gateclient_loss_lab.ps1',
    'gateclient-loss-result.json',
    'unexpectedDisconnectObserved',
    'failSafeWriteDenied',
    'failSafeCreateDenied',
    'differentRootRejected',
    'sameRootReconnectActivated',
    'sameRootCompletionDurable',
    'orderlyDisconnectAuthorized',
    'postCleanDifferentRootActivated',
    'cleanupPassed',
    'Ensure LAB minifilter is unloaded after run',
    'ransomguard-gateclient-loss-evidence'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "GateClient-loss workflow missing invariant: $required"}
}
if($workflow -match '(?m)^\s+(push|pull_request|schedule):'){
    throw 'GateClient-loss VM workflow must remain manual workflow_dispatch only.'
}

$harness=Get-Content -LiteralPath $harnessPath -Raw
foreach($required in @(
    'Assert-DisposableVm',
    'RANSOMGUARD_LAB_VM',
    'Prepare-GateRoot $gateExe $rootA',
    'Prepare-GateRoot $gateExe $rootB',
    'Stop-Process -Id $initialGate.Id -Force',
    'unexpectedDisconnectObserved',
    'containment-probe',
    'failSafeWriteDenied',
    'create-new',
    'failSafeCreateDenied',
    'different-root-rejected',
    'differentRootRejected',
    '--shutdown-marker',
    'same-root-reconnect',
    'sameRootReconnectActivated',
    'create-completion-journal.jsonl',
    'sameRootCompletionDurable',
    'Stop-GateClientClean $reconnectGate',
    'Kernel disconnect authorization:',
    'orderlyDisconnectAuthorized',
    'post-clean-different-root',
    'postCleanDifferentRootActivated',
    'Stop-GateClientClean $postCleanGate',
    'unload_minifilter_lab.ps1',
    'gateclient-loss-result.json'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "GateClient-loss harness missing invariant: $required"}
}

$forceKillCount=([regex]::Matches($harness,[regex]::Escape('Stop-Process -Id $initialGate.Id -Force'))).Count
if($forceKillCount -ne 1){
    throw "GateClient-loss qualification must contain exactly one intentional initial GateClient force-kill. Found $forceKillCount."
}
if($harness -match [regex]::Escape('Stop-Process -Id $reconnectGate.Id -Force -ErrorAction Stop') -or
   $harness -match [regex]::Escape('Stop-Process -Id $postCleanGate.Id -Force -ErrorAction Stop')){
    throw 'Reconnect and post-clean success paths must use orderly disconnect, not intentional force-kill.'
}

$gateClient=Get-Content -LiteralPath $gateClientPath -Raw
foreach($required in @(
    'case "--shutdown-marker"',
    '--shutdown-marker must be outside the protected LAB root.',
    'shutdownMarkerWatcher = Task.Run',
    'LAB orderly shutdown marker observed; draining GateClient.',
    'RgControlCommand.AuthorizeDisconnect',
    'Kernel disconnect authorization: GRANTED after clean durable shutdown state.'
)){
    if($gateClient -notmatch [regex]::Escape($required)){throw "GateClient-loss qualification client invariant missing: $required"}
}

$driver=Get-Content -LiteralPath $driverPath -Raw
foreach($required in @(
    'gProtectionArmed',
    'gFailSafeActive',
    'gDisconnectAuthorized',
    'RgControlAuthorizeDisconnect',
    'InterlockedCompareExchange(&gDisconnectAuthorized, 1, 0)',
    'RtlCompareMemory(gGateRoot, context->GateRoot, rootBytes) != rootBytes',
    'InterlockedExchange(&gFailSafeActive, 1)'
)){
    if($driver -notmatch [regex]::Escape($required)){throw "GateClient-loss qualification driver invariant missing: $required"}
}

$forbidden=@(
    'Restart-Computer',
    'shutdown.exe',
    'verifier.exe',
    'verifier /',
    'diskpart',
    'Format-Volume',
    'Initialize-Disk',
    'Clear-Disk',
    'Set-MpPreference',
    'bcdedit'
)
foreach($path in @($workflowPath,$harnessPath)){
    $text=Get-Content -LiteralPath $path -Raw
    foreach($token in $forbidden){
        if($text -match [regex]::Escape($token)){throw "GateClient-loss qualification must not mutate boot/disk/security state: $token in $path"}
    }
}

Write-Host 'GateClient-loss VM harness source gate PASSED: manual disposable-VM only, one intentional activated-client kill, fail-safe WRITE/CREATE denial, different-root rejection, same-root revalidation, durable completion, orderly disconnect, post-clean root transition, bounded cleanup, no reboot/Verifier/disk/security mutation.' -ForegroundColor Green
