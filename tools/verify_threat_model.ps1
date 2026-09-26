[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$threatPath=Join-Path $RepositoryRoot 'docs\THREAT_MODEL.md'
$securityPath=Join-Path $RepositoryRoot 'docs\SECURITY.md'
$containmentRecoveryPath=Join-Path $RepositoryRoot 'docs\CONTAINMENT_ACTUATOR_RECOVERY.md'
$driverPath=Join-Path $RepositoryRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
$policyPath=Join-Path $RepositoryRoot 'src\RansomGuard.Core\DecisionPolicy.cs'
$workerPath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\GuardWorker.cs'
$gateClientPath=Join-Path $RepositoryRoot 'src\RansomGuard.GateClient\Program.cs'
$lifecyclePath=Join-Path $RepositoryRoot 'src\RansomGuard.Service\ProductionProtectionLifecycle.cs'
$protocolPath=Join-Path $RepositoryRoot 'native\shared\rg_minifilter_protocol.h'
$verifierGatePath=Join-Path $RepositoryRoot 'tools\verify_driver_verifier_vm_harness.ps1'
$buildPath=Join-Path $RepositoryRoot 'build_windows.ps1'
$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
if(-not(Test-Path -LiteralPath $workflowRoot -PathType Container)){
    throw "Threat-model workflow root missing: $workflowRoot"
}
$workflowPaths=@(
    Get-ChildItem -LiteralPath $workflowRoot -File |
        Where-Object { $_.Extension -in @('.yml','.yaml') } |
        Sort-Object FullName |
        Select-Object -ExpandProperty FullName
)
if($workflowPaths.Count -eq 0){
    throw 'Threat-model gate found no GitHub Actions workflows to audit.'
}
$globalPath=Join-Path $RepositoryRoot 'global.json'
$supplyGatePath=Join-Path $RepositoryRoot 'tools\verify_supply_chain.ps1'
$codeOwnersPath=Join-Path $RepositoryRoot '.github\CODEOWNERS'

foreach($path in @($threatPath,$securityPath,$containmentRecoveryPath,$driverPath,$policyPath,$workerPath,$gateClientPath,$lifecyclePath,$protocolPath,$verifierGatePath,$buildPath,$globalPath,$supplyGatePath,$codeOwnersPath)+$workflowPaths){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Threat-model source missing: $path"
    }
}

$threat=Get-Content -LiteralPath $threatPath -Raw
$security=Get-Content -LiteralPath $securityPath -Raw
$containmentRecovery=Get-Content -LiteralPath $containmentRecoveryPath -Raw
$driver=Get-Content -LiteralPath $driverPath -Raw
$policy=Get-Content -LiteralPath $policyPath -Raw
$worker=Get-Content -LiteralPath $workerPath -Raw
$gateClient=Get-Content -LiteralPath $gateClientPath -Raw
$lifecycle=Get-Content -LiteralPath $lifecyclePath -Raw
$protocol=Get-Content -LiteralPath $protocolPath -Raw
$verifierGate=Get-Content -LiteralPath $verifierGatePath -Raw
$global=Get-Content -LiteralPath $globalPath -Raw | ConvertFrom-Json
$supplyGate=Get-Content -LiteralPath $supplyGatePath -Raw
$codeOwners=Get-Content -LiteralPath $codeOwnersPath -Raw

foreach($required in @(
    'The default normal package remains Audit',
    'Version 0.8.6 retains the cryptographically bound ProductionProtection package',
    'The connection identity itself is kernel-derived.',
    'references `PsGetCurrentProcess()`',
    'derives its PID with `PsGetProcessId`',
    'rejects a `ClientProcessId` mismatch',
    'referenced `PEPROCESS` is retained for the live connection',
    'wire PID is therefore not a trust anchor',
    'known data-mutating filesystem controls that can change file content or extent layout without ordinary `IRP_MJ_WRITE` delivery',
    '`FSCTL_SET_ZERO_DATA`, duplicate-extents/block-clone, offload-write, file-level trim and sparse-state operations',
    'No synchronous user-mode preservation is attempted from `IRP_MJ_FILE_SYSTEM_CONTROL`.',
    'Protected regular file has `NumberOfLinks != 1` during activation',
    '`FileLinkInformation` / `FileLinkInformationEx` touches protected source or destination',
    'proven outside↔outside links remain allowed',
    'A `ReadyForLifecycle` package allows the separate 0.8.6 lifecycle to proceed only after rollback repository validation',
    'Ambiguous-scope analysis',
    'Kernel-mode requestor / compromised kernel component / BYOVD path',
    'preserve-before-allow',
    'Restart observations can move a pending transaction to Review but do not manufacture a missing authoritative kernel completion',
    '0.8.7 adds an **authorization-only** production contract.',
    '`Eligible` means only that the evidence snapshot satisfied the policy contract; it is not evidence that an actuator ran',
    'The ordinary response path records `ActuationAttempted=false` and returns before the LAB-only actuator path.',
    'The strict actuation binding is now implemented but remains non-reachable from ordinary incident handling.',
    'The older per-thread `ContainmentActuator` remains qualified engineering evidence',
    'It is **not** the production crash-safe primitive and must not be used as a fallback',
    'The production containment candidate is `WindowsProcessStateChangeLease`.',
    'The final state-change handle lifetime is the crash-release safety backstop',
    'Unsupported API availability fails closed; production code must not fall back to `SuspendThread`',
    'Exact-SHA disposable-VM run `36225304884` qualified source `8983455fde991a2a85682058a45ed9f8773fc03d`.',
    'Artifact `ransomguard-containment-actuator-8983455fde991a2a85682058a45ed9f8773fc03d` has digest `sha256:6f73539191cb6bd466a210fc2774c16ff81710f1e5ab2656958376bc57b14a26`',
    'The current `GuardWorker` is source-gated against referencing the production state-change backend while `AutomaticContainment=false`.',
    'After an unexpected service/helper exit, RansomGuard must not fabricate an explicit-resume record.',
    'No LAB fast-path threshold or `Eligible` authorization result may be promoted directly into a production blocking action.',
    'one synchronous communication handle',
    'reply-required preservation is deliberately serialized',
    'current wire contract is protocol v18',
    'For the exact 0.7.30 Driver Verifier qualification head',
    'overflow width of 16 against a kernel admission cap of 8 (8 allowed / 8 denied)',
    'Persisted reboot timestamps are SHA-bound and parsed from raw offset-bearing JSON',
    '0.7.31 sustained mixed-workload qualification is now backed by exact-head disposable-VM evidence',
    '0.7.32 introduced the protocol-v16 disconnect fail-safe state',
    '0.7.33 protocol-v17 protected-volume scope classification is backed by exact-head disposable-VM evidence',
    'LAB-only negative fault-injection control',
    'It cannot manufacture an allow decision or disable scope enforcement',
    'runtime run #50 (`36030318084`)',
    'current runner reported ReFS creation unsupported',
    'Do not describe the current normal bundle as production ransomware blocking'
)){
    if(-not $threat.Contains($required)){
        throw "Threat model is missing required current-boundary statement: $required"
    }
}

if(-not $security.Contains('[THREAT_MODEL.md](THREAT_MODEL.md)')){
    throw 'SECURITY.md must link to the canonical threat model.'
}
if(-not $threat.Contains('[CONTAINMENT_ACTUATOR_RECOVERY.md](CONTAINMENT_ACTUATOR_RECOVERY.md)')){
    throw 'Threat model must link to the production containment recovery runbook.'
}
if(-not $security.Contains('[CONTAINMENT_ACTUATOR_RECOVERY.md](CONTAINMENT_ACTUATOR_RECOVERY.md)')){
    throw 'SECURITY.md must link to the production containment recovery runbook.'
}
foreach($required in @(
    'Production containment must use the qualified process state-change object path, not the older per-thread `SuspendThread` executor.',
    'The ownership primitive is one live Windows process state-change object',
    'The crash-safety backstop is handle lifetime',
    'The legacy per-thread actuator and its exact-thread ownership ledger remain useful engineering qualification evidence, but they are not a production fallback',
    'Keep new automatic containment admission disabled until recovery review is complete.',
    'Unsupported platforms fail closed.',
    'Do not call `ResumeThread`, `NtResumeProcess`, terminate the process, or normalize suspend counts as a recovery shortcut.',
    'If the exact target still appears non-progressing after service/helper loss, treat that as a failed safety assumption',
    'Handle destruction is a crash-release safety net, not the normal success path.',
    'Exact-SHA disposable-VM run `36225304884` qualified source:',
    '`8983455fde991a2a85682058a45ed9f8773fc03d`',
    '`sha256:6f73539191cb6bd466a210fc2774c16ff81710f1e5ab2656958376bc57b14a26`',
    'Automatic production containment is still disabled.'
)){
    if(-not $containmentRecovery.Contains($required)){
        throw "Containment recovery runbook is missing required safety statement: $required"
    }
}
foreach($required in @(
    'current engineering minifilter/GateClient wire contract is protocol v18',
    'The 0.7.30 qualification campaign materially increases confidence in this LAB boundary but does not change it into a production claim.',
    '16 requests against cap 8 -> 8 allowed / 8 denied',
    '0.7.31 sustained mixed-workload qualification does not widen the security boundary',
    '0.7.32 introduced protocol v16 and the GateClient-loss fail-safe foundation',
    '0.7.33 advanced the wire contract to protocol v17 and bound the protected root to an exact referenced Filter Manager volume',
    'Version 0.8.6 retains fail-closed ProductionProtection admission',
    '0.8.2 advances the current engineering contract to protocol v18 and separates LAB from ProductionGate',
    'Version 0.8.4 also mediates the reviewed data-mutating FSCTL class',
    'GateClient identity is kernel-bound in 0.8.5',
    'The 0.8.6 service lifecycle consumes ProductionGate only after admitted package verification',
    'GateClient and the driver catalog must use the same signer',
    'SYS/INF must verify as catalog members',
    'CODEOWNERS',
    'does not itself require approval'
)){
    if(-not $security.Contains($required)){
        throw "SECURITY.md is missing required current-boundary statement: $required"
    }
}

foreach($required in @(
    'Data->RequestorMode == KernelMode',
    'RgScopeAmbiguous',
    'RgClassifyMutationScope(&event, FltObjects)',
    'RgEventDestinationPathMatchesGateRoot',
    'RgIsHardLinkSetInfo',
    'FileLinkInformation',
    'FileLinkInformationEx',
    'RgPopulateLinkDestination',
    'RgClassifyHardLinkScope',
    'RgPreFileSystemControl',
    'RgIsDataMutatingFsctl',
    'RgStreamHasDurablePreservation',
    'FSCTL_SET_ZERO_DATA',
    'FSCTL_DUPLICATE_EXTENTS_TO_FILE',
    'FSCTL_OFFLOAD_WRITE',
    'IRP_MJ_FILE_SYSTEM_CONTROL',
    'FltGetVolumeFromName(gFilter, &volumeName, &candidateVolume)',
    'gGateVolume != candidateVolume',
    'FltObjectDereference(releaseVolume)',
    'return FLT_PREOP_SUCCESS_NO_CALLBACK',
    'gProtectionRequired',
    'gDegradedProtected',
    'gMaintenanceRequested',
    'gGracefulDisconnectAuthorized',
    'RgProtectionDegradedProtected',
    'RgControlDeactivateGate',
    'RgControlArmScopeAmbiguity',
    'RgClientProductionGate',
    'gProtectedClientMode',
    'RgCurrentProtectedClientMode',
    'RgIsGateClientMode',
    'gClientProcess',
    'RgIsGateClientRequestor',
    'candidateClientProcess = PsGetCurrentProcess()',
    'actualClientProcessId = (ULONGLONG)(ULONG_PTR)PsGetProcessId(candidateClientProcess)',
    'context->ClientProcessId != actualClientProcessId',
    'gClientProcess = candidateClientProcess',
    'ObDereferenceObject(releaseClientProcess)',
    'STATUS_NOT_SUPPORTED',
    'gScopeAmbiguityProcess',
    'RgInjectScopeAmbiguityProbe',
    'InterlockedExchange(&gMaintenanceRequested, 1)',
    'InterlockedExchange(&gDegradedProtected, 1)',
    'InterlockedExchange(&gClientConnected, 0)'
)){
    if(-not $driver.Contains($required)){
        throw "Driver boundary changed without threat-model review: $required"
    }
}

if($driver -notmatch 'FltCreateCommunicationPort\([^;]+RgConnect\s*,\s*RgDisconnect\s*,\s*RgMessage\s*,\s*1\s*\)'){
    throw 'Threat-model single-client port boundary changed without review.'
}
if(-not $protocol.Contains('#define RG_PROTOCOL_VERSION 18u')){
    throw 'Threat-model protocol-v18 boundary changed without review.'
}
if(-not $protocol.Contains('RgClientProductionGate')){
    throw 'Threat-model ProductionGate client-mode boundary changed without review.'
}
if(-not $protocol.Contains('GateVolumeLengthBytes')){
    throw 'Threat-model protocol-v18 protected-volume field changed without review.'
}
foreach($required in @(
    'public const uint Version = 18;',
    'ProtocolVersion = ProtocolContract.Version',
    'RgClientMode.ProductionGate',
    'GateVolumeLengthBytes = checked((uint)(ntVolume.Length * 2))',
    'DevicePathResolver.ToNtScope(options.Root)',
    'case "--production"',
    'ProductionGate forbids LAB prepare/fault/reconciliation/shutdown/containment options.',
    'ProductionGate rollback store is fixed to',
    'options.Profile == GateProfile.Lab ? options.ContainPid : null',
    '--service-control-stdin',
    'productionServiceShutdownAuthorized',
    'Production service control channel closed unexpectedly; disconnect will remain fail-safe.',
    'gate-shutdown-faulted:production-service-shutdown-not-authorized',
    'RG-LIFECYCLE READY schema=1',
    'RG-LIFECYCLE STOPPED schema=1'
)){
    if(-not $gateClient.Contains($required)){
        throw "GateClient protocol-v18 LAB/Production profile boundary changed without threat-model review: $required"
    }
}
foreach($required in @(
    'using var workerSlots = new SemaphoreSlim(options.GateWorkers, options.GateWorkers);',
    'if (GateMessagePolicy.RequiresReply((RgEventType)ev.EventType))',
    'await worker.ConfigureAwait(false);',
    'FilterReplyMessage',
    'synchronous handle',
    'RgControlCommand.DeactivateGate',
    'RgProtectionState.Maintenance',
    'Kernel gate graceful deactivation NOT authorized',
    'ProductionGate received forbidden containment activation evidence.'
)){
    if(-not $gateClient.Contains($required)){
        throw "Threat-model synchronous GateClient boundary changed without review: $required"
    }
}


foreach($required in @(
    '_admission.ReadyForLifecycle',
    '_protection.BeginKernelStartup()',
    'ProductionDriverLifecycle.EnsureReadyAsync',
    '_protection.MarkKernelConnected()',
    '_protection.MarkProtected()',
    '_protection.MarkDegraded(',
    '_protection.MarkReconnectedProtected(',
    '--production',
    '--service-control-stdin',
    'ProductionDriverLifecycle.StopAfterMaintenanceAsync',
    '_protection.BeginMaintenance(',
    'newdev.dll',
    'DiInstallDriverW',
    'InstallPrimitiveDriverPackage(inf)',
    'fltmc.exe',
    'DecisionPolicy.HashEqual(packageHash, installedHash)'
)){
    if(-not $lifecycle.Contains($required)){
        throw "Production lifecycle boundary changed without threat-model review: $required"
    }
}
$initialStart=$lifecycle.IndexOf('_protection.BeginKernelStartup()')
$driverReady=$lifecycle.IndexOf('ProductionDriverLifecycle.EnsureReadyAsync',$initialStart)
$gateStart=$lifecycle.IndexOf('StartGateClient(',$driverReady)
$kernelReady=$lifecycle.IndexOf('_protection.MarkKernelConnected()',$gateStart)
$protected=$lifecycle.IndexOf('_protection.MarkProtected()',$kernelReady)
if($initialStart -lt 0 -or $driverReady -lt 0 -or $gateStart -lt 0 -or $kernelReady -lt 0 -or $protected -lt 0 -or
   $initialStart -gt $driverReady -or $driverReady -gt $gateStart -or $gateStart -gt $kernelReady -or $kernelReady -gt $protected){
    throw 'Threat-model production activation ordering changed without review.'
}

if(-not $policy.Contains('AuditOnly: automatic action against ordinary applications is disabled in this build.')){
    throw 'DecisionPolicy ordinary-process AuditOnly boundary changed without threat-model review.'
}
if(-not $worker.Contains('RequestedMode={RequestedMode}; ProtectionState={ProtectionState}; KernelEnforcement={KernelEnforcement}')){
    throw 'GuardWorker explicit requested/effective protection-state statement changed without threat-model review.'
}
if(-not $worker.Contains('Diagnostics-only state. There is NO file monitoring.')){
    throw 'GuardWorker explicit ETW degradation boundary changed without threat-model review.'
}

if([string]$global.sdk.version -ne '10.0.401' -or [string]$global.sdk.rollForward -ne 'disable'){
    throw 'Threat-model supply-chain statement requires exact SDK 10.0.401 with roll-forward disabled.'
}
foreach($required in @(
    'committed win-x64 lock graphs',
    'full-SHA action pins',
    'restore drift is disabled'
)){
    if(-not $supplyGate.Contains($required)){
        throw "Threat-model supply-chain control changed without review: $required"
    }
}
if(-not $codeOwners.Contains('does not require approval or provide independent review')){
    throw 'CODEOWNERS must explicitly state that routing alone does not enforce review.'
}
foreach($required in @(
    '/driver/ @EritikWoW',
    '/src/RansomGuard.GateClient/ @EritikWoW',
    '/.github/workflows/ @EritikWoW',
    '/docs/THREAT_MODEL.md @EritikWoW',
    '/tools/verify_threat_model.ps1 @EritikWoW'
)){
    if(-not $codeOwners.Contains($required)){
        throw "CODEOWNERS security-routing invariant missing: $required"
    }
}

if(-not $verifierGate.Contains('persisted reboot timestamps are parsed from raw offset-bearing JSON without timezone coercion')){
    throw 'Threat model requires the timezone-safe Driver Verifier reboot-proof source gate.'
}

$build=Get-Content -LiteralPath $buildPath -Raw
if(-not $build.Contains("tools\verify_threat_model.ps1")){
    throw 'build_windows.ps1 must run the threat-model gate before building release artifacts.'
}
foreach($workflowPath in $workflowPaths){
    $workflow=Get-Content -LiteralPath $workflowPath -Raw
    if(-not $workflow.Contains('.\tools\verify_threat_model.ps1')){
        throw "Threat-model gate is not wired into workflow: $workflowPath"
    }
}

Write-Host "Threat-model gate PASSED: docs match default Audit plus admitted 0.8.6 Enforce lifecycle, protocol v18 LAB/ProductionGate separation, retained-profile fail-safe behavior, serialized synchronous gate semantics, current Driver Verifier/fault qualification limits, supply-chain controls, CODEOWNERS routing, build_windows.ps1 and all $($workflowPaths.Count) repository workflows invoke this gate."
