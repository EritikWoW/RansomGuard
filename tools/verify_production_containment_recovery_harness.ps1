[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Join-Path $PSScriptRoot '..'
}
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-containment-recovery-vm.yml'
$harnessPath=Join-Path $root 'minifilter-tools\run_production_containment_crash_recovery_lab.ps1'
$fixturePath=Join-Path $root 'qualification\RansomGuard.ProductionContainmentE2EFixture\Program.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'
$readinessPath=Join-Path $root 'src\RansomGuard.Service\ProductionContainmentReadiness.cs'
$leasePath=Join-Path $root 'src\RansomGuard.Service\WindowsProcessStateChangeLease.cs'
$serviceProgramPath=Join-Path $root 'src\RansomGuard.Service\Program.cs'

foreach($path in @($workflowPath,$harnessPath,$fixturePath,$dispatcherPath,$windowsCiPath,$readinessPath,$leasePath,$serviceProgramPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Production containment recovery qualification source missing: $path"
    }
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$windowsCi=Get-Content -LiteralPath $windowsCiPath -Raw
$readiness=Get-Content -LiteralPath $readinessPath -Raw
$lease=Get-Content -LiteralPath $leasePath -Raw
$serviceProgram=Get-Content -LiteralPath $serviceProgramPath -Raw

foreach($required in @(
    'RansomGuard production containment crash recovery VM qualification',
    'expected_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'prepare_runtime_driver_package.ps1',
    'prepare_production_lifecycle_qualification_package.ps1',
    'RansomGuard.ProductionContainmentE2EFixture',
    'run_production_containment_crash_recovery_lab.ps1',
    'ransomguard-production-containment-recovery-${{ inputs.expected_sha }}'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Production containment recovery workflow invariant missing: $required"
    }
}
if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Production containment recovery workflow must not continue after a failed qualification step.'
}

foreach($required in @(
    '$config.Mode=''Enforce''',
    '$config.Enforce.AutomaticContainment=$true',
    '$config.Enforce.ContainmentHoldMilliseconds=5000',
    'Wait-JournalPhaseForProcess',
    'cancellationStopIssued',
    'ActuationCancelledAfterResume',
    'cancellationExplicitResumeRecorded',
    'cancellationAbnormalRecorded',
    'cancellationCompletedAbsent',
    'cancellationHeartbeatRecovered',
    'cancellationAutomaticContainmentReady',
    'Handled cancellation request fabricated a Completed terminal phase.',
    'Stop-Process -Id $servicePid -Force',
    'kernelFailSafeRetained',
    'Wait-HeartbeatAdvance',
    'crashReleaseHeartbeatObserved',
    '$crashPhases -notcontains 1',
    '$crashPhases -notcontains 2',
    'foreach($forbidden in @(3,4,5))',
    'AutomaticContainmentUnavailable',
    'IncompleteStateChangeSessionsRequireReview',
    'AutomaticContainmentReady',
    'AutomaticContainmentNotActive',
    'postRestartNoContainment',
    '''AuditOnly''',
    'journalCorruptionRejected',
    'journalExactRestoreApplied',
    'restoredJournalFailClosed',
    'containment-state-change-journal.pre-corruption.jsonl',
    '$journalStream.SetLength($journalStream.Length-1)',
    'Truncated containment journal allowed production kernel lifecycle activation.',
    'Exact journal restoration did not recover the original incomplete-session fail-closed state.',
    'ProductionProtectionMaintenanceStop',
    'CRASH-RECOVERY-EVIDENCE'
)){
    if($harness -notmatch [regex]::Escape($required)){
        throw "Production containment recovery harness invariant missing: $required"
    }
}

$holdMatch=[regex]::Match($harness,'\$config\.Enforce\.ContainmentHoldMilliseconds\s*=\s*([0-9]+)')
if(-not $holdMatch.Success){
    throw 'Crash recovery harness containment hold assignment is missing.'
}
$holdMilliseconds=[int]$holdMatch.Groups[1].Value
if($holdMilliseconds -lt 100 -or $holdMilliseconds -gt 5000){
    throw "Crash recovery harness containment hold is outside the product-qualified 100..5000ms range: $holdMilliseconds"
}

foreach($forbidden in @(
    '\bRestart-Computer\b',
    '\bshutdown\.exe\b',
    '\bStop-Computer\b',
    '\bNtResumeProcess\b',
    '\bResumeThread\b',
    '\bNtSuspendProcess\b',
    '\bSuspendThread\b'
)){
    if($harness -match $forbidden){
        throw "Crash recovery harness contains a forbidden recovery primitive: $forbidden"
    }
}

foreach($required in @(
    'journal.IncompleteRequests()',
    'IncompleteStateChangeSessionsRequireReview',
    'return new(true, "QualifiedStateChangeBackendReady", 0)'
)){
    if($readiness -notmatch [regex]::Escape($required)){
        throw "Production containment readiness invariant missing: $required"
    }
}

foreach($required in @(
    'live.Value != Process',
    'NtCreateProcessStateChange',
    'NtChangeProcessState',
    '_stateChangeHandle.Dispose()',
    '_processHandle.Dispose()'
)){
    if($lease -notmatch [regex]::Escape($required)){
        throw "Process state-change lease recovery invariant missing: $required"
    }
}
if($lease.IndexOf('_stateChangeHandle.Dispose()', [StringComparison]::Ordinal) -gt
   $lease.IndexOf('_processHandle.Dispose()', [StringComparison]::Ordinal)){
    throw 'Process state-change handle must be released before the process handle.'
}

$journalInit=$serviceProgram.IndexOf('stateChangeJournal=new ContainmentStateChangeJournal', [StringComparison]::Ordinal)
$journalVerify=$serviceProgram.IndexOf('stateChangeJournal.VerifyAll()', [StringComparison]::Ordinal)
$lifecycleRegistration=$serviceProgram.IndexOf('builder.Services.AddHostedService(sp=>new ProductionProtectionLifecycle', [StringComparison]::Ordinal)
if($journalInit -lt 0 -or $journalVerify -lt 0 -or $lifecycleRegistration -lt 0 -or
   $journalInit -ge $journalVerify -or $journalVerify -ge $lifecycleRegistration){
    throw 'Production service must validate the containment state-change journal before registering the kernel lifecycle hosted service.'
}

foreach($required in @(
    '/run-production-containment-recovery-vm ',
    'production-containment-recovery-vm.yml',
    'Dispatched production containment crash recovery VM qualification for exact SHA'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){
        throw "Production containment recovery dispatcher invariant missing: $required"
    }
}

if($windowsCi -notmatch [regex]::Escape('.\tools\verify_production_containment_recovery_harness.ps1')){
    throw 'Windows required CI does not execute the production containment recovery source gate.'
}

Write-Host 'Production containment fault/recovery qualification source gate passed: handled cancellation during SuspendApplied must explicitly resume into Abnormal (never Completed) and cleanly re-admit automatic containment before the separate hard-crash/incomplete-session recovery campaign.'
