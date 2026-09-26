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

foreach($path in @($workflowPath,$harnessPath,$fixturePath,$dispatcherPath,$windowsCiPath,$readinessPath,$leasePath)){
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
    '$config.Enforce.ContainmentHoldMilliseconds=10000',
    'Wait-JournalPhaseForProcess',
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
    'ProductionProtectionMaintenanceStop',
    'CRASH-RECOVERY-EVIDENCE'
)){
    if($harness -notmatch [regex]::Escape($required)){
        throw "Production containment recovery harness invariant missing: $required"
    }
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

foreach($required in @(
    '/run-production-containment-recovery-vm ',
    'production-containment-recovery-vm.yml',
    'RansomGuard production containment crash recovery VM qualification'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){
        throw "Production containment recovery dispatcher invariant missing: $required"
    }
}

if($windowsCi -notmatch [regex]::Escape('.\tools\verify_production_containment_recovery_harness.ps1')){
    throw 'Windows required CI does not execute the production containment recovery source gate.'
}

Write-Host 'Production containment crash/restart recovery qualification source gate passed.'
