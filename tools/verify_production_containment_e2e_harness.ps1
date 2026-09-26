[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Join-Path $PSScriptRoot '..'
}
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-containment-e2e-vm.yml'
$harnessPath=Join-Path $root 'minifilter-tools\run_production_containment_e2e_lab.ps1'
$fixturePath=Join-Path $root 'qualification\RansomGuard.ProductionContainmentE2EFixture\Program.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$repairPath=Join-Path $root 'tools\repair_state_store.ps1'
$guardWorkerPath=Join-Path $root 'src\RansomGuard.Service\GuardWorker.cs'
$authorizationPath=Join-Path $root 'src\RansomGuard.Core\ContainmentAuthorization.cs'
$leasePath=Join-Path $root 'src\RansomGuard.Service\WindowsProcessStateChangeLease.cs'
$actuatorQualificationPath=Join-Path $root 'qualification\RansomGuard.ContainmentActuatorQualification\Program.cs'

foreach($path in @($workflowPath,$harnessPath,$fixturePath,$dispatcherPath,$repairPath,$guardWorkerPath,$authorizationPath,$leasePath,$actuatorQualificationPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Production containment E2E qualification source missing: $path"
    }
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$fixture=Get-Content -LiteralPath $fixturePath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$repair=Get-Content -LiteralPath $repairPath -Raw
$guardWorker=Get-Content -LiteralPath $guardWorkerPath -Raw
$authorization=Get-Content -LiteralPath $authorizationPath -Raw
$lease=Get-Content -LiteralPath $leasePath -Raw
$actuatorQualification=Get-Content -LiteralPath $actuatorQualificationPath -Raw

foreach($required in @(
    'RansomGuard production containment E2E VM qualification',
    'expected_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'prepare_runtime_driver_package.ps1',
    'prepare_production_lifecycle_qualification_package.ps1',
    'RansomGuard.ProductionContainmentE2EFixture',
    'run_production_containment_e2e_lab.ps1',
    'ransomguard-production-containment-e2e-${{ inputs.expected_sha }}'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Production containment E2E workflow invariant missing: $required"
    }
}

if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Production containment E2E workflow must not continue after a failed qualification step.'
}

foreach($required in @(
    '$config.Mode=''Enforce''',
    '$config.Enforce.AutomaticContainment=$true',
    '$config.Enforce.ContainmentHoldMilliseconds=1200',
    'Quarantine-ExistingQualificationState',
    'QUALIFICATION-QUARANTINE',
    '''.ransomguard-state-v1''',
    'priorStateQuarantine',
    'stateGenerationMarkerReady',
    'Wait-Audit ''Type'' ''ProductionProtectionActivated''',
    'Wait-Audit ''Type'' ''AutomaticContainmentReady''',
    'Wait-Audit ''Event'' ''Startup''',
    '$startup.Protection.RequestedMode -ne ''Enforce''',
    '$startup.Lab -ne $false',
    '$startup.SessionName',
    '$startupRoots.Count -ne 1',
    '''--malicious''',
    '''--malicious-exit''',
    '''--benign''',
    '''process-exit-race-canary.txt''',
    'Find-IncidentForProcess',
    'Get-JournalRecordsForProcess',
    '''ProcessIdentityNotVerified''',
    'exitRaceIncidentPersisted',
    'exitRaceProcessIdentityDenied',
    'exitRaceNoContainment',
    '$_.phase -eq 4',
    '''authorization.json''',
    '''response.json''',
    '''StateChangeContained''',
    '$requiredPhase in @(1,2,3,4)',
    '$phases -contains 5',
    'range-journal.jsonl',
    'benignNoIncident',
    'benignNoContainment',
    '''ProductionProtectionMaintenanceStop'''
)){
    if($harness -notmatch [regex]::Escape($required)){
        throw "Production containment E2E harness invariant missing: $required"
    }
}

foreach($required in @(
    '$generationMarkerName=''.ransomguard-state-v1''',
    "RansomGuard state generation v1",
    'Set-PrivateFile $marker',
    '$fs.Flush($true)'
)){
    if($repair -notmatch [regex]::Escape($required)){
        throw "State-store repair invariant missing: $required"
    }
}

foreach($forbidden in @(
    'AutomaticContainment=$false',
    'containmentCompleted=$true #',
    'benignNoContainment=$true #'
)){
    if($harness -match [regex]::Escape($forbidden)){
        throw "Production containment E2E harness contains a forbidden shortcut: $forbidden"
    }
}

foreach($required in @(
    'args[0] is not ("--malicious" or "--malicious-exit" or "--benign")',
    'mode is "malicious" or "malicious-exit"',
    'if (mode == "malicious-exit")',
    'return 0;',
    'RandomNumberGenerator.GetBytes(4096)',
    'for (var i = 0; i < 200; i++)',
    'maxHeartbeatGapMs',
    'creationFileTimeUtc',
    'FileOptions.WriteThrough'
)){
    if($fixture -notmatch [regex]::Escape($required)){
        throw "Production containment E2E fixture invariant missing: $required"
    }
}

foreach($required in @(
    'current==risk.Process',
    'WinPaths.Equal(imagePath,risk.ImagePath)'
)){
    if($guardWorker -notmatch [regex]::Escape($required)){
        throw "Production containment live-process identity invariant missing: $required"
    }
}

if($authorization -notmatch [regex]::Escape('ProcessIdentityNotVerified')){
    throw 'Containment authorization must fail closed when the exact live process identity is unavailable.'
}

foreach($required in @(
    'live.Value != Process',
    'ProcessIdentityChanged'
)){
    if($lease -notmatch [regex]::Escape($required)){
        throw "Process state-change lease PID-reuse invariant missing: $required"
    }
}

foreach($required in @(
    'targetKey with { CreationFileTimeUtc = targetKey.CreationFileTimeUtc + 1 }',
    'identityMismatchRejected'
)){
    if($actuatorQualification -notmatch [regex]::Escape($required)){
        throw "Containment actuator PID-reuse qualification invariant missing: $required"
    }
}

foreach($required in @(
    '/run-production-containment-e2e-vm ',
    'production-containment-e2e-vm.yml',
    'RansomGuard production containment E2E VM qualification'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){
        throw "Production containment E2E dispatcher invariant missing: $required"
    }
}

Write-Host 'Production containment E2E qualification source gate passed: ordinary service-path malicious/benign coverage plus exact PID+CreationFileTime short-lived-process fail-closed race and lower-level PID-reuse rejection.'
