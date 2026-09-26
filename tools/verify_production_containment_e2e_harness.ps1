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

foreach($path in @($workflowPath,$harnessPath,$fixturePath,$dispatcherPath,$repairPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Production containment E2E qualification source missing: $path"
    }
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$fixture=Get-Content -LiteralPath $fixturePath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$repair=Get-Content -LiteralPath $repairPath -Raw

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
    '''--malicious''',
    '''--benign''',
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
    'args[0] is not ("--malicious" or "--benign")',
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
    '/run-production-containment-e2e-vm ',
    'production-containment-e2e-vm.yml',
    'RansomGuard production containment E2E VM qualification'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){
        throw "Production containment E2E dispatcher invariant missing: $required"
    }
}

Write-Host 'Production containment E2E qualification source gate passed.'
