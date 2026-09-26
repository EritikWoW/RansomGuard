[CmdletBinding()]
param([string]$RepositoryRoot='')

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){$RepositoryRoot=Join-Path $PSScriptRoot '..'}
$root=[IO.Path]::GetFullPath($RepositoryRoot)

$workflowPath=Join-Path $root '.github\workflows\production-containment-reboot-recovery-vm.yml'
$harnessPath=Join-Path $root 'minifilter-tools\run_production_containment_reboot_recovery_lab.ps1'
$fixturePath=Join-Path $root 'qualification\RansomGuard.ProductionContainmentE2EFixture\Program.cs'
$dispatcherPath=Join-Path $root '.github\workflows\vm-lab-dispatcher.yml'
$windowsCiPath=Join-Path $root '.github\workflows\windows-ci.yml'
$readinessPath=Join-Path $root 'src\RansomGuard.Service\ProductionContainmentReadiness.cs'
$programPath=Join-Path $root 'src\RansomGuard.Service\Program.cs'

foreach($path in @($workflowPath,$harnessPath,$fixturePath,$dispatcherPath,$windowsCiPath,$readinessPath,$programPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Containment reboot-recovery source missing: $path"}
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
$harness=Get-Content -LiteralPath $harnessPath -Raw
$dispatcher=Get-Content -LiteralPath $dispatcherPath -Raw
$windowsCi=Get-Content -LiteralPath $windowsCiPath -Raw
$readiness=Get-Content -LiteralPath $readinessPath -Raw
$program=Get-Content -LiteralPath $programPath -Raw

foreach($required in @(
    'RansomGuard production containment reboot recovery VM qualification',
    'phase:',
    '- arm',
    '- resume',
    '- verify',
    'expected_sha',
    'runs-on: [self-hosted, Windows, X64, ransomguard-lab-vm]',
    'RANSOMGUARD_LAB_VM: I_UNDERSTAND',
    'RANSOMGUARD_LAB_CERT_THUMBPRINT',
    'ref: ${{ inputs.expected_sha }}',
    'verify_production_containment_reboot_recovery_harness.ps1',
    'prepare_runtime_driver_package.ps1',
    'prepare_production_lifecycle_qualification_package.ps1',
    'RansomGuard.ProductionContainmentE2EFixture',
    'run_production_containment_reboot_recovery_lab.ps1',
    'ransomguard-production-containment-reboot-recovery-${{ inputs.phase }}-${{ inputs.expected_sha }}',
    "success() && (inputs.phase == 'arm' || inputs.phase == 'resume')",
    'shutdown.exe'
)){
    if($workflow -notmatch [regex]::Escape($required)){throw "Containment reboot-recovery workflow invariant missing: $required"}
}
if($workflow -match '(?im)^\s*continue-on-error\s*:\s*true\s*$'){
    throw 'Containment reboot-recovery workflow must not continue after qualification failure.'
}
if($workflow -match '(?m)^\s*push\s*:'){
    throw 'Containment reboot-recovery workflow must remain manual-only.'
}
if($workflow -notmatch [regex]::Escape("if: ${{ inputs.phase == 'arm' }}")){
    throw 'Persistent qualification package must be created only during ARM.'
}

foreach($required in @(
    "ValidateSet('arm','resume','verify')",
    'containment-reboot-recovery-campaign.json',
    "Get-FileHash -LiteralPath $Path -Algorithm SHA256",
    'Campaign state SHA-256 mismatch.',
    'LastBootUpTime',
    'No real VM reboot was observed between ARM and RESUME.',
    'No second real VM reboot was observed between RESUME and VERIFY.',
    'Wait-JournalPhaseForProcess',
    'Stop-Process -Id $servicePid -Force',
    'Assert-FilterPresent ''post-crash ARM fail-safe''',
    'failSafeRetainedBeforeReboot',
    'Assert-IncompleteJournal',
    'IncompleteStateChangeSessionsRequireReview',
    'AutomaticContainmentReady was published after first reboot',
    'AutomaticContainmentReady was published after second reboot',
    'AutomaticContainmentNotActive',
    '''AuditOnly''',
    'firstRebootObserved',
    'firstBootFailClosed',
    'firstBootAuditOnly',
    'secondRebootObserved',
    'idempotentFailClosed',
    'secondBootAuditOnly',
    'containment-state-change-journal.final.jsonl',
    'cleanupPassed',
    'PRODUCTION-CONTAINMENT-REBOOT-RECOVERY ARM PASS',
    'PRODUCTION-CONTAINMENT-REBOOT-RECOVERY RESUME PASS',
    'PRODUCTION-CONTAINMENT-REBOOT-RECOVERY VERIFY PASS'
)){
    if($harness -notmatch [regex]::Escape($required)){throw "Containment reboot-recovery harness invariant missing: $required"}
}

foreach($forbidden in @(
    '\bRestart-Computer\b',
    '\bStop-Computer\b',
    '\bshutdown(?:\.exe)?\b',
    '\bNtResumeProcess\b',
    '\bResumeThread\b',
    '\bNtSuspendProcess\b',
    '\bSuspendThread\b'
)){
    if($harness -match $forbidden){throw "Containment reboot-recovery harness contains forbidden reboot/actuation shortcut: $forbidden"}
}

foreach($required in @(
    'journal.IncompleteRequests()',
    'IncompleteStateChangeSessionsRequireReview'
)){
    if($readiness -notmatch [regex]::Escape($required)){throw "Containment readiness invariant missing: $required"}
}

$journalInit=$program.IndexOf('stateChangeJournal=new ContainmentStateChangeJournal', [StringComparison]::Ordinal)
$journalVerify=$program.IndexOf('stateChangeJournal.VerifyAll()', [StringComparison]::Ordinal)
$lifecycleRegistration=$program.IndexOf('builder.Services.AddHostedService(sp=>new ProductionProtectionLifecycle', [StringComparison]::Ordinal)
if($journalInit -lt 0 -or $journalVerify -lt 0 -or $lifecycleRegistration -lt 0 -or
   $journalInit -ge $journalVerify -or $journalVerify -ge $lifecycleRegistration){
    throw 'Production service must validate containment state-change evidence before registering kernel lifecycle.'
}

foreach($required in @(
    '/run-production-containment-reboot-recovery-arm-vm ',
    '/run-production-containment-reboot-recovery-resume-vm ',
    '/run-production-containment-reboot-recovery-verify-vm ',
    'production-containment-reboot-recovery-vm.yml',
    'Dispatched containment reboot-recovery phase'
)){
    if($dispatcher -notmatch [regex]::Escape($required)){throw "Containment reboot-recovery dispatcher invariant missing: $required"}
}
if($windowsCi -notmatch [regex]::Escape('.\tools\verify_production_containment_reboot_recovery_harness.ps1')){
    throw 'Windows required CI must execute the containment reboot-recovery source gate.'
}

Write-Host 'Production containment reboot-recovery source gate PASSED: exact-SHA three-phase real reboot campaign, durable incomplete journal, first- and second-boot fail-closed readiness, AuditOnly denial and final cleanup.'
