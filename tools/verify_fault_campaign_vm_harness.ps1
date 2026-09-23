$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$repo=Split-Path -Parent $PSScriptRoot
$lowDisk=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\run_low_disk_fault_lab.ps1') -Raw
$arm=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\arm_reboot_reconciliation_lab.ps1') -Raw
$verify=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\verify_reboot_reconciliation_lab.ps1') -Raw
$workflow=Get-Content -LiteralPath (Join-Path $repo '.github\workflows\minifilter-crash-vm.yml') -Raw

foreach($required in @(
    'Assert-DisposableVm',
    'RANSOMGUARD_LAB_VM',
    'create vdisk file=',
    'select vdisk file=',
    'type=expandable',
    'Format-Volume -DriveLetter $letter -FileSystem NTFS',
    'RansomGuard-low-disk-filler.bin',
    'Rollback storage budget denied gate-event:Create',
    'failClosedObserved',
    'sourcePreservedOnDenial',
    'destinationAbsentOnDenial',
    'budgetDenialObserved',
    'deniedIntentAbsent',
    'deniedCompletionAbsent',
    'retryPassed',
    'retryEvidenceDurable',
    'preimageHashMatched',
    'preimageObjectVerified',
    'snapshotRelativePath',
    'cleanup partially provisioned low-disk VHD',
    'Remove-LowDiskVhd'
)){
    if($lowDisk -notmatch [regex]::Escape($required)){
        throw "Low-disk fault harness invariant missing: $required"
    }
}

foreach($forbidden in @(
    '(?im)^\s*select\s+disk\b',
    '(?im)^\s*clean(\s+all)?\s*$',
    '\bClear-Disk\b',
    '\bRemove-Partition\b',
    '\bInitialize-Disk\b',
    'Format-Volume\s+-DriveLetter\s+[''"]?[A-Z][''"]?'
)){
    if($lowDisk -match $forbidden){
        throw "Low-disk harness contains forbidden host-disk operation pattern: $forbidden"
    }
}

if($lowDisk -notmatch [regex]::Escape('ScratchDirectory must contain RansomGuard') -and
   $lowDisk -notmatch [regex]::Escape('$Label must contain RansomGuard')){
    throw 'Low-disk VHD scratch path must be guarded by a RansomGuard path invariant.'
}

foreach($required in @(
    '--drop-first-truncate-completion',
    'Write-DurableJson',
    'reboot-arm-state.json',
    'truncate-intent-journal.jsonl',
    'truncate-completion-journal.jsonl',
    'preimageHashMatched',
    'preimageObjectVerified',
    'preservationBindingVerified',
    'snapshotRelativePath',
    'snapshotSha256',
    'failedCampaignRemoved',
    'filterLeftLoadedForReboot',
    'rebootRequired',
    'RG_WORKFLOW_SHA',
    'REBOOT REQUIRED'
)){
    if($arm -notmatch [regex]::Escape($required)){
        throw "Reboot ARM invariant missing: $required"
    }
}

if($arm -match [regex]::Escape('--reconcile-only')){
    throw 'Reboot ARM must stop before restart reconciliation; VERIFY owns post-reboot reconciliation.'
}
if($arm -match [regex]::Escape('unload_minifilter_lab.ps1') -and
   $arm -notmatch [regex]::Escape('if(-not $summary.passed -and $installed)')){
    throw 'Reboot ARM may unload the filter only on failure.'
}

foreach($required in @(
    "`$stateHashPath=`$statePath+'.sha256'",
    'Get-FileHash -LiteralPath $statePath -Algorithm SHA256',
    'LastBootUpTime',
    'No VM reboot was observed between ARM and VERIFY',
    'RansomGuardMinifilter is unexpectedly still loaded after reboot',
    'Reboot ARM state topology does not match the fixed Active/protected/rollback-store campaign layout.',
    'preimageBindingVerified',
    'snapshotRelativePath',
    'snapshotSha256',
    '--reconcile-only',
    'truncate-restart-journal.jsonl',
    'restartSupportsCompleted',
    'recoveryTransactionNotReady',
    'readyPreimageCopyOutPresent',
    'preimageHashMatched',
    'automaticTopologyMutationAllowed',
    'Completed-'
)){
    if($verify -notmatch [regex]::Escape($required)){
        throw "Reboot VERIFY invariant missing: $required"
    }
}

foreach($source in @($arm,$verify,$workflow)){
    foreach($forbidden in @(
        '\bRestart-Computer\b',
        '\bStop-Computer\b',
        '\bshutdown(\.exe)?\b',
        '\bbcdedit(\.exe)?\b',
        '\bverifier(\.exe)?\b'
    )){
        if($source -match $forbidden){
            throw "0.7.29 reboot campaign must not reboot the runner or change boot/Verifier policy from inside the Actions job: $forbidden"
        }
    }
}

foreach($required in @(
    'name: Minifilter fault campaign VM lab',
    'campaign:',
    '- completion-loss',
    '- low-disk',
    '- reboot-arm',
    '- reboot-verify',
    'run_low_disk_fault_lab.ps1',
    'arm_reboot_reconciliation_lab.ps1',
    'verify_reboot_reconciliation_lab.ps1',
    "inputs.campaign == 'low-disk'",
    "inputs.campaign == 'reboot-arm'",
    "inputs.campaign == 'reboot-verify'",
    "inputs.campaign != 'reboot-verify'",
    "inputs.campaign != 'reboot-arm'",
    '$selectedRoot=switch($env:RG_FAULT_CAMPAIGN)',
    '''low-disk'' {$env:RG_LOW_DISK_ROOT_BASE}',
    '''reboot-verify'' {$env:RG_REBOOT_ROOT_BASE}',
    'ransomguard-low-disk-fault-evidence',
    'ransomguard-reboot-arm-evidence',
    'ransomguard-reboot-verify-evidence'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Fault campaign workflow invariant missing: $required"
    }
}

if($workflow -match '(?m)^\s*push\s*:'){
    throw 'Fault campaign VM workflow must remain manual-only.'
}

Write-Host 'Fault campaign source gate PASSED: isolated low-disk VHD pressure fails closed at the mutation-capable CREATE/open admission boundary before RENAME intent, retry evidence is durable, reboot proof is explicit ARM/real-boot/VERIFY with exact-commit state, and the workflow never reboots the self-hosted runner or enables Driver Verifier.'
