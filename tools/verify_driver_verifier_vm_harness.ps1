$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$repo=Split-Path -Parent $PSScriptRoot
$arm=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\arm_driver_verifier_lab.ps1') -Raw
$runtime=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\run_driver_verifier_lab.ps1') -Raw
$clear=Get-Content -LiteralPath (Join-Path $repo 'minifilter-tools\verify_driver_verifier_clear_lab.ps1') -Raw
$workflow=Get-Content -LiteralPath (Join-Path $repo '.github\workflows\minifilter-verifier-vm.yml') -Raw

foreach($required in @(
    "TargetDriver='RansomGuardMinifilter.sys'",
    '$StandardMask=[uint32]0x000209BB',
    'Invoke-Verifier @(''/standard'',''/driver'',$TargetDriver)',
    "Invoke-Verifier @('/bootmode','oneboot')",
    'VerifyDrivers',
    'VerifyDriverLevel',
    'Assert-OnlyTargetDriver',
    'querysettings-after',
    'preExistingDriverNames',
    'DriverPackageDirectory',
    'install_minifilter_lab.ps1',
    '-StageOnly',
    'driverPackageRegistered',
    'StageOnly unexpectedly loaded RansomGuardMinifilter',
    'EXIT_CODE_REBOOT_NEEDED (2)',
    'Assert-VerifierMutationResult',
    "verifier /querysettings did not confirm bootmode=OneBoot",
    "phase='armed'",
    'bootMode=''oneboot''',
    'stateDurable',
    'rebootRequired'
)){
    if($arm -notmatch [regex]::Escape($required)){
        throw "Driver Verifier ARM invariant missing: $required"
    }
}

foreach($required in @(
    "TargetDriver='RansomGuardMinifilter.sys'",
    '$StandardMask=[uint32]0x000209BB',
    "phase -ne 'armed'",
    'No reboot was observed between Driver Verifier ARM and runtime',
    'Microsoft-Windows-WER-SystemErrorReporting',
    'run_concurrency_stress_lab.ps1',
    "Invoke-Verifier @('/query')",
    'armStandardSettingsBound',
    'verifierObservedTargetLoaded',
    'stressPassed',
    'noBugcheckAfterStress',
    "Invoke-Verifier @('/reset')",
    'Assert-VerifierMutationResult',
    'resetCommandExitCode',
    'persistentSettingsCleared',
    'phase=if($summary.stressPassed -and $summary.noBugcheckAfterStress){''runtime-reset''}else{''runtime-failed-reset''}',
    'resetStateDurable',
    'rebootRequired'
)){
    if($runtime -notmatch [regex]::Escape($required)){
        throw "Driver Verifier runtime invariant missing: $required"
    }
}

foreach($required in @(
    "TargetDriver='RansomGuardMinifilter.sys'",
    "phase -ne 'runtime-reset'",
    'No reboot was observed after verifier /reset',
    'persistentSettingsAbsent',
    'querySettingsClear',
    'currentActivityClear',
    'filterNotLoaded',
    'Completed-',
    'activeCampaignArchived'
)){
    if($clear -notmatch [regex]::Escape($required)){
        throw "Driver Verifier CLEAR invariant missing: $required"
    }
}

foreach($source in @($arm,$runtime,$clear,$workflow)){
    foreach($forbidden in @(
        '(?i)\bverifier(\.exe)?\s+/all\b',
        '(?i)/bootmode\s+persistent\b',
        '(?i)\b/volatile\b',
        '(?i)\*\.sys\b',
        '(?i)\bRestart-Computer\b',
        '(?i)\bStop-Computer\b',
        '(?i)\bshutdown(\.exe)?\b',
        '(?i)\bbcdedit(\.exe)?\b',
        '(?i)\bSet-ItemProperty\b.*VerifyDriver',
        '(?i)\bNew-ItemProperty\b.*VerifyDriver',
        '(?i)\bRemove-ItemProperty\b.*VerifyDriver'
    )){
        if($source -match $forbidden){
            throw "Driver Verifier campaign contains forbidden safety pattern: $forbidden"
        }
    }
}

foreach($required in @(
    'name: Minifilter Driver Verifier VM lab',
    'workflow_dispatch:',
    'phase:',
    '- arm',
    '- runtime',
    '- clear',
    'arm_driver_verifier_lab.ps1',
    '-DriverPackageDirectory $env:RG_DRIVER_PACKAGE',
    "inputs.phase == 'arm' || inputs.phase == 'runtime'",
    'driverPackageRegistered',
    'run_driver_verifier_lab.ps1',
    'verify_driver_verifier_clear_lab.ps1',
    "inputs.phase == 'arm'",
    "inputs.phase == 'runtime'",
    "inputs.phase == 'clear'",
    'Refuse unexpected loaded LAB minifilter',
    'ransomguard-driver-verifier-arm-evidence',
    'ransomguard-driver-verifier-runtime-evidence',
    'ransomguard-driver-verifier-clear-evidence'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Driver Verifier workflow invariant missing: $required"
    }
}

if($workflow -match '(?m)^\s*push\s*:'){
    throw 'Driver Verifier VM workflow must remain manual-only.'
}
if($workflow.Contains('\${{')){
    throw 'Driver Verifier workflow contains an escaped GitHub expression and would pass a literal instead of evaluating inputs/secrets.'
}

if($arm -notmatch [regex]::Escape('Driver Verifier already has persistent settings')){
    throw 'Driver Verifier ARM must refuse pre-existing verifier state instead of overwriting it.'
}
if($arm -match '(?i)fltmc\s+(load|attach)'){
    throw 'Driver Verifier ARM must not load or attach the minifilter before the verifier reboot.'
}
if($arm -notmatch [regex]::Escape('-StageOnly')){
    throw 'Driver Verifier ARM must register the exact signed driver package without loading it.'
}
if($runtime -notmatch [regex]::Escape('Driver Verifier current activity did not name loaded target')){
    throw 'Driver Verifier runtime must prove the exact loaded RansomGuard driver is under current verification.'
}
if($runtime -notmatch [regex]::Escape('Driver Verifier stress invariant')){
    throw 'Driver Verifier runtime must require the bounded concurrency stress evidence contract.'
}
if($clear -notmatch [regex]::Escape('Driver Verifier current activity still names ''$TargetDriver''')){
    throw 'Driver Verifier CLEAR must prove current verification activity is gone after the reset reboot.'
}

Write-Host 'Driver Verifier source gate PASSED: standard settings target only RansomGuardMinifilter.sys, bootmode is oneboot, runtime proves the loaded target is verified under bounded stress, /reset is mandatory, a second reboot proves clear state, and no workflow step can reboot the VM automatically.'
