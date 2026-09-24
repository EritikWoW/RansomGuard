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
    'Read-And-VerifyState',
    'RawJson',
    'Get-JsonStringProperty',
    'Get-JsonUtcTimestamp',
    '[Text.Json.JsonDocument]::Parse',
    '[DateTimeOffset]::Parse',
    "phase -ne 'runtime-failed-reset'",
    'prior.resetScheduled',
    'prior.runtimeBootUtc',
    'querysettings-prior-failed-reset',
    'priorFailedCampaignArchived',
    'Failed-',
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
foreach($source in @($arm,$runtime,$clear)){
    foreach($required in @(
        'RawJson',
        'Get-JsonStringProperty',
        'Get-JsonUtcTimestamp',
        '[Text.Json.JsonDocument]::Parse',
        '[DateTimeOffset]::Parse'
    )){
        if($source -notmatch [regex]::Escape($required)){
            throw "Driver Verifier UTC-state invariant missing: $required"
        }
    }
}
if($runtime -notmatch [regex]::Escape('Get-JsonUtcTimestamp $verified.RawJson ''bootUpUtc''') -or
   $runtime -notmatch [regex]::Escape('Get-JsonUtcTimestamp $verified.RawJson ''armedUtc''') -or
   $runtime -notmatch [regex]::Escape('Get-JsonStringProperty $verified.RawJson ''armedUtc''')){
    throw 'Driver Verifier runtime must preserve ARM timestamps directly from raw JSON.'
}
if($clear -notmatch [regex]::Escape('Get-JsonUtcTimestamp $verified.RawJson ''runtimeBootUtc''')){
    throw 'Driver Verifier CLEAR must parse runtimeBootUtc directly from raw JSON.'
}
if($arm -notmatch [regex]::Escape('Get-JsonUtcTimestamp $priorVerified.RawJson ''runtimeBootUtc''')){
    throw 'Driver Verifier failed-reset recovery must parse runtimeBootUtc directly from raw JSON.'
}
foreach($source in @($arm,$runtime,$clear)){
    if($source -match '(?s)\[DateTime\]::Parse\s*\(\s*\[string\]\$(?:state|prior)\.(?:bootUpUtc|armedUtc|runtimeBootUtc)'){
        throw 'Driver Verifier persisted timestamps must not be reparsed from ConvertFrom-Json DateTime values.'
    }
}
$recoverPhase=$arm.IndexOf("phase -ne 'runtime-failed-reset'")
$recoverReset=$arm.IndexOf('prior.resetScheduled',$recoverPhase)
$recoverBoot=$arm.IndexOf('prior.runtimeBootUtc',$recoverReset)
$recoverQuery=$arm.IndexOf("Invoke-Verifier @('/querysettings') 'querysettings-prior-failed-reset'",$recoverBoot)
$recoverArchive=$arm.IndexOf('Move-Item -LiteralPath $active -Destination $failedArchive',$recoverQuery)
$newActive=$arm.IndexOf('New-Item -ItemType Directory -Path $active -Force',$recoverArchive)
if($recoverPhase -lt 0 -or $recoverReset -lt 0 -or $recoverBoot -lt 0 -or
   $recoverQuery -lt 0 -or $recoverArchive -lt 0 -or $newActive -lt 0 -or
   $recoverPhase -gt $recoverReset -or $recoverReset -gt $recoverBoot -or
   $recoverBoot -gt $recoverQuery -or $recoverQuery -gt $recoverArchive -or
   $recoverArchive -gt $newActive){
    throw 'Driver Verifier ARM failed-reset recovery must remain state-hash/phase -> reset proof -> reboot proof -> querysettings-clear -> archive -> new Active.'
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

Write-Host 'Driver Verifier source gate PASSED: standard settings target only RansomGuardMinifilter.sys, persisted reboot timestamps are parsed from raw offset-bearing JSON without timezone coercion, runtime proves the loaded target is verified under bounded stress, failed-reset campaigns can be archived only after hash/phase/reset/reboot/querysettings proof, /reset is mandatory, a second reboot proves clear state, and no workflow step can reboot the VM automatically.'
