$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot

$scriptPath=Join-Path $root 'minifilter-tools\run_filesystem_matrix_lab.ps1'
$workflowPath=Join-Path $root '.github\workflows\minifilter-runtime-vm.yml'
$buildPath=Join-Path $root 'build_windows.ps1'
foreach($path in @($scriptPath,$workflowPath,$buildPath)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw "Filesystem matrix required file missing: $path"
    }
}

$tokens=$null
$parseErrors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,[ref]$tokens,[ref]$parseErrors)
if(@($parseErrors).Count -gt 0){
    $details=(@($parseErrors) | ForEach-Object {
        "$($_.Extent.StartLineNumber): $($_.Message)"
    }) -join '; '
    throw "Filesystem matrix PowerShell syntax check failed: $details"
}

$script=Get-Content -LiteralPath $scriptPath -Raw
foreach($required in @(
    'Assert-DisposableVm',
    'RANSOMGUARD_LAB_VM',
    'I_UNDERSTAND',
    'Assert-SafeScratchPath',
    'RansomGuard-Filesystem-Matrix-Scratch',
    'RansomGuard-Filesystem-Matrix-Results',
    'STALE MATRIX STATE',
    'RansomGuard-*.vhd',
    'Get-DiskImage -ImagePath $staleVhd.FullName -ErrorAction Stop',
    'if($image.Attached)',
    'Dismount-DiskImage -ImagePath $staleVhd.FullName -ErrorAction Stop | Out-Host',
    'RansomGuardMinifilter is loaded',
    'remained attached after Dismount-DiskImage',
    'Removed stale filesystem-matrix VHD',
    'unable to verify whether scratch VHD is detached',
    'RGFSNTFS',
    'RGFSREFS',
    'Provisioned=$false',
    'Provisioned=$true',
    'if(-not $activeVhd.Provisioned)',
    'scratch VHD provisioning failed',
    'create vdisk file=',
    'type=expandable',
    'attach vdisk',
    'create partition primary',
    'assign letter=',
    'Format-Volume -DriveLetter',
    '-FileSystem $FileSystem',
    'Get-FreeDriveLetter',
    'Remove-ScratchVhd',
    'detach vdisk',
    'if(-not $detach.Succeeded)',
    'leaving the VHD file intact for VM checkpoint recovery',
    'minifilter unload failed before VHD detach',
    'refusing to detach/delete the active scratch VHD',
    'install_minifilter_lab.ps1',
    'unload_minifilter_lab.ps1',
    "'NTFS','ReFS'",
    'ntfsAttempted',
    'ntfsSupported',
    'ntfsPassed',
    'refsAttempted',
    'refsSupported',
    'refsPassed',
    'refsUnsupportedReason',
    'create-new',
    'rename-file',
    'truncate-eof',
    'delete-file',
    '"CreateResult.*" + [regex]::Escape($truncateTarget)',
    '"CreateResult.*" + [regex]::Escape($deleteTarget)',
    'map-write',
    'create-completion-journal.jsonl',
    'rename-completion-journal.jsonl',
    'truncate-completion-journal.jsonl',
    'delete-completion-journal.jsonl',
    'delete-finalization-journal.jsonl',
    'writable-section-journal.jsonl',
    'paging-write-journal.jsonl',
    'originalSha256',
    'filesystem-matrix-result.json',
    '$summary.passed=$summary.ntfsPassed',
    '((-not $summary.refsSupported) -or $summary.refsPassed)',
    'cleanupPassed=$true',
    'FILESYSTEM MATRIX LAB PASSED',
    '$prepareOutput=@(& $GateExe --root $Root --prepare-root 2>&1)',
    '& $installScript -Volume $volume -PackageDirectory $DriverPackageDirectory -Confirmation ''LAB-MINIFILTER'' | Out-Host',
    '& $helperExe create-new --file $createTarget | Out-Host',
    '& $helperExe rename-file --source $renameSource --destination $renameDestination | Out-Host',
    '& $helperExe map-write --file $mappedTarget | Out-Host',
    'return [pscustomobject][ordered]@{',
    '$scenario -is [Array]',
    'filesystem matrix scenario must return exactly one structured result object.',
    '$scenarioFailure=$null',
    '& $unloadScript -Volume ([string]$activeVhd.Volume) | Out-Host',
    'if($null -ne $scenarioFailure)',
    'throw $scenarioFailure'
)){
    if($script -notmatch [regex]::Escape($required)){
        throw "Filesystem matrix invariant missing: $required"
    }
}

$forbiddenDiskPartPatterns=@(
    '(?im)["'']\s*select\s+disk\b',
    '(?im)["'']\s*clean(?:\s+all)?\s*["'']',
    '(?im)["'']\s*delete\s+(?:disk|partition|volume)\b',
    '(?im)["'']\s*convert\s+(?:gpt|mbr)\b'
)
foreach($pattern in $forbiddenDiskPartPatterns){
    if($script -match $pattern){
        throw "Filesystem matrix contains forbidden host-disk DiskPart operation matching: $pattern"
    }
}
foreach($forbidden in @(
    'Set-MpPreference',
    'Add-MpPreference',
    'Remove-MpPreference',
    'bcdedit /set',
    'Disable-WindowsOptionalFeature',
    'Enable-WindowsOptionalFeature'
)){
    if($script -match [regex]::Escape($forbidden)){
        throw "Filesystem matrix contains forbidden boot/security operation: $forbidden"
    }
}

if($script -match '(?im)\bFormat-Volume\b[^\r\n]*-DriveLetter\s+[A-Z](?:\s|$)'){
    throw 'Filesystem matrix must never format a hard-coded existing drive letter.'
}
if($script -notmatch [regex]::Escape('$vhdPath=Join-Path $ScratchDirectory')){
    throw 'Disposable VHD must be created under the guarded scratch directory.'
}

$staleStart=$script.IndexOf('$staleVhds=@(Get-ChildItem -LiteralPath $ScratchDirectory')
$staleImage=$script.IndexOf('Get-DiskImage -ImagePath $staleVhd.FullName -ErrorAction Stop',$staleStart)
$staleAttached=$script.IndexOf('if($image.Attached)',$staleImage)
$staleFilterCheck=$script.IndexOf("if($filters -match '(?m)^\s*RansomGuardMinifilter\b')",$staleAttached)
$staleDismount=$script.IndexOf('Dismount-DiskImage -ImagePath $staleVhd.FullName -ErrorAction Stop | Out-Host',$staleFilterCheck)
$staleRequery=$script.IndexOf('$image=Get-DiskImage -ImagePath $staleVhd.FullName -ErrorAction Stop',$staleDismount)
$staleRecheck=$script.IndexOf('if($image.Attached)',$staleRequery)
$staleDelete=$script.IndexOf('Remove-Item -LiteralPath $staleVhd.FullName -Force -ErrorAction Stop',$staleRecheck)
$staleVolumeCheck=$script.IndexOf('$staleVolumes=@(Get-Volume',$staleDelete)
if($staleStart -lt 0 -or $staleImage -lt 0 -or $staleAttached -lt 0 -or
   $staleFilterCheck -lt 0 -or $staleDismount -lt 0 -or $staleRequery -lt 0 -or
   $staleRecheck -lt 0 -or $staleDelete -lt 0 -or $staleVolumeCheck -lt 0 -or
   $staleStart -gt $staleImage -or $staleImage -gt $staleAttached -or
   $staleAttached -gt $staleFilterCheck -or $staleFilterCheck -gt $staleDismount -or
   $staleDismount -gt $staleRequery -or $staleRequery -gt $staleRecheck -or
   $staleRecheck -gt $staleDelete -or $staleDelete -gt $staleVolumeCheck){
    throw 'Stale VHD recovery must verify minifilter unload, dismount the guarded scratch image, re-check Attached=false, and only then delete it.'
}

$scenarioFunctionStart=$script.IndexOf('function Run-FileSystemScenario(')
$scenarioFunctionEnd=$script.IndexOf('Assert-Administrator',$scenarioFunctionStart)
if($scenarioFunctionStart -lt 0 -or $scenarioFunctionEnd -lt 0){
    throw 'Filesystem matrix scenario function bounds are missing.'
}
$scenarioFunction=$script.Substring(
    $scenarioFunctionStart,
    $scenarioFunctionEnd-$scenarioFunctionStart)
foreach($unsafeOutput in @(
    '& $helperExe create-new --file $createTarget' + [Environment]::NewLine,
    '& $helperExe rename-file --source $renameSource --destination $renameDestination' + [Environment]::NewLine,
    '& $helperExe map-write --file $mappedTarget' + [Environment]::NewLine
)){
    if($scenarioFunction.Contains($unsafeOutput)){
        throw 'Runtime helper stdout must not leak into Run-FileSystemScenario structured return values.'
    }
}
if($script -notmatch [regex]::Escape('if($full -notmatch ''(?i)RansomGuard'')')){
    throw 'Scratch/results paths must retain the explicit RansomGuard name guard.'
}
if($script -notmatch [regex]::Escape('if(-not $activeVhd.Provisioned)') -or
   $script -notmatch [regex]::Escape('if(-not $activeVhd.Supported)')){
    throw 'Filesystem matrix must distinguish VHD provisioning failure from an unsupported filesystem format capability.'
}

$scenarioStart=$script.IndexOf('$scenario=Run-FileSystemScenario $activeVhd')
$scenarioCatch=$script.IndexOf('$scenarioFailure=$_',$scenarioStart)
$scenarioFinally=$script.IndexOf('finally{',$scenarioCatch)
$unload=$script.IndexOf('& $unloadScript -Volume ([string]$activeVhd.Volume) | Out-Host',$scenarioFinally)
$detach=$script.IndexOf('Remove-ScratchVhd $activeVhd',$unload)
$rethrow=$script.IndexOf('throw $scenarioFailure',$detach)
if($scenarioStart -lt 0 -or $scenarioCatch -lt 0 -or $scenarioFinally -lt 0 -or
   $unload -lt 0 -or $detach -lt 0 -or $rethrow -lt 0 -or
   $scenarioStart -gt $scenarioCatch -or $scenarioCatch -gt $scenarioFinally -or
   $scenarioFinally -gt $unload -or $unload -gt $detach -or $detach -gt $rethrow){
    throw 'Filesystem matrix must guarantee minifilter unload in finally before VHD detach and only then rethrow a scenario failure.'
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'Run NTFS and ReFS filesystem compatibility matrix',
    'run_filesystem_matrix_lab.ps1',
    'filesystem-matrix-result.json',
    "'ntfsAttempted','ntfsSupported','ntfsPassed','refsAttempted','cleanupPassed','passed'",
    'refsUnsupportedReason',
    'ransomguard-filesystem-matrix-evidence',
    'Upload filesystem matrix evidence',
    'STALE MATRIX KERNEL STATE',
    'Do not retry unload; revert the disposable VM checkpoint.'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Runtime VM workflow missing filesystem matrix invariant: $required"
    }
}
if($workflow -match [regex]::Escape('Remove-Item -LiteralPath $matrixScratch -Recurse -Force')){
    throw 'Runtime workflow must not blindly delete filesystem matrix scratch before stale-state detection.'
}
if($workflow -match '(?m)^\s+(push|pull_request|schedule):'){
    throw 'Filesystem matrix must remain behind the manual runtime VM workflow.'
}

$build=Get-Content -LiteralPath $buildPath -Raw
if($build -notmatch [regex]::Escape('verify_filesystem_matrix_vm_harness.ps1')){
    throw 'Windows source gates must execute verify_filesystem_matrix_vm_harness.ps1.'
}

Write-Host 'Filesystem matrix source gate PASSED: disposable VHD only, NTFS required, ReFS explicit supported/unsupported state, CREATE/RENAME/TRUNCATE/DELETE/mapped-I/O coverage, no host-disk or boot/security mutation.' -ForegroundColor Green
