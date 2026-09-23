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
    'FILESYSTEM MATRIX LAB PASSED'
)){
    if($script -notmatch [regex]::Escape($required)){
        throw "Filesystem matrix invariant missing: $required"
    }
}

foreach($forbidden in @(
    'select disk',
    'clean',
    'clean all',
    'delete disk',
    'delete partition',
    'delete volume',
    'convert gpt',
    'convert mbr',
    'Set-MpPreference',
    'Add-MpPreference',
    'Remove-MpPreference',
    'bcdedit /set',
    'Disable-WindowsOptionalFeature',
    'Enable-WindowsOptionalFeature'
)){
    if($script -match [regex]::Escape($forbidden)){
        throw "Filesystem matrix contains forbidden host/destructive operation: $forbidden"
    }
}

if($script -match '(?im)\bFormat-Volume\b[^\r\n]*-DriveLetter\s+[A-Z](?:\s|$)'){
    throw 'Filesystem matrix must never format a hard-coded existing drive letter.'
}
if($script -notmatch [regex]::Escape('$vhdPath=Join-Path $ScratchDirectory')){
    throw 'Disposable VHD must be created under the guarded scratch directory.'
}
if($script -notmatch [regex]::Escape('if($full -notmatch ''(?i)RansomGuard'')')){
    throw 'Scratch/results paths must retain the explicit RansomGuard name guard.'
}
if($script -notmatch [regex]::Escape("if(-not $activeVhd.Supported)")){
    throw 'Filesystem matrix must distinguish unsupported filesystem creation from a failed supported scenario.'
}

$scenarioStart=$script.IndexOf('$scenario=Run-FileSystemScenario $activeVhd')
$unload=$script.IndexOf('& $unloadScript -Volume ([string]$activeVhd.Volume)',$scenarioStart)
$detach=$script.IndexOf('Remove-ScratchVhd $activeVhd',$unload)
if($scenarioStart -lt 0 -or $unload -lt 0 -or $detach -lt 0 -or
   $scenarioStart -gt $unload -or $unload -gt $detach){
    throw 'Filesystem matrix must unload the minifilter before detaching/deleting a supported scratch VHD.'
}

$workflow=Get-Content -LiteralPath $workflowPath -Raw
foreach($required in @(
    'Run NTFS and ReFS filesystem compatibility matrix',
    'run_filesystem_matrix_lab.ps1',
    'filesystem-matrix-result.json',
    "'ntfsAttempted','ntfsSupported','ntfsPassed','refsAttempted','cleanupPassed','passed'",
    'refsUnsupportedReason',
    'ransomguard-filesystem-matrix-evidence',
    'Upload filesystem matrix evidence'
)){
    if($workflow -notmatch [regex]::Escape($required)){
        throw "Runtime VM workflow missing filesystem matrix invariant: $required"
    }
}
if($workflow -match '(?m)^\s+(push|pull_request|schedule):'){
    throw 'Filesystem matrix must remain behind the manual runtime VM workflow.'
}

$build=Get-Content -LiteralPath $buildPath -Raw
if($build -notmatch [regex]::Escape('verify_filesystem_matrix_vm_harness.ps1')){
    throw 'Windows source gates must execute verify_filesystem_matrix_vm_harness.ps1.'
}

Write-Host 'Filesystem matrix source gate PASSED: disposable VHD only, NTFS required, ReFS explicit supported/unsupported state, CREATE/RENAME/TRUNCATE/DELETE/mapped-I/O coverage, no host-disk or boot/security mutation.' -ForegroundColor Green
