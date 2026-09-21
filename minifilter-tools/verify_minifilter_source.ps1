$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$sourceRoot=if(Test-Path -LiteralPath (Join-Path $root 'driver')){$root}elseif(Test-Path -LiteralPath (Join-Path $root 'MinifilterLab\Source\driver')){Join-Path $root 'MinifilterLab\Source'}else{throw 'Minifilter source tree not found.'}
$c=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.c'
$h=Join-Path $sourceRoot 'native\shared\rg_minifilter_protocol.h'
$inf=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuardMinifilter.inf'
if(-not (Test-Path -LiteralPath $c) -or -not (Test-Path -LiteralPath $h) -or -not (Test-Path -LiteralPath $inf)){throw 'Minifilter source/protocol/INF missing.'}
$src=Get-Content -LiteralPath $c -Raw
$proto=Get-Content -LiteralPath $h -Raw
$infText=Get-Content -LiteralPath $inf -Raw

$vcx=Join-Path $sourceRoot 'driver\RansomGuard.Minifilter\RansomGuard.Minifilter.vcxproj'
$buildScript=Join-Path $PSScriptRoot 'build_minifilter.ps1'
if(-not (Test-Path -LiteralPath $vcx) -or -not (Test-Path -LiteralPath $buildScript)){throw 'Minifilter project/build script missing.'}
$vcxText=Get-Content -LiteralPath $vcx -Raw
$buildText=Get-Content -LiteralPath $buildScript -Raw
if($vcxText -notmatch '<PreferredToolArchitecture>\s*x64\s*</PreferredToolArchitecture>'){throw 'x64 tool architecture invariant missing from vcxproj.'}
if($buildText -notmatch '/p:PreferredToolArchitecture=x64'){throw 'x64 tool architecture invariant missing from build script.'}
if($buildText -notmatch 'MSBuild\\Current\\Bin\\amd64\\MSBuild\.exe'){throw '64-bit MSBuild host invariant missing from build script.'}
if($buildText -match '(?i)ApiValidatorEnabled\s*=\s*false|/p:ApiValidatorEnabled=false'){throw 'ApiValidator must not be disabled in this build.'}

$banned=@('FltWriteFile(','ZwWriteFile(','FltSetInformationFile(','FltCancelFileOpen(','FltDeleteFile(','ZwDeleteFile(','ZwTerminateProcess(','PsTerminateSystemThread(','NtSuspendProcess','SuspendThread(')
foreach($token in $banned){if($src.Contains($token)){throw "Kernel gate invariant violated: banned token '$token' found."}}
foreach($required in @(
    'RgClientLabGate',
    'RgEventIsInsideGateRoot',
    'gClientProcessId',
    'RG_GATE_TIMEOUT_MS',
    'FltSendMessage',
    'RgGateSnapshotCommitted',
    'FLT_PREOP_COMPLETE',
    'STATUS_ACCESS_DENIED',
    'RgEventTruncate',
    'FileEndOfFileInformation',
    'FileAllocationInformation',
    'IRP_MJ_CREATE',
    'RgPreCreate',
    'RgEventCreate',
    'Parameters.Create.Options',
    'RgGateBaselineCommitted',
    'RgGateNoPreservationRequired',
    'FltGetDestinationFileNameInformation',
    'FltGetTunneledName',
    'FltDoCompletionProcessingWhenSafe',
    'RgPostSetInformation',
    'RgEventRenameResult',
    'RgPostCreate',
    'RgEventCreateResult',
    'RgPopulatePostOperationIdentity',
    'FltQueryInformationFile',
    'FileIdInformation',
    'IdentityStatus',
    'RelatedSequence',
    'CompletionStatus',
    'DestinationPathStatus',
    'DestinationPath'
)){
    if($src -notmatch [regex]::Escape($required)){throw "LAB write-gate invariant missing: $required"}
}
if($proto -notmatch '#define\s+RG_PROTOCOL_VERSION\s+7u'){throw 'Minifilter protocol must be v7 for CREATE completion and identity reconciliation.'}
if($proto -notmatch 'RG_GATE_ROOT_CHARS'){throw 'Protocol must carry an explicit bounded gate root.'}
if($src -notmatch 'Unresolved/out-of-root paths fail open'){throw 'LAB gate must document fail-open behavior outside the explicitly resolved gate root.'}
if($src -notmatch 'requestorPid\s*==\s*\(ULONGLONG\)InterlockedCompareExchange64\(&gClientProcessId'){throw 'Gate client PID must be excluded to prevent rollback-store self-deadlock.'}
if($proto -notmatch 'RG_CREATE_DISPOSITION_SHIFT'){throw 'Protocol must carry CREATE disposition/options semantics.'}
if($proto -notmatch 'DestinationPathStatus' -or $proto -notmatch 'DestinationPath\[RG_PATH_CHARS\]'){throw 'Protocol v7 must carry bounded rename destination path metadata.'}
if($proto -notmatch 'RgEventRenameResult' -or $proto -notmatch 'RelatedSequence' -or $proto -notmatch 'CompletionStatus'){throw 'Protocol v7 must carry correlated post-rename completion metadata.'}
if($proto -notmatch 'RgEventCreateResult' -or $proto -notmatch 'IdentityStatus' -or
   $proto -notmatch 'VolumeSerialNumber' -or $proto -notmatch 'FileIdLow' -or $proto -notmatch 'FileIdHigh'){
    throw 'Protocol v7 must carry correlated post-operation identity metadata.'
}
if($proto -notmatch 'RgGateBaselineCommitted' -or $proto -notmatch 'RgGateNoPreservationRequired'){throw 'Protocol must distinguish committed absence baselines from no-op create opens.'}
if($infText -notmatch 'StartType\s*=\s*3'){throw 'Driver must remain demand-start in the lab prototype.'}
if($infText -notmatch 'Instance1\.Flags\s*=\s*0x1'){throw 'Automatic volume attachment must remain suppressed.'}
if($infText -notmatch 'Instance1\.Altitude\s*=\s*"370099\.4242"'){throw 'Unexpected LAB altitude. Review altitude policy manually.'}
Write-Host 'LAB pre-write gate source check PASSED.' -ForegroundColor Green
Write-Host 'Gate scope: one explicit NT root negotiated by the single connected client.'
Write-Host 'In-scope CREATE/WRITE/RENAME/DELETE/TRUNCATE require an explicit user-mode preservation decision; allowed CREATE/RENAME operations emit correlated post-operation name and FILE_ID_INFO reconciliation.'
Write-Host 'Out-of-scope/unresolved I/O remains fail-open; no process-control or kernel file-writing APIs are present.'
Write-Host 'Demand start: yes; automatic attachment suppressed: yes.'
Write-Host 'x64 build/validation tools required; ApiValidator remains enabled.'
Write-Warning 'Altitude 370099.4242 is an UNASSIGNED LAB placeholder. Never ship it. Microsoft must allocate the production altitude.'
Write-Warning 'The blocking gate is LAB ONLY. Do not load this prototype on a primary workstation.'
