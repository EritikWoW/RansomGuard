$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$store=Join-Path $root 'src\RansomGuard.Rollback\RollbackStore.cs'
$program=Join-Path $root 'src\RansomGuard.Service\Program.cs'
$rangeStore=Join-Path $root 'src\RansomGuard.Rollback\RangeRollbackStore.cs'
$createStore=Join-Path $root 'src\RansomGuard.Rollback\CreateRollbackStore.cs'
$createOperationStore=Join-Path $root 'src\RansomGuard.Rollback\CreateOperationStore.cs'
$createPolicy=Join-Path $root 'src\RansomGuard.Rollback\CreateGatePolicy.cs'
$identityStore=Join-Path $root 'src\RansomGuard.Rollback\FileIdentityStore.cs'
$renameStore=Join-Path $root 'src\RansomGuard.Rollback\RenameRollbackStore.cs'
$truncateStore=Join-Path $root 'src\RansomGuard.Rollback\TruncateOperationStore.cs'
$deleteStore=Join-Path $root 'src\RansomGuard.Rollback\DeleteOperationStore.cs'
$restartStore=Join-Path $root 'src\RansomGuard.Rollback\RestartReconciliationStore.cs'
$pagingStore=Join-Path $root 'src\RansomGuard.Rollback\PagingWriteEvidenceStore.cs'
$sectionStore=Join-Path $root 'src\RansomGuard.Rollback\WritableSectionEvidenceStore.cs'
$activationStore=Join-Path $root 'src\RansomGuard.Rollback\ActivationPreflightStore.cs'
$topologyStore=Join-Path $root 'src\RansomGuard.Rollback\ActivationTopologyStore.cs'
$containmentStore=Join-Path $root 'src\RansomGuard.Rollback\ContainmentEvidenceStore.cs'
if(-not(Test-Path -LiteralPath $rangeStore)){throw 'RangeRollbackStore.cs missing.'}
if(-not(Test-Path -LiteralPath $createStore)){throw 'CreateRollbackStore.cs missing.'}
if(-not(Test-Path -LiteralPath $createOperationStore)){throw 'CreateOperationStore.cs missing.'}
if(-not(Test-Path -LiteralPath $createPolicy)){throw 'CreateGatePolicy.cs missing.'}
if(-not(Test-Path -LiteralPath $identityStore)){throw 'FileIdentityStore.cs missing.'}
if(-not(Test-Path -LiteralPath $renameStore)){throw 'RenameRollbackStore.cs missing.'}
if(-not(Test-Path -LiteralPath $truncateStore)){throw 'TruncateOperationStore.cs missing.'}
if(-not(Test-Path -LiteralPath $deleteStore)){throw 'DeleteOperationStore.cs missing.'}
if(-not(Test-Path -LiteralPath $restartStore)){throw 'RestartReconciliationStore.cs missing.'}
if(-not(Test-Path -LiteralPath $pagingStore)){throw 'PagingWriteEvidenceStore.cs missing.'}
if(-not(Test-Path -LiteralPath $sectionStore)){throw 'WritableSectionEvidenceStore.cs missing.'}
if(-not(Test-Path -LiteralPath $activationStore)){throw 'ActivationPreflightStore.cs missing.'}
if(-not(Test-Path -LiteralPath $topologyStore)){throw 'ActivationTopologyStore.cs missing.'}
if(-not(Test-Path -LiteralPath $containmentStore)){throw 'ContainmentEvidenceStore.cs missing.'}
$rangeText=Get-Content -LiteralPath $rangeStore -Raw
foreach($required in @(
    'CaptureWritePreimageAsync',
    'DefaultBlockSize',
    'RangeJournalKind.Baseline',
    'RangeJournalKind.Block',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'RestoreToNewCopyAsync',
    'output.SetLength(baseline.OriginalLength)',
    'Range rollback block SHA-256 mismatch',
    'Unjournaled range rollback object found',
    'Incomplete range rollback temp artifact found',
    'Range rollback block does not match the original file geometry',
    'Range pre-image source handle identity does not match the expected incident identity',
    'FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle)'
)){
    if($rangeText -notmatch [regex]::Escape($required)){throw "Range rollback source gate missing invariant: $required"}
}
if($rangeText -match 'File\.Move\(temp,\s*full' -or $rangeText -match 'File\.WriteAllBytes\([^,]*damagedPath'){
    throw 'Range rollback source gate FAILED: recovery must not overwrite the damaged source.'
}

$createText=Get-Content -LiteralPath $createStore -Raw
foreach($required in @(
    'CaptureAbsentAsync',
    'WasOriginallyAbsent',
    'create-journal.jsonl',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Create rollback journal hash chain mismatch',
    'Cannot record an originally-absent baseline because the target exists'
)){
    if($createText -notmatch [regex]::Escape($required)){throw "Create rollback source gate missing invariant: $required"}
}
if($createText -match 'File\.Delete\(' -or $createText -match 'Directory\.Delete\('){
    throw 'Create rollback source gate FAILED: absence baseline store must not delete created data.'
}
$createOperationText=Get-Content -LiteralPath $createOperationStore -Raw
foreach($required in @(
    'create-intent-journal.jsonl',
    'create-completion-journal.jsonl',
    'RecordIntentAsync',
    'RecordCompletionAsync',
    'PendingIntents',
    'CreateCompletionState.Succeeded',
    'CreateCompletionState.SucceededNameUnresolved',
    'CreateCompletionState.SucceededIdentityUnresolved',
    'CreateCompletionState.SucceededNameAndIdentityUnresolved',
    'CreateCompletionState.Failed',
    'IntentRecordSha256',
    'Conflicting duplicate CREATE completion',
    'CREATE intent preservation action does not match the disposition/target policy',
    'CreateGatePolicy.Decide(disposition, targetState, createOptions, desiredAccess)',
    'FileOptions.WriteThrough',
    'Flush(true)'
)){
    if($createOperationText -notmatch [regex]::Escape($required)){throw "CREATE operation source gate missing invariant: $required"}
}

$policyText=Get-Content -LiteralPath $createPolicy -Raw
foreach($required in @(
    'CreatePreservationAction.CaptureExistingPreimage',
    'CreatePreservationAction.RecordOriginallyAbsent',
    'CreateDisposition.Supersede',
    'CreateDisposition.Overwrite',
    'CreateDisposition.OverwriteIf',
    'CreateDisposition.OpenIf',
    'FileDeleteOnClose',
    'FileWriteData',
    'FileAppendData',
    'GenericWrite',
    'HasContentWriteAccess',
    'CreatePreservationAction.DenyUnsupported'
)){
    if($policyText -notmatch [regex]::Escape($required)){throw "Create gate policy missing invariant: $required"}
}

$identityText=Get-Content -LiteralPath $identityStore -Raw
foreach($required in @(
    'GetFileInformationByHandleEx',
    'FileIdInfo',
    'FileStandardInfo',
    'QueryPathStandardInfo',
    'QueryHandleStandardInfo',
    'VolumeSerialHex',
    'FileIdHex',
    'identity-journal.jsonl',
    'File identity changed for a path already observed in this incident',
    'FileOptions.WriteThrough',
    'Flush(true)'
)){
    if($identityText -notmatch [regex]::Escape($required)){throw "File identity source gate missing invariant: $required"}
}

$renameText=Get-Content -LiteralPath $renameStore -Raw
foreach($required in @(
    'rename-journal.jsonl',
    'rename-completion-journal.jsonl',
    'CaptureIntentAsync',
    'RecordCompletionAsync',
    'PendingIntents',
    'RenameCompletionState.Succeeded',
    'RenameCompletionState.SucceededNameUnresolved',
    'RenameCompletionState.SucceededIdentityUnresolved',
    'RenameCompletionState.SucceededNameAndIdentityUnresolved',
    'RenameCompletionState.Failed',
    'FinalVolumeSerialHex',
    'FinalFileIdHex',
    'Completed rename identity does not match the source identity from the committed intent',
    'RenameDestinationState.OriginallyAbsent',
    'RenameDestinationState.ExistingFile',
    'RenameDestinationState.SameAsSource',
    'RequestSequence',
    'SourceVolumeSerialHex',
    'DestinationVolumeSerialHex',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Rename rollback journal hash chain mismatch',
    'Rename completion journal hash chain mismatch',
    'Rename completion intent hash mismatch',
    'Conflicting duplicate rename completion',
    'IntentRecordSha256'
)){
    if($renameText -notmatch [regex]::Escape($required)){throw "Rename rollback source gate missing invariant: $required"}
}

$truncateText=Get-Content -LiteralPath $truncateStore -Raw
foreach($required in @(
    'truncate-intent-journal.jsonl',
    'truncate-completion-journal.jsonl',
    'truncate-restart-journal.jsonl',
    'RecordIntentAsync',
    'RecordCompletionAsync',
    'RecordRestartObservationAsync',
    'PendingIntents',
    'IntentRecordSha256',
    'Conflicting duplicate TRUNCATE completion',
    'TRUNCATE intent hash chain mismatch',
    'TRUNCATE completion hash chain mismatch',
    'TRUNCATE restart hash chain mismatch',
    'ClassifyRestart',
    'TruncateMetric.EndOfFile',
    'RestartEvidenceState.SupportsCompleted',
    'RestartEvidenceState.SupportsNotCompleted',
    'RestartEvidenceState.Indeterminate',
    'RestartEvidenceState.Ambiguous',
    'TRUNCATE restart observation intent binding mismatch',
    'TRUNCATE restart observation path does not match its committed intent',
    'TRUNCATE restart assessment intent binding mismatch',
    'FileOptions.WriteThrough',
    'Flush(true)'
)){
    if($truncateText -notmatch [regex]::Escape($required)){throw "TRUNCATE operation source gate missing invariant: $required"}
}
if($truncateText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'TRUNCATE transaction store must remain evidence-only and must not mutate live topology.'
}

$deleteText=Get-Content -LiteralPath $deleteStore -Raw
foreach($required in @(
    'delete-intent-journal.jsonl',
    'delete-completion-journal.jsonl',
    'delete-finalization-journal.jsonl',
    'RecordIntentAsync',
    'RecordCompletionAsync',
    'RecordFinalizationAsync',
    'PendingIntents',
    'UnsettledIntents',
    'IntentRecordSha256',
    'DELETE intent hash chain mismatch',
    'DELETE completion hash chain mismatch',
    'DELETE finalization hash chain mismatch',
    'Conflicting duplicate DELETE completion',
    'DELETE finalization intent binding mismatch',
    'DELETE finalization path does not match its committed intent',
    'DeleteFinalizationState.CleanupObserved',
    'DeleteFinalizationAssessmentState.CleanupObservedOnly',
    'DeleteFinalizationAssessmentState.Unresolved',
    'ClassifyPathObservation',
    'FileOptions.WriteThrough',
    'Flush(true)'
)){
    if($deleteText -notmatch [regex]::Escape($required)){throw "DELETE operation source gate missing invariant: $required"}
}
if($deleteText -match '\b(File\.Delete|Directory\.Delete|File\.Move|Directory\.Move)\s*\('){
    throw 'DELETE transaction store must remain evidence-only and must not mutate live topology.'
}

$restartText=Get-Content -LiteralPath $restartStore -Raw
foreach($required in @(
    'restart-reconciliation-journal.jsonl',
    'RecordObservationAsync',
    'RestartReconciliationClassifier',
    'RestartEvidenceState.SupportsCompleted',
    'RestartEvidenceState.SupportsNotCompleted',
    'RestartEvidenceState.Indeterminate',
    'RestartEvidenceState.Ambiguous',
    'IntentRecordSha256',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Restart reconciliation journal hash chain mismatch'
)){
    if($restartText -notmatch [regex]::Escape($required)){throw "Restart reconciliation source gate missing invariant: $required"}
}

$pagingText=Get-Content -LiteralPath $pagingStore -Raw
foreach($required in @(
    'paging-write-journal.jsonl',
    'RecordAsync',
    'KernelSequence',
    'ByteOffset',
    'Length',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Paging-write journal hash chain mismatch',
    'Conflicting duplicate paging-write kernel sequence'
)){
    if($pagingText -notmatch [regex]::Escape($required)){throw "Paging-write evidence source gate missing invariant: $required"}
}

$sectionText=Get-Content -LiteralPath $sectionStore -Raw
foreach($required in @(
    'writable-section-journal.jsonl',
    'WritableSectionAttestation',
    'WritableSectionAttestationState.BaselineVerified',
    'WritableSectionAttestationState.Unprotected',
    'MissingCreateIntent',
    'DecisionMismatch',
    'PathMismatch',
    'CreateRequestSequence',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Writable-section journal hash chain mismatch'
)){
    if($sectionText -notmatch [regex]::Escape($required)){throw "Writable-section evidence source gate missing invariant: $required"}
}

$activationText=Get-Content -LiteralPath $activationStore -Raw
foreach($required in @(
    'activation-preflight-journal.jsonl',
    'RecordAsync',
    'WritableViewPresent',
    'KernelSequence',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Activation-preflight journal hash chain mismatch',
    'Conflicting duplicate activation-preflight kernel sequence'
)){
    if($activationText -notmatch [regex]::Escape($required)){throw "Activation preflight source gate missing invariant: $required"}
}

$topologyText=Get-Content -LiteralPath $topologyStore -Raw
foreach($required in @(
    'activation-topology-journal.jsonl',
    'RecordAsync',
    'DirectoryPath',
    'IsRoot',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Activation-topology journal hash chain mismatch',
    'Conflicting activation-topology record for directory path',
    'Duplicate activation-topology directory path'
)){
    if($topologyText -notmatch [regex]::Escape($required)){throw "Activation topology source gate missing invariant: $required"}
}

$containmentText=Get-Content -LiteralPath $containmentStore -Raw
foreach($required in @(
    'containment-journal.jsonl',
    'ContainmentEvidencePhase.Requested',
    'ContainmentEvidencePhase.KernelActive',
    'RecordRequestAsync',
    'RecordKernelActiveAsync',
    'ProcessCreationFileTimeUtc',
    'EvidenceCount',
    'DistinctPathCount',
    'kernelStatus != 0',
    'line.KernelStatus != 0',
    'FileOptions.WriteThrough',
    'Flush(true)',
    'Containment evidence journal hash chain mismatch',
    'Containment kernel-active evidence is not linked to the exact durable request'
)){
    if($containmentText -notmatch [regex]::Escape($required)){throw "Containment evidence source gate missing invariant: $required"}
}

if(-not(Test-Path -LiteralPath $store)){throw 'RollbackStore.cs missing.'}
$text=Get-Content -LiteralPath $store -Raw
foreach($required in @(
    'FileOptions.WriteThrough',
    'Flush(true)',
    'FileMode.CreateNew',
    'OriginalSha256',
    'PreviousRecordSha256',
    'RecordSha256',
    'RestoreToNewCopyAsync',
    'Rollback pre-image hash mismatch',
    'Recovery output already exists',
    'Committed rollback object SHA-256 mismatch',
    'Unjournaled rollback object found',
    'Incomplete rollback temp artifact found',
    'Full pre-image source handle identity does not match the expected incident identity',
    'FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle)'
)){
    if($text -notmatch [regex]::Escape($required)){throw "Rollback source gate missing invariant: $required"}
}
if($text -match 'File\.Move\(temp,\s*capture\.OriginalPath' -or $text -match 'File\.WriteAllBytes\([^,]*OriginalPath'){
    throw 'Rollback source gate FAILED: recovery must not overwrite the original path.'
}
$service=Get-Content -LiteralPath $program -Raw
if($service -notmatch 'rollbackRepository\.VerifyAll\(\)'){throw 'Service must validate the rollback repository before monitoring starts.'}
if($service -match 'CapturePreimageAsync\('){throw 'Normal service must not claim automatic pre-image capture before the minifilter write gate is validated.'}
$gate=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.GateClient\Program.cs') -Raw
if($gate -notmatch 'repository\.VerifyAll\(\)'){throw 'LAB gate must validate all existing rollback sessions before starting a new session.'}
$repository=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Rollback\RollbackRepository.cs') -Raw
if($repository -notmatch 'new RangeRollbackStore\(rangeRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested write-cow stores.'}
if($repository -notmatch 'new CreateRollbackStore\(createRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested create-state stores.'}
if($repository -notmatch 'new CreateOperationStore\(createRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include CREATE intent/completion journals.'}
if($repository -notmatch 'new FileIdentityStore\(identityRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested identity-state stores.'}
if($repository -notmatch 'new RenameRollbackStore\(renameRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested rename-state stores.'}
if($repository -notmatch 'new TruncateOperationStore\(truncateRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include TRUNCATE intent/completion/restart journals.'}
if($repository -notmatch 'new DeleteOperationStore\(deleteRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include DELETE intent/completion/finalization journals.'}
if($repository -notmatch 'new RestartReconciliationStore\(restartRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested restart-state stores.'}
if($repository -notmatch 'new PagingWriteEvidenceStore\(pagingRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested paging-state stores.'}
if($repository -notmatch 'new WritableSectionEvidenceStore\(sectionRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested section-state stores.'}
if($repository -notmatch 'new ActivationPreflightStore\(activationRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested activation-state stores.'}
if($repository -notmatch 'new ActivationTopologyStore\(topologyRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested activation-topology-state stores.'}
if($repository -notmatch 'new ContainmentEvidenceStore\(containmentRoot, createIfMissing: _createIfMissing\)\.VerifyAll\(\)'){throw 'Repository verification must include nested containment-state stores.'}
Write-Host 'Rollback source gate PASSED: full-file/range COW, CREATE/RENAME/TRUNCATE/DELETE transactions, identity, restart, paging, section, activation, topology and containment journals, hashes, write-through commits and copy-only restore.'
Write-Host 'Normal service capture remains disabled; blocking preservation and containment remain inside the explicit Engineering LAB gate. Paging/section callbacks remain evidence-only.'

