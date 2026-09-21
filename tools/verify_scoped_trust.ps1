[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$core=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Core\ScopedTrust.cs') -Raw
$verifier=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Service\ScopedRuleVerifier.cs') -Raw
$worker=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Service\GuardWorker.cs') -Raw
$admin=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Service\ScopedRuleAdmin.cs') -Raw
$store=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Service\ScopedRuleStore.cs') -Raw
foreach($required in @('CanaryOverridesRule','ContentEvidenceOverridesRule','IncompleteEvidence','RenameDestinationUnknownOrOutsideRule','ImageChangedOrNotFresh','SignatureNotVerified','ProcessOrUserNotVerified','BehaviorBudgetExceeded')){
 if(-not$core.Contains($required)){throw "Missing scoped rule veto: $required"}
}
if($verifier -match 'NtSuspend|NtResume|TerminateProcess|WriteProcessMemory|AdjustTokenPrivileges'){throw 'Scoped verifier contains a process-control primitive.'}
if($verifier -notmatch 'SHA256.HashDataAsync' -or $verifier -notmatch 'FileShare.Read' -or $verifier -notmatch '0x0008'){throw 'Fresh hashing/token query contract missing.'}
if($admin -notmatch 'DemandAdministrator' -or $admin -notmatch 'Confirm\("TRUST ' -or $store -notmatch 'expectedDigest'){throw 'Administrator review/concurrency guard missing.'}
if($worker -notmatch 'ScopedTrust=scoped' -or $worker -notmatch 'Action="AuditOnly"'){throw 'Scoped decision must be audited without an ordinary process action.'}
if($core -match '\bMD5\.(Create|HashData)|Score\s*-='){throw 'Weak digest or score discount in rule policy.'}
Write-Host 'Scoped trust source gate PASSED: exact SHA256/SID/path, current context, bounded lifetime, immutable scores, admin review.'
Write-Host 'This is a static guard, not proof of Windows integration or malware-detection efficacy.'
