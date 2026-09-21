$ErrorActionPreference='Stop'
$root=Join-Path $env:ProgramData 'RansomGuardV03'
$adminSid='S-1-5-32-544'
$systemSid='S-1-5-18'
function SidOf($identity) {
    try {
        if($identity -is [Security.Principal.SecurityIdentifier]) { return $identity.Value }
        return $identity.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return '<unresolved>' }
}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {
    Write-Host "State directory does not exist: $root"
    exit 0
}
$item=Get-Item -LiteralPath $root -Force
if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Write-Host 'UNSAFE: state root itself is a reparse point.' -ForegroundColor Red
    exit 2
}
$acl=Get-Acl -LiteralPath $root
try {$ownerSid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value} catch {$ownerSid='<unresolved>'}
Write-Host "State root: $root"
Write-Host "Owner: $($acl.Owner) [$ownerSid]"
Write-Host "Inheritance protected: $($acl.AreAccessRulesProtected)"
$writeMask=[Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
$bad=@()
foreach($rule in $acl.Access) {
    $sid=SidOf $rule.IdentityReference
    $isWrite=($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) -and (($rule.FileSystemRights -band $writeMask) -ne 0)
    $allowed=($sid -eq $adminSid -or $sid -eq $systemSid)
    $flag=if($isWrite -and -not $allowed){'UNSAFE-WRITE'}else{'OK/READ'}
    Write-Host ("{0,-12} SID={1,-18} inherited={2,-5} rights={3}" -f $flag,$sid,$rule.IsInherited,$rule.FileSystemRights)
    if($isWrite -and -not $allowed){$bad += $rule}
}
if($ownerSid -notin @($adminSid,$systemSid)) {
    Write-Host 'UNSAFE: owner is not Administrators or LocalSystem.' -ForegroundColor Red
    exit 3
}
if(-not $acl.AreAccessRulesProtected) {
    Write-Host 'UNSAFE: ACL inheritance is still enabled.' -ForegroundColor Red
    exit 4
}
if($bad.Count -gt 0) {
    Write-Host "UNSAFE: $($bad.Count) writable ACE(s) belong to another principal." -ForegroundColor Red
    exit 5
}
Write-Host 'State root ACL passes the strict RansomGuard check.' -ForegroundColor Green
