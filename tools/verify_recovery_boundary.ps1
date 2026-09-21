[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$paths=@((Join-Path $root 'src\RansomGuard.Recovery'),(Join-Path $root 'src\RansomGuard.RecoveryCli'))
$text=($paths | ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter *.cs -File } | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join "`n"
foreach($pattern in @('recovery-key\.bin','ReadProcessMemory','WriteProcessMemory','NtSuspendProcess','VirtualAllocEx','CreateRemoteThread','Process\.Start','FileMode\.Create\b','FileMode\.Truncate','FileMode\.OpenOrCreate')){
 if($text -match $pattern){throw "Offline recovery boundary failed: $pattern"}
}
foreach($required in @('AuthenticationTagMismatchException','FileMode.CreateNew','CryptographicOperations.ZeroMemory','MaxDumpBytes','MaxFiles','TryReadVirtual')){
 if(-not $text.Contains($required)){throw "Missing offline recovery invariant: $required"}
}
Write-Host 'Offline recovery source boundary PASSED. This does not replace runtime tests.'
