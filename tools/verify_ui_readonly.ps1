[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$ui=Join-Path $root 'src\RansomGuard.Ui'
$server=Join-Path $root 'src\RansomGuard.Service\ReadOnlyPipeServer.cs'
$core=Join-Path $root 'src\RansomGuard.Core\LocalApi.cs'
$manifest=Join-Path $ui 'app.manifest'
foreach($p in @($ui,$server,$core,$manifest)){if(-not(Test-Path -LiteralPath $p)){throw "Missing UI safety input: $p"}}
$text=(Get-ChildItem -LiteralPath $ui -File -Recurse | Where-Object {$_.Extension -in '.cs','.xaml','.csproj','.manifest'} | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
$forbidden=@(
  'Process\.Kill\s*\(', 'NtSuspendProcess', 'NtResumeProcess', 'TerminateProcess\s*\(', 'OpenProcess\s*\(',
  'fltmc(?:\.exe)?\s+(?:load|attach|unload|detach)', 'sc(?:\.exe)?\s+(?:start|stop|create|delete)',
  'bcdedit', 'testsigning', 'DisableRealtimeMonitoring', 'Set-MpPreference', 'ServiceController\s*\.\s*Stop',
  'WriteAllText\s*\([^\)]*appsettings', 'RegistryKey\s*\.\s*(?:CreateSubKey|SetValue)'
)
foreach($pattern in $forbidden){if($text -match $pattern){throw "UI read-only gate FAILED: forbidden pattern '$pattern'"}}
[xml]$xml=Get-Content -LiteralPath $manifest -Raw
$ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable);$ns.AddNamespace('asmv3','urn:schemas-microsoft-com:asm.v3')
$node=$xml.SelectSingleNode('//asmv3:requestedExecutionLevel',$ns)
if($null -eq $node -or [string]$node.level -ne 'asInvoker'){throw 'UI read-only gate FAILED: UI must run asInvoker.'}
$contract=Get-Content -LiteralPath $core -Raw
foreach($cmd in @('status','incidents','diagnostics','subscribe')){if($contract -notmatch ('"'+[regex]::Escape($cmd)+'"')){throw "UI read-only gate FAILED: missing expected command $cmd"}}
if($contract -match '"(?:kill|suspend|terminate|trust|block|install|attach|detach|unload)"'){throw 'UI read-only gate FAILED: mutating command literal detected in LocalApi contract.'}
$serverText=Get-Content -LiteralPath $server -Raw
if($serverText -notmatch 'NetworkSid' -or $serverText -notmatch 'AnonymousSid'){throw 'UI read-only gate FAILED: pipe must explicitly deny NETWORK and ANONYMOUS.'}
Write-Host 'READ-ONLY DATA API gate PASSED. Administrative UI uses a separate explicitly elevated instance.'
Write-Host 'UI manifest: asInvoker. Protocol v2: status/incidents/diagnostics/subscribe only. No recovery or mutating requests.'
Write-Host 'No process/driver control in UI. Native own-service control is isolated in Management and checked by verify_administration.ps1.'

$client=Get-Content -LiteralPath (Join-Path $ui 'LocalApiClient.cs') -Raw
if($client -notmatch 'OpenForImageQuery\(0x1000,false,pid\)' -or $client -notmatch '0x00120083'){
    throw 'Live pipe peer query/least-privilege transport contract is missing.'
}
if($client -match '0x001F0FFF|0x1F0FFF|PROCESS_ALL_ACCESS'){throw 'UI must not request all process access.'}
if($serverText -notmatch 'TimeSpan.FromSeconds\(3\)' -or $serverText -notmatch 'Enumerable.Range\(0,4\)'){
    throw 'Live pipe client/write bounds are missing.'
}
Write-Host 'Live stream gate PASSED: bounded frames, four connections, read-only protocol, limited image query.'
