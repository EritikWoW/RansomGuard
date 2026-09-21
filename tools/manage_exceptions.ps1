#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$exe=Join-Path $root 'RansomGuard.Service.exe'
if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw 'Run this tool from a built release, not the source folder.'}
Write-Host 'Scoped trust manager - monitoring, incident records and risk scores stay enabled.'
Write-Host '1 List | 2 Add reviewed rule | 3 Disable | 4 Remove | 5 Native selftest | Enter Exit'
$choice=Read-Host 'Action'
switch($choice){
 '1' {$arguments=@('--rules','list')}
 '2' {
    $path=(Read-Host 'Full path to the EXE').Trim('"')
    $name=Read-Host 'Rule name'
    $user=Read-Host 'Process account SID (use whoami /user in THAT account, not necessarily this admin)'
    $folder=(Read-Host 'One exact directory of expected activity (no wildcards)').Trim('"').TrimEnd('\')
    $operations=Read-Host 'Operations: Write,Delete (Rename requires a known destination; current ETW does not provide it)'
    if([string]::IsNullOrWhiteSpace($operations)){$operations='Write'}
    $hours=Read-Host 'Lifetime in hours, 1-720 (default 8)'
    if([string]::IsNullOrWhiteSpace($hours)){$hours='8'}
    $effect=Read-Host 'Effect: AnnotateOnly or QuietRepeat (default AnnotateOnly)'
    if([string]::IsNullOrWhiteSpace($effect)){$effect='AnnotateOnly'}
    $reason=Read-Host 'Why is this exact operation expected?'
    $arguments=@('--rules','add','--exe',$path,'--name',$name,'--user-sid',$user,'--scope',$folder,
        '--operations',$operations,'--hours',$hours,'--effect',$effect,'--reason',$reason)
    $pidText=Read-Host 'Optional running process ID to restrict the rule to ONE instance (Enter for hash-based rule)'
    if(-not[string]::IsNullOrWhiteSpace($pidText)){$arguments+=@('--pid',$pidText)}
    $unsigned=Read-Host 'Only for your reviewed UNSIGNED binary: type UNSIGNED to opt in (otherwise Enter)'
    if($unsigned -ceq 'UNSIGNED'){$arguments+='--allow-unsigned-exact-hash'}
 }
 '3' {$arguments=@('--rules','disable','--id',(Read-Host 'Full rule ID'),'--reason',(Read-Host 'Reason'))}
 '4' {$arguments=@('--rules','remove','--id',(Read-Host 'Full rule ID'),'--reason',(Read-Host 'Reason'))}
 '5' {$arguments=@('--rules','selftest')}
 default {exit 0}
}
# Invoke the EXE directly with an argument array. Never construct/evaluate a shell expression.
& $exe @arguments
if($LASTEXITCODE -ne 0){throw "Rule manager returned exit code $LASTEXITCODE. Read the diagnostic above."}
