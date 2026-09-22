[CmdletBinding()]
param(
    [string]$RepositoryRoot=''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if([string]::IsNullOrWhiteSpace($RepositoryRoot)){
    $RepositoryRoot=Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot=[IO.Path]::GetFullPath($RepositoryRoot)

$excluded='(?i)[\\/](?:\.git|bin|obj|release|build-logs|minifilter-build|runtime-driver-package|packages)[\\/]'
$scripts=@(Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.ps1' -File -Recurse -ErrorAction Stop |
    Where-Object { $_.FullName -notmatch $excluded } |
    Sort-Object FullName)
$workflows=@()
$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
if(Test-Path -LiteralPath $workflowRoot -PathType Container){
    $workflows=@(Get-ChildItem -LiteralPath $workflowRoot -File -ErrorAction Stop |
        Where-Object { $_.Extension -in @('.yml','.yaml') } |
        Sort-Object FullName)
}

$findings=New-Object System.Collections.Generic.List[string]

foreach($script in $scripts){
    $tokens=$null
    $parseErrors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach($parseError in @($parseErrors)){
        $relative=$script.FullName.Substring($RepositoryRoot.Length).TrimStart('\','/')
        $findings.Add(('{0}:{1}:{2}: PowerShell parser: {3}' -f
            $relative,
            $parseError.Extent.StartLineNumber,
            $parseError.Extent.StartColumnNumber,
            $parseError.Message))
    }

    $lines=@(Get-Content -LiteralPath $script.FullName)
    for($i=0;$i -lt ($lines.Count-1);$i++){
        # LASTEXITCODE belongs to the most recent native process. It is not a reliable
        # success result for another PowerShell script invoked with the call operator.
        if($lines[$i] -match '&\s+\$[A-Za-z_][A-Za-z0-9_]*Script\b' -and
           $lines[$i+1] -match '\$LASTEXITCODE\b'){
            $relative=$script.FullName.Substring($RepositoryRoot.Length).TrimStart('\','/')
            $findings.Add(('{0}:{1}: PowerShell script invocation is followed by stale-prone $LASTEXITCODE inspection.' -f
                $relative,($i+1)))
        }
    }
}

foreach($workflow in $workflows){
    $lines=@(Get-Content -LiteralPath $workflow.FullName)
    for($i=0;$i -lt $lines.Count;$i++){
        if($lines[$i] -notmatch '^\s*\.\\[^\r\n]*\.ps1(?:\s|$)'){continue}

        $j=$i+1
        while($j -lt $lines.Count -and [string]::IsNullOrWhiteSpace($lines[$j])){$j++}
        if($j -lt $lines.Count -and $lines[$j] -match '\$LASTEXITCODE\b'){
            $relative=$workflow.FullName.Substring($RepositoryRoot.Length).TrimStart('\','/')
            $findings.Add(('{0}:{1}: workflow invokes a PowerShell script and then inspects stale-prone $LASTEXITCODE.' -f
                $relative,($i+1)))
        }
    }
}

if($findings.Count -gt 0){
    $details=$findings -join [Environment]::NewLine
    throw "PowerShell automation audit failed:$([Environment]::NewLine)$details"
}

Write-Host ("PowerShell automation audit PASSED: {0} scripts parsed; {1} workflows checked; no script/LASTEXITCODE handoff hazards found." -f
    $scripts.Count,$workflows.Count) -ForegroundColor Green
