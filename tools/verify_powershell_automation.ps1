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
$cmdFiles=@(Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.cmd' -File -Recurse -ErrorAction Stop |
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
        $relative=$script.FullName.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
        $findings.Add(('{0}:{1}:{2}: PowerShell parser: {3}' -f
            $relative,
            $parseError.Extent.StartLineNumber,
            $parseError.Extent.StartColumnNumber,
            $parseError.Message))
    }

    $lines=@(Get-Content -LiteralPath $script.FullName)
    for($i=0;$i -lt $lines.Count;$i++){
        # LASTEXITCODE belongs to the most recent native process. It is not a reliable
        # success result for another PowerShell script invoked with the call operator.
        if($lines[$i] -notmatch '&\s+(?:\$[A-Za-z_][A-Za-z0-9_]*Script\b|.*\.ps1(?:''|"|\)|\s|$))'){continue}

        $j=$i+1
        while($j -lt $lines.Count -and
              ([string]::IsNullOrWhiteSpace($lines[$j]) -or $lines[$j] -match '^\s*#')){
            $j++
        }
        if($j -lt $lines.Count -and $lines[$j] -match '\$LASTEXITCODE\b'){
            $relative=$script.FullName.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
            $findings.Add(('{0}:{1}: PowerShell script invocation is followed by stale-prone $LASTEXITCODE inspection.' -f
                $relative,($i+1)))
        }
    }
}

foreach($cmd in $cmdFiles){
    $lines=@(Get-Content -LiteralPath $cmd.FullName)
    $text=$lines -join [Environment]::NewLine

    # Interactive -NoExit launchers deliberately transfer control to a PowerShell window.
    # Other wrappers that pause must preserve the child exit code before PAUSE overwrites it.
    if($text -match '(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\r\n]*\s-File\s' -and
       $text -notmatch '(?i)\s-NoExit(?:\s|$)' -and
       $text -match '(?im)^\s*pause\s*$'){
        $pauseIndex=-1
        $captureIndex=-1
        $exitIndex=-1
        for($i=0;$i -lt $lines.Count;$i++){
            if($pauseIndex -lt 0 -and $lines[$i] -match '(?i)^\s*pause\s*$'){$pauseIndex=$i}
            if($captureIndex -lt 0 -and $lines[$i] -match '(?i)^\s*set\s+"?[A-Za-z_][A-Za-z0-9_]*=%ERRORLEVEL%"?\s*$'){$captureIndex=$i}
            if($exitIndex -lt 0 -and $lines[$i] -match '(?i)^\s*exit\s+/b\s+%[A-Za-z_][A-Za-z0-9_]*%\s*$'){$exitIndex=$i}
        }
        if($captureIndex -lt 0 -or $pauseIndex -lt 0 -or $exitIndex -lt 0 -or
           $captureIndex -gt $pauseIndex -or $exitIndex -lt $pauseIndex){
            $relative=$cmd.FullName.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
            $findings.Add(('{0}: command wrapper pauses without reliably preserving the child exit status.' -f $relative))
        }
    }
}

foreach($workflow in $workflows){
    $lines=@(Get-Content -LiteralPath $workflow.FullName)
    for($i=0;$i -lt $lines.Count;$i++){
        if($lines[$i] -match '^\s*\.\\[^\r\n]*\.ps1(?:\s|$)'){
            $j=$i+1
            while($j -lt $lines.Count -and
                  ([string]::IsNullOrWhiteSpace($lines[$j]) -or $lines[$j] -match '^\s*#')){$j++}
            if($j -lt $lines.Count -and $lines[$j] -match '\$LASTEXITCODE\b'){
                $relative=$workflow.FullName.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
                $findings.Add(('{0}:{1}: workflow invokes a PowerShell script and then inspects stale-prone $LASTEXITCODE.' -f
                    $relative,($i+1)))
            }
        }

        if($lines[$i] -notmatch '^(\s*)run:\s*\|\s*

if($findings.Count -gt 0){
    $details=$findings -join [Environment]::NewLine
    throw "PowerShell automation audit failed:$([Environment]::NewLine)$details"
}

Write-Host ("Automation audit PASSED: {0} PowerShell scripts parsed; {1} command wrappers checked; {2} workflows checked; no parser, script/LASTEXITCODE, or wrapper exit-propagation hazards found." -f
    $scripts.Count,$cmdFiles.Count,$workflows.Count) -ForegroundColor Green
){continue}
        $runIndent=$Matches[1].Length
        $shell=''
        for($s=$i-1;$s -ge 0;$s--){
            if($lines[$s] -match '^\s*-\s+name:'){break}
            if($lines[$s] -match '^\s*shell:\s*(pwsh|powershell)\s*

if($findings.Count -gt 0){
    $details=$findings -join [Environment]::NewLine
    throw "PowerShell automation audit failed:$([Environment]::NewLine)$details"
}

Write-Host ("Automation audit PASSED: {0} PowerShell scripts parsed; {1} command wrappers checked; {2} workflows checked; no parser, script/LASTEXITCODE, or wrapper exit-propagation hazards found." -f
    $scripts.Count,$cmdFiles.Count,$workflows.Count) -ForegroundColor Green
){
                $shell=$Matches[1]
                break
            }
        }
        if(-not $shell){continue}

        $block=New-Object System.Collections.Generic.List[string]
        $blockStart=$i+2
        $minIndent=[int]::MaxValue
        for($j=$i+1;$j -lt $lines.Count;$j++){
            $line=$lines[$j]
            if([string]::IsNullOrWhiteSpace($line)){
                $block.Add('')
                continue
            }
            $indent=($line.Length-$line.TrimStart().Length)
            if($indent -le $runIndent){break}
            if($indent -lt $minIndent){$minIndent=$indent}
            $block.Add($line)
        }
        if($block.Count -eq 0){continue}
        if($minIndent -eq [int]::MaxValue){$minIndent=0}
        $normalized=($block | ForEach-Object {
            if($_.Length -ge $minIndent){$_.Substring($minIndent)}else{''}
        }) -join [Environment]::NewLine

        $tokens=$null
        $parseErrors=$null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $normalized,
            $workflow.FullName,
            [ref]$tokens,
            [ref]$parseErrors
        )
        foreach($parseError in @($parseErrors)){
            $relative=$workflow.FullName.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
            $lineNumber=$blockStart+$parseError.Extent.StartLineNumber-1
            $findings.Add(('{0}:{1}:{2}: inline {3} parser: {4}' -f
                $relative,
                $lineNumber,
                $parseError.Extent.StartColumnNumber,
                $shell,
                $parseError.Message))
        }
    }
}

if($findings.Count -gt 0){
    $details=$findings -join [Environment]::NewLine
    throw "PowerShell automation audit failed:$([Environment]::NewLine)$details"
}

Write-Host ("Automation audit PASSED: {0} PowerShell scripts parsed; {1} command wrappers checked; {2} workflows checked; no parser, script/LASTEXITCODE, or wrapper exit-propagation hazards found." -f
    $scripts.Count,$cmdFiles.Count,$workflows.Count) -ForegroundColor Green
