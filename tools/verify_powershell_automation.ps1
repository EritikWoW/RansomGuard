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
$scripts=@(
    Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.ps1' -File -Recurse -ErrorAction Stop |
        Where-Object { $_.FullName -notmatch $excluded } |
        Sort-Object FullName
)
$cmdFiles=@(
    Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.cmd' -File -Recurse -ErrorAction Stop |
        Where-Object { $_.FullName -notmatch $excluded } |
        Sort-Object FullName
)
$workflows=@()
$workflowRoot=Join-Path $RepositoryRoot '.github\workflows'
if(Test-Path -LiteralPath $workflowRoot -PathType Container){
    $workflows=@(
        Get-ChildItem -LiteralPath $workflowRoot -File -ErrorAction Stop |
            Where-Object { $_.Extension -in @('.yml','.yaml') } |
            Sort-Object FullName
    )
}

$findings=New-Object System.Collections.Generic.List[string]

function Get-RelativePath([string]$Path){
    return $Path.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\','/'))
}

function Get-NextCodeLineIndex([string[]]$Lines,[int]$StartIndex){
    $j=$StartIndex
    while($j -lt $Lines.Count -and
          ([string]::IsNullOrWhiteSpace($Lines[$j]) -or $Lines[$j] -match '^\s*#')){
        $j++
    }
    return $j
}

foreach($script in $scripts){
    $tokens=$null
    $parseErrors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach($parseError in @($parseErrors)){
        $findings.Add(('{0}:{1}:{2}: PowerShell parser: {3}' -f
            (Get-RelativePath $script.FullName),
            $parseError.Extent.StartLineNumber,
            $parseError.Extent.StartColumnNumber,
            $parseError.Message))
    }

    $lines=@(Get-Content -LiteralPath $script.FullName)
    for($i=0;$i -lt $lines.Count;$i++){
        # $LASTEXITCODE belongs to the most recent native process. It is not a reliable
        # success result for another PowerShell script invoked with the call operator.
        $looksLikePowerShellScriptCall=
            $lines[$i] -match '&\s+\$[A-Za-z_][A-Za-z0-9_]*Script\b' -or
            $lines[$i] -match '&\s+.*\.ps1(?:''|"|\)|\s|$)'
        if(-not $looksLikePowerShellScriptCall){continue}

        $j=Get-NextCodeLineIndex $lines ($i+1)
        if($j -lt $lines.Count -and $lines[$j] -match '\$LASTEXITCODE\b'){
            $findings.Add(('{0}:{1}: PowerShell script invocation is followed by stale-prone $LASTEXITCODE inspection.' -f
                (Get-RelativePath $script.FullName),($i+1)))
        }
    }
}

foreach($cmd in $cmdFiles){
    $lines=@(Get-Content -LiteralPath $cmd.FullName)
    $text=$lines -join [Environment]::NewLine

    # Interactive -NoExit launchers deliberately transfer control to a PowerShell window.
    # Other wrappers that PAUSE must preserve the child exit code before PAUSE overwrites it.
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
            $findings.Add(('{0}: command wrapper pauses without reliably preserving the child exit status.' -f
                (Get-RelativePath $cmd.FullName)))
        }
    }
}

foreach($workflow in $workflows){
    $lines=@(Get-Content -LiteralPath $workflow.FullName)
    for($i=0;$i -lt $lines.Count;$i++){
        # Detect stale LASTEXITCODE checks after direct .ps1 invocation in workflow script text.
        if($lines[$i] -match '^\s*\.\\[^\r\n]*\.ps1(?:\s|$)'){
            $j=Get-NextCodeLineIndex $lines ($i+1)
            if($j -lt $lines.Count -and $lines[$j] -match '\$LASTEXITCODE\b'){
                $findings.Add(('{0}:{1}: workflow invokes a PowerShell script and then inspects stale-prone $LASTEXITCODE.' -f
                    (Get-RelativePath $workflow.FullName),($i+1)))
            }
        }

        # Parse block-style PowerShell run sections before expensive build/runtime work.
        if($lines[$i] -notmatch '^(\s*)run:\s*\|\s*$'){continue}
        $runIndent=$Matches[1].Length

        $shell=''
        for($s=$i-1;$s -ge 0;$s--){
            if($lines[$s] -match '^\s*-\s+name:'){break}
            if($lines[$s] -match '^\s*shell:\s*(pwsh|powershell)\s*$'){
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

            $indent=$line.Length-$line.TrimStart().Length
            if($indent -le $runIndent){break}
            if($indent -lt $minIndent){$minIndent=$indent}
            $block.Add($line)
        }

        if($block.Count -eq 0){continue}
        if($minIndent -eq [int]::MaxValue){$minIndent=0}

        $normalized=($block | ForEach-Object {
            if($_.Length -ge $minIndent){$_.Substring($minIndent)}else{''}
        }) -join [Environment]::NewLine

        # Workflow dispatch inputs and event payload values are user-controlled. Injecting
        # them directly into PowerShell source can turn quoting mistakes into code execution
        # on an elevated self-hosted runner. Pass such values through env instead.
        if($normalized -match '\$\{\{\s*(?:inputs|github\.event)\.'){
            $findings.Add(('{0}:{1}: inline PowerShell embeds user/event workflow expressions directly. Pass them through env instead.' -f
                (Get-RelativePath $workflow.FullName),$blockStart))
        }

        $tokens=$null
        $parseErrors=$null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $normalized,
            $workflow.FullName,
            [ref]$tokens,
            [ref]$parseErrors
        )
        foreach($parseError in @($parseErrors)){
            $lineNumber=$blockStart+$parseError.Extent.StartLineNumber-1
            $findings.Add(('{0}:{1}:{2}: inline {3} parser: {4}' -f
                (Get-RelativePath $workflow.FullName),
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

Write-Host ("Automation audit PASSED: {0} PowerShell scripts parsed; {1} command wrappers checked; {2} workflows checked; no parser, script/LASTEXITCODE, wrapper exit-propagation, inline PowerShell, or direct input-interpolation hazards found." -f
    $scripts.Count,$cmdFiles.Count,$workflows.Count) -ForegroundColor Green
