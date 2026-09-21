$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramData 'RansomGuardV03\Incidents'
if(-not (Test-Path -LiteralPath $base)){throw 'No RansomGuardV03 incident directory exists.'}
$case=Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if(-not $case){throw 'No incident cases found.'}
$responsePath=Join-Path $case.FullName 'response.json'
$incidentPath=Join-Path $case.FullName 'incident.json'
if(-not (Test-Path -LiteralPath $responsePath)){throw "Latest case has no response.json: $($case.FullName)"}
$r=Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
Write-Host ''
Write-Host ('Latest case: {0}' -f $case.FullName) -ForegroundColor Cyan
Write-Host ('Action: {0}' -f $r.Action)
if($r.Freeze){
    Write-Host ('Freeze API accepted: {0}; threads observed suspended: {1}; freeze duration: {2:N3} ms' -f $r.Freeze.ApiAccepted,$r.Freeze.AllThreadsObservedSuspended,[double]$r.Freeze.DurationMs)
}
if($null -ne $r.LockedFilesAtFreeze){Write-Host ('Synthetic fixtures locked at freeze: {0}/10; before resume: {1}/10; stable while frozen: {2}' -f $r.LockedFilesAtFreeze,$r.LockedFilesBeforeResume,$r.FixtureProgressStable)}
if($null -ne $r.FirstEvidenceToDecisionMs){Write-Host ('First evidence -> decision: {0:N1} ms; decision -> freeze start: {1:N1} ms' -f [double]$r.FirstEvidenceToDecisionMs,[double]$r.DetectionToFreezeStartMs)}
if($null -ne $r.EvidenceDeliveryP95Ms){Write-Host ('Evidence delivery p95: {0:N1} ms; max: {1:N1} ms' -f [double]$r.EvidenceDeliveryP95Ms,[double]$r.EvidenceDeliveryMaxMs)}
if($r.Dump){Write-Host ('Dump: {0}; succeeded={1}' -f $r.Dump.Status,$r.Dump.Succeeded)}
$cryptoPath=Join-Path $case.FullName 'crypto-recovery.json'
if(Test-Path -LiteralPath $cryptoPath){
    $crypto=Get-Content -LiteralPath $cryptoPath -Raw | ConvertFrom-Json
    Write-Host ('Independent dump key recovery: {0}; algorithm: {1}; source-key-file-used: {2}' -f $crypto.KeyRecovered,$crypto.Algorithm,$crypto.ReferenceKeyFileUsed)
    Write-Host ('Recovered NEW copies: {0}/{1}; original SHA-256 matches: {2}; status: {3}' -f $crypto.WrittenFiles,$crypto.SelectedFiles,$crypto.OriginalHashVerifiedFiles,$crypto.Status)
    Write-Host ('crypto-recovery.json: {0}' -f $cryptoPath)
}else{Write-Host 'No independent crypto-recovery report: do not infer recovery from a successful dump.'}
if($r.PostFreezeContent){
    $changed=@($r.PostFreezeContent | Where-Object {$_.SampleChanged -eq $true})
    $renamed=@($r.PostFreezeContent | Where-Object {$_.Status -eq 'ComparedAfterVerifiedLabRename'})
    Write-Host ('Post-freeze sampled changes: {0}; verified lab rename correlations: {1}' -f $changed.Count,$renamed.Count)
}
if(Test-Path -LiteralPath $incidentPath){Write-Host ('incident.json: {0}' -f $incidentPath)}
Write-Host ('response.json: {0}' -f $responsePath)
Write-Host 'Do not upload process.dmp unless specifically needed; it may contain secrets.' -ForegroundColor Yellow
