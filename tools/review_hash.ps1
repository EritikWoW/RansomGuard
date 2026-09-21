param([Parameter(Mandatory=$true)][string]$Executable,
      [Parameter(Mandatory=$true)][ValidateSet('ReviewedTrusted','BlockedByAdministrator')][string]$Disposition,
      [Parameter(Mandatory=$true)][string]$Reason)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$exe=Join-Path $root 'RansomGuard.Service.exe'
try {
    if ([string]::IsNullOrWhiteSpace($Reason)) { throw 'An explicit review reason is required.' }
    $p=Get-Item -LiteralPath $Executable
    if ($p.PSIsContainer -or $p.Length -gt 512MB -or ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid executable file.' }
    # The native inspector also rejects reparse ancestors and returns fresh bytes + Authenticode evidence.
    $raw=& $exe --inspect $p.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Native image inspection failed.' }
    $entry=($raw -join [Environment]::NewLine)|ConvertFrom-Json
    if ($entry.Status -ne 'Hashed' -or $entry.Sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'No verified SHA-256. Review was not saved.' }
    $entry|Format-List
    Write-Host 'This is your explicit local review. It does not whitelist behavior or permit process termination.'
    if ((Read-Host "Type the full SHA-256 to record $Disposition") -ine $entry.Sha256) { throw 'Confirmation mismatch.' }
    $dir=Join-Path $env:ProgramData 'RansomGuardV03'
    $dest=Join-Path $dir 'trust-store.json'
    if ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe state directory.' }
    $items=@()
    if (Test-Path -LiteralPath $dest) {
        $file=Get-Item -LiteralPath $dest
        if ($file.Length -gt 256KB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe trust store.' }
        $items=@((Get-Content -LiteralPath $dest -Raw|ConvertFrom-Json)|Where-Object {$_.Sha256 -ine $entry.Sha256})
    }
    if ($items.Count -ge 1000) { throw 'Trust entry limit reached.' }
    $items+= [pscustomobject]@{Sha256=$entry.Sha256;Disposition=$Disposition;Reason=$Reason}
    $temp=Join-Path $dir ('trust-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temp,(ConvertTo-Json -InputObject @($items) -Depth 8),$utf8)
    if (Test-Path -LiteralPath $dest) {[IO.File]::Replace($temp,$dest,$null)} else {[IO.File]::Move($temp,$dest)}
    Write-Host 'Saved. No executable name/publisher blanket allowlist was added.'
} catch {Write-Error $_ -ErrorAction Continue;exit 1}
