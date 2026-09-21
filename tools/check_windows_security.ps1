# Read-only: never disables Defender, tamper protection, controlled folder access or other security controls.
$ErrorActionPreference='Stop'
try {
    $s=Get-MpComputerStatus
    $p=Get-MpPreference
    [pscustomobject]@{
        AntivirusEnabled=$s.AntivirusEnabled
        RealTimeProtection=$s.RealTimeProtectionEnabled
        BehaviorMonitor=$s.BehaviorMonitorEnabled
        TamperProtected=$s.IsTamperProtected
        AntivirusSignatureLastUpdated=$s.AntivirusSignatureLastUpdated
        ControlledFolderAccess=$p.EnableControlledFolderAccess
        Note='CFA commonly uses 0=Disabled,1=Enabled,2=AuditMode. Review Windows Security; this script changes nothing.'
    } | Format-List
} catch { Write-Warning ('Defender status unavailable (not proof that it is disabled): '+$_.Exception.Message) }
