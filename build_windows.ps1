[CmdletBinding()]
param([switch]$IncludeLab)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logs = Join-Path $PSScriptRoot 'build-logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
Start-Transcript -Path (Join-Path $logs "build-$stamp.log") | Out-Null
function Run-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed, exit=${LASTEXITCODE}: $($Arguments -join ' ')" }
}
try {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Install .NET 10 SDK on the BUILD PC. Target PCs do not need a runtime.' }
    $version = (& dotnet --version).Trim()
    if ([int]($version.Split('.')[0]) -lt 10) { throw "SDK 10+ required. Found: $version" }
    $svc = 'src\RansomGuard.Service\RansomGuard.Service.csproj'
    $sim = 'src\RansomGuard.Simulator\RansomGuard.Simulator.csproj'
    $filterClient = 'src\RansomGuard.FilterClient\RansomGuard.FilterClient.csproj'
    $gateClient = 'src\RansomGuard.GateClient\RansomGuard.GateClient.csproj'
    $runtimeHarness = 'tests\RansomGuard.Minifilter.RuntimeHarness\RansomGuard.Minifilter.RuntimeHarness.csproj'
    $ui = 'src\RansomGuard.Ui\RansomGuard.Ui.csproj'
    $recovery = 'src\RansomGuard.RecoveryCli\RansomGuard.RecoveryCli.csproj'
    $rollbackRecovery = 'src\RansomGuard.RollbackRecoveryCli\RansomGuard.RollbackRecoveryCli.csproj'
    $rollbackMaintenance = 'src\RansomGuard.RollbackMaintenanceCli\RansomGuard.RollbackMaintenanceCli.csproj'
    $recoveryTests = 'tests\RansomGuard.Recovery.Tests\RansomGuard.Recovery.Tests.csproj'
    $tests = 'tests\RansomGuard.Tests\RansomGuard.Tests.csproj'
    $scopedTests = 'tests\RansomGuard.ScopedTrust.Tests\RansomGuard.ScopedTrust.Tests.csproj'
    $adminTests = 'tests\RansomGuard.Administration.Tests\RansomGuard.Administration.Tests.csproj'
    $localizationTests = 'tests\RansomGuard.Localization.Tests\RansomGuard.Localization.Tests.csproj'
    $rollbackTests = 'tests\RansomGuard.Rollback.Tests\RansomGuard.Rollback.Tests.csproj'
    $auditErrors = '-warnaserror:NU1900,NU1901,NU1902,NU1903,NU1904,NU1801'

    Write-Host '[0/6] Validate Windows manifests, scoped LAB minifilter gate, and READ-ONLY UI/API gate.'
    $manifestPath = Join-Path $PSScriptRoot 'src\RansomGuard.Service\app.manifest'
    $propsPath = Join-Path $PSScriptRoot 'Directory.Build.props'
    [xml]$manifestXml = Get-Content -LiteralPath $manifestPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($manifestXml.NameTable)
    $ns.AddNamespace('asmv1','urn:schemas-microsoft-com:asm.v1')
    $identity = $manifestXml.SelectSingleNode('/asmv1:assembly/asmv1:assemblyIdentity',$ns)
    if ($null -eq $identity) { throw 'Windows manifest is missing assemblyIdentity.' }
    $manifestVersion = [string]$identity.version
    if ($manifestVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Invalid Win32 assemblyIdentity version '$manifestVersion'. Windows Side-by-Side manifests require exactly four numeric components."
    }
    [xml]$propsXml = Get-Content -LiteralPath $propsPath -Raw
    $productVersion = [string]$propsXml.Project.PropertyGroup.Version
    if ([string]::IsNullOrWhiteSpace($productVersion)) { throw 'Directory.Build.props does not define Version.' }
    if ($manifestVersion -ne $productVersion) {
        throw "Version mismatch: app.manifest=$manifestVersion, Directory.Build.props=$productVersion."
    }
    Write-Host "Service manifest OK: $manifestVersion"
    $filterManifestPath = Join-Path $PSScriptRoot 'src\RansomGuard.FilterClient\app.manifest'
    [xml]$filterManifestXml = Get-Content -LiteralPath $filterManifestPath -Raw
    $filterNs = New-Object System.Xml.XmlNamespaceManager($filterManifestXml.NameTable)
    $filterNs.AddNamespace('asmv1','urn:schemas-microsoft-com:asm.v1')
    $filterIdentity = $filterManifestXml.SelectSingleNode('/asmv1:assembly/asmv1:assemblyIdentity',$filterNs)
    if ($null -eq $filterIdentity -or [string]$filterIdentity.version -ne $productVersion) { throw 'Filter client manifest version mismatch.' }
    Write-Host "Filter client manifest OK: $productVersion"
    $gateManifestPath = Join-Path $PSScriptRoot 'src\RansomGuard.GateClient\app.manifest'
    [xml]$gateManifestXml = Get-Content -LiteralPath $gateManifestPath -Raw
    $gateNs = New-Object System.Xml.XmlNamespaceManager($gateManifestXml.NameTable)
    $gateNs.AddNamespace('asmv1','urn:schemas-microsoft-com:asm.v1')
    $gateIdentity = $gateManifestXml.SelectSingleNode('/asmv1:assembly/asmv1:assemblyIdentity',$gateNs)
    if ($null -eq $gateIdentity -or [string]$gateIdentity.version -ne $productVersion) { throw 'Gate client manifest version mismatch.' }
    Write-Host "Gate client manifest OK: $productVersion"
    $uiManifestPath = Join-Path $PSScriptRoot 'src\RansomGuard.Ui\app.manifest'
    [xml]$uiManifestXml = Get-Content -LiteralPath $uiManifestPath -Raw
    $uiNs = New-Object System.Xml.XmlNamespaceManager($uiManifestXml.NameTable)
    $uiNs.AddNamespace('asmv1','urn:schemas-microsoft-com:asm.v1')
    $uiIdentity = $uiManifestXml.SelectSingleNode('/asmv1:assembly/asmv1:assemblyIdentity',$uiNs)
    if ($null -eq $uiIdentity -or [string]$uiIdentity.version -ne $productVersion) { throw 'UI manifest version mismatch.' }
    Write-Host "UI manifest OK: $productVersion"
    $serviceProjectText = Get-Content -LiteralPath (Join-Path $PSScriptRoot $svc) -Raw
    if ($serviceProjectText -match '<PackageReference\s+Include="System\.IO\.Pipes\.AccessControl"') {
        throw 'RansomGuard.Service must not explicitly reference System.IO.Pipes.AccessControl on .NET 10; it is supplied by the Windows target framework and explicit PackageReference triggers NU1510 under TreatWarningsAsErrors.'
    }
    Write-Host 'Service package gate OK: no redundant System.IO.Pipes.AccessControl PackageReference.'
    $localApiText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'src\RansomGuard.Core\LocalApi.cs') -Raw
    $etwMonitorText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'src\RansomGuard.Service\EtwMonitor.cs') -Raw
    if ($localApiText -notmatch 'int\?\s+EventsLost') {
        throw 'Telemetry contract gate FAILED: TelemetryDto.EventsLost must preserve the nullable ETW counter as int?.'
    }
    if ($etwMonitorText -notmatch 'int\?\s+EventsLost') {
        throw 'Telemetry contract gate FAILED: EtwMonitor.EventsLost no longer matches the nullable local API contract.'
    }
    Write-Host 'Telemetry type gate OK: nullable ETW EventsLost is preserved end-to-end.'
    $uiLocalApiClientText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'src\RansomGuard.Ui\LocalApiClient.cs') -Raw
    if ($uiLocalApiClientText -match '\b(StreamWriter|StreamReader|IOException)\b' -and $uiLocalApiClientText -notmatch '(?m)^using\s+System\.IO\s*;') {
        throw 'UI compile gate FAILED: LocalApiClient uses System.IO types but does not explicitly import System.IO.'
    }
    Write-Host 'UI compile gate OK: LocalApiClient explicitly imports System.IO for StreamReader/StreamWriter/IOException.'
    & (Join-Path $PSScriptRoot 'minifilter-tools\verify_minifilter_source.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_ui_readonly.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_ui_design.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_administration.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_localization.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_rollback.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_storage_budget.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_rollback_recovery.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_rollback_retention.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_gate_client.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_runtime_vm_harness.ps1')
    Write-Host '[1/6] Restore and execute policy/recovery/rollback tests (no process suspension in these tests).'
    Run-Dotnet -Arguments @('restore',$tests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$tests,'-c','Release','--no-restore')
    Run-Dotnet -Arguments @('restore',$recoveryTests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$recoveryTests,'-c','Release','--no-restore')
    Run-Dotnet -Arguments @('restore',$scopedTests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$scopedTests,'-c','Release','--no-restore')
    Run-Dotnet -Arguments @('restore',$adminTests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$adminTests,'-c','Release','--no-restore')
    Run-Dotnet -Arguments @('restore',$localizationTests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$localizationTests,'-c','Release','--no-restore')
    Run-Dotnet -Arguments @('restore',$rollbackTests,$auditErrors)
    Run-Dotnet -Arguments @('run','--project',$rollbackTests,'-c','Release','--no-restore')
    & (Join-Path $PSScriptRoot 'tools\verify_scoped_trust.ps1')
    & (Join-Path $PSScriptRoot 'tools\verify_recovery_boundary.ps1')
    Write-Host '[2/6] Restore Windows projects. Known package vulnerabilities/audit failures block this build.'
    $projects=@($svc,$ui,$recovery)
    if($IncludeLab){$projects+=@($sim,$filterClient,$gateClient,$runtimeHarness,$rollbackRecovery,$rollbackMaintenance)}
    foreach ($project in $projects) {
        Run-Dotnet -Arguments @('restore',$project,'-r','win-x64','-p:SelfContained=true',$auditErrors)
    }
    $auditPath = Join-Path $logs "dependencies-$stamp.json"
    $json = & dotnet list $svc package --include-transitive --vulnerable --format json
    if ($LASTEXITCODE -ne 0) { throw 'Package vulnerability audit failed. Do not bypass it for deployment.' }
    $json | Set-Content -LiteralPath $auditPath -Encoding UTF8
    $audit = ($json -join [Environment]::NewLine) | ConvertFrom-Json
    foreach ($entry in @($audit.logs)) {
        if ($entry.level -match 'error|warning') { throw "Dependency audit incomplete: $($entry.message)" }
    }
    foreach ($project in @($audit.projects)) {
        foreach ($framework in @($project.frameworks)) {
            foreach ($package in (@($framework.topLevelPackages)+@($framework.transitivePackages))) {
                if ($null -ne $package -and @($package.vulnerabilities).Where({$null -ne $_}).Count -gt 0) {
                    throw "Known vulnerable dependency: $($package.id). Review $auditPath"
                }
            }
        }
    }
    Write-Host '[3/6] Publish self-contained AUDIT console (no driver/simulator in the normal bundle).'
    $release = Join-Path $PSScriptRoot ("release\RansomGuard-v{0}-{1}" -f $productVersion,$stamp)
    New-Item -ItemType Directory -Path $release | Out-Null
    # Debug symbols remain in obj/bin for developers; they are not in user-facing packages.
    $publishFlags=@('-c','Release','-r','win-x64','--self-contained','true','--no-restore','-p:CopyOutputSymbolsToPublishDirectory=false')
    Run-Dotnet -Arguments (@('publish',$svc)+$publishFlags+@('-o',$release))
    $uiDir=Join-Path $release 'UI'
    New-Item -ItemType Directory -Path $uiDir | Out-Null
    # Embed the exact published service identity in the UI, not in an editable sidecar manifest.
    $pairedServiceHash=(Get-FileHash -LiteralPath (Join-Path $release 'RansomGuard.Service.exe') -Algorithm SHA256).Hash
    Run-Dotnet -Arguments (@('publish',$ui)+$publishFlags+@('-o',$uiDir,('-p:RansomGuardServiceHash='+$pairedServiceHash)))
    $recoveryDir=Join-Path $release 'Recovery'
    New-Item -ItemType Directory -Path $recoveryDir | Out-Null
    Run-Dotnet -Arguments (@('publish',$recovery)+$publishFlags+@('-o',$recoveryDir))
    foreach($file in @('launch_ui.cmd','run_audit.cmd','status_instances.cmd','diagnose_etw.cmd','recover_from_dump.cmd')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $release
    }
    $runtimeTools=Join-Path $release 'tools'
    New-Item -ItemType Directory -Path $runtimeTools | Out-Null
    foreach($file in @('launch.ps1','status_instances.ps1','diagnose_etw.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('tools\'+$file)) -Destination $runtimeTools
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\AUDIT_QUICKSTART.txt') -Destination (Join-Path $release 'START_HERE.txt')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\RECOVERY_AND_LIVE.md') -Destination $release
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\SCOPED_TRUST.md') -Destination $release
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\UI_ADMINISTRATION.md') -Destination $release
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\LOCALIZATION_AND_STATE_RECOVERY.md') -Destination $release
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\GUIDED_SETUP.md') -Destination $release
    Copy-Item -LiteralPath $auditPath -Destination (Join-Path $release 'dependency-audit.json')
    # Preserve a lab-ready engineering package separately, only when requested.
    $labRelease=$null
    if($IncludeLab){
        $labRelease=Join-Path $PSScriptRoot ("release\RansomGuard-Lab-v{0}-{1}" -f $productVersion,$stamp)
        New-Item -ItemType Directory -Path $labRelease | Out-Null
        Get-ChildItem -LiteralPath $release -Force | Copy-Item -Destination $labRelease -Recurse
        $simDir=Join-Path $labRelease 'Simulator'
        $clientDir=Join-Path $labRelease 'MinifilterLab\Client'
        $gateClientDir=Join-Path $labRelease 'MinifilterLab\GateClient'
        $runtimeHarnessDir=Join-Path $labRelease 'MinifilterLab\RuntimeHarness'
        $rollbackRecoveryDir=Join-Path $labRelease 'RollbackRecovery'
        $rollbackMaintenanceDir=Join-Path $labRelease 'RollbackMaintenance'
        New-Item -ItemType Directory -Path $simDir,$clientDir,$gateClientDir,$runtimeHarnessDir,$rollbackRecoveryDir,$rollbackMaintenanceDir -Force | Out-Null
        Run-Dotnet -Arguments (@('publish',$sim)+$publishFlags+@('-o',$simDir))
        Run-Dotnet -Arguments (@('publish',$filterClient)+$publishFlags+@('-o',$clientDir))
        Run-Dotnet -Arguments (@('publish',$gateClient)+$publishFlags+@('-o',$gateClientDir))
        Run-Dotnet -Arguments (@('publish',$runtimeHarness)+$publishFlags+@('-o',$runtimeHarnessDir))
        Run-Dotnet -Arguments (@('publish',$rollbackRecovery)+$publishFlags+@('-o',$rollbackRecoveryDir))
        Run-Dotnet -Arguments (@('publish',$rollbackMaintenance)+$publishFlags+@('-o',$rollbackMaintenanceDir))
        $simHash=(Get-FileHash -LiteralPath (Join-Path $simDir 'RansomGuard.Simulator.exe') -Algorithm SHA256).Hash
        [IO.File]::WriteAllText((Join-Path $simDir 'simulator.sha256'),$simHash,[Text.Encoding]::ASCII)
        foreach($file in @('test_lab.cmd','test_lab_full_dump.cmd','native_selftest.cmd','install_service.cmd','uninstall_service.cmd','summarize_last_lab.cmd','inspect_state_acl.cmd','repair_state_store.cmd','build_minifilter.cmd','verify_minifilter_source.cmd','install_minifilter_lab.cmd','unload_minifilter_lab.cmd','minifilter_status.cmd','run_minifilter_audit.cmd','run_minifilter_gate_lab.cmd','rollback_recovery.cmd','rollback_maintenance.cmd','preview_ui.cmd','ui_smoketest.cmd')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $labRelease
        }
        # Copy only tools with a corresponding command; no build/design scripts in runtime packages.
        foreach($file in @('test_ui.ps1','inspect_state_acl.ps1','repair_state_store.ps1','summarize_last_lab.ps1','recover_lab.ps1','install_service.ps1','uninstall_service.ps1','review_hash.ps1','check_windows_security.ps1')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('tools\'+$file)) -Destination (Join-Path $labRelease 'tools')
        }
        $mfSource=Join-Path $labRelease 'MinifilterLab\Source'
        New-Item -ItemType Directory -Path $mfSource -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'driver') -Destination $mfSource -Recurse
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'native') -Destination $mfSource -Recurse
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'minifilter-tools') -Destination $labRelease -Recurse
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs\LAB_QUICKSTART.txt') -Destination (Join-Path $labRelease 'START_HERE.txt') -Force
        $labDocs=Join-Path $labRelease 'docs'
        New-Item -ItemType Directory -Path $labDocs -Force | Out-Null
        foreach($file in @('MINIFILTER_LAB.md','ROLLBACK_ARCHITECTURE.md','ROLLBACK_RECOVERY.md','PRODUCT_TARGET.md','SECURITY.md','TESTING.md')){
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('docs\'+$file)) -Destination $labDocs
        }
    }
    Write-Host '[4/6] Validate published package boundaries and installation image version.'
    $uiExe=Join-Path $uiDir 'RansomGuard.Ui.exe'
    foreach($exe in @($uiExe,(Join-Path $release 'RansomGuard.Service.exe'))){
        if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw "Missing executable: $exe"}
    }
    $installedImageVersion=(Get-Item -LiteralPath (Join-Path $release 'RansomGuard.Service.exe')).VersionInfo.FileVersion
    if($installedImageVersion -ne $productVersion){throw "Published service FileVersion '$installedImageVersion' does not match '$productVersion'; UI installation would refuse it."}
    # Publish may emit symbols from project references: remove symbols only in NEW build outputs.
    foreach($bundle in @($release,$labRelease)){
        if([string]::IsNullOrWhiteSpace($bundle)){continue}
        Get-ChildItem -LiteralPath $bundle -File -Recurse -Filter *.pdb | Remove-Item
    }
    $unexpected=@(Get-ChildItem -LiteralPath $release -File -Recurse | Where-Object {
        $_.Extension -in @('.sys','.cat','.inf','.dmp','.pdb','.cs','.xaml','.svg') -or
        $_.Name -like '*Simulator*' -or $_.Name -like '*FilterClient*' -or $_.Name -like '*GateClient*' -or
        $_.Name -like '*RuntimeHarness*' -or $_.Name -like '*RollbackRecovery*' -or $_.Name -like '*RollbackMaintenance*'
    })
    if($unexpected.Count -gt 0){throw 'Audit bundle contains engineering-only files.'}
    Write-Host '[5/6] Run synthetic WPF rendering test, including all four activity icons.'
    & (Join-Path $PSScriptRoot 'tools\test_ui.ps1') -Exe $uiExe -OutputDirectory (Join-Path $logs "ui-$stamp")
    & (Join-Path $PSScriptRoot 'tools\verify_ui_readonly.ps1')
    # No bundle is zipped before the actual WPF test succeeds.
    Write-Host '[6/6] Write manifests and package validated outputs.'
    foreach($bundle in @($release,$labRelease)){
        if([string]::IsNullOrWhiteSpace($bundle)){continue}
        $isLab=$bundle -eq $labRelease
        $state=[ordered]@{schema=1;version=$productVersion;profile=$(if($isLab){'EngineeringLab'}else{'AuditConsole'});ordinaryApps='AuditOnly';uiTransport='PushFramedPipeV2';recovery='OfflineRGTEST03';rollback='VerifiedRecoveryRetentionAndStorageBudgetLab';scopedTrust='ExactHashContextAuditOnly';uiAdministration='SameExeUacOwnServiceAndReviewedRules';driverInstalledByBuild=$false;kernelWriteGateActive=$false;labKernelGateAvailable=$isLab;labKernelGate='ExplicitSingleRootRangeCowAndFullMetadataPreimage';uiTestPassed=$true}
        $state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $bundle 'BUILD_STATUS.json') -Encoding UTF8
        $hashes=Get-ChildItem -LiteralPath $bundle -File -Recurse | Sort-Object FullName | ForEach-Object {
            '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash,$_.FullName.Substring($bundle.Length+1)
        }
        $hashes | Set-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS.txt') -Encoding UTF8
        Compress-Archive -Path (Join-Path $bundle '*') -DestinationPath "$bundle.zip"
        Write-Host "BUILD PASSED: $bundle.zip"
    }
    # Log resolved dependencies beside logs, not scattered through the deployment folder.
    $lockDir=Join-Path $logs "locks-$stamp"
    New-Item -ItemType Directory -Path $lockDir -Force | Out-Null
    foreach($project in $projects){
        $projectDir=Split-Path -Parent (Join-Path $PSScriptRoot $project)
        $lock=Join-Path $projectDir 'packages.lock.json'
        if(Test-Path -LiteralPath $lock){Copy-Item -LiteralPath $lock -Destination (Join-Path $lockDir ((Split-Path $projectDir -Leaf)+'.packages.lock.json'))}
    }
    Write-Host "WPF activity-card screenshots: $logs\ui-$stamp\Dark-activity-card.png / Light-activity-card.png"
    Write-Host 'Normal bundle: UI + AUDIT engine + durable rollback foundations. No driver. It DOES NOT yet block ransomware or capture pre-images automatically.'
    Write-Host 'No old release, user configuration, incident, backup or installed driver was removed.'
    exit 0
}
catch { Write-Error $_ -ErrorAction Continue; exit 1 }
finally { Stop-Transcript | Out-Null }
