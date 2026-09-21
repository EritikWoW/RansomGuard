[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$ui=Join-Path $root 'src\RansomGuard.Ui'
$catalogs=@{}
foreach($locale in @('uk-UA','en-US')) {
    $path=Join-Path $ui ('Localization\'+$locale+'.json')
    $catalog=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $keys=@($catalog.PSObject.Properties.Name | Sort-Object)
    if($keys.Count -lt 350){throw "Incomplete language resource: $locale"}
    foreach($p in $catalog.PSObject.Properties){if([string]::IsNullOrWhiteSpace([string]$p.Value)){throw "Empty $locale translation: $($p.Name)"}}
    $catalogs[$locale]=$keys
}
if(@(Compare-Object $catalogs['uk-UA'] $catalogs['en-US']).Count -ne 0){throw 'Locale key sets differ.'}
[xml]$window=Get-Content -LiteralPath (Join-Path $ui 'MainWindow.xaml') -Raw -Encoding UTF8
$ns=New-Object System.Xml.XmlNamespaceManager($window.NameTable)
$ns.AddNamespace('x','http://schemas.microsoft.com/winfx/2006/xaml')
$selector=$window.SelectSingleNode('//*[@x:Name="LanguageSelector"]',$ns)
$settings=$window.SelectSingleNode('//*[@x:Name="SettingsPage"]',$ns)
if($null -eq $selector -or $null -eq $settings){throw 'Missing language selector.'}
$inside=$false;$node=$selector
while($null -ne $node){if([object]::ReferenceEquals($node,$settings)){$inside=$true;break};$node=$node.ParentNode}
if(-not$inside){throw 'Language selector must remain in Settings.'}
foreach($file in Get-ChildItem -LiteralPath $ui -Recurse -File -Filter '*.xaml' | Where-Object {$_.FullName -notmatch '\\(obj|bin)\\'}) {
    [xml]$xaml=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    foreach($a in $xaml.SelectNodes('//@*')) {
        if($a.Value -match '[\u0400-\u04ff]'){throw "Hardcoded Cyrillic XAML text: $($file.Name) / $($a.Name)"}
    }
}
$text=(Get-ChildItem -LiteralPath $ui -Recurse -File | Where-Object {$_.Extension -in '.cs','.xaml' -and $_.FullName -notmatch '\\(obj|bin)\\'} | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8}) -join "`n"
foreach($match in [regex]::Matches($text,'(?:L\.[TF]\("|\{loc:Loc\s+)([A-Za-z0-9_.]+)')) {
    if($match.Groups[1].Value -notin $catalogs['en-US']) {throw "Missing localization key: $($match.Groups[1].Value)"}
}
$launch=Get-Content -LiteralPath (Join-Path $ui 'Administration\AdminLauncher.cs') -Raw -Encoding UTF8
if(-not$launch.Contains('L.Supported(language)') -or -not$launch.Contains('info.ArgumentList.Add(language)')){throw 'UAC language forwarding must validate its closed locale list.'}
$recovery=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Management\StateStoreAdministration.cs') -Raw
foreach($required in @('DemandAdministrator','CheckConfirmation("state-repair"','expectedRevision','StateMaintenanceGate.Acquire()','EnsureIdle()','SetFileInformationByHandle','HardenLegacyRootAcl','TrustedMarkerName','SetSecurityInfo','MoveFileExW','new SecureStore()')) {
    if(-not$recovery.Contains($required)){throw "Missing state recovery invariant: $required"}
}
if($recovery -match 'Directory\.Delete|File\.Delete|SetAccessControl|Process\.Kill|Set-MpPreference|EnumerateFiles|EnumerateDirectories|GetFiles\(|GetDirectories\(') {throw 'State recovery must not delete/recursively rewrite legacy content or control other processes.'}
$secureStore=Get-Content -LiteralPath (Join-Path $root 'src\RansomGuard.Service\SecureStore.cs') -Raw
foreach($required in @('.ransomguard-state-v1','Existing state directory has no trusted generation marker','FileMode.CreateNew')) {
    if(-not$secureStore.Contains($required)){throw "Missing trusted state-generation invariant: $required"}
}
Write-Host "Localization gate PASSED: Ukrainian / English, $($catalogs['uk-UA'].Count) matching keys, Settings-only language selector."
Write-Host 'State recovery source gate PASSED: explicit UAC confirmation, fixed root, idle check, root-only ACL hardening, handle rename with bounded compatibility fallback, no import/deletion/recursive ACL rewrite.'
Write-Host 'Resource C# tests and bilingual WPF smoke rendering must still run; source checks alone are not a Windows recovery test.'
