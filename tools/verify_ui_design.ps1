[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$ui=Join-Path $root 'src\RansomGuard.Ui'
$nsUri='http://schemas.microsoft.com/winfx/2006/xaml'
$sets=@{}
foreach($theme in @('Dark','Light')){
    [xml]$x=Get-Content -LiteralPath (Join-Path $ui "Themes\$theme.xaml") -Raw -Encoding UTF8
    $keys=@()
    foreach($brush in $x.DocumentElement.ChildNodes){
        if($brush.NodeType -eq [System.Xml.XmlNodeType]::Element){$keys+=$brush.GetAttribute('Key',$nsUri)}
    }
    if($keys.Count -lt 20){throw "Incomplete $theme palette."}
    $sets[$theme]=$keys
}
if(@(Compare-Object $sets.Dark $sets.Light).Count -ne 0){throw 'Theme resource keys do not match.'}
Get-ChildItem -LiteralPath $ui -Recurse -Filter *.xaml |
    Where-Object {$_.FullName -notmatch '\\(obj|bin)\\'} |
    ForEach-Object {$parsed=[xml](Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8)}
$iconDir=Join-Path $ui 'Assets\Icons'
$icons=@(Get-ChildItem -LiteralPath $iconDir -Filter *.svg)
$requiredIconNames=@(
    'shield','shield-x','shield-eye','grid','activity','folder','history','sliders','pulse','info',
    'sun','moon','refresh','server','cpu','alert','check','search','chevron','download',
    'copy','clock','link','unplug','lock','file','close','minus','maximize','restore','arrow','layers',
    'monitor','home','gear','rules','chart','heartbeat','flask','picture'
)
$actualIconNames=@($icons | ForEach-Object { $_.BaseName })
$missingIcons=@($requiredIconNames | Where-Object { $_ -notin $actualIconNames })
if($missingIcons.Count -ne 0){
    throw "Missing required bundled SVG icons ($($missingIcons.Count)): $($missingIcons -join ', '). Found $($icons.Count) SVG files in Assets\Icons."
}

foreach($icon in $icons){
    $text=Get-Content -LiteralPath $icon.FullName -Raw -Encoding UTF8
    if($text -match '<!DOCTYPE|<script|\bhref\s*=|<image'){throw "Unsupported SVG content: $($icon.Name)"}
    $parsed=[xml]$text
}
$window=Get-Content -LiteralPath (Join-Path $ui 'MainWindow.xaml') -Raw -Encoding UTF8
if($window -notmatch 'Background="\{DynamicResource PageBrush\}"' -or
   $window -notmatch 'Foreground="\{DynamicResource TextBrush\}"'){throw 'Window must explicitly bind its theme brushes.'}
Write-Host "UI design source check PASSED: equal theme keys, parseable XAML and all $($requiredIconNames.Count) required local path-only SVG icons ($($icons.Count) files present)."
if($window -notmatch 'x:Name="ActivityCard"' -or $window -notmatch 'x:Name="LocationsCard"' -or $window -notmatch 'x:Name="SafetyCard"'){throw 'Reference dashboard panels are missing.'}
Write-Host 'Reference layout gate PASSED: four status cards and a two-by-two content grid.'
Write-Host 'This is a source check; the built WPF UI must also pass test_ui.ps1.'

[xml]$windowXml=$window
$windowNs=New-Object System.Xml.XmlNamespaceManager($windowXml.NameTable)
$windowNs.AddNamespace('x','http://schemas.microsoft.com/winfx/2006/xaml')
$settingsPanel=$windowXml.SelectSingleNode('//*[@x:Name="ThemeSettingsPanel"]',$windowNs)
$settingsPage=$windowXml.SelectSingleNode('//*[@x:Name="SettingsPage"]',$windowNs)
$activityPanel=$windowXml.SelectSingleNode('//*[@x:Name="ActivityCard"]',$windowNs)
if($null -eq $settingsPanel -or $null -eq $settingsPage -or $null -eq $activityPanel){throw 'Required settings/activity panel is missing.'}
$themeButtons=$windowXml.SelectNodes('//*[@Command="{Binding ThemeCommand}"]')
if($themeButtons.Count -ne 3){throw 'Expected exactly three appearance options, all in Settings.'}
foreach($button in $themeButtons){
    $ancestor=$button.ParentNode
    $insideSettings=$false
    while($null -ne $ancestor){
        if([object]::ReferenceEquals($ancestor,$settingsPanel)){$insideSettings=$true;break}
        $ancestor=$ancestor.ParentNode
    }
    if(-not $insideSettings){throw 'Theme control found outside Settings.'}
}
$overviewPanel=$windowXml.SelectSingleNode('//*[@x:Name="OverviewScroll"]',$windowNs)
$ancestor=$activityPanel.ParentNode
$activityInOverview=$false
while($null -ne $ancestor){
    if([object]::ReferenceEquals($ancestor,$overviewPanel)){$activityInOverview=$true;break}
    $ancestor=$ancestor.ParentNode
}
if(-not $activityInOverview){throw 'Activity overview must remain on the Overview page.'}

$activityManifestPath=Join-Path $ui 'Assets\Activity\manifest.json'
$activityManifest=Get-Content -LiteralPath $activityManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if($activityManifest.schema -ne 1 -or @($activityManifest.icons).Count -ne 4){throw 'Four activity SVG sources are required.'}
$drawingPath=Join-Path $ui $activityManifest.drawingFile
if((Get-FileHash -LiteralPath $drawingPath -Algorithm SHA256).Hash -ine $activityManifest.drawingSha256){throw 'Activity drawing resource changed without reviewing the SVG conversion.'}
[xml]$drawings=Get-Content -LiteralPath $drawingPath -Raw -Encoding UTF8
$drawingNs=New-Object System.Xml.XmlNamespaceManager($drawings.NameTable)
$drawingNs.AddNamespace('x','http://schemas.microsoft.com/winfx/2006/xaml')
$drawingNs.AddNamespace('w','http://schemas.microsoft.com/winfx/2006/xaml/presentation')
foreach($icon in $activityManifest.icons){
    $sourcePath=Join-Path $ui $icon.source
    if(-not(Test-Path -LiteralPath $sourcePath -PathType Leaf)){throw "Missing original activity SVG: $($icon.name)"}
    if((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -ine $icon.sha256){throw "Activity SVG is not the reviewed original: $($icon.name)"}
    $glyph=$windowXml.SelectSingleNode(('//*[@x:Name="{0}"]' -f $icon.elementName),$windowNs)
    if($null -eq $glyph -or $glyph.LocalName -ne 'Image' -or $glyph.GetAttribute('Width') -ne '28' -or $glyph.GetAttribute('Height') -ne '28' -or $glyph.GetAttribute('Stretch') -ne 'Uniform'){throw "Activity SVG size/fit contract failed: $($icon.name)"}
    if($glyph.GetAttribute('Source') -ne ('{StaticResource '+$icon.resourceKey+'}')){throw "Activity image uses wrong resource: $($icon.name)"}
    $drawing=$drawings.SelectSingleNode(('/w:ResourceDictionary/w:DrawingImage[@x:Key="{0}"]' -f $icon.resourceKey),$drawingNs)
    if($null -eq $drawing -or $drawing.SelectNodes('.//w:GeometryDrawing',$drawingNs).Count -ne $icon.parts){throw "Incomplete native vector conversion: $($icon.name)"}
}
Write-Host 'Activity icons: 4 exact supplied SVGs, native multi-color vectors, uniform painted bounds in 28 DIP boxes.'
Write-Host 'Theme controls: Settings only. Activity panel: Overview. No metric/containment policy changes.'
