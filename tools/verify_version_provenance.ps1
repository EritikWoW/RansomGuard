$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$props=Join-Path $root 'Directory.Build.props'
$productInfo=Join-Path $root 'src\RansomGuard.Core\ProductInfo.cs'
$worker=Join-Path $root 'src\RansomGuard.Service\GuardWorker.cs'
$filterClient=Join-Path $root 'src\RansomGuard.FilterClient\Program.cs'
$gateClient=Join-Path $root 'src\RansomGuard.GateClient\Program.cs'

foreach($path in @($props,$productInfo,$worker,$filterClient,$gateClient)){
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Version provenance source missing: $path"}
}

$propsText=Get-Content -LiteralPath $props -Raw
$productText=Get-Content -LiteralPath $productInfo -Raw
$workerText=Get-Content -LiteralPath $worker -Raw
$filterClientText=Get-Content -LiteralPath $filterClient -Raw
$gateClientText=Get-Content -LiteralPath $gateClient -Raw

if($propsText -notmatch '<Version>\d+\.\d+\.\d+\.\d+</Version>'){
    throw 'Directory.Build.props must define the canonical four-part product version.'
}

foreach($required in @(
    'Assembly.GetEntryAssembly()',
    'AssemblyInformationalVersionAttribute',
    'InformationalVersion',
    "informational.IndexOf('+')",
    'assembly.GetName().Version'
)){
    if($productText -notmatch [regex]::Escape($required)){
        throw "ProductInfo version provenance invariant missing: $required"
    }
}

$uses=([regex]::Matches($workerText,[regex]::Escape('ProductInfo.Version'))).Count
if($uses -lt 3){
    throw "GuardWorker must use ProductInfo.Version for startup log, startup audit and incident evidence; found $uses uses."
}

foreach($forbidden in @(
    'RansomGuard v0.',
    'Version="0.',
    'Version = "0.'
)){
    if($workerText -match [regex]::Escape($forbidden)){
        throw "GuardWorker contains a manual runtime version literal: $forbidden"
    }
}

if($workerText -match '(?i)Version\s*=\s*"\d+\.\d+\.\d+\.\d+"'){
    throw 'GuardWorker must not persist a hard-coded product version.'
}

foreach($entry in @(
    @('FilterClient',$filterClientText,'RansomGuard Minifilter AUDIT client v'),
    @('GateClient',$gateClientText,'RansomGuard LAB pre-write gate v')
)){
    $name=[string]$entry[0]
    $text=[string]$entry[1]
    $prefix=[string]$entry[2]
    if($text -notmatch [regex]::Escape('Assembly.GetEntryAssembly()') -or
       $text -notmatch [regex]::Escape('.GetName().Version')){
        throw "$name must derive its display version from assembly metadata."
    }
    if($text -match ([regex]::Escape($prefix) + '\d+\.\d+\.\d+\.\d+')){
        throw "$name contains a hard-coded display version."
    }
}

Write-Host 'Version provenance source gate PASSED: service evidence and native clients derive product version from assembly metadata.'
