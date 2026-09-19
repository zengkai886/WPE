param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ProjectRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
$contractPath = Join-Path $ProjectRoot 'contracts\rpc-status.json'
$csvPath = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'docs') -File -Filter '*.csv' |
    Select-Object -First 1 -ExpandProperty FullName
$mainPath = Join-Path $ProjectRoot 'src\shell\main.cpp'
$dataPath = Join-Path $ProjectRoot 'src\shell\data_service.cpp'

function Read-Required([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing RPC audit input: $Path" }
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$contract = Read-Required $contractPath | ConvertFrom-Json
$csv = @(Read-Required $csvPath | ConvertFrom-Csv)
$main = Read-Required $mainPath
$data = Read-Required $dataPath
$methods = @($contract.methods)
if ($contract.originalRpcCount -ne 217 -or $methods.Count -ne 217 -or $csv.Count -ne 217) {
    throw "RPC inventory must contain exactly 217 methods (contract=$($methods.Count), csv=$($csv.Count))"
}

$dataStart = $data.IndexOf('std::vector<std::string> DataService::Methods')
if ($dataStart -lt 0) { throw 'Cannot find DataService::Methods()' }
$dataEnd = $data.IndexOf('};', $dataStart)
if ($dataEnd -lt 0) { throw 'Cannot find end of DataService::Methods()' }
$dataMethods = @([regex]::Matches($data.Substring($dataStart, $dataEnd - $dataStart), '"([A-Za-z][A-Za-z0-9]*)"') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$hostMethods = @([regex]::Matches($main, 'Register(?:Async)?\s*\(\s*"([^"]+)"') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$sourceMethods = @($dataMethods + $hostMethods | Sort-Object -Unique)
$contractNames = @($methods | ForEach-Object method)

$duplicateContract = @($contractNames | Group-Object | Where-Object Count -gt 1)
if ($duplicateContract.Count -ne 0) { throw "Duplicate contract methods: $($duplicateContract.Name -join ', ')" }
$csvMethod = { param($row) @($row.PSObject.Properties)[0].Value }
$csvRegisteredValue = { param($row) @($row.PSObject.Properties)[2].Value }
$duplicateCsv = @($csv | ForEach-Object { & $csvMethod $_ } | Group-Object | Where-Object Count -gt 1)
if ($duplicateCsv.Count -ne 0) { throw "Duplicate CSV methods: $($duplicateCsv.Name -join ', ')" }
$csvNames = @($csv | ForEach-Object { & $csvMethod $_ })
$missingCsv = @($contractNames | Where-Object { $csvNames -notcontains $_ })
$extraCsv = @($csvNames | Where-Object { $contractNames -notcontains $_ })
if ($missingCsv.Count -or $extraCsv.Count) { throw "Contract/CSV method sets differ" }

$registered = @($methods | Where-Object registered | ForEach-Object method)
$unregistered = @($methods | Where-Object { -not $_.registered } | ForEach-Object method)
$sourceRegistered = @($sourceMethods | Where-Object { $contractNames -contains $_ })
$missingSource = @($registered | Where-Object { $sourceMethods -notcontains $_ })
$staleUnregistered = @($unregistered | Where-Object { $sourceMethods -contains $_ })
if ($missingSource.Count) { throw "Registered RPCs missing from source registration: $($missingSource -join ', ')" }
if ($staleUnregistered.Count) { throw "Source-registered RPCs still marked unregistered: $($staleUnregistered -join ', ')" }

$csvMismatch = @()
foreach ($item in $methods) {
    $row = @($csv | Where-Object { (& $csvMethod $_) -eq $item.method })
    if ($row.Count -ne 1) { throw "CSV row missing for $($item.method)" }
    $csvRegistered = (& $csvRegisteredValue $row[0]) -eq ([char]0x662f)
    if ($csvRegistered -ne [bool]$item.registered) { $csvMismatch += $item.method }
}
if ($csvMismatch.Count) { throw "Contract/CSV registration flags differ: $($csvMismatch -join ', ')" }

$expectedData = @($dataMethods | Where-Object { $contractNames -contains $_ }).Count
$expectedHostOnly = @($hostMethods | Where-Object { $contractNames -contains $_ -and $dataMethods -notcontains $_ }).Count
$expectedRegistered = $sourceRegistered.Count
$expectedUnregistered = 217 - $expectedRegistered
if ($contract.nativeDataRegistered -ne $expectedData -or
    $contract.nativeHostRegistered -ne $expectedHostOnly -or
    $contract.remainingUnregistered -ne $expectedUnregistered -or
    $registered.Count -ne $expectedRegistered) {
    throw "RPC summary counters are stale"
}

$unexpectedSource = @($sourceMethods | Where-Object { $contractNames -notcontains $_ -and $_ -notlike '__test*' })
$intentional = @($methods | Where-Object { -not $_.registered -and $sourceMethods -notcontains $_.method })
$result = [ordered]@{
    result = 'passed'
    originalRpcCount = 217
    contractRegistered = $registered.Count
    contractUnregistered = $unregistered.Count
    sourceDataMethods = $dataMethods.Count
    sourceHostMethods = $hostMethods.Count
    sourceRegisteredInOriginal = $sourceRegistered.Count
    nativeDataRegistered = $expectedData
    nativeHostRegistered = $expectedHostOnly
    remainingUnregistered = $expectedUnregistered
    intentionalNotImplemented = @($intentional | ForEach-Object method)
    sourceOnlyNonTest = $unexpectedSource
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Output "PASS: RPC inventory audit ($($registered.Count) registered, $($unregistered.Count) intentionally/unimplemented, data=$expectedData, host-only=$expectedHostOnly)."
