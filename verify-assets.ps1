$ErrorActionPreference='Stop'
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contracts\preserved-assets.json') -Raw | ConvertFrom-Json
foreach($file in $manifest.files){
    $path=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot $file.path))
    if(-not $path.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Asset path escaped project'}
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing asset: $($file.path)"}
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256){throw "Changed asset: $($file.path)"}
}
$actual=@(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'frontend'),(Join-Path $PSScriptRoot 'wwwroot'),(Join-Path $PSScriptRoot 'remote-web') -Recurse -File -Force |
    Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' })
if($actual.Count -ne $manifest.files.Count){throw "Asset inventory count mismatch: $($actual.Count) vs $($manifest.files.Count)"}
Write-Output "PASS: $($manifest.files.Count) original assets preserved; $($manifest.vueFiles) Vue files."
