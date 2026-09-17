$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
$script=Join-Path $project 'build-test.ps1'
$unused=Join-Path (Split-Path $project -Parent) ('must-not-create-'+[Guid]::NewGuid().ToString('N'))
$checks=0
foreach($case in @(
    @{BuildRoot=$unused;Architecture=@()},
    @{BuildRoot=$unused;Architecture=@('x64','x64')},
    @{BuildRoot=$project;Architecture=@('x64')},
    @{BuildRoot=(Join-Path $project '.build');Architecture=@('Win32')}
)){
    $rejected=$false
    try { & $script @case } catch { $rejected=$true }
    if(-not $rejected){throw 'Invalid build request was accepted'}
    ++$checks
}
if(Test-Path -LiteralPath $unused){throw 'Validation created output before rejecting arguments'}
Write-Output "PASS: $checks invalid build argument cases rejected before creating outputs."
