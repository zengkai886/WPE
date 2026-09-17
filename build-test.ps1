param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BuildRoot,
    [ValidateNotNullOrEmpty()][ValidateCount(1,2)][ValidateSet('x64','Win32')][string[]]$Architecture = @('x64','Win32')
)
$ErrorActionPreference='Stop'
$BuildRoot=[IO.Path]::GetFullPath($BuildRoot)
$sourceRoot=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
if($BuildRoot.TrimEnd('\').Equals($sourceRoot,[StringComparison]::OrdinalIgnoreCase) -or $BuildRoot.StartsWith($sourceRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'BuildRoot must be outside the source tree'
}
if(@($Architecture | Sort-Object -Unique).Count -ne $Architecture.Count){throw 'Architecture entries must be unique'}
$run=Join-Path $BuildRoot ('run-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run -Force | Out-Null
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Run([string]$Executable,[string[]]$Arguments,[string]$Log) {
    $lines=& $Executable @Arguments 2>&1
    $code=$LASTEXITCODE
    $lines | Set-Content -LiteralPath $Log -Encoding utf8
    $lines | ForEach-Object { Write-Output "$_" }
    if($code -ne 0){ throw "$Executable failed ($code); see $Log" }
}
$manifest=[ordered]@{
    schemaVersion=1
    testId='CPP-COMMON-PARITY-001'
    specificationSections=@('0','2.3','3.1','3.2','4.2','4.4','13.1')
    scope='C++ common codecs only; no native pipe transport, injection, hooks, full snapshots or GUI acceptance'
    startedUtc=[DateTime]::UtcNow.ToString('o')
    finishedUtc=$null
    result='running'
    runDirectory=$run
    command="$PSCommandPath -BuildRoot $BuildRoot -Architecture $($Architecture -join ',')"
    architectures=@()
    cleanup='Synchronous test processes only. No injection, target hooks, certificates, system proxy, sockets or database changes. Build files retained.'
}
try {
    $lock=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contracts\oracle-source.json') -Raw | ConvertFrom-Json
    foreach($file in $lock.files){
        $path=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot $file.path))
        if(-not $path.StartsWith($PSScriptRoot+'\',[StringComparison]::OrdinalIgnoreCase)){ throw 'Oracle source escaped project' }
        if((Hash $path) -ne $file.sha256){ throw "Original reference source changed: $($file.path)" }
    }
    $manifest.sourceArchiveSha256=$lock.sourceArchiveSha256
    $spec=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contracts\active-spec.json') -Raw | ConvertFrom-Json
    if((Hash (Join-Path $PSScriptRoot $spec.activeSpec)) -ne $spec.sha256){throw 'Active user spec hash mismatch'}
    $manifest.specification=$spec
    $files=@(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src'),(Join-Path $PSScriptRoot 'tests') -File -Recurse | Where-Object {$_.Extension -in '.cpp','.h','.cs','.csproj' -and $_.FullName -notmatch '[\\/](obj|bin)[\\/]'})
    $files+=Get-Item -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'CMakeLists.txt'),(Join-Path $PSScriptRoot 'contracts\oracle-source.json'),(Join-Path $PSScriptRoot 'contracts\active-spec.json')
    $manifest.sourceFiles=@($files | Sort-Object FullName | ForEach-Object {[ordered]@{path=$_.FullName.Substring($PSScriptRoot.Length+1);sha256=(Hash $_.FullName)}})
    $revision=& git -C $PSScriptRoot rev-parse HEAD
    if($LASTEXITCODE -ne 0){throw 'Cannot read Git revision'}
    $changes=& git -C $PSScriptRoot status --porcelain
    if($LASTEXITCODE -ne 0){throw 'Cannot read Git worktree'}
    $manifest.git=[ordered]@{commit="$revision";dirty=(@($changes).Count -gt 0)}
    $manifest.environment=[ordered]@{os=[Environment]::OSVersion.VersionString;powershell=$PSVersionTable.PSVersion.ToString();cmake=(& cmake --version | Select-Object -First 1);dotnetSdk=(& dotnet --version)}
    $oracle=Join-Path $run 'oracle'
    $obj=Join-Path $run 'oracle-obj'
    Run 'dotnet' @('build',(Join-Path $PSScriptRoot 'tests\oracle\Oracle.csproj'),'-c','Release','-o',$oracle,"-p:BaseIntermediateOutputPath=$obj\",'--nologo','--verbosity','minimal') (Join-Path $run 'oracle-build.log')
    $oracleExe=Join-Path $oracle 'WpeProtocolOracle.exe'
    $vectors=Join-Path $run 'vectors.tsv'
    Run $oracleExe @('generate',$vectors) (Join-Path $run 'oracle-generate.log')
    $manifest.oracleRuntime=Get-Content -LiteralPath (Join-Path $run 'oracle-generate.log')
    $manifest.fixtures=[ordered]@{sha256=(Hash $vectors);rows=(Get-Content -LiteralPath $vectors).Count}
    foreach($arch in $Architecture){
        $build=Join-Path $run $arch
        Run 'cmake' @('-S',$PSScriptRoot,'-B',$build,'-G','Visual Studio 17 2022','-A',$arch) (Join-Path $run "$arch-configure.log")
        Run 'cmake' @('--build',$build,'--config','Release','--parallel','2') (Join-Path $run "$arch-build.log")
        Run 'ctest' @('--test-dir',$build,'-C','Release','--output-on-failure') (Join-Path $run "$arch-ctest.log")
        $test=Join-Path $build 'Release\wpe64-parity-test.exe'
        $packets=Join-Path $run "$arch-packets.tsv"
        Run $test @($vectors,$packets) (Join-Path $run "$arch-parity.log")
        Run $oracleExe @('verify-native',$vectors,$packets) (Join-Path $run "$arch-reverse.log")
        $manifest.architectures += [ordered]@{
            architecture=$arch;result='passed'
            parity=(Get-Content -LiteralPath (Join-Path $run "$arch-parity.log"))
            reverse=(Get-Content -LiteralPath (Join-Path $run "$arch-reverse.log"))
            artifacts=@($test,(Join-Path $build 'Release\wpe64-common.lib'),$packets,(Join-Path $build 'CMakeCache.txt')) | ForEach-Object {[ordered]@{path=$_;sha256=(Hash $_)}}
        }
    }
    & (Join-Path $PSScriptRoot 'verify-assets.ps1')
    if(-not $?){throw 'Preserved frontend verification failed'}
    if($manifest.architectures.Count -eq 0 -or $manifest.architectures.Count -ne $Architecture.Count){throw 'Architecture test matrix was not completed'}
    $manifest.result='passed'
} catch {
    $manifest.result='failed'
    $manifest.error=$_.ToString()
    throw
} finally {
    $manifest.finishedUtc=[DateTime]::UtcNow.ToString('o')
    $json=$manifest | ConvertTo-Json -Depth 12
    $json | Set-Content -LiteralPath (Join-Path $run 'run-manifest.json') -Encoding utf8
    $json | Set-Content -LiteralPath (Join-Path $BuildRoot 'latest-run.json') -Encoding utf8
}
Write-Output "PASS: requested architectures completed; evidence: $run"
