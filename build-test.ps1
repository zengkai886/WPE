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
    testId='CPP-EXCHANGE-WIRING-010'
    specificationSections=@('0','2.3','3.1','3.2','3.3','4.1','4.2','4.3','4.4','4.5','5.1','5.4','5.5','9.2','9.3','13.1')
    scope='Protocol/ring, real three-channel Windows named-pipe transport with current-user ACL, shell/target session lifecycle, target headless command core, and real same-bitness Windows process injection through remote LoadLibraryW plus suspended-process launch/cleanup; native SQLite, editors, plaintext XML export, private-station OS clipboard, original Vue/HexView/export/clipboard buttons and restart. The injector is exercised against an actual child process and probe DLL on x64 and Win32. There is still no production target DLL, MinHook/Winsock detour, pre-entry suspended-injection wake choreography, real capture, proxy/executor engine or complete acceptance'
    startedUtc=[DateTime]::UtcNow.ToString('o')
    finishedUtc=$null
    result='running'
    runDirectory=$run
    command="$PSCommandPath -BuildRoot $BuildRoot -Architecture $($Architecture -join ',')"
    architectures=@()
    cleanup='Owned test processes, WebView2 controller and named-pipe instances closed. No injection, target hooks, certificates, system proxy or listening sockets. Only isolated test SQLite databases and WebView2 profiles changed; retained under the external build directory.'
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
    $deps=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contracts\third-party.json') -Raw | ConvertFrom-Json
    foreach($dependency in $deps.files){if((Hash (Join-Path $PSScriptRoot $dependency.path)) -ne $dependency.sha256){throw "Dependency hash mismatch: $($dependency.path)"}}
    $manifest.dependencies=$deps
    $dataOracle=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contracts\data-oracle.json') -Raw | ConvertFrom-Json
    foreach($file in $dataOracle.files){if((Hash (Join-Path $PSScriptRoot $file.path)) -ne $file.sha256){throw "Data contract hash mismatch: $($file.path)"}}
    $manifest.dataOracle=$dataOracle
    $files=@(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src'),(Join-Path $PSScriptRoot 'tests') -File -Recurse | Where-Object {$_.Extension -in '.cpp','.h','.cs','.csproj','.ps1','.manifest','.json','.py' -and $_.FullName -notmatch '[\\/](obj|bin)[\\/]'})
    $files+=Get-Item -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'CMakeLists.txt'),(Join-Path $PSScriptRoot 'contracts\oracle-source.json'),(Join-Path $PSScriptRoot 'contracts\active-spec.json'),(Join-Path $PSScriptRoot 'contracts\preserved-assets.json'),(Join-Path $PSScriptRoot 'verify-assets.ps1')
    $manifest.sourceFiles=@($files | Sort-Object FullName | ForEach-Object {[ordered]@{path=$_.FullName.Substring($PSScriptRoot.Length+1);sha256=(Hash $_.FullName)}})
    # A source ZIP intentionally has no .git directory. Its byte hashes remain
    # the build identity; Git is optional provenance, not a build dependency.
    $manifest.git=[ordered]@{commit=$null;dirty=$null;available=$false}
    if((Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)){
        $revision=& git -C $PSScriptRoot rev-parse HEAD
        if($LASTEXITCODE -ne 0){throw 'Cannot read Git revision'}
        $changes=& git -C $PSScriptRoot status --porcelain
        if($LASTEXITCODE -ne 0){throw 'Cannot read Git worktree'}
        $manifest.git=[ordered]@{commit="$revision";dirty=(@($changes).Count -gt 0);available=$true}
    }
    $manifest.environment=[ordered]@{os=[Environment]::OSVersion.VersionString;powershell=$PSVersionTable.PSVersion.ToString();cmake=(& cmake --version | Select-Object -First 1);dotnetSdk=(& dotnet --version)}
    $oracle=Join-Path $run 'oracle'
    $obj=Join-Path $run 'oracle-obj'
    Run 'dotnet' @('build',(Join-Path $PSScriptRoot 'tests\oracle\Oracle.csproj'),'-c','Release','-o',$oracle,"-p:BaseIntermediateOutputPath=$obj\",'--nologo','--verbosity','minimal') (Join-Path $run 'oracle-build.log')
    $oracleExe=Join-Path $oracle 'WpeProtocolOracle.exe'
    $vectors=Join-Path $run 'vectors.tsv'
    Run $oracleExe @('generate',$vectors) (Join-Path $run 'oracle-generate.log')
    $manifest.oracleRuntime=Get-Content -LiteralPath (Join-Path $run 'oracle-generate.log')
    $manifest.fixtures=[ordered]@{sha256=(Hash $vectors);rows=(Get-Content -LiteralPath $vectors).Count}
    $ringVectors=Join-Path $run 'ring-vectors.tsv'
    Run $oracleExe @('generate-ring',$ringVectors) (Join-Path $run 'oracle-ring.log')
    $manifest.ringFixtures=[ordered]@{sha256=(Hash $ringVectors);rows=(Get-Content -LiteralPath $ringVectors).Count}
    foreach($arch in $Architecture){
        $build=Join-Path $run $arch
        Run 'cmake' @('-S',$PSScriptRoot,'-B',$build,'-G','Visual Studio 17 2022','-A',$arch) (Join-Path $run "$arch-configure.log")
        Run 'cmake' @('--build',$build,'--config','Release','--parallel','2') (Join-Path $run "$arch-build.log")
        Run 'ctest' @('--test-dir',$build,'-C','Release','--verbose','--output-on-failure') (Join-Path $run "$arch-ctest.log")
        $test=Join-Path $build 'Release\wpe64-parity-test.exe'
        $packets=Join-Path $run "$arch-packets.tsv"
        Run $test @($vectors,$packets) (Join-Path $run "$arch-parity.log")
        Run $oracleExe @('verify-native',$vectors,$packets) (Join-Path $run "$arch-reverse.log")
        Run (Join-Path $build 'Release\wpe64-ring-test.exe') @($ringVectors) (Join-Path $run "$arch-ring.log")
        if($arch -eq 'x64'){
            $hostEvidence=Join-Path $run 'host'
            $app=Join-Path $build 'Release\wpe64-app.exe'
            $arguments=@('--assets',('"'+(Join-Path $PSScriptRoot 'wwwroot')+'"'),'--data-dir',('"'+(Join-Path $run 'webview-profile')+'"'),'--self-test',('"'+$hostEvidence+'"'))
            $process=Start-Process -FilePath $app -ArgumentList $arguments -WindowStyle Hidden -PassThru
            try {
                if(-not $process.WaitForExit(105000)){Stop-Process -Id $process.Id -ErrorAction SilentlyContinue;throw 'Native host self-test timeout'}
                $process.Refresh()
                if($process.ExitCode -ne 0){throw "Native host failed ($($process.ExitCode)); see $hostEvidence"}
            } finally {$process.Dispose()}
            $manifest.host=Get-Content -LiteralPath (Join-Path $hostEvidence 'host-self-test.json') -Raw | ConvertFrom-Json
            if($manifest.host.result -ne 'passed'){throw 'Native host did not pass'}
            if(-not $manifest.host.frontend.originalExportButtons -or -not $manifest.host.frontend.originalClipboardButtons -or -not $manifest.host.frontend.encryptedExportAndImport -or -not $manifest.host.frontend.wrongPasswordRetried -or -not $manifest.host.frontend.importGrantRestricted -or -not $manifest.host.frontend.batchAccountRoundTrip -or -not $manifest.host.frontend.autoStoresRoundTrip -or -not $manifest.host.frontend.configurationListsRoundTrip){throw 'Export/encryption/clipboard/batch-account/auto-store/configuration-list original UI test did not pass'}
            [xml]$sendExport=Get-Content -LiteralPath (Join-Path $hostEvidence 'export.sc') -Raw
            [xml]$storeExport=Get-Content -LiteralPath (Join-Path $hostEvidence 'export.whs') -Raw
            if(@($sendExport.SendCollection.Collection).Count -ne 2 -or $sendExport.SendCollection.Collection[0].Socket -ne '99' -or $sendExport.SendCollection.Collection[0].Buffer -ne 'AA FF 80 42'){throw 'Native send export content mismatch'}
            if(@($storeExport.Stores.Data).Count -ne 2 -or $storeExport.Stores.Data[0].PacketData -ne '00 FF 80'){throw 'Native warehouse export content mismatch'}
            $batchExport=[IO.File]::ReadAllBytes((Join-Path $hostEvidence 'export.xls'))
            $batchGolden=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'tests\fixtures\config-files\original\batch-accounts.xls'))
            $headerEnd=-1;for($i=0;$i -lt $batchGolden.Length-1;$i++){if($batchGolden[$i] -eq 13 -and $batchGolden[$i+1] -eq 10){$headerEnd=$i+2;break}}
            if($headerEnd -lt 2 -or $batchExport.Length -le $headerEnd){throw 'Native batch-account XLS is missing or empty'}
            for($i=0;$i -lt $headerEnd;$i++){if($batchExport[$i] -ne $batchGolden[$i]){throw 'Native batch-account XLS header/ACP encoding mismatch'}}
            $manifest.exportArtifacts=@('export.sc','export.whs','encrypted-export.sc','export.xls') | ForEach-Object {$path=Join-Path $hostEvidence $_;[ordered]@{path=$path;sha256=(Hash $path)}}
            $manifest.hostArtifacts=@($app,(Join-Path $hostEvidence 'host-self-test.json'),(Join-Path $hostEvidence 'original-vue.png')) | ForEach-Object {[ordered]@{path=$_;sha256=(Hash $_)}}
            $reopenEvidence=Join-Path $run 'host-reopen'
            $arguments=@('--assets',('"'+(Join-Path $PSScriptRoot 'wwwroot')+'"'),'--data-dir',('"'+(Join-Path $run 'webview-profile')+'"'),'--self-test',('"'+$reopenEvidence+'"'))
            $process=Start-Process -FilePath $app -ArgumentList $arguments -WindowStyle Hidden -PassThru
            try{
                if(-not $process.WaitForExit(105000)){Stop-Process -Id $process.Id -ErrorAction SilentlyContinue;throw 'Native host restart test timeout'}
                $process.Refresh();if($process.ExitCode -ne 0){throw 'Native host restart test failed'}
            } finally {$process.Dispose()}
            $manifest.hostRestart=Get-Content -LiteralPath (Join-Path $reopenEvidence 'host-self-test.json') -Raw | ConvertFrom-Json
            if($manifest.hostRestart.result -ne 'passed' -or -not $manifest.hostRestart.frontend.restartPersistence -or -not $manifest.hostRestart.frontend.batchAccountRoundTrip -or -not $manifest.hostRestart.frontend.autoStoresRoundTrip -or -not $manifest.hostRestart.frontend.configurationListsRoundTrip -or $manifest.hostRestart.frontend.persistentFilterId -ne $manifest.host.frontend.persistentFilterId){throw 'Native host did not restore the same saved data'}
            if(-not $manifest.host.frontend.originalEditorButtons -or -not $manifest.hostRestart.frontend.editorRestartPersistence){throw 'Native editor UI/restart did not pass'}
        }
        $manifest.architectures += [ordered]@{
            architecture=$arch;result='passed'
            parity=(Get-Content -LiteralPath (Join-Path $run "$arch-parity.log"))
            reverse=(Get-Content -LiteralPath (Join-Path $run "$arch-reverse.log"))
            ring=(Get-Content -LiteralPath (Join-Path $run "$arch-ring.log"))
            artifacts=@($test,(Join-Path $build 'Release\wpe64-pipe-test.exe'),(Join-Path $build 'Release\wpe64-session-test.exe'),(Join-Path $build 'Release\wpe64-headless-core-test.exe'),(Join-Path $build 'Release\wpe64-injector-test.exe'),(Join-Path $build 'Release\wpe64-inject-target.exe'),(Join-Path $build 'Release\wpe64-inject-probe.dll'),(Join-Path $build 'Release\wpe64-common.lib'),(Join-Path $build 'Release\wpe64-target-core.lib'),(Join-Path $build 'Release\wpe64-injector.lib'),$packets,(Join-Path $build 'CMakeCache.txt')) | ForEach-Object {[ordered]@{path=$_;sha256=(Hash $_)}}
        }
    }
    if($Architecture -contains 'x64' -and $Architecture -contains 'Win32'){
        $crossLogs=@()
        foreach($injectorArch in @('x64','Win32')){
            $otherArch=if($injectorArch -eq 'x64'){'Win32'}else{'x64'}
            $release=Join-Path (Join-Path $run $injectorArch) 'Release'
            $otherTarget=Join-Path (Join-Path (Join-Path $run $otherArch) 'Release') 'wpe64-inject-target.exe'
            $log=Join-Path $run "$injectorArch-cross-inject.log"
            Run (Join-Path $release 'wpe64-injector-test.exe') @((Join-Path $release 'wpe64-inject-target.exe'),(Join-Path $release 'wpe64-inject-probe.dll'),$otherTarget) $log
            $crossLogs+=[ordered]@{injectorArchitecture=$injectorArch;targetArchitecture=$otherArch;result=(Get-Content -LiteralPath $log);sha256=(Hash $log)}
        }
        $manifest.crossArchitectureInjection=$crossLogs
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
