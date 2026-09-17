# 原 C# 数据参照运行器（仅测试）

产品运行不需要本目录的 C#、原 EXE 或其 DLL。参照运行器载入用户提供、未修改源码编译出的 `WinsockPacketEditor.exe`，直接调用原 `Operate` 的数据方法；不启动原窗口，不抓包、不注入、不启动代理。

## 常规测试

`build-test.ps1` 自动校验 `contracts/data-oracle.json` 中的文件哈希，并让 x64/Win32 数据测试读取已提交的 `tests/fixtures/filter-edit.json`。因此常规构建不需要另行编译整个原项目。

参照包括 120 条**连续**编辑案例；失败保存后的旧数据也参与下一案例，不能把它们当成 120 个独立重置样本。GUID 被规范为 `ID`，其他字段保留原程序输出。生成器固定随机种子。

## 重生成参照

前提：从用户 ZIP 原样解压并构建原项目，得到 Release 输出目录。需要 .NET Framework 4.8 及其依赖；下面所有路径换成自己的路径。

```powershell
$project = 'E:\codex\2026-09-17\bi-a\outputs\WPE64-Cpp'
$originalBin = 'E:\codex\2026-09-17\bi-a\work\baseline-build\WinsockPacketEditor-master\WinsockPacketEditor\bin\Release'
$scratch = 'E:\codex\2026-09-17\bi-a\work\data-oracle-' + [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $scratch | Out-Null
$runner = Join-Path $scratch 'runner'

dotnet build "$project\tests\data_oracle\DataOracle.csproj" -c Release -o $runner `
  "-p:OriginalBin=$originalBin" "-p:BaseIntermediateOutputPath=$scratch\obj\"
if ($LASTEXITCODE -ne 0) { throw 'Reference runner build failed' }

# 测试隔离目录中准备原程序集的运行依赖；绝不复制到产品发布包。
Copy-Item -LiteralPath "$originalBin\WinsockPacketEditor.exe" -Destination $runner
Get-ChildItem -LiteralPath $originalBin -Filter '*.dll' -File | Copy-Item -Destination $runner
Copy-Item -LiteralPath "$originalBin\x86","$originalBin\x64" -Destination $runner -Recurse

& "$runner\WpeDataOracle.exe" "$scratch\fresh-db" "$scratch\filter-edit.json"
if ($LASTEXITCODE -ne 0) { throw 'Reference generation failed' }
Get-FileHash -LiteralPath "$scratch\filter-edit.json" -Algorithm SHA256
```

生成器拒绝已存在 `oracle.db` 的目录，避免复用污染数据。当前固定参照的程序集 SHA-256 为 `76C33B88188F7F921AE5B21117533FF1D3F1861A04A723B8087DE42B17E5FEED`；如果另一次原构建产生不同 PE 哈希，需记录真实来源，不要直接伪造相同值。

重生成后先比较字段和测试结果；确认有意更新才替换固定参照并更新哈希清单。不要为“通过哈希”随意改写黄金输出。

## 反向数据库读取

数据服务测试会打印独立数据目录，其中 `中文持久化.db` 是用于反向读取的指定案例库。不要传入用户数据库。

```powershell
& "$runner\WpeDataOracle.exe" verify-native `
  '完整路径\data-test\本次编号\中文持久化.db' `
  "$scratch\native-db-original-read.json"
if ($LASTEXITCODE -ne 0) { throw 'Original loader rejected native data' }
```

这会通过原加载器验证偏好、滤镜负偏移以及发送/机器人/仓库数量。它不是任意数据库的通用校验器，也不是全 20 表兼容性认证。

## 原契约提取

`extract_contracts.py <包含Operate.cs的原项目目录> <C++项目目录>` 从原源码重提取：217 个 RPC、20 张建表 SQL、当前使用的 8 张表头文件，以及业务翻译/国家字典。此工具会覆盖生成文件，只供明确更新契约时使用；普通构建不运行它。
