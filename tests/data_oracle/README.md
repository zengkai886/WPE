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

## 编辑器连续参照

本轮新增 `EditorOracle.cs`，在相同未修改原业务程序集上实际执行 184 条连续调用：机器人九类指令校验/移动/保存/取消、发送集明文导入及封包 Base64 编辑、原浅拷贝行为、仓库导入和条目动作。包括数字参数与鼠标坐标不同的 Unicode 空白处理。

```powershell
& "$runner\WpeDataOracle.exe" editors "$scratch\fresh-editor-db" `
  "$project\tests\fixtures" "$scratch\editor-sequence.json"
if ($LASTEXITCODE -ne 0) { throw 'Editor reference generation failed' }
```

依赖与上述构建准备相同。生成的 GUID/运行期数字 ID 按出现顺序变成 `$idN`；只有 ID 字段与已知 GUID 引用被替换，不改 IP、Socket 或字节文本。原随机运行期 ID 不参与严格比较，其余 DTO 字段完整比较。

固定明文 XML：`editor-send.sc`、`editor-stores.whs`；固定调用参照：`editor-sequence.json`。常规 C++ 构建直接读取并校验这些已提交文件，不需要原业务程序集。

参照导入调用原底层加载器，绕过人工选择文件和密码提示；原 `IUiHost` 测试实现同意确认，不执行实际网络或键鼠操作。成功通知在原 Vue 和 C++ 回归中另行测试，不把仅返回值相等解释为全部界面事件已对拍。

## 原契约提取

`extract_contracts.py <包含Operate.cs的原项目目录> <C++项目目录>` 从原源码重提取：217 个 RPC、20 张建表 SQL、当前使用的 12 张表头文件，以及业务翻译/国家字典。此工具会覆盖生成文件，只供明确更新契约时使用；普通构建不运行它。

## 明文导出原版参照

同一 DataOracle 构建新增三个命令（路径仍替换为独立测试目录）：

```powershell
& "$runner\WpeDataOracle.exe" exports "$project\tests\fixtures" "$scratch\export-golden"
& "$runner\WpeDataOracle.exe" exports "$project\tests\fixtures\export-edge" "$scratch\export-edge"
& "$runner\WpeDataOracle.exe" verify-export 'C++测试产生的完整路径\native.sc' "$scratch\original-roundtrip.sc"
& "$runner\WpeDataOracle.exe" verify-export 'C++测试产生的完整路径\native.whs' "$scratch\original-roundtrip.whs"
& "$runner\WpeDataOracle.exe" export-snapshot "$scratch\original-snapshot.sc"
```

exports 用未修改原加载器和保存器生成 XML 黄金。verify-export 通过原版读取 C++ 文件再保存并比较字节。export-snapshot 真调用原 SaveSendCollection_Dialog，在 PickSaveAsync 回调修改同一 PacketInfo，断言导出 Socket=99、Buffer=AA BB。不是本地重写序列化代码当作对照。

export-edge 覆盖 CR/LF/CRLF、Tab、中文、emoji、XML 特殊字符与未知负枚举。XML 回读的行尾归一化与原版相同；比较导出字节，不误要求回读字段保留原 CR。产品仍不附带原 C# 程序或依赖。

## 父列表与原加密对照

`config-files <tests/fixtures/config-files> <新的隔离输出目录>` 调用原加载器/保存器，输出四父列表、五组历史备份、ProxyMode/InjectMode、WhiteList/BlackList 九组备份、系统默认 null 导入前后 XML，以及 49 个实际原 AES 密文。`crypto.json` 记录原程序集 SHA256 和 Encoding.Default.CodePage。中文/emoji/NUL 密码均是固定合成测试输入，不是用户密码。

`verify-settings-db <原生测试数据库> <输出.sb>` 让未修改原程序集从原生 SQLite 实际加载 ProxyMode/InjectMode 并重新序列化；当前固定输出与 `settings.sb` 逐字节一致。只对隔离测试数据库使用，不要传入真实业务库。

`verify-ip-rules-db <原生测试数据库> <输出.sb>` 让未修改原程序集从原生 SQLite 实际加载 WhiteList/BlackList 并重新序列化。原加载器会异步查询归属地，测试会等待两张表全部落入原内存列表；输出顺序可能受该异步过程影响，不把顺序当作数据库兼容判据。

`verify-encrypted <C++测试输出文件绝对路径> <固定测试密码>` 用原程序真实 DecryptXMLFile 验证，不运行 UI、注入或代理。产品不携带/运行该 .NET 程序。`extract_xml_fields.py <原项目目录> <C++项目目录>` 可重新提取 65 系统字段和 27 滤镜字段。

`config-files/edges` 的尾分隔符、继承 namespace、带前缀根名样本由独立原程序运行产生对应黄金文件，捕获原 Enum.Parse/String.Split/Root.Elements/XElement.Value 行为。黄金数据不从 C++ 生成。
