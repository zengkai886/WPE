# WPE64 C++ 重写工程

**当前是 C++ 宿主、双向消息桥、公共协议库和封包队列的开发增量，不是完整抓包软件。** 原 Vue 已在原生 WebView2 宿主中运行；注入 DLL、滤镜、代理和完整业务接口尚未实现。版本栏明确标为 `C++ M0-dev`，未实现的方法返回错误，不伪造抓包结果。

## 当前开发依据

- 生效需求：`docs/用户提供-重写工程文档-更新版.md`，即用户上传的 `WPE x64 C++ 重写工程文档 (1).md`。
- 界面固定为：**C++ WebView2 宿主 + 全部原 Vue 前端**。主方案没有 Qt 依赖，不重画界面。
- 本目录独立于旧 Java 工程；生产库为 C++20，不调用 Java，也不启动原版 C# 业务程序。
- C# 只用于测试：原版编解码源码生成参照数据，并反向验证 C++ 产生的封包。
- 原版源码 ZIP 与两版用户文档均保持原件不变。当前版本及 SHA-256 在 `contracts/active-spec.json`。

## 本次已经实现

| 内容 | 状态 |
|---|---|
| CMake / MSVC C++20 / 静态 CRT，x64 与 Win32 公共库构建 | 通过 |
| LE 基础类型、null/空区分、UTF-8、GUID 编解码 | 已实现并对拍 |
| v4 命令/事件/状态/配置类别编号、管道命名 | 已实现并对拍；不是命令处理器 |
| 长度前缀分帧、分片读取、EOF/畸形长度边界 | 已实现并对拍；不是 Windows 管道传输实现 |
| 封包帧原始/修改缓冲区及同内容省略位 | 已实现并双向对拍 |
| PacketRing 丢旧包/累计丢弃/批量预算/清空/唤醒 | 已实现；每架构通过 6,416 条原 C# 队列状态对拍及并发守恒测试 |
| C++ WebView2 宿主加载原 wwwroot | 已构建 x64 exe，原 Vue 启动及真实消息往返测试通过 |
| call/result/ask/answer/event 消息桥 | 已实现消息路由、来源检查、超时、取消和错误路径；不等于已实现全部业务方法 |
| 窗口最小化、最大化、关闭、置顶、拖动 | 已接原前端的方法名；自动化实测置顶开关，其他窗口操作仍需人工体验回归 |
| 原 Vue/TypeScript/语言/静态资源及远程页面 | 从原 ZIP 提取，555 文件哈希校验通过，其中 70 个 Vue 文件 |
| 两端真实管道、心跳/卸钩、配置快照、注入、滤镜、代理、完整 GUI 业务、数据及发布 | 后续实现，尚未验收 |

M0 的桌面启动和基础库已有可运行实现；注入 DLL/测试靶子等工程目标及后续 M1～M8 仍未完成。**没有把整套工程或全功能 GUI 标记为完成。**

## 启动宿主联调版

构建完成后，使用 x64 输出目录里的 `wpe64-app.exe`。发布的宿主联调 ZIP 已将原 `wwwroot` 放在 exe 旁，解压后可以直接双击。不要把它当成最终产品：目前注入/代理业务按钮会返回“尚未实现”，数据库/归属地未加载，语言主题设置也尚未接入持久化。

需要 Windows WebView2 Runtime。仅 SDK 的 x64 loader 静态链接进 exe，**浏览器 Runtime 没有打进 exe**。本机自动化测试使用 Runtime `153.0.4234.32`。宿主目前使用普通权限，不会在联调阶段强制提权；目标注入权限属于后续模块。

可显式指定资源和浏览器数据目录：

```powershell
& '完整路径\wpe64-app.exe' --assets '完整路径\wwwroot' --data-dir '完整路径\browser-data'
```

宿主的 `--self-test '结果目录'` 会在隐藏窗口中加载真正的原 Vue，测试首屏、窗口置顶、未知方法拒绝、C++ 提问/原 Vue 对话框回答、通知事件，然后写 JSON 与实际渲染截图并退出；它不会执行注入、抓包或代理。自测方法仅在该模式下注册。默认浏览器缓存放在 exe 旁的 `runtime`，联调包没有包含测试缓存。

## 一键构建和原版对拍

需要 Visual Studio 2022 C++ Build Tools（x64/x86）、Windows SDK、CMake ≥ 3.24、.NET SDK 及 .NET Framework 4.8。C# 工具仅是测试依赖，不是 C++ 产品运行依赖。

在 PowerShell 执行：

```powershell
& 'E:\codex\2026-09-17\bi-a\outputs\WPE64-Cpp\build-test.ps1' `
  -BuildRoot 'E:\codex\2026-09-17\bi-a\work\cpp-parity'
```

必须提供位于源码目录之外的 `-BuildRoot`，如上例。默认分别构建并测试 x64 和 Win32；拒绝空架构列表及重复架构。每次使用新的 `run-<GUID>` 目录，不读入旧编译文件。

最近一次完整结果：**每个架构 74,684 条原 C# 参照数据、76,618 条断言通过；每个架构输出的 600 个封包又由原 C# 解码器验证通过。** 编译启用 `/W4 /WX`，两个架构均无编译警告。

本轮另增加每架构 **6,416 条队列状态对拍**、四项 CTest（codec、frame、queue、bridge），以及 x64 原 Vue 宿主自测。证据见 `evidence/host-ring-run-manifest.json`、`evidence/host-ring-full.log`、`evidence/host-self-test.json`、`evidence/original-vue.png`。

原版参考文件的哈希每次执行前检查；测试证据记录新文档哈希、源码哈希、构建环境、产物哈希和测试范围。参见 `evidence/protocol-run-manifest.json`、`evidence/build-test.log`。

## 目录

- `src/common`：C++ 公共协议库。
- `src/shell`：Win32/WebView2 宿主与 JSON 消息桥。
- `tests`：公共接口测试和原 C# 对照运行器。
- `frontend`：原 `WebUI`，未改动。
- `wwwroot`：原包内预构建前端，未改动。
- `remote-web`：原远程管理静态页面，未删除。
- `contracts`：当前文档、源文件、界面资源的校验清单。
- `third_party`：固定版本 JSON 头文件、WebView2 SDK 头文件/x64 loader 及许可证；全部有 SHA-256 清单。
- `docs/实施校核.md`：文档差异、必须修正的示例和后续验收边界。

`wwwroot` 是原压缩包里的产物。本次没有重新构建前端，也没有声称原预构建资源与重新构建产物相同。已测试原页面加载和真实双向桥；完整窗口体验、全部业务方法、七语言持久化及十万包列表性能仍需单独验收。

实现参考：[Microsoft 本地资源映射](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_3)、[Microsoft WebView2 安全建议](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)、[nlohmann/json 3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0)。宿主限定原页面来源、拒绝跨域导航/新窗口/网页权限，使用原生 `PostWebMessageAsJson`，不通过拼接脚本传递业务 JSON。
