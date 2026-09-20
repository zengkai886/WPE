# WPE64 C++：TCP 流重组与 zlib 业务包解析接入完成

## 交付范围

已把 `WPE64_TCP_Zlib_接入交付文档.md` 中的只读解析链路接入现有 native 捕获链路：

```text
Winsock 捕获字节
  → 按四元组/方向隔离的流缓存
  → [uint32_be 长度][zlib 数据] 帧边界解析
  → zlib 解压
  → UTF-8 JSON 规范化
  → body 字符串的二次 JSON 解析
  → 现有只读 Log 事件（source=tcp-zlib）
```

本功能只观察捕获数据，不改写网络通信、不参与 TLS 解密、不把业务正文写入 `WPE.db`。

## 实现位置

- `src/target/tcp_zlib_inspector.h/.cpp`
  - 增量 TCP 流缓存和业务帧边界处理。
  - 每个 `source/destination/protocol + direction` 使用独立状态。
  - 压缩帧上限 16 MiB，解压结果上限 64 MiB，单流缓存上限 64 MiB。
  - TLS `14/15/16/17 03 xx` 记录只分类并输出 `tls_session_key_required`，不会送入 zlib。
  - JSON 中的 `token`、`cookie`、`authorization`、`password`、`secret`、`private_key` 等字段默认替换为 `<redacted>`。
  - `body` 为字符串时执行二次 JSON 解析；失败保留脱敏后的 `body_raw` 和错误状态。
- `src/target/winsock_hook.cpp`
  - 在现有 writer 线程中调用解析器，确保 detour 线程不做解压、JSON、IPC 或阻塞操作。
  - 解析事件通过既有 `IpcEvent::Log` 发往宿主，source 固定为 `tcp-zlib`。
  - 停止捕获时清理所有流状态；5 分钟未活动流和超过 4096 条流会回收。
- `third_party/miniz/miniz.h/.cpp`
  - 以 vendored、只读 zlib-compatible inflate 实现提供解压能力；不依赖服务器系统安装的 zlib DLL。
- `tests/tcp_zlib_inspector_test.cpp`
  - 覆盖拆包、粘包、多帧、双向/多四元组隔离、TLS 分类、零长度错误和敏感字段脱敏。

## 错误状态

统一输出以下状态名：

```text
flow_reassembly_error
invalid_frame_length
frame_too_large
zlib_header_error
zlib_inflate_error
decompressed_payload_too_large
json_parse_error
nested_body_parse_error
tls_session_key_required
unknown_protocol
```

错误事件只包含流标识、方向、帧长度和错误原因，不包含完整业务 Payload。

## 构建与验证

已更新 CMake 目标：

- `wpe64-miniz`
- `wpe64-tcp-zlib`
- `wpe64-tcp-zlib-test`

验证结果：

```text
tcp-zlib-inspector ............... Passed
proxy-capture-filter-semantics ... Passed
winsock-hook-pipeline ............ Passed
```

同时重新构建通过：

```text
wpe64-hook-runtime
wpe64-hook.dll
wpe64-app.exe
```

## 明确未包含的内容

- 不提取 TLS 会话密钥，不绕过证书校验或 TLS 保护。
- 不修改现有代理过滤 AND/OR 语义、数据编辑器、导入导出、SQLite 表结构或窗口逻辑。
- 不把 overlapped sequence number 重新实现为网卡级 TCP 协议栈；当前接入点是现有 Winsock hook 已交付的按序 payload。
