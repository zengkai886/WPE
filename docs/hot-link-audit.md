# WPE-陈北玄 2.3.0：注入/代理列表热链审计

## 结论

这次审计把“保存列表后是否进入正在运行的 native 链路”与“仅保存到 SQLite、等待下一次启动”分开记录。保存成功后，原 Vue 页面仍通过 `feed:replace` 更新列表；运行中的 native 链路再按下面的规则同步。

## 注入模式

已接入实时同步的项目：

- Hook/拦截设置、过滤/采集设置、系统执行设置和列表设置；
- 滤镜的新增、编辑、启用、批量启用、排序/删除；
- 发送项及其报文的编辑、启用、批量启用、排序/删除、导入；
- 封包编辑、滤镜导入和备份导入。

同步路径是：`DataService::Submit` 提交并提交数据库 → `Host::SyncTargetConfiguration` → Target IPC `SetConfig`（HookFlags、Filters、Runtime、Sends）。目标未连接时只保存；目标连接后保存会立即发送四组配置，失败会向界面返回“已保存但同步失败”。

## 代理模式

已接入实时同步的运行配置：

- 代理监听设置、认证开关和账号列表；
- 本地/远程映射设置及映射列表；
- 账号导入、批量编辑、启用、删除；
- 代理配置导入。

同步路径是：保存 SQLite 后读取 `__proxyRuntimeConfiguration`，完整校验账号、端口、映射规则，再以同一份配置重建正在运行的 SOCKS5/HTTP 监听。这样新连接立即使用新账号/映射；为避免并发读写，配置切换期间会结束现有代理会话，界面会收到新的 `proxy:state` 和地址。

WPC 服务器/通知列表继续由现有 `wpc:state` / `WpcRuntime::Update` 热更新。

## 明确的非执行列表

代理模式中的滤镜、发送、机器人、仓库列表仍是共享数据编辑器/持久化列表；代理监听本身没有注入目标，因此不会把这些列表误发送到 SOCKS5/HTTP 链路。机器人执行器仍按约定不加入。它们在注入模式下的滤镜/发送项则通过上面的 Target IPC 热同步。

代理防火墙开关、白名单和黑名单目前也仍是数据层；现有 SOCKS5/HTTP 监听器没有把 IP 规则作为连接准入条件，因此本轮没有把它们标记成“已热链”，避免出现界面显示已保存但 native 实际未执行的假完成。

## 验证

- `npm run build`：Vue 页面与原生资源构建成功；
- `cmake --build build-native2 --config Release --parallel 4`：x64 Release 构建成功；
- `ctest --test-dir build-native2 -C Release --output-on-failure`：23/23 通过；
- 原 Vue/native 自测：`result=passed`，包含标题栏、列表往返、数据库切换、编辑器和文件流程。
