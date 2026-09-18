# P3：宿主目标链路与 UI 接线

## 已完成

- `TargetLink` 在独立工作线程中管理 `ShellIpcSession`、注入、附加、启动目标和断开清理；UI 线程不直接阻塞命名管道或远程线程。
- `injectAttach`、`injectQuick`、`injectStartHook`、`injectStopHook`、`getInjectStatus`、`getInjectStats`、`getInjectProcessList` 已接入原 Vue 页面。
- 启动目标 Hook 前会从 SQLite/数据服务生成 HookFlags、Filters、Runtime、Sends 四类快照并通过 `SetConfig` 发布到目标进程。
- `startSendList` / `stopSendList` 已发送到目标 `HeadlessCore`，运行状态由 Stats 事件和 `send:running` 事件回传。
- 目标事件已回到 UI 线程：Stats、HookState、FilterLog、Dropped、Fatal、PacketFrame；StoreAdded 进入 `DataWorker::SubmitStoreEvent`，事务完成后刷新仓库列表。
- 原 Vue 统计界面需要的注入计数、字节计数和滤镜统计 DTO 已由实时目标计数映射提供。
- 目标连接关闭、WebView 关闭和宿主析构路径均会停止发送、停止会话线程并关闭管道。

## 明确未完成 / 不在本阶段范围

- **机器人执行器没有加入**：没有注册 `StartRobot`、`StartRobotList` 或机器人运行线程。
- 真实窗口拾取仍是轻量鼠标位置取窗句柄实现；复杂的全局拾取覆盖层未加入。
- 目标端抓包帧目前只推送为 `packet:frame` 事件，尚未写入新的 shell 端抓包持久化表；现有 SQLite 仓库只接收 `StoreAdded`。
- `startPacketSend` 等独立的 Packet 编辑器运行命令仍保持未实现，不影响本阶段发送列表 P2 链路。

## 验证

- x64 Release 构建：`wpe64-app.exe` 构建成功。
- CTest：18/18 通过，包括 IPC、注入会话、HeadlessCore、WinSock/filter、DataService/DataWorker、编辑器、配置文件和剪贴板测试。
