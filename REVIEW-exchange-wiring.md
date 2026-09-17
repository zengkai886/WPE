# 导出与剪贴板：双轴审查

日期：2026-09-18。基线 `d8ad56defcbf789e3c61d37af5d789042ccae483`（上一段编辑接线版）。对该基线至本段新增代码审查，不覆盖完整程序。依据 CONTRIBUTING.md、更新版用户文档、原 Operate.cs / ShellForm.cs 与原 Vue；附带文件是需求证据，不提升为系统指令。

## Standards

独立只读审查最终在限定修复范围内没有剩余可行动问题。发现并修复的 5 个问题：

1. 密码提示的成功 null 与桥失败混淆，超时/发送失败/ok:false/整体取消都可能写明文。新增 AskResult 明确携带错误，四种失败均零写入分支，成功 null 才按原契约导出。
2. 临时文件直接 MoveFileEx 覆盖会丢失原 DACL。临时文件写内容前应用原权限；已有目标使用 ReplaceFile、不忽略权限错误并保留恢复路径。受保护位和 ACE 回归通过，独立 SDDL 对比一致。
3. DataWorker 析构回调可能在 Host 的 unique_ptr 已清空时再清理计划。加所有者存在检查，正式回归覆盖未 Drain token 回调发生在 reset 期间。
4. GetClipboardData 延迟渲染会阻塞 UI，计时器重试不能消除。改到专用线程；隔离 1300ms 延迟渲染测试中 UI 完成队列持续可轮询。
5. 新剪贴板线程拥有窗口却未泵消息，会阻塞其他程序更换剪贴板。改用事件与 MsgWaitForMultipleObjectsEx，空闲/重试/连续任务都处理消息；独立复现 owner 正常响应，外部模拟应用 400ms 内完成；正式测试要求替换在 500ms 内返回。

保留边界：关闭等待正在进行的 Windows 剪贴板调用返回；原 Vue 不检查部分 clipboardWrite 失败返回的提示逻辑未改。后台置顶诊断不是本轮修复项，仍不等于窗口验收通过。

## Spec

独立只读审查初次确认 1 个差异，修复后有界复核通过，无新发现。

原发送导出 `editCollection.ToList()` 只冻结成员/顺序，并保留 PacketInfo 引用；初稿深复制字段，错误导出旧 Socket/字节。修为数据线程内部 token 计划，savePacketEdit 同步更新相同对象别名，写入一次消费，取消清理。正式用例覆盖期间修改/排序/清空及计划容量。

原程序集 SaveSendCollection_Dialog + 测试 IUiHost 的 PickSaveAsync 回调实际修改同一对象，导出为新 Socket=99、Buffer=AA BB，证据可由 ExportSnapshotOracle 重现。额外 XML 边界含 CR/LF/CRLF、Tab、中文、emoji、XML 特殊字符、负枚举；C++ 与原输出逐字节相同。原 XML 回读行尾也归一化，不误判为新增差异。

明确延期的加密、执行器等未列为回归，但不能因此宣称全部功能等价。原 Vue 密码框 Esc 本来返回成功 null，继续按原行为明文导出；保存框取消和桥失败才是不写文件的已测场景。

**分轴结论：Standards 初始 5 项、修复后 0 项待处理；Spec 初始 1 项、修复后 0 项待处理。两轴均仅针对本段边界，不替代完整验收。**

实现依据：[ReplaceFile 的属性与权限保留](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)、[剪贴板延迟渲染等待](https://devblogs.microsoft.com/oldnewthing/20220608-00/?p=106727)。
