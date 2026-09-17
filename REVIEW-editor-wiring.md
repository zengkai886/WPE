# 编辑接线增量审查

基线：`adfeb2271f1c1705cdff8bb8ac5ffe67f4957447`。比较本次工作区新增与修改，不将完整 WPE 重写要求缩成编辑器范围。规格为用户更新版文档与原源码。

## Standards

发现 1 项 P2，已修复并独立复核：导入出错时 toast 发送抛异常会跳过实际 RPC 完成。现在由 `WebBridge::WithErrorToast` 分离通知和完成，并使用导航 epoch 抑制旧页面的迟到通知。回归验证通知抛异常仍返回一次结果、导航/销毁后的迟到完成无消息且不访问已销毁对象。

没有额外发现可定位的事务回滚或文件选择回调悬空问题。文件选择被延后到窗口消息处理，浏览器传入的文件路径被清除，不从 WebView2 回调同步启动模态窗口。

## Spec

发现并修复 5 项 P2（含修复复核阶段发现的边界）：

1. 数字参数错误接受原 `int.TryParse` 拒绝的 Unicode 空白。区分字符串 Trim 与 NumberStyles.Integer 的空白集合，原程序集生成边界参照。
2. XML 文件新增 64 MiB 硬上限。改为只读文件流，65 MiB 合法 XML 已回归。
3. 导入成功缺少原通知。补 `notify`、级别 2、本地化标题和文件路径；数据测试及原 Vue 自测检查。
4. 收紧数字解析后鼠标坐标遗漏原本显式的 Trim。MoveTo/MoveBy 每个坐标先 Trim，再执行原数字校验；加入原程序集参照。
5. GUID X 格式忽略空白/前导零及 B/P/N 形式的接受范围不符。按 .NET 空白集合及数值宽度处理 X，B/P 单独要求带连字符形式；补接受与拒绝案例。

以上是限定边界的对拍与复核，不是任意字符串的完全等价证明。损坏 XML 原子拒绝、DTD/深度约束、未逐语言对齐提示、未完成执行器/加密/导出等仍明确列于进度文档。

## 证据与范围

- `evidence/editor-run-manifest.json` / `editor-full.log`：全新双架构、原 Vue 首次编辑与重启。
- `evidence/editor-x64-ctest.log` / `editor-Win32-ctest.log`：每架构 7/7、229 条编辑检查，其中 184 条原 C# 调用。
- `evidence/editor-spec-*-red.log`：独立审查发现差异时的失败证据；不覆盖或删除历史失败。
- `evidence/editor-archive-*`、`editor-package-*`：无 Git 源码重建与运行包复验，以实际 manifest 为准。

**汇总：Standards 1 项 P2 修复；Spec 5 项 P2 修复。两轴分开报告；剩余全工程缺口没有因此消失。**

最后有界 Spec 复核独立重跑此前失败的 184 条参照及当前 229 项编辑检查，均通过；证据为 `editor-spec-move-fixed.log`、`editor-spec-bounded-final.log`。Standards 复核额外验证桥销毁后迟到通知不会访问已销毁对象。

发布重建第一次因临时构建路径过长，触发 MSBuild 260 字符限制，在编译器探测阶段失败。保留失败日志，改用较短的独立 BuildRoot 后重新执行完整验证；不修改系统策略或用户环境设置。

后续两次发布宿主测试重现旧的后台置顶问题，导致尚未进入编辑器就停止。保留失败报告，并把该窗口诊断与本轮编辑验收拆开：`topmostProbe` 保留真实 passed/failed 状态，`windowRoundTrip` 不再硬编码成功；编辑器/持久化仍要求全部实际通过。窗口问题并未修复，不能把后续“编辑验收通过”写成“全部窗口测试通过”。
