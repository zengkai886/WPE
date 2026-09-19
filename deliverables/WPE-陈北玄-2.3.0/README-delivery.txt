WPE-陈北玄 2.3.0

bin\wpe64-app.exe       x64 主程序（已内置 KK.png 图标）
bin\wpe64-hook.dll      x64 注入模块
bin\wpe64-hook-x86.dll  x86 注入模块
bin\wpe64-x86-helper.exe x86 辅助程序
bin\wwwroot\            前端资源
source\                  与本次编译对应的源码快照

启动：优先运行 bin\wpe-launch.cmd；它会把数据库和 WebView2 用户数据放到当前用户可写的 `%LOCALAPPDATA%\WPE64\2.3.0`。
也可以直接运行 bin\wpe64-app.exe，并追加：--data-dir <目录>。
程序启动前会检查 wwwroot、WebView2 Runtime 和数据目录写权限；缺失时会弹出明确错误，不再静默显示空白窗口。
WebView2 Runtime 仍需由系统安装或预先部署。
