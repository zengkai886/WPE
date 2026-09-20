WPE-陈北玄 2.3.0 集成环境版

启动方式：双击 bin\wpe-launch.cmd，或直接运行 WPE-陈北玄-2.3.0-集成环境.exe。

集成内容：
- WPE 主程序、前端资源、Hook DLL 和 x86 Helper
- WebView2 自动安装引导程序
- WebView2 缺失时会提示 UAC 并安装 Evergreen Runtime；安装完成后自动启动 WPE
- 使用 %LOCALAPPDATA%\WPE64\2.3.0 作为可写数据目录

说明：WebView2 引导安装器需要服务器能够访问 Microsoft 下载服务；如果服务器完全离线，请使用微软官方 Evergreen Standalone Installer x64 替换同名安装器。
