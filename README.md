# Campus Flow

Campus Flow 是面向 Windows 11 的校园网后台认证工具。它会在网络连接后静默检查认证状态，并按配置向校园网门户提交表单，不打开 Edge，也不显示终端窗口。
cpu占用率几乎为零,同时也可减少后台运行,让程序只有在网络不可用的时候进行扫描并连接,当网络连接成功的时候不再进行扫描,降低内存占比
密码会加密保存在本地
开机后约 500ms 开始首次检测，启动响应更快。
网络不可用或尚未认证时，按配置间隔进行扫描和认证尝试。
一旦确认网络已经正常连接，自动停止定时轮询，减少 CPU、内存和网络请求。
只有检测到网络状态变化或重新断网时，才会重新唤醒扫描。
增加了防重复检测机制，避免多个后台任务同时运行。
## 项目结构

- `work/`：源码与构建脚本
- `outputs/`：可直接运行的程序、图标和发布压缩包

## 构建

在 Windows PowerShell 中运行：

```powershell
Set-Location .\work
powershell -ExecutionPolicy Bypass -File .\Build-CampusAutoLogin.ps1
```
