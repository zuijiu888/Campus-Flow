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
版本：1314.5.2.0

## 普通用户使用

普通用户不需要安装 Visual Studio、C# 编译器或任何开发工具。下载 `outputs/CampusFlow-v1314.5.2.0-win-x64.zip`，解压后直接运行 `CampusFlow.exe`，在基础设置中填写校园网账号和密码即可。

程序默认使用校园网门户直连模式：会自动读取当前电脑的内网 IPv4 地址替换 `{local_ip}`，不依赖 Windows 的 `msftconnecttest.com` 跳转。Windows 需要先在 Wi‑Fi 设置中勾选“在信号范围内自动连接”对应校园网。

## 开发者构建

开发者也不需要额外安装编译器。Windows 11 通常自带 .NET Framework C# 编译器；运行 `work/Build-CampusAutoLogin.ps1` 即可生成 `outputs/CampusFlow.exe`。如果系统没有该编译器，可将 .NET Framework Developer Pack 安装到任意磁盘（例如 D 盘），普通用户仍只需运行已打包的 EXE。

## 更新日志

### 1314.5.2.0

- 默认改为直接访问校园网门户，不再依赖 Windows 的 `msftconnecttest.com` 重定向。
- 移动校园网模板的登录页和提交地址自动携带 `{local_ip}`、`wlanacname` 参数。
- 兼容旧版本设置文件，首次启动时自动迁移旧的固定 `/login.do` 地址。
- 认证失败时记录 HTTP 状态码（例如 500），但不记录账号和密码。
- 网络认证成功后停止定时轮询，断网或网络地址变化时再自动唤醒。
- 普通用户无需安装编译器，解压发布包后直接运行 `CampusFlow.exe`。
