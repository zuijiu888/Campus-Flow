# CampusFlow

Windows 11 校园网后台认证工具，支持配置校园网门户登录地址并静默提交认证。

## 构建

在 Windows PowerShell 中运行 `build.ps1`。图标位于 `assets/CampusFlow.ico`。

版本：1314.5.2.0

普通用户无需安装编译工具：下载发布 ZIP，解压后直接运行 `CampusFlow.exe`。首次使用时填写校园网登录页面、账号和密码；Windows Wi‑Fi 需开启对应网络的“自动连接”。程序默认直接访问校园网门户，并自动替换 `{local_ip}`。
