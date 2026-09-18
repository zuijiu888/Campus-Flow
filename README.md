# Campus Flow

Campus Flow 是面向 Windows 11 的校园网后台认证工具。它会在网络连接后静默检查认证状态，并按配置向校园网门户提交表单，不打开 Edge，也不显示终端窗口。
密码保存在本地
## 项目结构

- `work/`：源码与构建脚本
- `outputs/`：可直接运行的程序、图标和发布压缩包

## 构建

在 Windows PowerShell 中运行：

```powershell
Set-Location .\work
powershell -ExecutionPolicy Bypass -File .\Build-CampusAutoLogin.ps1
```
