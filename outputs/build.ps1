$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'CampusAutoLogin.cs'
$output = Join-Path (Split-Path $PSScriptRoot -Parent) 'outputs\CampusFlow.exe'
$icon = Join-Path $PSScriptRoot 'assets\CampusFlow.ico'

if (Test-Path -LiteralPath $output) {
    Remove-Item -LiteralPath $output -Force
}

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
& $csc /nologo /target:winexe /out:$output /win32icon:$icon /reference:System.dll,System.Core.dll,System.Drawing.dll,System.Security.dll,System.Xml.dll,System.Windows.Forms.dll $source
if ($LASTEXITCODE -ne 0) { throw "编译失败，退出码 $LASTEXITCODE" }

Write-Host "Built: $output"
