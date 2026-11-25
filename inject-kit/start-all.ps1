# start-all.ps1 —— Apex ESP 一键启动
# 用法：右键"使用 PowerShell 运行"，或在管理员 PowerShell 里执行
# 作用：映射驱动 → 启动 overlay → 等待游戏

$ErrorActionPreference = 'SilentlyContinue'
$root = 'E:\Users\MYX\Desktop\test-game\inject-kit'
$kdmapper = 'E:\Users\MYX\Desktop\test-game\kdmapper\kdmapper\x64\Release\kdmapper_Release.exe'
$driver = Join-Path $root 'bin\mdump.sys'
$overlay = Join-Path $root 'bin\overlay.exe'
$kmaplog = 'C:\ProgramData\kmaplog.txt'

Write-Host "=== Apex ESP 启动 ===" -ForegroundColor Cyan

# 0) 管理员检查
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "需要管理员权限，正在提权重启..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# 1) 驱动是否已映射
$mapped = $false
if (Test-Path $kmaplog) {
    $entries = (Get-Content $kmaplog | Select-String '=== entry ===').Count
    if ($entries -gt 0) { $mapped = $true; Write-Host "驱动已映射（实例 $entries）" -ForegroundColor Green }
}

if (-not $mapped) {
    Write-Host "映射驱动中..." -ForegroundColor Yellow
    # 游戏未启动时映射最稳
    $gameProc = Get-Process r5apex_dx12 -ErrorAction SilentlyContinue
    if ($gameProc) {
        Write-Host "  注意：游戏正在运行，映射可能失败。建议先退出游戏。" -ForegroundColor Yellow
    }
    Remove-Item $kmaplog -ErrorAction SilentlyContinue
    & $kdmapper $driver 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $entries = 0
    if (Test-Path $kmaplog) { $entries = (Get-Content $kmaplog | Select-String '=== entry ===').Count }
    if ($entries -eq 1) {
        Write-Host "  驱动映射成功（单实例）" -ForegroundColor Green
    } elseif ($entries -gt 1) {
        Write-Host "  警告：有 $entries 个实例，请重启电脑后再试" -ForegroundColor Red
    } else {
        Write-Host "  映射失败，请确认 EAAntiCheatService 已停止、游戏未运行" -ForegroundColor Red
    }
}

# 2) 配置 overlay
$ini = 'C:\ProgramData\sc_overlay.ini'
if (-not (Test-Path $ini)) {
    @"
gameFov=110
fov=110
offX=0.00
offY=0.00
boxH=72.00
boxW=0.420
pxPerDeg=18.180
assist=1
"@ | Set-Content $ini -Encoding ASCII
    Write-Host "已生成默认配置 $ini" -ForegroundColor Green
}

# 3) 启动 overlay
Get-Process overlay -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
Start-Process -FilePath $overlay -WorkingDirectory $root
Start-Sleep -Seconds 2
$ov = Get-Process overlay -ErrorAction SilentlyContinue
if ($ov) { Write-Host "overlay 已启动 pid=$($ov.Id)" -ForegroundColor Green }
else     { Write-Host "overlay 启动失败" -ForegroundColor Red }

Write-Host ""
Write-Host "=== 就绪 ===" -ForegroundColor Cyan
Write-Host "现在启动 Apex 即可。进入对局后：" -ForegroundColor White
Write-Host "  · 描边自动生效（驱动每 0.25 秒维持）" -ForegroundColor Gray
Write-Host "  · 血条/护甲/名字/距离自动绘制" -ForegroundColor Gray
Write-Host "  · F1/F2 调 FOV，F3/F4 调垂直偏移" -ForegroundColor Gray
Write-Host "  · F7 开关手雷弹道，Shift+左键 自动抬角" -ForegroundColor Gray
