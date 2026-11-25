# start-all.ps1 —— Apex ESP 一键启动
# 用法：双击 启动.cmd（会自动提权）
# 作用：映射驱动 → 启动 overlay

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
    Write-Host "需要管理员权限，正在提权..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# 1) 驱动是否已映射
$mapped = $false
$entries = 0
if (Test-Path $kmaplog) {
    $entries = (Get-Content $kmaplog | Select-String '=== entry ===').Count
    if ($entries -gt 0) {
        $mapped = $true
        Write-Host "驱动已映射（实例 $entries）" -ForegroundColor Green
    }
}

if (-not $mapped) {
    Write-Host "映射驱动中..." -ForegroundColor Yellow
    if (Get-Process r5apex_dx12 -ErrorAction SilentlyContinue) {
        Write-Host "  注意：游戏正在运行，映射可能失败" -ForegroundColor Yellow
    }
    Remove-Item $kmaplog -ErrorAction SilentlyContinue
    & $kdmapper $driver | Out-Null
    Start-Sleep -Seconds 3
    $entries = 0
    if (Test-Path $kmaplog) { $entries = (Get-Content $kmaplog | Select-String '=== entry ===').Count }
    if ($entries -eq 1) {
        Write-Host "  映射成功（单实例）" -ForegroundColor Green
    } elseif ($entries -gt 1) {
        Write-Host "  警告：$entries 个实例，请重启电脑" -ForegroundColor Red
    } else {
        Write-Host "  映射失败：确认游戏未运行、EAAntiCheatService 已停止" -ForegroundColor Red
    }
}

# 2) 配置 overlay
$ini = 'C:\ProgramData\sc_overlay.ini'
if (-not (Test-Path $ini)) {
    $conf = "gameFov=110`nfov=110`noffX=0.00`noffY=0.00`nboxH=72.00`nboxW=0.420`npxPerDeg=18.180`nassist=1"
    Set-Content -Path $ini -Value $conf -Encoding ASCII
    Write-Host "已生成默认配置" -ForegroundColor Green
}

# 3) 启动 overlay
Get-Process overlay -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
Start-Process -FilePath $overlay -WorkingDirectory $root
Start-Sleep -Seconds 2
$ov = Get-Process overlay -ErrorAction SilentlyContinue
if ($ov) {
    Write-Host "overlay 已启动 pid=$($ov.Id)" -ForegroundColor Green
} else {
    Write-Host "overlay 启动失败" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== 就绪，现在启动 Apex ===" -ForegroundColor Cyan
Write-Host "  F1/F2 调 FOV     F3/F4 调垂直偏移" -ForegroundColor Gray
Write-Host "  F7 手雷弹道      Shift+左键 自动抬角" -ForegroundColor Gray
