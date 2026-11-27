# glowtest.ps1 —— 高亮验证三步流程（按文档第 121.4 / 122.8 节的判据）
#
# 用法（管理员 PowerShell）:
#   .\glowtest.ps1                 # 跑全部三步
#   .\glowtest.ps1 -Step 1         # 只跑第 1 步（队伍字段 + 行 dump + 空闲行）
#   .\glowtest.ps1 -Step 2 -Row 200 -Color "0 0 1"   # 第 2 步：配置单个实体
#
# 前提:
#   · 已重启并映射新驱动（kmaplog 里 entry 计数 = 1）
#   · Apex 已进入训练场（假人存在，且本地玩家实体可读）

param(
    [int]$Step = 0,
    [int]$Row = 0,            # 0 = 自动挑一个空闲行
    [string]$Color = "0 0 1", # 纯蓝，避免和原生高亮撞色
    [switch]$NoTeam
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$root = "E:\Users\MYX\Desktop\test-game\inject-kit"
Set-Location $root
. .\sc-send.ps1

function Section($t) { "`n" + ("=" * 62); "  $t"; ("=" * 62) }
function Note($t)    { "  · $t" }

# ---------------- 前置检查 ----------------
Section "0. 前置检查"

$entries = 0
if (Test-Path C:\ProgramData\kmaplog.txt) {
    $entries = (Get-Content C:\ProgramData\kmaplog.txt | Select-String '=== entry ===').Count
}
"  驱动实例数: $entries"
if ($entries -eq 0) { "  ✗ 驱动未加载，先重启并跑 启动.cmd"; exit 1 }
if ($entries -gt 1) { "  ⚠ 有多个实例，请求可能乱序，建议重启" }

$game = Get-Process r5apex_dx12 -ErrorAction SilentlyContinue
"  游戏进程: $(if ($game) { "pid=$($game.Id)" } else { '未运行' })"
if (-not $game) { "  ✗ 先启动 Apex 并进入训练场"; exit 1 }

# 模块基址 + 假人类地址
$modLine = (Get-Content C:\ProgramData\kmaplog.txt | Select-String 'esp loop start' | Select-Object -Last 1).Line
if (-not $modLine) { "  ✗ 日志里没有 esp loop start，驱动还没 attach"; exit 1 }
$mod = [Convert]::ToUInt64(("0x" + ($modLine -replace '.*module=0x', '')), 16)
$dummyVt = $mod + 0x30E9330
"  模块基址: 0x{0:X}" -f $mod
"  假人类地址: 0x{0:X}" -f $dummyVt

# ---------------- 第 1 步：队伍字段 + 行 dump + 空闲行 ----------------
Section "1. 队伍字段 / 样式行原生值 / 空闲行"

Note "枚举假人实体..."
Send-Req ("ent 0x{0:X}`r`n" -f $dummyVt) | Out-Null
Start-Sleep -Seconds 2
$insts = @()
if (Test-Path C:\ProgramData\sc_ents.txt) {
    $insts = (Get-Content C:\ProgramData\sc_ents.txt) | Where-Object { $_ -match '^0x' } | ForEach-Object { ($_ -split ' ')[0] }
}
"  假人实例: $($insts.Count) 个"
if ($insts.Count -eq 0) {
    "  ✗ 没找到假人，确认在训练场"
    exit 1
}
$target = $insts[0]
"  测试对象: $target"

Note "glowfields —— 看 0x1D4 / 0x1E4 是否非零（队伍过滤线索）"
Send-Req ("glowfields {0}`r`n" -f $target) | Out-Null
Start-Sleep -Seconds 1
if (Test-Path C:\ProgramData\sc_glowfields.txt) {
    Get-Content C:\ProgramData\sc_glowfields.txt | ForEach-Object { "    $_" }
} else { "    ✗ 没有输出（驱动版本旧？）" }

Note "glowdump 50 —— 行 50 的原生 functionBits / Flags / DrawFunc"
Send-Req "glowdump 50`r`n" | Out-Null
Start-Sleep -Seconds 1
Get-Content C:\ProgramData\kmaplog.txt | Select-String 'glowdump|functionBits|color=' |
    Select-Object -Last 12 | ForEach-Object { "    " + ($_.Line -replace '\[mdump\] ', '') }

Note "glowfind —— 找可用的空闲行"
Send-Req "glowfind`r`n" | Out-Null
Start-Sleep -Seconds 2
Get-Content C:\ProgramData\kmaplog.txt | Select-String 'glowfind|^[0-9 ]+$' |
    Select-Object -Last 8 | ForEach-Object { "    " + $_.Line }

if ($Step -eq 1) { exit 0 }

# ---------------- 第 2 步：单实体高亮 ----------------
Section "2. 单实体高亮（只写这一个假人）"

if ($Row -eq 0) {
    # 从 glowfind 输出里取第一个空闲行
    $zf = (Get-Content C:\ProgramData\kmaplog.txt | Select-String 'glowfind zero_rows') | Select-Object -Last 1
    $rowCandidates = (Get-Content C:\ProgramData\kmaplog.txt | Select-String '^[0-9 ]+\s*$' | Select-Object -Last 1).Line
    if ($rowCandidates) {
        $Row = [int](($rowCandidates -split '\s+') | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
    }
    if (-not $Row -or $Row -eq 0) { $Row = 200; Note "没解析到空闲行，默认用 200（先确认它确实是空的）" }
}
"  使用样式行: $Row"
"  颜色: $Color"

Note "克隆行 50（继承半径 64 + 绘制位）"
Send-Req ("glowclone 50 {0}`r`n" -f $Row) | Out-Null
Start-Sleep -Milliseconds 600

Note "整行写入（解除距离/视线/队伍约束）"
Send-Req ("glowrow {0} {1}`r`n" -f $Row, $Color) | Out-Null
Start-Sleep -Milliseconds 600

if ($NoTeam) {
    Note "glowteam 0 0（解除队伍过滤）"
    Send-Req "glowteam 0 0`r`n" | Out-Null
    Start-Sleep -Milliseconds 400
}

Note "验证该行"
Send-Req ("glowdump {0}`r`n" -f $Row) | Out-Null
Start-Sleep -Milliseconds 800
Get-Content C:\ProgramData\kmaplog.txt | Select-String 'functionBits|color=' |
    Select-Object -Last 4 | ForEach-Object { "    " + ($_.Line -replace '\[mdump\] ', '') }

Note "对单个假人执行四步写入"
$seq = ""
$seq += ("w {0} {1}`r`n" -f ([Convert]::ToUInt64($target.Replace('0x',''),16) + 0x2A0), $Row.ToString("X2"))   # contexts[0]
Send-Req $seq | Out-Null
Start-Sleep -Milliseconds 300
$b = [Convert]::ToUInt64($target.Replace('0x',''),16)
Send-Req ("w 0x{0:X} 01000000`r`n" -f ($b + 0x2A8)) | Out-Null   # focused bit0
Start-Sleep -Milliseconds 300
Send-Req ("w 0x{0:X} 0000803F`r`n" -f ($b + 0x2AC)) | Out-Null # fadeDuration = 1.0f
Start-Sleep -Milliseconds 300

Note "parity 翻转（读当前值再异或）"
Send-Req ("r 0x{0:X} 4`r`n" -f ($b + 0x2B4)) | Out-Null
Start-Sleep -Milliseconds 500
$par = (Get-Content C:\ProgramData\kmaplog.txt | Select-String 'req.*done' | Select-Object -Last 1)
"    已写入四步。"
"`n  ⚠ parity 需要按当前值异或，这里没自动做："
"     先跑 glow 的自动路径（glowauto）它会在首次见到实体时翻转 parity"
"     手动验证时可以用：glowauto 1 $Row $Color"

Section "3. 请人工判定（121.4 判据）"
@"
  □ 蓝色剪影是否出现在 overlay 框住的【同一个假人】身上
  □ 颜色是否为纯蓝（不是原生的橙/红/黄）
  □ 关闭后是否立即消失
  □ 换另一个假人重复，结果是否一致

  任何一条不满足 → 高亮仍未验证通过
  日志里若有 glowrow reclaimed, re-applied → 说明行被引擎回收，自动修复生效
"@
