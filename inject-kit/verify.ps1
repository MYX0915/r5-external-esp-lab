# verify.ps1 —— 重启后一键校验（高亮 + 骨骼 + 队伍字段）
#
# 顺序：重启 → 启动.cmd → 开 Apex 进训练场 → .\verify.ps1
#
# 参数:
#   -Row 200          指定样式行（0 = 自动从 glowfind 结果里挑）
#   -Color "0 0 1"    高亮颜色（默认纯蓝，避免撞原生色）
#   -Team             同时执行 glowteam 0 0 解除队伍过滤
#   -SkipHighlight    只跑骨骼

param(
    [int]$Row = 0,
    [string]$Color = "0 0 1",
    [switch]$Team,
    [switch]$SkipHighlight
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$root = "E:\Users\MYX\Desktop\test-game\inject-kit"
Set-Location $root
. .\sc-send.ps1

function H1($t) { "`n" + ("=" * 64); "  $t"; ("=" * 64) }
function Li($t) { "    $t" }

# ---------------------------------------------------------------- 前置
H1 "0. 前置检查"

$entries = 0
if (Test-Path C:\ProgramData\kmaplog.txt) {
    $entries = (Get-Content C:\ProgramData\kmaplog.txt | Select-String '=== entry ===').Count
}
Li "驱动实例数: $entries"
if ($entries -eq 0) { Li "✗ 驱动未加载：先重启并运行 启动.cmd"; exit 1 }
if ($entries -gt 1) { Li "⚠ 多个实例，请求可能乱序" }

if (-not (Get-Process r5apex_dx12 -ErrorAction SilentlyContinue)) {
    Li "✗ Apex 未运行：启动游戏并进入训练场"; exit 1
}
$modLine = (Get-Content C:\ProgramData\kmaplog.txt | Select-String 'esp loop start' | Select-Object -Last 1).Line
if (-not $modLine) { Li "✗ 驱动还没 attach（日志无 esp loop start）"; exit 1 }
$mod = [Convert]::ToUInt64(("0x" + ($modLine -replace '.*module=0x', '')), 16)
$dummyVt = $mod + 0x30E9330
Li ("模块基址: 0x{0:X}" -f $mod)
Li ("假人类:   0x{0:X}" -f $dummyVt)

Li "枚举假人..."
Send-Req ("ent 0x{0:X}`r`n" -f $dummyVt) | Out-Null
Start-Sleep -Seconds 2
$insts = @()
if (Test-Path C:\ProgramData\sc_ents.txt) {
    $insts = (Get-Content C:\ProgramData\sc_ents.txt) | Where-Object { $_ -match '^0x' } |
        ForEach-Object { ($_ -split ' ')[0] }
}
Li "假人数量: $($insts.Count)"
if ($insts.Count -eq 0) { Li "✗ 没找到假人，确认在训练场"; exit 1 }
$target = $insts[0]
Li "测试对象: $target"

# ---------------------------------------------------------------- 偏移诊断
H1 "0.5 偏移诊断（locdump + possel）"
Li "偏移表: localplayerHandle 0x3d3a8d0 / LocalPlayer 0x3eac668 / m_vecAbsOrigin 0x170"
Li "驱动默认: 句柄 0x3D3DCD0 / 坐标 0x978 -> 0x7830 -> 0x376C"
Send-Req "locdump`r`n" | Out-Null
Start-Sleep -Seconds 1
if (Test-Path C:\ProgramData\sc_loc.txt) {
    Get-Content C:\ProgramData\sc_loc.txt | ForEach-Object { Li $_ }
} else { Li "✗ 无输出" }

Li ""
Li "切换到 m_vecAbsOrigin 0x170 测试"
Send-Req "possel 0x170`r`n" | Out-Null
Start-Sleep -Milliseconds 500
Send-Req "possel`r`n" | Out-Null
Start-Sleep -Milliseconds 500
Get-Content C:\ProgramData\kmaplog.txt | Select-String 'possel' | Select-Object -Last 2 | ForEach-Object { Li $_.Line }
Li "（跑一会儿再看 possel 无参数输出的命中统计，posOff 命中数 >0 说明 0x170 有效）"

# ---------------------------------------------------------------- 骨骼
H1 "1. 骨骼（bonescan 签名搜索）"
Li "依据 UC Wiki 索引表：0=delta 4=hip 7=spineC 11=neckB 12=head"
Send-Req ("bonescan {0}`r`n" -f $target) | Out-Null
Start-Sleep -Seconds 3
if (Test-Path C:\ProgramData\sc_bonescan.txt) {
    Get-Content C:\ProgramData\sc_bonescan.txt | ForEach-Object { Li $_ }
} else { Li "✗ 无输出" }
Li ""
Li "判据：命中后看 h=（head.z - origin.z）是否在 60~80（人体比例）"

# ---------------------------------------------------------------- 血量字段
H1 "1.5 血量字段（hptest）"
Li "DT_Player: m_iHealth 0x330 / m_bleedoutState 0x27A8 / m_damageComboStartHealth 0x2968"
Li "           m_tempShieldHealth 0x3034 / m_extraShieldHealth 0x3038"
Send-Req ("hptest {0}`r`n" -f $target) | Out-Null
Start-Sleep -Seconds 2
if (Test-Path C:\ProgramData\sc_hp.txt) {
    Get-Content C:\ProgramData\sc_hp.txt | ForEach-Object { Li $_ }
} else { Li "✗ 无输出" }
Li ""
Li "判据：训练场假人 m_iHealth 应该是 100"
Li "      对局中打敌人后 m_damageComboStartHealth 是否变成非零 ← 关键"

# ---------------------------------------------------------------- 高亮
if (-not $SkipHighlight) {
    H1 "2. 高亮：队伍字段 / 行原生值 / 空闲行"

    Li "glowfields —— 重点看 0x1D4 / 0x1E4 是否非零"
    Send-Req ("glowfields {0}`r`n" -f $target) | Out-Null
    Start-Sleep -Seconds 1
    if (Test-Path C:\ProgramData\sc_glowfields.txt) {
        Get-Content C:\ProgramData\sc_glowfields.txt | ForEach-Object { Li $_ }
    } else { Li "✗ 无输出" }

    Li ""
    Li "glowdump 50 —— 行 50 原生 functionBits / Flags / DrawFunc"
    Send-Req "glowdump 50`r`n" | Out-Null
    Start-Sleep -Seconds 1
    Get-Content C:\ProgramData\kmaplog.txt | Select-String 'functionBits|color=' |
        Select-Object -Last 4 | ForEach-Object { Li ($_.Line -replace '\[mdump\] ', '') }

    Li ""
    Li "glowfind —— 空闲行"
    Send-Req "glowfind`r`n" | Out-Null
    Start-Sleep -Seconds 2
    Get-Content C:\ProgramData\kmaplog.txt | Select-String 'glowfind' |
        Select-Object -Last 4 | ForEach-Object { Li $_.Line }

    H1 "3. 配置样式行 + 单实体写入"

    if ($Row -eq 0) {
        $line = (Get-Content C:\ProgramData\kmaplog.txt | Select-String 'glowfind zero_rows') | Select-Object -Last 1
        $cand = (Get-Content C:\ProgramData\kmaplog.txt | Where-Object { $_ -match '^\d[\d\s]+$' } | Select-Object -Last 1)
        if ($cand) {
            $n = ($cand -split '\s+') | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
            if ($n) { $Row = [int]$n }
        }
        if ($Row -eq 0) { $Row = 200; Li "未解析到空闲行，暂用 200（先确认它确实为空）" }
    }
    Li "样式行: $Row   颜色: $Color"

    Li "clone 50 -> $Row"
    Send-Req ("glowclone 50 {0}`r`n" -f $Row) | Out-Null
    Start-Sleep -Milliseconds 600

    Li "glowrow 整行写入（解除距离/视线约束）"
    Send-Req ("glowrow {0} {1}`r`n" -f $Row, $Color) | Out-Null
    Start-Sleep -Milliseconds 600

    if ($Team) {
        Li "glowteam 0 0（解除队伍过滤）"
        Send-Req "glowteam 0 0`r`n" | Out-Null
        Start-Sleep -Milliseconds 400
    }

    Li "验证该行"
    Send-Req ("glowdump {0}`r`n" -f $Row) | Out-Null
    Start-Sleep -Milliseconds 800
    Get-Content C:\ProgramData\kmaplog.txt | Select-String 'functionBits|color=' |
        Select-Object -Last 4 | ForEach-Object { Li ($_.Line -replace '\[mdump\] ', '') }

    Li ""
    Li "对【单个假人】执行四步写入"
    $b = [Convert]::ToUInt64($target.Replace('0x', ''), 16)
    Send-Req ("w 0x{0:X} {1}`r`n" -f ($b + 0x2A0), $Row.ToString('X2')) | Out-Null
    Start-Sleep -Milliseconds 250
    Send-Req ("w 0x{0:X} 01000000`r`n" -f ($b + 0x2A8)) | Out-Null   # focused bit0
    Start-Sleep -Milliseconds 250
    Send-Req ("w 0x{0:X} 0000803F`r`n" -f ($b + 0x2AC)) | Out-Null   # 1.0f
    Start-Sleep -Milliseconds 250
    Li "已写 contexts[0] / focused / fadeDuration"
    Li "parity 由 glowauto 的首次见实体逻辑翻转，或手动 glowauto 1 $Row $Color"
}

# ---------------------------------------------------------------- 判据
H1 "4. 人工判定（缺一不可）"
@"
  【骨骼】
  □ bonescan 是否命中（hits > 0）
  □ 命中的 h= 是否在 60~80 单位
  □ 若 stride 0x30/0x40 都不命中 → 试 0x20 / 0x48 / 0x60

  【偏移】
  □ locdump 三个候选里哪个 ser_match=1 且有相机值
  □ possel 0x170 后，posOff 命中数是否 > 0
  □ 若 0x170 有效 → 可简化 ReadEntPos 三级回退

  【血量】
  □ 假人 m_iHealth 是否 = 100（基准正确性）
  □ 对局中打敌人后 m_damageComboStartHealth 是否非零
  □ m_bleedoutState 是否随倒地变化（0=正常）
  □ m_tempShieldHealth / m_extraShieldHealth 是否反映临时护盾

  【高亮】
  □ 0x1D4 / 0x1E4 是否非零（非零 ⇒ 队伍过滤是卡点）
  □ 行 50 的 Flags / DrawFunc 原生值是多少
  □ 蓝色剪影是否出现在 overlay 框住的【同一个假人】身上
  □ 颜色是否纯蓝（不是原生橙/红/黄）
  □ 关闭后是否立即消失
  □ 换另一个假人重复，结果是否一致
"@
