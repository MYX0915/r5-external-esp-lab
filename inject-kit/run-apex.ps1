# run-apex.ps1 -- 等待目标进程出现后做两级验证
#   1) probe   : 在目标里跑 16 字节壳，只写哨兵 -> 证明"内核级代码执行"
#   2) loadlib : 调目标自己的 LoadLibraryW 装载 payload.dll -> 证明"DLL 注入"
#
# 用法:
#   .\run-apex.ps1                       # 等 r5apex_dx12，最多 10 分钟
#   .\run-apex.ps1 -ProcessName target -TimeoutSec 30   # 用靶进程演练
param(
    [string]$ProcessName = 'r5apex_dx12',
    [int]$TimeoutSec = 900,
    [int]$SettleSec = 45,        # 等游戏把引擎/反作弊都拉起来再动手
    [int]$MinThreads = 10,
    [string]$Dll = 'payload.dll'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[-] $m" -ForegroundColor Red }

# ---- 1. 驱动就绪 ----
$q = sc.exe query KmapDrv 2>&1 | Out-String
if ($q -notmatch 'RUNNING') {
    Info 'driver not running, starting...'
    sc.exe start KmapDrv | Out-Null
    Start-Sleep 2
}
$ping = & .\bin\kmapctl.exe ping 2>&1
if ($ping -notmatch 'pong') { Bad "driver ping failed: $ping"; exit 1 }
Ok 'driver ready'

# ---- 2. 等进程 ----
Info "waiting for $ProcessName (up to $TimeoutSec s)..."
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$proc = $null
while ((Get-Date) -lt $deadline) {
    $proc = Get-Process $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $proc) { Bad "process $ProcessName not found"; exit 2 }

$pidTarget = $proc.Id
$modBase = $null
try { $modBase = $proc.MainModule.BaseAddress.ToInt64() } catch {}
Ok "found $ProcessName pid=$pidTarget threads=$($proc.Threads.Count) base=$('{0:X}' -f $modBase)"

# ---- 2.5 让进程"坐稳"：等引擎初始化完再注入，避免打在 AC 初始化窗口里 ----
Info "settling ${SettleSec}s (wait engine/AC init)..."
$settleEnd = (Get-Date).AddSeconds($SettleSec)
while ((Get-Date) -lt $settleEnd) {
    $proc = Get-Process -Id $pidTarget -ErrorAction SilentlyContinue
    if (-not $proc) { Bad "process exited while settling"; exit 5 }
    Start-Sleep -Seconds 1
}
$proc = Get-Process -Id $pidTarget -ErrorAction SilentlyContinue
if (-not $proc) { Bad "process exited"; exit 5 }
if ($proc.Threads.Count -lt $MinThreads) { Info "only $($proc.Threads.Count) threads (engine may still be loading)" }
Ok "settled: threads=$($proc.Threads.Count) ws=$([math]::Round($proc.WorkingSet64/1MB))MB"

# ---- 3. probe：内核级代码执行 ----
$dllPath = Join-Path $root ("bin\" + $Dll)
if (-not (Test-Path $dllPath)) { Bad "missing $dllPath"; exit 3 }

$out = & .\bin\kmapctl.exe inject $pidTarget $dllPath probe 2>&1
$out | ForEach-Object { "    $_" }
$shell = ($out | Select-String 'shell=(0x[0-9A-Fa-f]+)').Matches
if (-not $shell.Count) { Bad 'probe: no shell address returned'; exit 4 }

$sentAddr = '{0:X}' -f ([uint64]$shell[0].Groups[1].Value + 0x800)
Start-Sleep -Milliseconds 800
$sent = & .\bin\kmapctl.exe read $pidTarget $sentAddr 4 2>&1
$sentLine = ($sent | Select-String '^\s*[0-9A-F]{16}\s+(.+)$')
if ($sentLine -and $sentLine.Matches[0].Groups[1].Value -match 'AA AA AA AA') {
    Ok 'probe: sentinel=AAAAAAAA  -> kernel-level code execution works in target'
    $probeOk = $true
} else {
    Bad "probe: sentinel not set ($sent)"
    $probeOk = $false
}

# ---- 4. loadlib：DLL 注入 ----
$out2 = & .\bin\kmapctl.exe inject $pidTarget $dllPath 2>&1
$out2 | ForEach-Object { "    $_" }
Start-Sleep -Milliseconds 1500

$dllBase = & .\bin\kmapctl.exe base $pidTarget $Dll 2>&1
$dllBaseLine = ($dllBase | Select-String 'base = (0x[0-9A-Fa-f]+)')
$loaded = $dllBaseLine -and $dllBaseLine.Matches[0].Groups[1].Value -ne '0x0'

$proof = Join-Path $env:TEMP 'kmap-injected.txt'
if (Test-Path $proof) {
    $last = Get-Content $proof -Tail 1
    Ok "payload proof: $last"
} else { $last = '(no proof file)' }

Write-Host ''
Write-Host '================ SUMMARY ================' -ForegroundColor Yellow
Write-Host ("  process      : {0} (pid {1})" -f $ProcessName, $pidTarget)
Write-Host ("  probe  (exec): {0}" -f $(if ($probeOk) { 'PASS  (code ran in target)' } else { 'FAIL' }))
Write-Host ("  loadlib(dll) : {0}" -f $(if ($loaded) { "PASS  (module registered: $($dllBaseLine.Matches[0].Groups[1].Value))" } else { 'FAIL' }))
Write-Host ("  proof file   : {0}" -f $last)
Write-Host '=========================================' -ForegroundColor Yellow
