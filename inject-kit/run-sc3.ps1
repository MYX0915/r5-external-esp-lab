# run-sc3.ps1 -- one-shot pipeline for sc3.sys inside Apex (Javelin must be down while mapping)
#
#   .\run-sc3.ps1 -Phase 3                    # full chain: zero-page slot + pte nx clear + user apc
#   .\run-sc3.ps1 -Phase 1                    # read-only slot scan + canary only
#   .\run-sc3.ps1 -NoLaunch                   # map only, do not start the game
#   .\run-sc3.ps1 -TargetPid 24160 -NoStop    # dry run against a local target process
#
# why the dance: Javelin makes NtLoadDriver return 0xC000009A while the game (or its
# service) is alive, so the driver must be mapped first and then wait for the game.
param(
    [int]$Phase = 3,
    [string]$TargetName = 'r5apex_dx12.exe',
    [int]$TargetPid = 0,
    [string]$AppId = '1172470',
    [int]$Retries = 60,
    [int]$RetryGap = 6000,
    [int]$Limit = 900,
    [switch]$NoLaunch,
    [switch]$NoStop
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$kmapExe = 'E:\Users\MYX\Desktop\test-game\kdmapper\kdmapper\x64\Release\kdmapper_Release.exe'
$drv     = Join-Path $root 'bin\sc3.sys'
$jobPath = 'C:\ProgramData\sc_job.txt'
$logPath = 'C:\ProgramData\kmaplog.txt'

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[-] $m" -ForegroundColor Red }

if (-not (Test-Path $drv)) { Bad "missing $drv (run build-sc.cmd sc3)"; exit 1 }

# 1) clear the way -- the game and the anti-cheat service must both be gone
if (-not $NoStop) {
    Get-Process -Name ($TargetName -replace '\.exe$', '') -ErrorAction SilentlyContinue | ForEach-Object {
        Info "stopping $($_.ProcessName) pid=$($_.Id)"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    if ($TargetPid -ne 0) { Stop-Process -Id $TargetPid -Force -ErrorAction SilentlyContinue }
    $svc = Get-Service EAAntiCheatService -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Info 'stopping EAAntiCheatService'
        sc.exe stop EAAntiCheatService | Out-Null
        for ($i = 0; $i -lt 20 -and (Get-Service EAAntiCheatService).Status -ne 'Stopped'; $i++) { Start-Sleep 1 }
    }
    Ok "service=$((Get-Service EAAntiCheatService -ErrorAction SilentlyContinue).Status)"
}

# 2) job file
$pidLine = if ($TargetPid -ne 0) { $TargetPid } else { 0 }
$job = "pid=$pidLine`r`nname=$TargetName`r`nphase=$Phase`r`nsamples=2`r`ngap=100`r`nlimit=$Limit`r`nflush=ipi`r`nretries=$Retries`r`nretrygap=$RetryGap`r`n"
[IO.File]::WriteAllText($jobPath, $job, [Text.Encoding]::ASCII)
Remove-Item $logPath -ErrorAction SilentlyContinue
Info "job written: $($job -replace "`r`n", ' ')"

# 3) map
Info 'mapping sc3.sys via kdmapper'
& $kmapExe $drv 2>&1 | Select-Object -Last 3 | ForEach-Object { "    $_" }
if (-not (Test-Path $logPath)) { Bad 'driver did not start (no log)'; exit 2 }

# 4) launch the game
if (-not $NoLaunch -and $TargetPid -eq 0) {
    Info "launching appid $AppId"
    Start-Process "steam://rungameid/$AppId"
}

# 5) tail until the driver prints done/injection
$deadline = (Get-Date).AddMinutes(6)
while ((Get-Date) -lt $deadline) {
    Start-Sleep 3
    $tail = Get-Content $logPath -ErrorAction SilentlyContinue
    if ($tail -match '\[sc3\] done' -or $tail -match 'INJECTION OK') { break }
}

Write-Host ''
Write-Host '================ SC3 LOG ================' -ForegroundColor Yellow
Get-Content $logPath -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
Write-Host '=========================================' -ForegroundColor Yellow

$g = Get-Process -Name ($TargetName -replace '\.exe$', '') -ErrorAction SilentlyContinue
if ($g) { Ok "target still alive: pid=$($g.Id)" } else { Bad 'target not running' }
