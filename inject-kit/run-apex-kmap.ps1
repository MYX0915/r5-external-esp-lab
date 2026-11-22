# run-apex-kmap.ps1 -- wait for target, then map kinject.sys via kdmapper and inject
param(
    [string]$ProcessName = 'r5apex_dx12',
    [int]$TimeoutSec = 900,
    [int]$SettleSec = 30,
    [string]$Dll = 'payload.dll'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$kmapExe = 'E:\Users\MYX\Desktop\test-game\kdmapper\kdmapper\x64\Release\kdmapper_Release.exe'
$kinject = Join-Path $root 'bin\kinject.sys'
$job     = 'C:\ProgramData\kmap_job.txt'
$log     = 'C:\ProgramData\kmaplog.txt'

function Info($m) { Write-Host "[*] $m" }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[-] $m" -ForegroundColor Red }

# 0) kdmapper present? (AV may delete it)
if (-not (Test-Path $kmapExe)) {
    Info 'kdmapper missing, rebuilding...'
    Push-Location 'E:\Users\MYX\Desktop\test-game\kdmapper'
    & 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe' `
        kdmapper\kdmapper.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m /v:quiet | Out-Null
    Pop-Location
    if (-not (Test-Path $kmapExe)) { Bad 'kdmapper rebuild failed'; exit 1 }
}
Ok 'kdmapper ready'

# 1) wait for process
Info "waiting for $ProcessName (up to $TimeoutSec s)..."
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$proc = $null
while ((Get-Date) -lt $deadline) {
    $proc = Get-Process $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $proc) { Bad 'process not found'; exit 2 }
$pidTarget = $proc.Id
Ok "found pid=$pidTarget threads=$($proc.Threads.Count)"

# 2) settle
Info "settling ${SettleSec}s..."
$end = (Get-Date).AddSeconds($SettleSec)
while ((Get-Date) -lt $end) {
    if (-not (Get-Process -Id $pidTarget -ErrorAction SilentlyContinue)) { Bad 'process exited while settling'; exit 3 }
    Start-Sleep -Seconds 1
}
$proc = Get-Process -Id $pidTarget -ErrorAction SilentlyContinue
Ok "settled: threads=$($proc.Threads.Count) ws=$([math]::Round($proc.WorkingSet64/1MB))MB"

# 3) write job
$dllPath = Join-Path $root ("bin\" + $Dll)
[IO.File]::WriteAllText($job, "$pidTarget`r`n$dllPath`r`n", [Text.Encoding]::ASCII)
Remove-Item $log -ErrorAction SilentlyContinue

# 4) map injector
Info 'mapping kinject.sys via kdmapper...'
& $kmapExe $kinject 2>&1 | Select-Object -Last 4 | ForEach-Object { "    $_" }

Start-Sleep -Seconds 3
Write-Host ''
Write-Host '================ DRIVER LOG ================' -ForegroundColor Yellow
Get-Content $log -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
Write-Host '===========================================' -ForegroundColor Yellow
$proof = Join-Path $env:TEMP 'kmap-injected.txt'
if (Test-Path $proof) { Ok ('proof: ' + (Get-Content $proof -Tail 1)) } else { Bad 'no proof file yet' }
