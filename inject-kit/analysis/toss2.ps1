param(
    [double]$TargetPitch,
    [double]$TargetYaw,
    [int]$DoThrow = 0,
    [int]$DoPickup = 0
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class TOSS2 {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, IntPtr e);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, IntPtr e);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int i);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
"@

$ErrorActionPreference = 'SilentlyContinue'
$feedPath = 'C:\ProgramData\sc_feed.bin'

function GetFb {
    $fs = [System.IO.File]::Open($feedPath, 'Open', 'Read', 'ReadWrite')
    $b = New-Object byte[] 60
    [void]$fs.Read($b, 0, 60)
    $fs.Close()
    return $b
}
function GetPitch { $fb = GetFb; return [BitConverter]::ToSingle($fb, 20) }
function GetYaw   { $fb = GetFb; return [BitConverter]::ToSingle($fb, 24) }

$g = Get-Process r5apex_dx12
$hw = $g.MainWindowHandle
for ($i = 0; $i -lt 6; $i++) { [void][TOSS2]::SetForegroundWindow($hw); Start-Sleep -Milliseconds 150 }
Write-Output ("focus=" + ([TOSS2]::GetForegroundWindow() -eq $hw))

$sw = [TOSS2]::GetSystemMetrics(0)
$sh = [TOSS2]::GetSystemMetrics(1)
$cx = [int]($sw / 2)
$cy = [int]($sh / 2)

if ($DoPickup -eq 1) {
    Write-Output "pickup: E"
    [TOSS2]::keybd_event(0x45, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 90
    [TOSS2]::keybd_event(0x45, 0, 2, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 1300
    Write-Output "slot3: grenade"
    [TOSS2]::keybd_event(0x33, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 90
    [TOSS2]::keybd_event(0x33, 0, 2, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 900
}

Write-Output ("start pitch=" + [math]::Round((GetPitch), 2) + " yaw=" + [math]::Round((GetYaw), 2))
Write-Output ("target pitch=" + $TargetPitch + " yaw=" + $TargetYaw)

for ($i = 0; $i -lt 80; $i++) {
    $cur = [double](GetYaw)
    $d = $cur - $TargetYaw
    if ($d -gt 180) { $d -= 360 }
    if ($d -lt -180) { $d += 360 }
    if ([math]::Abs($d) -lt 1.2) { break }
    $px = [int]($d * 18.18)
    if ($px -gt 40) { $px = 40 }
    if ($px -lt -40) { $px = -40 }
    if ($px -eq 0) { if ($d -gt 0) { $px = 1 } else { $px = -1 } }
    [TOSS2]::mouse_event(0x0001, $px, 0, 0, [IntPtr]::Zero)
    [void][TOSS2]::SetCursorPos($cx, $cy)
    Start-Sleep -Milliseconds 18
}
Write-Output ("after yaw=" + [math]::Round((GetYaw), 2))

for ($i = 0; $i -lt 100; $i++) {
    $cur = [double](GetPitch)
    $d = $TargetPitch - $cur
    if ([math]::Abs($d) -lt 1.2) { break }
    $px = [int]($d * 18.18)
    if ($px -gt 40) { $px = 40 }
    if ($px -lt -40) { $px = -40 }
    if ($px -eq 0) { if ($d -gt 0) { $px = 1 } else { $px = -1 } }
    [TOSS2]::mouse_event(0x0001, 0, $px, 0, [IntPtr]::Zero)
    [void][TOSS2]::SetCursorPos($cx, $cy)
    Start-Sleep -Milliseconds 18
}
Write-Output ("after pitch=" + [math]::Round((GetPitch), 2) + " yaw=" + [math]::Round((GetYaw), 2))

if ($DoThrow -eq 1) {
    Write-Output "throwing (hold 1.3s)..."
    [TOSS2]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 1300
    [TOSS2]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Write-Output "thrown"
}
