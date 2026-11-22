# sc-send.ps1 -- send a dump request to the resident driver with retries
# usage: . .\sc-send.ps1 ; Send-Req "0x7FF6... 0x1000"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class ScAtomicMove {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool MoveFileEx(string src, string dst, uint flags);
  public static bool Go(string s, string d) { return MoveFileEx(s, d, 0x1 | 0x8); }
}
'@ -ErrorAction SilentlyContinue

function Send-Req([string]$text, [int]$tries = 4) {
    $tmp = 'C:\ProgramData\sc_req.tmp'
    $dst = 'C:\ProgramData\sc_req.txt'
    for ($t = 1; $t -le $tries; $t++) {
        Remove-Item C:\ProgramData\sc_ack.txt -ErrorAction SilentlyContinue
        [IO.File]::WriteAllText($tmp, $text)
        [ScAtomicMove]::Go($tmp, $dst) | Out-Null
        for ($w = 0; $w -lt 25; $w++) {
            if (Test-Path C:\ProgramData\sc_ack.txt) {
                Start-Sleep -Milliseconds 120
                return (Get-Content C:\ProgramData\sc_ack.txt -Raw).Trim()
            }
            Start-Sleep -Milliseconds 200
        }
        Start-Sleep -Milliseconds 300
    }
    return 'NO ACK'
}
