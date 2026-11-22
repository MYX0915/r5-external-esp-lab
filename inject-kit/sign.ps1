#Requires -RunAsAdministrator
<#
  sign.ps1 - sign kmap.sys with a lab self-signed cert and register the driver service.

  Usage (elevated PowerShell):
    .\sign.ps1 -Action status      # show testsigning / secureboot / hvci / service state
    .\sign.ps1 -Action cert        # create (or reuse) the lab code-signing cert
    .\sign.ps1 -Action sign        # sign bin\kmap.sys
    .\sign.ps1 -Action enable      # bcdedit /set testsigning on   (needs reboot)
    .\sign.ps1 -Action install     # sc create + sc start
    .\sign.ps1 -Action uninstall   # sc stop + sc delete
    .\sign.ps1 -Action cleanup     # uninstall + remove certs + testsigning off
#>
param(
    [ValidateSet('status', 'cert', 'sign', 'enable', 'install', 'uninstall', 'cleanup')]
    [string]$Action = 'status'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sys = Join-Path $root 'bin\kmap.sys'
$svc = 'KmapDrv'
$subj = 'CN=KmapLab-CodeSigning'

function Get-SignTool {
    $c = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
    if ($c) { return $c.FullName }
    throw 'signtool.exe not found (install Windows SDK)'
}

function Show-Status {
    Write-Host '== boot / protection ==' -ForegroundColor Cyan
    $bcd = (bcdedit /enum '{current}') -join "`n"
    foreach ($k in 'testsigning', 'nointegritychecks', 'hypervisorlaunchtype') {
        $line = ($bcd -split "`n" | Where-Object { $_ -match $k }) -join ' '
        Write-Host ("  {0,-22} {1}" -f $k, ($(if ($line) { $line.Trim() } else { '(not set)' })))
    }
    $sb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
    Write-Host ("  {0,-22} {1}" -f 'SecureBoot', $sb)
    $hvci = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue).Enabled
    Write-Host ("  {0,-22} {1}" -f 'HVCI', $hvci)
    Write-Host '== service ==' -ForegroundColor Cyan
    sc.exe query $svc 2>&1 | ForEach-Object { "  $_" }
    Write-Host '== cert ==' -ForegroundColor Cyan
    Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $subj |
        Select-Object Subject, Thumbprint, NotAfter | Format-Table | Out-String | Write-Host
}

function New-LabCert {
    $existing = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $subj | Select-Object -First 1
    if ($existing) {
        Write-Host "[=] reuse cert $($existing.Thumbprint)"
        $c = $existing
    } else {
        $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subj `
             -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
             -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(3)
        Write-Host "[+] created cert $($c.Thumbprint)"
    }

    # Import-Certificate 只接受 -FilePath，不接受证书对象（写成 -Cert 会报
    # "CertStoreLocation 被指定了多次" 这种误导性错误）
    $cer = Join-Path $root 'kmaplab.cer'
    Export-Certificate -Cert $c -FilePath $cer -Force | Out-Null

    foreach ($store in 'Root', 'TrustedPublisher') {
        $loc = "Cert:\LocalMachine\$store"
        $already = Get-ChildItem $loc | Where-Object Thumbprint -eq $c.Thumbprint
        if (-not $already) {
            Import-Certificate -FilePath $cer -CertStoreLocation $loc | Out-Null
            Write-Host "[+] trusted in LocalMachine\$store"
        } else {
            Write-Host "[=] already in LocalMachine\$store"
        }
    }
    return $c
}

function Invoke-Sign {
    if (-not (Test-Path $sys)) { throw "missing $sys (run build.cmd first)" }
    $st = Get-SignTool
    $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $subj | Select-Object -First 1
    if (-not $c) { $c = New-LabCert }
    # /sm = 本机存储（LocalMachine\My）；不加 /sm 时 signtool 只查当前用户存储
    & $st sign /fd SHA256 /sha1 $c.Thumbprint /s My /sm $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }
    & $st verify /pa /v $sys | Select-Object -Last 6
    (Get-AuthenticodeSignature $sys) | Select-Object Status, SignerCertificate | Format-List
}

switch ($Action) {
    'status' { Show-Status }
    'cert'   { New-LabCert | Out-Null; Write-Host '[+] done' }
    'sign'   { Invoke-Sign; Write-Host '[+] signed' }
    'enable' {
        bcdedit /set testsigning on
        Write-Host '[!] reboot required: shutdown /r /t 0' -ForegroundColor Yellow
        bcdedit /set nointegritychecks off | Out-Null
    }
    'install' {
        $full = (Resolve-Path $sys).Path
        sc.exe create $svc type= kernel start= demand error= normal binPath= "$full"
        sc.exe start $svc
        Write-Host '[+] installed (if start fails: 577/577 = signature, 1275 = driver blocked by AV)' -ForegroundColor Yellow
    }
    'uninstall' {
        sc.exe stop $svc | Out-Null
        sc.exe delete $svc | Out-Null
        Write-Host '[+] service removed'
    }
    'cleanup' {
        sc.exe stop $svc | Out-Null
        sc.exe delete $svc | Out-Null
        Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher |
            Where-Object Subject -eq $subj | Remove-Item -Force
        bcdedit /set testsigning off
        Write-Host '[+] cleanup done, reboot to leave testsigning mode'
    }
}
