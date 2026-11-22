@echo off
rem setup-admin.cmd -- self-elevating: status -> cert -> sign -> install -> status
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [*] requesting administrator...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ================ STATUS (before) ================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Action status

echo.
echo ================ CREATE CERT ===================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Action cert
if errorlevel 1 goto fail

echo.
echo ================ SIGN DRIVER ===================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Action sign
if errorlevel 1 goto fail

echo.
echo ================ INSTALL SERVICE ===============
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Action install
if errorlevel 1 goto fail

echo.
echo ================ PING DRIVER ===================
"%~dp0bin\kmapctl.exe" ping
echo.
echo ================ STATUS (after) ================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Action status
echo.
echo [*] If START failed with 577/577 -> signature not trusted (reboot after enable, and cert must be in Root+TrustedPublisher)
echo [*] If START failed with 1275     -> blocked by HVCI or security software (exit Huorong/HipsDaemon)
pause
exit /b 0

:fail
echo.
echo [!] step failed, see messages above
pause
exit /b 1
