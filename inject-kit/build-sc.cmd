@echo off
rem build-sc.cmd -- build one test driver from test\<name>.c into bin\<name>.sys
rem usage: build-sc.cmd sc3
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"
set "NAME=%~1"
if "%NAME%"=="" set "NAME=sc3"

if not exist bin mkdir bin
if not exist obj mkdir obj

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" goto novc
call "%VCVARS%" >nul
goto env
:novc
echo [!] vcvars64.bat not found
exit /b 1
:env
set "W10=C:\Program Files (x86)\Windows Kits\10"
set "WVER=10.0.26100.0"
set "KM=%W10%\Include\%WVER%\km"
set "KMLIB=%W10%\Lib\%WVER%\km\x64"
if not exist "%KM%\ntddk.h" goto nowdk
if not exist "%KMLIB%\ntoskrnl.lib" goto nowdk
goto build
:nowdk
echo [!] WDK missing
exit /b 1

:build
echo === building %NAME%.sys ===
cl /nologo /c /kernel /GS- /O2 /W3 /utf-8 /D_AMD64_ /DAMD64 /DWIN32 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C /I"%KM%" /I"%KM%\crt" /I"%W10%\Include\%WVER%\shared" /Fo:obj\%NAME%.obj /Fd:obj\ test\%NAME%.c
if errorlevel 1 goto fail
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /OUT:bin\%NAME%.sys obj\%NAME%.obj "%KMLIB%\ntoskrnl.lib" "%KMLIB%\BufferOverflowK.lib" "%KMLIB%\hal.lib"
if errorlevel 1 goto fail
echo OK bin\%NAME%.sys
dir /b bin\%NAME%.sys
exit /b 0
:fail
echo BUILD FAILED
exit /b 1
