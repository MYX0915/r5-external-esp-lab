@echo off
rem Build kmap.sys (kernel) + kmapctl.exe (usermode) -- ASCII only, no parens in blocks
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"

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
echo [!] WDK km headers/libs missing
exit /b 1

:build
echo === building kmap.sys ===
cl /nologo /c /kernel /GS- /O2 /W3 /utf-8 /D_AMD64_ /DAMD64 /DWIN32 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C /I"%KM%" /I"%KM%\crt" /I"%W10%\Include\%WVER%\shared" /Fo:obj\ /Fd:obj\ driver\kmap.c
if errorlevel 1 goto fail

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /OUT:bin\kmap.sys obj\kmap.obj "%KMLIB%\ntoskrnl.lib" "%KMLIB%\BufferOverflowK.lib" "%KMLIB%\hal.lib"
if errorlevel 1 goto fail

echo === building kmapctl.exe ===
cl /nologo /O2 /EHsc /MT /utf-8 /Fe:bin\kmapctl.exe /Fo:obj\ loader\loader.cpp /link advapi32.lib
if errorlevel 1 goto fail

echo === building test target/payload ===
cl /nologo /O2 /MT /utf-8 /Fe:bin\target.exe /Fo:obj\ test\target.cpp
if errorlevel 1 goto fail
cl /nologo /O2 /MT /utf-8 /LD /Fe:bin\payload.dll /Fo:obj\ test\payload.cpp
if errorlevel 1 goto fail

echo.
echo OK
dir /b bin
exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1




