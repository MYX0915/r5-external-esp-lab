@echo off
title Apex ESP Launcher
cd /d "%~dp0"
echo Requesting administrator privileges...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0start-all.ps1\"'"
exit
