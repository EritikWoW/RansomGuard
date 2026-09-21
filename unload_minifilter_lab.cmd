@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\unload_minifilter_lab.ps1" -Volume C:
pause
