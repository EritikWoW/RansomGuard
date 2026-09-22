@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\unload_minifilter_lab.ps1" -Volume C:
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
