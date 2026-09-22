@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\run_minifilter_audit.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
