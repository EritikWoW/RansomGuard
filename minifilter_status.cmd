@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\status_minifilter.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
