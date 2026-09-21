@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\summarize_last_lab.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
