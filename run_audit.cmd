@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\launch.ps1" -Mode Audit
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
