@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\install_service.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
