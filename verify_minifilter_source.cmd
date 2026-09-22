@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\verify_minifilter_source.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
