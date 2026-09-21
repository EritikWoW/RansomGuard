@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\diagnose_etw.ps1"
set "RG_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %RG_EXIT%
