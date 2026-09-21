@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\manage_exceptions.ps1"
set "rc=%ERRORLEVEL%"
if not "%rc%"=="0" echo Rule manager stopped. No protection setting was disabled.
pause
exit /b %rc%
