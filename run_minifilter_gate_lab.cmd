@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\run_minifilter_gate_lab.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo LAB gate ended with error %RC%.
pause
exit /b %RC%
