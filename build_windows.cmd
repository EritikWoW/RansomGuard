@echo off
setlocal
cd /d "%~dp0"
set "PS_EXE=powershell.exe"
where.exe pwsh.exe >nul 2>&1
if not errorlevel 1 set "PS_EXE=pwsh.exe"
"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1" %*
set "BUILD_RESULT=%ERRORLEVEL%"
echo.
if not "%BUILD_RESULT%"=="0" echo BUILD FAILED. Do not use a partially built release. See build-logs.
pause
exit /b %BUILD_RESULT%
