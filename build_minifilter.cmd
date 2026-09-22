@echo off
setlocal
cd /d "%~dp0"
set "PS_EXE=powershell.exe"
where.exe pwsh.exe >nul 2>&1
if not errorlevel 1 set "PS_EXE=pwsh.exe"
"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\build_minifilter.ps1" -Configuration Release
set "EC=%ERRORLEVEL%"
echo.
if not "%EC%"=="0" echo MINIFILTER BUILD FAILED.
if "%EC%"=="0" echo MINIFILTER BUILD PASSED. Driver is NOT installed.
if /I not "%GITHUB_ACTIONS%"=="true" pause
exit /b %EC%
