@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0minifilter-tools\build_minifilter.ps1" -Configuration Release
set EC=%ERRORLEVEL%
echo.
if not "%EC%"=="0" echo MINIFILTER BUILD FAILED.
if "%EC%"=="0" echo MINIFILTER BUILD PASSED. Driver is NOT installed.
pause
exit /b %EC%
