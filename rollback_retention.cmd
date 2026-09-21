@echo off
setlocal
set "EXE=%~dp0RollbackRetention\RansomGuard.RollbackRetention.exe"
if not exist "%EXE%" (
  echo RansomGuard.RollbackRetention.exe not found in Engineering LAB bundle.
  exit /b 2
)
"%EXE%" %*
exit /b %ERRORLEVEL%
