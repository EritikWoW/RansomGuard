@echo off
setlocal
set "EXE=%~dp0RollbackMaintenance\RansomGuard.RollbackMaintenance.exe"
if not exist "%EXE%" (
  echo RansomGuard.RollbackMaintenance.exe not found in Engineering LAB bundle.
  exit /b 2
)
"%EXE%" %*
exit /b %ERRORLEVEL%
