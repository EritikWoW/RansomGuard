@echo off
setlocal
set "EXE=%~dp0RollbackRecovery\RansomGuard.RollbackRecovery.exe"
if not exist "%EXE%" (
  echo RansomGuard.RollbackRecovery.exe not found in Engineering LAB bundle.
  exit /b 2
)
"%EXE%" %*
exit /b %ERRORLEVEL%
