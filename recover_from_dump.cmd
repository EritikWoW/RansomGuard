@echo off
setlocal
if not exist "%~dp0Recovery\RansomGuard.Recovery.exe" (
  echo Build the project first; this command belongs in the release directory.
  exit /b 2
)
"%~dp0Recovery\RansomGuard.Recovery.exe" %*
exit /b %ERRORLEVEL%
