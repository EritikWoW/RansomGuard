@echo off
setlocal
set "UI=%~dp0UI\RansomGuard.Ui.exe"
if not exist "%UI%" (
  echo RansomGuard UI not found: %UI%
  echo Build the release first with build_windows.cmd.
  pause
  exit /b 2
)
start "RansomGuard" "%UI%"
endlocal
