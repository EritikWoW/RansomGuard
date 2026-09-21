@echo off
setlocal
set "UI=%~dp0UI\RansomGuard.Ui.exe"
if not exist "%UI%" (
  echo Build the release first, then run preview_ui.cmd from that release.
  pause
  exit /b 2
)
start "RansomGuard UI - SYNTHETIC PREVIEW" "%UI%" --preview
endlocal
