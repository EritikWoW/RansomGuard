@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0tools\repair_state_store.ps1"
