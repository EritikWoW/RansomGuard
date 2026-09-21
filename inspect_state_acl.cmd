@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0tools\inspect_state_acl.ps1"
