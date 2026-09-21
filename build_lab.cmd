@echo off
setlocal
call "%~dp0build_windows.cmd" -IncludeLab
exit /b %ERRORLEVEL%
