@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_ai_proxy.ps1" -Action Disable
set "RESULT=%ERRORLEVEL%"

endlocal & exit /b %RESULT%
