@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_ai_proxy.ps1" -Action Enable
set "RESULT=%ERRORLEVEL%"

if not "%RESULT%"=="0" (
  echo.
  echo [ERROR] AI-only proxy routing was not enabled.
  echo [INFO] Run start_ai_dlp_capture.bat so the proxy starts before PAC routing.
)

endlocal & exit /b %RESULT%
