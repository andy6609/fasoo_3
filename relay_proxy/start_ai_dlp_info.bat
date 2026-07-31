@echo off
setlocal

rem Production-safe defaults: collect only AI/access/upload security events.
set "LOCAL_DLP_LOG_LEVEL=INFO"
set "LOCAL_DLP_DISCOVER_UPLOAD_HOSTS="
set "LOCAL_DLP_CAPTURE_UPLOAD_BODIES="
set "LOCAL_DLP_ALLOW_INSECURE_UPSTREAM="

cd /d "%~dp0.."

if not exist "x64\Debug\relay_proxy.exe" (
    echo [ERROR] x64\Debug\relay_proxy.exe was not found. Build Debug x64 first.
    exit /b 1
)

echo [AI DLP] INFO mode: AI security events only. Press Ctrl+C to stop.
"x64\Debug\relay_proxy.exe"

set "RELAY_EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %RELAY_EXIT_CODE%
