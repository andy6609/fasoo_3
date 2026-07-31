@echo off
setlocal

rem Explicit investigation mode: saves decrypted upload bodies, reconstructed
rem original files, extracted text, and endpoint metadata for configured AI hosts.
set "LOCAL_DLP_LOG_LEVEL=INFO"
set "LOCAL_DLP_DISCOVER_UPLOAD_HOSTS="
set "LOCAL_DLP_CAPTURE_UPLOAD_BODIES=1"
set "LOCAL_DLP_CAPTURE_MAX_BYTES=134217728"
set "LOCAL_DLP_SAVE_UPLOAD_RECORDS=1"
set "LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES=16777216"
set "LOCAL_DLP_BLOCK_UNSCANNABLE=1"
set "LOCAL_DLP_FORCE_HTTP1_UPLOAD_INSPECTION=1"
set "LOCAL_DLP_HTTP1_MAX_REQUEST_BYTES=134217728"
set "LOCAL_DLP_HTTP1_GLOBAL_BUFFER_BYTES=536870912"
set "LOCAL_DLP_HTTP1_REQUEST_TIMEOUT_MS=300000"
set "LOCAL_DLP_HTTP1_IDLE_TIMEOUT_MS=30000"
set "LOCAL_DLP_LOG_CONTENT_PREVIEW=0"
set "LOCAL_DLP_UPLOAD_RECORD_DIRECTORY=upload_records"
set "LOCAL_DLP_ALLOW_INSECURE_UPSTREAM="

cd /d "%~dp0"

set "RELAY_EXE=%~dp0..\x64\Release\relay_proxy.exe"

if not exist "%RELAY_EXE%" (
    echo [ERROR] x64\Release\relay_proxy.exe was not found. Build the solution for Release x64 first.
    exit /b 1
)

echo [AI DLP CAPTURE] Upload originals, extracted content, and PC metadata will be saved.
echo [AI DLP CAPTURE] Records: %CD%\upload_records
echo [AI DLP CAPTURE] Raw HTTP bodies: %CD%\upload_captures
echo [AI DLP CAPTURE] The proxy will start before AI-only PAC routing is enabled.
echo [AI DLP CAPTURE] Press Ctrl+C to stop and restore the previous proxy settings.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_ai_dlp_capture.ps1" -RelayProxyPath "%RELAY_EXE%"

set "RELAY_EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %RELAY_EXIT_CODE%
