@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\verify_upload_capture_safety.ps1"
if errorlevel 1 goto :failed
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\generate_test_pack.ps1"
if errorlevel 1 goto :failed
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\verify_test_pack.ps1" -StrictOcr
if errorlevel 1 goto :failed
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\verify_relay_proxy.ps1"
if errorlevel 1 goto :failed
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\verify_upload_records.ps1"
if errorlevel 1 goto :failed
echo.
echo PASS: Fixture, native policy, and upload-record checks completed.
echo Combined: C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\summary.json
echo Native C: C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\relay_proxy_results.json
echo Records: C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\upload_record_results.json
exit /b 0

:failed
echo.
echo FAIL: Read the error above, summary.json, relay_proxy_results.json, and relay_proxy_cli logs.
exit /b 1
