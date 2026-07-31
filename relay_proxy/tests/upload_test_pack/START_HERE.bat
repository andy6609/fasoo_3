@echo off
setlocal
set /p REPO_ROOT=<"%~dp0repo_path.txt"

echo ============================================================
echo  AI Upload DLP Test - Environment Setup
echo ============================================================
echo.

netstat -ano | findstr /R /C:":8000 .*LISTENING" >nul
if errorlevel 1 (
  echo [INFO] Starting relay_proxy in a separate window...
  start "AI DLP Proxy" /min cmd.exe /k call "%REPO_ROOT%\relay_proxy\start_ai_dlp_info.bat"
  timeout /t 3 /nobreak >nul
)

echo [1/3] Applying AI-only Windows PAC...
call "%REPO_ROOT%\relay_proxy\set_windows_proxy_127_0_0_1_8000.bat"
if errorlevel 1 goto :failed

echo [2/3] Checking environment...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\check_environment.ps1"
if errorlevel 1 goto :failed

echo [3/3] Verifying all test files locally...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\run_local_analyzer_tests.ps1"
if errorlevel 1 goto :failed

echo.
echo [SUCCESS] Setup and local tests passed.
echo [INFO] Opening event/runtime log monitor windows...
call "%~dp0tools\start_log_monitors.bat"
echo.
echo Next: fully restart Chrome and follow README_FIRST.md section 7.
pause
exit /b 0

:failed
echo.
echo [ERROR] Setup failed. Review the messages above and relay_runtime.log.
pause
exit /b 1
