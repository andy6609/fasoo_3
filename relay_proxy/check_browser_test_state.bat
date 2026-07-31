@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Browser Test State Check
echo ============================================================
echo.

echo [1] relay_proxy certificate files
echo ------------------------------------------------------------
if exist certs\mitm.crt (echo OK   certs\mitm.crt) else (echo MISS certs\mitm.crt)
if exist certs\mitm.key (echo OK   certs\mitm.key) else (echo MISS certs\mitm.key)
if exist certs\generated (dir certs\generated) else (echo INFO certs\generated not created yet.)
echo.

echo [2] CurrentUser Root store search
echo ------------------------------------------------------------
certutil -user -store Root "Local DLP MITM Root CA"
echo.

echo [3] Windows proxy settings
echo ------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_ai_proxy.ps1" -Action Status
echo.

echo [4] hosts entry for demo.local
echo ------------------------------------------------------------
findstr /I /C:"demo.local" "%SystemRoot%\System32\drivers\etc\hosts"
if errorlevel 1 echo INFO demo.local not found in hosts file.
echo.

echo [5] TLS intercept policy
echo ------------------------------------------------------------
if exist tls_intercept_policy.txt (type tls_intercept_policy.txt) else (echo MISS tls_intercept_policy.txt)
echo.

pause
endlocal
