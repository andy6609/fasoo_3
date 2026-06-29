@echo off
setlocal

echo ============================================================
echo  Open browser test URLs
echo ============================================================
echo.

echo [INFO] Make sure these are already running/enabled:
echo   1. tls_browser_test_server.py in WSL
echo   2. relay_proxy.exe
echo   3. Windows proxy 127.0.0.1:8000
echo   4. MITM root CA installed
echo   5. hosts entry: 127.0.0.1 demo.local
echo.

echo Opening test page...
start "" "https://demo.local:9443/"

echo.
echo Useful direct URLs:
echo   https://demo.local:9443/safe
echo   https://demo.local:9443/blocked-response
echo.
pause
endlocal
