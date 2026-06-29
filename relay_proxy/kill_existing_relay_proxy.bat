@echo off
echo ============================================================
echo Kill existing relay_proxy.exe processes
echo ============================================================
echo.

echo [INFO] Current relay_proxy.exe processes:
tasklist /FI "IMAGENAME eq relay_proxy.exe"
echo.

echo [INFO] Terminating relay_proxy.exe ...
taskkill /F /IM relay_proxy.exe

echo.
echo [INFO] Checking port 8000:
netstat -ano | findstr :8000
echo.
echo Done.
pause
