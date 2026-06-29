@echo off
setlocal

cd /d "%~dp0"

echo ============================================================
echo  Install Local DLP MITM Root CA - Current User
echo ============================================================
echo.

set CERT_FILE=%CD%\certs\mitm.crt

if not exist "%CERT_FILE%" (
    echo [ERROR] MITM root certificate not found:
    echo   %CERT_FILE%
    echo.
    echo Run make_relay_proxy_certs.bat first.
    pause
    exit /b 1
)

echo [INFO] Installing certificate into CurrentUser Root store:
echo   %CERT_FILE%
echo.

certutil -user -addstore Root "%CERT_FILE%"
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install MITM root certificate.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] MITM root certificate installed for Current User.
echo.
echo [INFO] Matching certificate in CurrentUser Root store:
certutil -user -store Root "Local DLP MITM Root CA"

echo.
echo You can now test browser HTTPS interception with this user's Chrome/Edge.
echo.
pause
endlocal
