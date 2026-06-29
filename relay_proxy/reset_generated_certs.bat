@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Reset dynamically generated leaf certificates
echo ============================================================
echo.

if exist certs\generated (
    echo [INFO] Removing certs\generated ...
    rmdir /S /Q certs\generated
) else (
    echo [INFO] certs\generated does not exist. Nothing to remove.
)

echo.
echo [SUCCESS] Generated certificate cache reset.
echo Next TLS SNI access will generate a fresh leaf certificate.
echo.
pause
endlocal
