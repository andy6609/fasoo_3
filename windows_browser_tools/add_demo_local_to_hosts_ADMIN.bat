@echo off
setlocal

echo ============================================================
echo  Add hosts entry: 127.0.0.1 demo.local
echo ============================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Administrator permission required.
    echo Right-click this file and choose "Run as administrator".
    pause
    exit /b 1
)

set HOSTS_FILE=%SystemRoot%\System32\drivers\etc\hosts

echo [INFO] hosts file:
echo   %HOSTS_FILE%
echo.

findstr /I /R "^[ ]*127\.0\.0\.1[ ]*demo\.local" "%HOSTS_FILE%" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] hosts entry already exists:
    findstr /I "demo.local" "%HOSTS_FILE%"
    echo.
    ipconfig /flushdns >nul
    echo [SUCCESS] DNS cache flushed.
    pause
    exit /b 0
)

echo.>> "%HOSTS_FILE%"
echo 127.0.0.1 demo.local>> "%HOSTS_FILE%"

if errorlevel 1 (
    echo [ERROR] Failed to update hosts file.
    pause
    exit /b 1
)

ipconfig /flushdns >nul

echo [SUCCESS] Added hosts entry:
echo   127.0.0.1 demo.local
echo.
pause
endlocal
