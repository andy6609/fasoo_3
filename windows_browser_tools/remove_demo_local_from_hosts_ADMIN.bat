@echo off
setlocal

echo ============================================================
echo  Remove hosts entry: demo.local
echo ============================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Administrator permission required.
    echo Right-click this file and choose "Run as administrator".
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts';" ^
  "$lines = Get-Content $hosts;" ^
  "$filtered = $lines | Where-Object { $_ -notmatch '^\s*127\.0\.0\.1\s+demo\.local(\s|$)' };" ^
  "Set-Content -Path $hosts -Value $filtered -Encoding ASCII;"

if errorlevel 1 (
    echo [ERROR] Failed to update hosts file.
    pause
    exit /b 1
)

ipconfig /flushdns >nul

echo [SUCCESS] Removed demo.local hosts entry if it existed.
echo.
pause
endlocal
