@echo off
setlocal

echo ============================================================
echo  Enable Windows User Proxy: 127.0.0.1:8000
echo ============================================================
echo.

echo [INFO] Setting WinINet proxy for current user...

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:8000" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "<-loopback>" /f >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$signature = '[DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);';" ^
  "Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace WinInet;" ^
  "[WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null;" ^
  "[WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null;"

echo.
echo [SUCCESS] Windows user proxy enabled.
echo   ProxyServer = 127.0.0.1:8000
echo.
echo Open Chrome or Edge after relay_proxy is running.
echo.
pause
endlocal
