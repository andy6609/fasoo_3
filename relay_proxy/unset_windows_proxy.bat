@echo off
setlocal

echo ============================================================
echo  Disable Windows User Proxy
echo ============================================================
echo.

echo [INFO] Disabling WinINet proxy for current user...

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$signature = '[DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);';" ^
  "Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace WinInet;" ^
  "[WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null;" ^
  "[WinInet.NativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null;"

echo.
echo [SUCCESS] Windows user proxy disabled.
echo.
pause
endlocal
