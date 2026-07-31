@echo off
setlocal
set /p REPO_ROOT=<"%~dp0repo_path.txt"

echo Restoring the Windows proxy settings saved before the test...
call "%REPO_ROOT%\relay_proxy\unset_windows_proxy.bat"
echo.
echo Windows routing was restored. Close the proxy/log windows if they are still open.
pause
endlocal
