@echo off
setlocal

echo ============================================================
echo  Remove Local DLP MITM Root CA - Current User
echo ============================================================
echo.

echo [INFO] Removing certificates with subject CN=Local DLP MITM Root CA from CurrentUser Root store...

echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser');" ^
  "$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);" ^
  "$matches = @($store.Certificates | Where-Object { $_.Subject -eq 'CN=Local DLP MITM Root CA' });" ^
  "foreach ($cert in $matches) { Write-Host ('Removing: ' + $cert.Subject + ' Thumbprint=' + $cert.Thumbprint); $store.Remove($cert); }" ^
  "$count = $matches.Count;" ^
  "$store.Close();" ^
  "Write-Host ('Removed count: ' + $count);"

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to remove MITM root certificate.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Removal completed.
echo.
pause
endlocal
