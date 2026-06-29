@echo off
setlocal

echo [INFO] generating TLS test server certificate...

set OPENSSL_EXE=C:\vcpkg\downloads\tools\perl\5.42.2.1\c\bin\openssl.exe

if not exist "%OPENSSL_EXE%" (
    echo [ERROR] openssl.exe not found:
    echo %OPENSSL_EXE%
    echo.
    echo Edit OPENSSL_EXE in this bat file or install OpenSSL.
    pause
    exit /b 1
)

if not exist certs (
    mkdir certs
)

(
echo [ req ]
echo distinguished_name = req_distinguished_name
echo prompt = no
echo.
echo [ req_distinguished_name ]
echo CN = 127.0.0.1
echo.
echo [ v3_server ]
echo basicConstraints = CA:FALSE
echo keyUsage = critical, digitalSignature, keyEncipherment
echo extendedKeyUsage = serverAuth
echo subjectAltName = @alt_names
echo.
echo [ alt_names ]
echo DNS.1 = localhost
echo IP.1 = 127.0.0.1
) > certs\openssl_server.cnf

set OPENSSL_CONF=%CD%\certs\openssl_server.cnf

"%OPENSSL_EXE%" req ^
    -x509 ^
    -newkey rsa:2048 ^
    -sha256 ^
    -days 365 ^
    -nodes ^
    -keyout certs\server.key ^
    -out certs\server.crt ^
    -subj "/CN=127.0.0.1" ^
    -config certs\openssl_server.cnf ^
    -extensions v3_server

if errorlevel 1 (
    echo [ERROR] failed to create TLS test server certificate
    pause
    exit /b 1
)

echo.
echo [SUCCESS] generated TLS test server certificate:
echo   certs\server.crt
echo   certs\server.key
echo.

dir certs
pause
endlocal
