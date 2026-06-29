@echo off
setlocal

echo [INFO] generating TLS MITM test certificates...

set OPENSSL_EXE=C:\vcpkg\downloads\tools\perl\5.42.2.1\c\bin\openssl.exe

if not exist "%OPENSSL_EXE%" (
    echo [ERROR] openssl.exe not found:
    echo %OPENSSL_EXE%
    pause
    exit /b 1
)

echo [INFO] using OpenSSL:
echo %OPENSSL_EXE%

if not exist certs (
    mkdir certs
)

echo [INFO] creating local openssl.cnf...

(
echo [ req ]
echo distinguished_name = req_distinguished_name
echo prompt = no
echo.
echo [ req_distinguished_name ]
echo CN = localhost
echo.
echo [ v3_ca ]
echo basicConstraints = critical, CA:TRUE
echo keyUsage = critical, keyCertSign, cRLSign
echo subjectKeyIdentifier = hash
echo authorityKeyIdentifier = keyid:always,issuer
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
) > certs\openssl.cnf

set OPENSSL_CONF=%CD%\certs\openssl.cnf

echo.
echo [INFO] creating MITM certificate...

"%OPENSSL_EXE%" req ^
    -x509 ^
    -newkey rsa:2048 ^
    -sha256 ^
    -days 365 ^
    -nodes ^
    -keyout certs\mitm.key ^
    -out certs\mitm.crt ^
    -subj "/CN=MITM Test CA" ^
    -config certs\openssl.cnf ^
    -extensions v3_ca

if errorlevel 1 (
    echo [ERROR] failed to create MITM certificate
    pause
    exit /b 1
)

echo.
echo [INFO] creating TLS test server certificate...

"%OPENSSL_EXE%" req ^
    -x509 ^
    -newkey rsa:2048 ^
    -sha256 ^
    -days 365 ^
    -nodes ^
    -keyout certs\server.key ^
    -out certs\server.crt ^
    -subj "/CN=127.0.0.1" ^
    -config certs\openssl.cnf ^
    -extensions v3_server

if errorlevel 1 (
    echo [ERROR] failed to create server certificate
    pause
    exit /b 1
)

echo.
echo [SUCCESS] certificates generated:
echo   certs\mitm.crt
echo   certs\mitm.key
echo   certs\server.crt
echo   certs\server.key
echo   certs\openssl.cnf
echo.

dir certs

pause
endlocal