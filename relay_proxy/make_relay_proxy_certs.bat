@echo off
setlocal

cd /d "%~dp0"

echo [INFO] generating relay_proxy MITM CA certificate...

if exist "certs\mitm.crt" if exist "certs\mitm.key" (
    echo [INFO] Existing matching CA certificate and private key will be reused.
    echo        certs\mitm.crt
    echo        certs\mitm.key
    exit /b 0
)

if exist "certs\mitm.crt" if not exist "certs\mitm.key" (
    echo [ERROR] certs\mitm.crt exists but certs\mitm.key is missing.
    echo         Do not silently replace one half of a CA pair.
    exit /b 1
)
if exist "certs\mitm.key" if not exist "certs\mitm.crt" (
    echo [ERROR] certs\mitm.key exists but certs\mitm.crt is missing.
    echo         Do not silently replace one half of a CA pair.
    exit /b 1
)

set "OPENSSL_EXE=C:\vcpkg\downloads\tools\perl\5.42.2.1\c\bin\openssl.exe"
if not exist "%OPENSSL_EXE%" (
    for /f "delims=" %%I in ('where openssl.exe 2^>nul') do set "OPENSSL_EXE=%%I"
)

if not exist "%OPENSSL_EXE%" (
    echo [ERROR] openssl.exe not found:
    echo %OPENSSL_EXE%
    echo.
    echo Edit OPENSSL_EXE in this bat file or install OpenSSL.
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
echo CN = Local DLP MITM Root CA
echo.
echo [ v3_ca ]
echo basicConstraints = critical, CA:TRUE
echo keyUsage = critical, keyCertSign, cRLSign
echo subjectKeyIdentifier = hash
echo authorityKeyIdentifier = keyid:always,issuer
) > certs\openssl_ca.cnf

set OPENSSL_CONF=%CD%\certs\openssl_ca.cnf

"%OPENSSL_EXE%" req ^
    -x509 ^
    -newkey rsa:2048 ^
    -sha256 ^
    -days 365 ^
    -nodes ^
    -keyout certs\mitm.key ^
    -out certs\mitm.crt ^
    -subj "/CN=Local DLP MITM Root CA" ^
    -config certs\openssl_ca.cnf ^
    -extensions v3_ca

if errorlevel 1 (
    echo [ERROR] failed to create MITM CA certificate
    exit /b 1
)

echo.
echo [SUCCESS] generated relay_proxy MITM CA:
echo   certs\mitm.crt
echo   certs\mitm.key
echo.
echo Dynamic leaf certs will be generated under:
echo   certs\generated\
echo.

dir certs
endlocal
