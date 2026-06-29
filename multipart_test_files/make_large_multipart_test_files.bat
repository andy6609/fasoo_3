@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0make_large_multipart_test_files.ps1"
endlocal
