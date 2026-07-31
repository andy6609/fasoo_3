@echo off
setlocal
cd /d "%~dp0.."

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD_EXE="
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do if not defined MSBUILD_EXE set "MSBUILD_EXE=%%I"
)
if not defined MSBUILD_EXE if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"

if not defined MSBUILD_EXE (
    echo [FAIL] MSBuild was not found. Install Visual Studio C++ build tools.
    exit /b 1
)

echo [BUILD] Release x64 relay_proxy
"%MSBUILD_EXE%" ".\tcp_proxy_lab.sln" /t:relay_proxy /p:Configuration=Release /p:Platform=x64 /m /nologo
if errorlevel 1 (
    echo [FAIL] Release x64 build failed.
    exit /b 1
)

cd /d "%~dp0tests\phase1_phase2"
call ".\RUN_ALL_TESTS.bat"
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (
    echo [PASS] Phase 1 and Phase 2 verification completed.
) else (
    echo [FAIL] Open C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results for details.
)
endlocal & exit /b %RESULT%
