[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $scriptRoot "upload_capture_safety_tests.c"
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe not found"
}
$installation = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($installation)) {
    throw "Visual C++ x64 build tools not found"
}
$devCmd = Join-Path $installation "Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path -LiteralPath $devCmd -PathType Leaf)) {
    throw "VsDevCmd.bat not found: $devCmd"
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("local_dlp_upload_capture_test_{0}_{1}" -f $PID, [Guid]::NewGuid().ToString("N"))
$testRoot = [System.IO.Path]::GetFullPath($testRoot)
$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
if (-not $testRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing unsafe test directory: $testRoot"
}
New-Item -ItemType Directory -Path $testRoot | Out-Null
$testExe = Join-Path $testRoot "upload_capture_safety_tests.exe"

try {
    $compile = 'call "{0}" -no_logo -arch=x64 -host_arch=x64 && cl.exe /nologo /W4 /WX /TC /Fe:"{1}" "{2}"' -f `
        $devCmd, $testExe, $source
    Push-Location $testRoot
    try {
        & $env:ComSpec /d /s /c $compile
        if ($LASTEXITCODE -ne 0) { throw "upload_capture safety test compilation failed" }
        & $testExe
        if ($LASTEXITCODE -ne 0) { throw "upload_capture safety tests failed" }
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "PASS: upload_capture bounds, fail-closed storage, atomic commit, and metadata sanitization"
