$ErrorActionPreference = 'Stop'

$packRoot = Split-Path $PSScriptRoot -Parent
$repoPathFile = Join-Path $packRoot 'repo_path.txt'
$repoRoot = (Get-Content -LiteralPath $repoPathFile -Raw).Trim()
$analyzer = Join-Path $repoRoot 'x64\Debug\relay_proxy.exe'

if (-not (Test-Path -LiteralPath $analyzer)) {
    throw "relay_proxy.exe not found: $analyzer"
}

$tests = @(
    @{ File='01_GPT_SAFE.txt'; Mime='text/plain'; ExpectedExit=0; Expected='ALLOW' },
    @{ File='02_GEMINI_SAFE.txt'; Mime='text/plain'; ExpectedExit=0; Expected='ALLOW' },
    @{ File='03_CLAUDE_SAFE.txt'; Mime='text/plain'; ExpectedExit=0; Expected='ALLOW' },
    @{ File='04_COMMON_SAFE.docx'; Mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'; ExpectedExit=0; Expected='ALLOW' },
    @{ File='05_COMMON_SAFE.pdf'; Mime='application/pdf'; ExpectedExit=0; Expected='ALLOW' },
    @{ File='90_BLOCK_script.bat'; Mime='application/octet-stream'; ExpectedExit=2; Expected='BLOCK' },
    @{ File='91_BLOCK_nested_script.zip'; Mime='application/zip'; ExpectedExit=2; Expected='BLOCK' },
    @{ File='92_BLOCK_fake_pdf.pdf'; Mime='application/pdf'; ExpectedExit=2; Expected='BLOCK' }
)

$failed = $false
foreach ($test in $tests) {
    $path = Join-Path $packRoot $test.File
    Write-Host "`n=== $($test.File) / expected $($test.Expected) ===" -ForegroundColor Cyan
    & $analyzer --analyze-file $path $test.Mime
    $actualExit = $LASTEXITCODE
    if ($actualExit -ne $test.ExpectedExit) {
        Write-Host "FAIL: expected exit $($test.ExpectedExit), actual $actualExit" -ForegroundColor Red
        $failed = $true
    }
    else {
        Write-Host "PASS: $($test.Expected)" -ForegroundColor Green
    }
}

if ($failed) {
    exit 1
}

Write-Host "`nALL LOCAL ANALYZER TESTS PASSED" -ForegroundColor Green
