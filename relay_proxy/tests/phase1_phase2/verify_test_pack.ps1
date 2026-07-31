[CmdletBinding()]
param(
    [string]$PackDirectory = "C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack",
    [switch]$StrictOcr
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCandidates = @()
if ($env:LOCAL_DLP_PYTHON) { $pythonCandidates += $env:LOCAL_DLP_PYTHON }
$pythonCandidates += (Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe")
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCommand) { $pythonCandidates += $pythonCommand.Source }
$python = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $python) { throw "Python 3 not found. Set LOCAL_DLP_PYTHON." }

$arguments = @((Join-Path $root "verify_test_pack.py"), "--pack", $PackDirectory)
if ($StrictOcr) { $arguments += "--strict-ocr" }
& $python @arguments
exit $LASTEXITCODE
