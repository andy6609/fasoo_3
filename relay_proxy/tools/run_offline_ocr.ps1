[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$OcrArguments
)

$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "offline_ocr.py"
$candidates = @()

if ($env:LOCAL_DLP_PYTHON) {
    $candidates += $env:LOCAL_DLP_PYTHON
}

$command = Get-Command python.exe -ErrorAction SilentlyContinue
if ($command) {
    $candidates += $command.Source
}

$candidates += (Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe")

$python = $null
foreach ($candidate in ($candidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        continue
    }
    & $candidate -c "import sys; print(sys.version_info[0])" *> $null
    if ($LASTEXITCODE -eq 0) {
        $python = $candidate
        break
    }
}

if (-not $python) {
    Write-Error "Python 3 was not found. Set LOCAL_DLP_PYTHON to an offline Python 3 executable."
    exit 2
}

& $python $scriptPath @OcrArguments
exit $LASTEXITCODE
