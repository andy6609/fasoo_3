[CmdletBinding()]
param(
    [string]$OutputDirectory = "C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$volumeRoot = [System.IO.Path]::GetPathRoot($resolvedOutput).TrimEnd('\')
if ($resolvedOutput -eq $volumeRoot -or ([System.IO.Path]::GetFileName($resolvedOutput) -notmatch "AI_DLP")) {
    throw "Unsafe output directory. Choose a dedicated directory whose name contains AI_DLP."
}
$fixtures = Join-Path $OutputDirectory "fixtures"
$qa = Join-Path $OutputDirectory "qa"
New-Item -ItemType Directory -Force -Path $fixtures, $qa | Out-Null
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination (Join-Path $OutputDirectory "README_FIRST.md") -Force

$pythonCandidates = @()
if ($env:LOCAL_DLP_PYTHON) { $pythonCandidates += $env:LOCAL_DLP_PYTHON }
$pythonCandidates += (Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe")
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCommand) { $pythonCandidates += $pythonCommand.Source }
$python = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $python) { throw "Python 3 not found. Set LOCAL_DLP_PYTHON." }

& $python (Join-Path $root "generate_test_pack.py") --output $fixtures
if ($LASTEXITCODE -ne 0) { throw "Base fixture generation failed with exit code $LASTEXITCODE" }

$node = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
$nodeModules = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules"
if (-not (Test-Path -LiteralPath $node -PathType Leaf) -or -not (Test-Path -LiteralPath $nodeModules -PathType Container)) {
    throw "Bundled Node/@oai-artifact-tool runtime not found. Generate XLSX/PPTX on a Codex workstation or set up the official runtime."
}

$artifactWorkspace = Join-Path $env:TEMP ("local_dlp_artifacts_" + $PID)
New-Item -ItemType Directory -Force -Path $artifactWorkspace | Out-Null
try {
    New-Item -ItemType Junction -Path (Join-Path $artifactWorkspace "node_modules") -Target $nodeModules | Out-Null
    Copy-Item -LiteralPath (Join-Path $root "build_office_fixtures.mjs") -Destination (Join-Path $artifactWorkspace "build_office_fixtures.mjs")
    & $node (Join-Path $artifactWorkspace "build_office_fixtures.mjs") $fixtures $qa
    if ($LASTEXITCODE -ne 0 -and -not ((Test-Path (Join-Path $fixtures "safe_sample.xlsx")) -and (Test-Path (Join-Path $fixtures "safe_sample.pptx")))) {
        throw "Office fixture generation failed with exit code $LASTEXITCODE"
    }
    Remove-Item -LiteralPath (Join-Path $fixtures "safe_sample.xlsx.inspect.ndjson") -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $fixtures "safe_sample.pptx.inspect.ndjson") -Force -ErrorAction SilentlyContinue
}
finally {
    $moduleLink = Join-Path $artifactWorkspace "node_modules"
    if (Test-Path -LiteralPath $moduleLink) {
        try { [System.IO.Directory]::Delete($moduleLink) } catch { Write-Warning "Temporary node_modules junction cleanup failed: $($_.Exception.Message)" }
    }
    $resolvedTemp = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    $resolvedWorkspace = [System.IO.Path]::GetFullPath($artifactWorkspace)
    if ($resolvedWorkspace.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedWorkspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Optional Windows-native fixtures are generated only when the corresponding
# Office application is installed and not already running.  The helper never
# opens an existing document/workbook/presentation and records transparent
# SKIPs in manifest.json when user-safety prevents automation.
$optionalGenerator = Join-Path $root "generate_optional_windows_fixtures.ps1"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $optionalGenerator -OutputDirectory $fixtures
if ($LASTEXITCODE -ne 0) {
    throw "Optional Windows fixture generation failed with exit code $LASTEXITCODE"
}

Write-Host "Generated DRM-exempt test pack: $OutputDirectory"
Write-Host "Run: .\verify_test_pack.ps1 -PackDirectory `"$OutputDirectory`""
