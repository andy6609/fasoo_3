$packRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = (Get-Content -LiteralPath (Join-Path $packRoot 'repo_path.txt') -Raw).Trim()
$logPath = Join-Path $repoRoot 'relay_runtime.log'

Write-Host "Watching proxy warnings and errors: $logPath" -ForegroundColor Yellow
while (-not (Test-Path -LiteralPath $logPath)) {
    Start-Sleep -Seconds 1
}
Get-Content -LiteralPath $logPath -Tail 50 -Wait
