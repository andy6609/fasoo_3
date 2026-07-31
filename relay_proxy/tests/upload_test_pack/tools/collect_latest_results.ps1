$packRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = (Get-Content -LiteralPath (Join-Path $packRoot 'repo_path.txt') -Raw).Trim()
$eventLog = Join-Path $repoRoot 'relay_events.log'
$runtimeLog = Join-Path $repoRoot 'relay_runtime.log'
$output = Join-Path $packRoot 'latest_test_results.txt'

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("AI DLP upload test result collected at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$lines.Add('')
$lines.Add('=== AI SECURITY EVENTS ===')
if (Test-Path -LiteralPath $eventLog) {
    Get-Content -LiteralPath $eventLog -Tail 500 |
        Where-Object { $_ -match 'AI ACCESS|UPLOAD|BLOCK|ALLOW' } |
        ForEach-Object { $lines.Add($_) }
}
else {
    $lines.Add('relay_events.log not found')
}

$lines.Add('')
$lines.Add('=== RECENT RUNTIME WARN/ERROR ===')
if (Test-Path -LiteralPath $runtimeLog) {
    Get-Content -LiteralPath $runtimeLog -Tail 500 |
        Where-Object { $_ -match '\[WARN\]|\[ERROR\]' } |
        ForEach-Object { $lines.Add($_) }
}
else {
    $lines.Add('relay_runtime.log not found')
}

$lines | Set-Content -LiteralPath $output -Encoding UTF8
Write-Host "Saved: $output" -ForegroundColor Green
