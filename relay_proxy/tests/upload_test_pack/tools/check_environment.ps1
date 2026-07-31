$ErrorActionPreference = 'Stop'

$packRoot = Split-Path $PSScriptRoot -Parent
$repoPathFile = Join-Path $packRoot 'repo_path.txt'
$repoRoot = (Get-Content -LiteralPath $repoPathFile -Raw).Trim()
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'x64\Debug\relay_proxy.exe'))) {
    throw "Invalid repository path in ${repoPathFile}: $repoRoot"
}
$failures = New-Object System.Collections.Generic.List[string]

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    [pscustomobject]@{
        Check = $Name
        Result = if ($Passed) { 'PASS' } else { 'FAIL' }
        Detail = $Detail
    }
    if (-not $Passed) {
        $failures.Add($Name)
    }
}

$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
Add-Check 'relay_proxy listener' ($null -ne $listener) $(if ($listener) { "PID $($listener.OwningProcess)" } else { 'port 8000 is not listening' })

$settingsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$settings = Get-ItemProperty -LiteralPath $settingsPath
$pacEnabled = $settings.ProxyEnable -eq 0 -and $settings.AutoConfigURL -like 'http://127.0.0.1:8000/proxy.pac*'
Add-Check 'AI-only PAC setting' $pacEnabled "ProxyEnable=$($settings.ProxyEnable), AutoConfigURL=$($settings.AutoConfigURL)"

try {
    $client = New-Object System.Net.WebClient
    $client.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    $pac = $client.DownloadString('http://127.0.0.1:8000/proxy.pac?v=2')
    $pacAvailable = $pac -match 'FindProxyForURL' -and $pac -match 'return\s+"DIRECT"'
}
catch {
    $pacAvailable = $false
}
finally {
    if ($client) { $client.Dispose() }
}
Add-Check 'PAC endpoint' $pacAvailable $(if ($pacAvailable) { 'HTTP response contains AI-only PAC function' } else { 'PAC endpoint unavailable' })

$proxy = [System.Net.WebRequest]::DefaultWebProxy
$routes = @(
    @{ Host='https://chatgpt.com/'; ExpectedBypass=$false },
    @{ Host='https://gemini.google.com/'; ExpectedBypass=$false },
    @{ Host='https://claude.ai/'; ExpectedBypass=$false },
    @{ Host='https://outlook.office.com/'; ExpectedBypass=$true },
    @{ Host='https://login.microsoftonline.com/'; ExpectedBypass=$true }
)
foreach ($route in $routes) {
    $uri = [uri]$route.Host
    $actualBypass = $proxy.IsBypassed($uri)
    $selected = $proxy.GetProxy($uri).AbsoluteUri
    Add-Check "route $($uri.Host)" ($actualBypass -eq $route.ExpectedBypass) "bypassed=$actualBypass, selected=$selected"
}

$rootCa = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like '*Local DLP MITM Root CA*' } | Select-Object -First 1
Add-Check 'CurrentUser MITM root CA' ($null -ne $rootCa) $(if ($rootCa) { $rootCa.Thumbprint } else { 'certificate not found' })

$requiredFiles = @(
    '01_GPT_SAFE.txt', '02_GEMINI_SAFE.txt', '03_CLAUDE_SAFE.txt',
    '04_COMMON_SAFE.docx', '05_COMMON_SAFE.pdf', '90_BLOCK_script.bat',
    '91_BLOCK_nested_script.zip', '92_BLOCK_fake_pdf.pdf'
)
foreach ($name in $requiredFiles) {
    Add-Check "fixture $name" (Test-Path -LiteralPath (Join-Path $packRoot $name)) $name
}

if ($failures.Count -gt 0) {
    Write-Host "`nFAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host "`nALL ENVIRONMENT CHECKS PASSED" -ForegroundColor Green
