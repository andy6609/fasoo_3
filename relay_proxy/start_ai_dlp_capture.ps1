[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$RelayProxyPath,
    [int]$StartupTimeoutSeconds = 15,
    [switch]$SmokeTest
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$settingsScript = Join-Path $scriptRoot "windows_ai_proxy.ps1"
$proxyProcess = $null
$routingEnabled = $false
$routingEnableAttempted = $false
$preserveRoutingOnFailure = $false
$exitCode = 1

# Preventive mode invariants are set here as well as in the .bat wrapper so a
# direct PowerShell invocation cannot silently negotiate HTTP/2 or allow an
# unscannable upload.
$env:LOCAL_DLP_FORCE_HTTP1_UPLOAD_INSPECTION = "1"
$env:LOCAL_DLP_LOG_LEVEL = "INFO"
$env:LOCAL_DLP_DISCOVER_UPLOAD_HOSTS = ""
$env:LOCAL_DLP_CAPTURE_UPLOAD_BODIES = "1"
$env:LOCAL_DLP_CAPTURE_MAX_BYTES = "134217728"
$env:LOCAL_DLP_SAVE_UPLOAD_RECORDS = "1"
$env:LOCAL_DLP_BLOCK_UNSCANNABLE = "1"
$env:LOCAL_DLP_HTTP1_MAX_REQUEST_BYTES = "134217728"
$env:LOCAL_DLP_HTTP1_GLOBAL_BUFFER_BYTES = "536870912"
$env:LOCAL_DLP_LOG_CONTENT_PREVIEW = "0"
$env:LOCAL_DLP_ALLOW_INSECURE_UPSTREAM = ""

function Test-LocalPacEndpoint {
    $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:8000/proxy.pac?v=3")
    $request.Proxy = $null
    $request.Timeout = 1000
    $request.ReadWriteTimeout = 1000
    $response = $null
    $reader = $null
    try {
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $content = $reader.ReadToEnd()
        return $content -match "FindProxyForURL" -and $content -match 'return\s+"DIRECT"'
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

try {
    $RelayProxyPath = (Resolve-Path -LiteralPath $RelayProxyPath).Path
    $relayItem = Get-Item -LiteralPath $RelayProxyPath
    $sourceExtensions = @('.c', '.cpp', '.h', '.vcxproj')
    $latestSource = Get-ChildItem -LiteralPath $scriptRoot -File |
        Where-Object { $sourceExtensions -contains $_.Extension.ToLowerInvariant() } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -ne $latestSource -and $latestSource.LastWriteTimeUtc -gt $relayItem.LastWriteTimeUtc) {
        throw "relay_proxy.exe is older than $($latestSource.Name). Rebuild Release x64 before starting capture."
    }

    $caPath = Join-Path $scriptRoot 'certs\mitm.crt'
    $keyPath = Join-Path $scriptRoot 'certs\mitm.key'
    if (-not (Test-Path -LiteralPath $caPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        throw "MITM CA files are missing. Run make_relay_proxy_certs.bat first."
    }
    $caCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath)
    $trusted = @(Get-ChildItem Cert:\CurrentUser\Root, Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $caCertificate.Thumbprint }).Count -gt 0
    if (-not $trusted) {
        throw "The MITM CA is not trusted. Run install_mitm_root_ca_current_user.bat first."
    }

    if (Test-LocalPacEndpoint) {
        throw "A proxy is already serving the Local DLP PAC on 127.0.0.1:8000. Stop the existing instance first."
    }
    $proxyProcess = Start-Process -FilePath $RelayProxyPath -WorkingDirectory $scriptRoot `
        -NoNewWindow -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    while (-not (Test-LocalPacEndpoint)) {
        if ($proxyProcess.HasExited) {
            throw "relay_proxy.exe exited before its PAC endpoint became ready (exit=$($proxyProcess.ExitCode))."
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Timed out waiting for http://127.0.0.1:8000/proxy.pac."
        }
        Start-Sleep -Milliseconds 150
    }

    $routingEnableAttempted = $true
    & $settingsScript -Action Enable
    $routingEnabled = $true

    if ($SmokeTest) {
        Start-Sleep -Milliseconds 500
        $systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $routeChecks = @(
            @{ Uri = [Uri]'https://chatgpt.com/'; Bypass = $false },
            @{ Uri = [Uri]'https://gemini.google.com/'; Bypass = $false },
            @{ Uri = [Uri]'https://claude.ai/'; Bypass = $false },
            @{ Uri = [Uri]'https://outlook.office.com/'; Bypass = $true },
            @{ Uri = [Uri]'https://login.microsoftonline.com/'; Bypass = $true }
        )
        foreach ($check in $routeChecks) {
            $actualBypass = $systemProxy.IsBypassed($check.Uri)
            if ($actualBypass -ne $check.Bypass) {
                $selected = $systemProxy.GetProxy($check.Uri).AbsoluteUri
                throw "PAC route check failed for $($check.Uri.Host): bypass=$actualBypass selected=$selected"
            }
        }
        Write-Host "[PASS] Proxy startup, preventive policy, CA trust, and AI-only PAC routes succeeded." -ForegroundColor Green
        $exitCode = 0
    }
    else {
        Write-Host "[AI DLP CAPTURE] Proxy is ready and AI-only routing is enabled." -ForegroundColor Green
        Write-Host "[AI DLP CAPTURE] Upload ChatGPT, Gemini, and Claude test files now."
        Write-Host "[AI DLP CAPTURE] Press Ctrl+C to stop; Windows proxy settings will be restored."

        while (-not $proxyProcess.WaitForExit(500)) { }
        $preserveRoutingOnFailure = $true
        throw "relay_proxy.exe exited unexpectedly (exit=$($proxyProcess.ExitCode)). AI PAC routing remains enabled to fail closed; run unset_windows_proxy.bat after diagnosis."
    }
}
catch {
    Write-Host ("[ERROR] " + $_.Exception.Message) -ForegroundColor Red
    $exitCode = 1
}
finally {
    if ($routingEnableAttempted -and -not $preserveRoutingOnFailure) {
        try { & $settingsScript -Action Disable }
        catch { Write-Host ("[WARN] Automatic proxy restore failed: " + $_.Exception.Message) -ForegroundColor Yellow }
    }
    elseif ($preserveRoutingOnFailure) {
        Write-Host "[WARN] AI-only PAC was intentionally left enabled so AI uploads fail closed." -ForegroundColor Yellow
        Write-Host "       Outlook and non-AI destinations remain DIRECT. Run unset_windows_proxy.bat after diagnosis."
    }
    if ($null -ne $proxyProcess -and -not $proxyProcess.HasExited) {
        try {
            $proxyProcess.Kill()
            $proxyProcess.WaitForExit(5000) | Out-Null
        }
        catch { Write-Host "[WARN] relay_proxy.exe is still running; stop it manually." -ForegroundColor Yellow }
    }
}

exit $exitCode
