[CmdletBinding()]
param(
    [string]$PackDirectory = "C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack",
    [string]$RelayProxyPath
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot "..\..\.."))
$fixtures = Join-Path $PackDirectory "fixtures"
$manifestPath = Join-Path $PackDirectory "manifest.json"
$resultDirectory = Join-Path $PackDirectory "verification_results"

if ([string]::IsNullOrWhiteSpace($RelayProxyPath)) {
    $RelayProxyPath = Join-Path $repoRoot "relay_proxy\x64\Release\relay_proxy.exe"
}
if (-not (Test-Path -LiteralPath $RelayProxyPath -PathType Leaf)) {
    throw "relay_proxy.exe not found: $RelayProxyPath"
}
if (-not (Test-Path -LiteralPath $fixtures -PathType Container)) {
    throw "Fixture directory not found: $fixtures"
}

function Get-Sha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            return (($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }) -join "")
        }
        finally { $algorithm.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Read-Metadata {
    param([Parameter(Mandatory=$true)][string]$Path)
    $values = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
        }
    }
    return $values
}

function Normalize-OcrText {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $Value, "[^0-9A-Za-z\uAC00-\uD7A3]", "").ToLowerInvariant()
    return $normalized.Replace("l", "i").Replace("1", "i").Replace("0", "o")
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$blockMarker = [string]$manifest.expected.marker
$allowMarker = [string]$manifest.expected.allow_marker
$runId = "{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss_fff"), $PID
$recordRoot = Join-Path $resultDirectory ("upload_records_" + $runId)
New-Item -ItemType Directory -Force -Path $recordRoot | Out-Null

$cases = @(
    [pscustomobject]@{ Service="ChatGPT"; Host="chatgpt.com"; File="safe_sample.docx"; Mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"; Exit=2; Action="BLOCK"; Marker=$blockMarker },
    [pscustomobject]@{ Service="Claude"; Host="claude.ai"; File="safe_scan.pdf"; Mime="application/pdf"; Exit=2; Action="BLOCK"; Marker=$blockMarker },
    [pscustomobject]@{ Service="Gemini"; Host="gemini.google.com"; File="safe_sample.xlsx"; Mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; Exit=2; Action="BLOCK"; Marker=$blockMarker },
    [pscustomobject]@{ Service="ChatGPT"; Host="chatgpt.com"; File="allow_public.txt"; Mime="text/plain"; Exit=0; Action="ALLOW"; Marker=$allowMarker }
)

$previousDirectory = $env:LOCAL_DLP_UPLOAD_RECORD_DIRECTORY
$previousUnscannable = $env:LOCAL_DLP_BLOCK_UNSCANNABLE
$execution = @()
try {
    $env:LOCAL_DLP_UPLOAD_RECORD_DIRECTORY = $recordRoot
    $env:LOCAL_DLP_BLOCK_UNSCANNABLE = "1"
    foreach ($case in $cases) {
        $fixturePath = Join-Path $fixtures $case.File
        $output = @(& $RelayProxyPath --store-file $fixturePath $case.Mime $case.Service 2>&1) -join [Environment]::NewLine
        $execution += [pscustomobject]@{ case=$case; exit=$LASTEXITCODE; output=$output }
    }
}
finally {
    if ($null -eq $previousDirectory) { Remove-Item Env:\LOCAL_DLP_UPLOAD_RECORD_DIRECTORY -ErrorAction SilentlyContinue }
    else { $env:LOCAL_DLP_UPLOAD_RECORD_DIRECTORY = $previousDirectory }
    if ($null -eq $previousUnscannable) { Remove-Item Env:\LOCAL_DLP_BLOCK_UNSCANNABLE -ErrorAction SilentlyContinue }
    else { $env:LOCAL_DLP_BLOCK_UNSCANNABLE = $previousUnscannable }
}

$recordDirectories = @(Get-ChildItem -LiteralPath $recordRoot -Directory -Recurse |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "metadata.txt") })
$results = @()

foreach ($run in $execution) {
    $case = $run.case
    $failures = @()
    if ($run.exit -ne $case.Exit) { $failures += "exit expected=$($case.Exit) actual=$($run.exit)" }

    $record = $null
    $metadata = $null
    foreach ($candidate in $recordDirectories) {
        $candidateMetadata = Read-Metadata (Join-Path $candidate.FullName "metadata.txt")
        if ($candidateMetadata["service"] -eq $case.Service -and
            $candidateMetadata["filename"] -eq $case.File) {
            $record = $candidate
            $metadata = $candidateMetadata
            break
        }
    }

    if ($null -eq $record) {
        $failures += "matching upload record missing"
    }
    else {
        $original = @(Get-ChildItem -LiteralPath $record.FullName -File |
            Where-Object { $_.Name -like "original_*" }) | Select-Object -First 1
        $contentPath = Join-Path $record.FullName "content.txt"
        $fixturePath = Join-Path $fixtures $case.File

        if ($null -eq $original) { $failures += "original_* missing" }
        elseif ((Get-Sha256 $original.FullName) -ne (Get-Sha256 $fixturePath)) {
            $failures += "saved original SHA-256 differs from fixture"
        }
        if (-not (Test-Path -LiteralPath $contentPath -PathType Leaf)) {
            $failures += "content.txt missing"
        }
        else {
            $content = Get-Content -LiteralPath $contentPath -Raw -Encoding UTF8
            if ((Normalize-OcrText $content) -notlike ("*" + (Normalize-OcrText $case.Marker) + "*")) {
                $failures += "content marker missing"
            }
        }

        foreach ($field in @("captured_local","captured_utc","computer","windows_user",
            "client_ip","process_id","process_name","service","protocol","host","path",
            "filename","content_type","file_bytes","sha256","format","action","reason")) {
            if ([string]::IsNullOrWhiteSpace([string]$metadata[$field])) { $failures += "metadata field missing=$field" }
        }
        if ($metadata["host"] -ne $case.Host) { $failures += "host expected=$($case.Host) actual=$($metadata['host'])" }
        if ($metadata["action"] -ne $case.Action) { $failures += "action expected=$($case.Action) actual=$($metadata['action'])" }
        if ($metadata["original_complete"] -ne "true") { $failures += "original_complete is not true" }
        if ($null -ne $original -and $metadata["sha256"] -ne (Get-Sha256 $original.FullName)) {
            $failures += "metadata SHA-256 differs from original"
        }
    }

    $status = if ($failures.Count -eq 0) { "PASS" } else { "FAIL" }
    $recordPath = if ($null -ne $record) { $record.FullName } else { $null }
    $results += [pscustomobject][ordered]@{
        service=$case.Service; file=$case.File; expected_action=$case.Action;
        status=$status; failures=$failures; record=$recordPath
    }
    $color = if ($status -eq "PASS") { "Green" } else { "Red" }
    $detail = if ($failures.Count) { $failures -join "; " } else { "original/content/metadata verified" }
    Write-Host ("[{0}] store/{1}/{2}: {3}" -f $status,$case.Service,$case.File,$detail) -ForegroundColor $color
}

$passCount = @($results | Where-Object { $_.status -eq "PASS" }).Count
$failCount = @($results | Where-Object { $_.status -eq "FAIL" }).Count
$summary = [pscustomobject][ordered]@{
    executed_utc=[DateTime]::UtcNow.ToString("o"); record_root=$recordRoot;
    counts=[pscustomobject]@{PASS=$passCount; FAIL=$failCount}; results=$results
}
$resultPath = Join-Path $resultDirectory "upload_record_results.json"
[System.IO.File]::WriteAllText($resultPath, ($summary | ConvertTo-Json -Depth 10),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Upload-record results: $resultPath"
Write-Host "Upload-record checks: PASS=$passCount FAIL=$failCount"
if ($failCount -gt 0) { exit 1 }
exit 0
