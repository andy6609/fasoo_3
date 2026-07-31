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
$rawOutputDirectory = Join-Path $resultDirectory "relay_proxy_cli"

if (-not (Test-Path -LiteralPath $fixtures -PathType Container)) {
    throw "Fixture directory not found: $fixtures"
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Manifest not found: $manifestPath"
}
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot "relay_proxy\policy_rules.txt") -PathType Leaf)) {
    throw "Policy file not found below repository root: $repoRoot"
}

$coreSources = Get-ChildItem -LiteralPath (Join-Path $repoRoot "relay_proxy") -File |
    Where-Object { $_.Extension -in @(".c", ".cpp", ".h", ".vcxproj") }
$latestSource = $coreSources | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($RelayProxyPath)) {
    # The standalone relay_proxy project Release output is the canonical test
    # binary.  Solution-level and Debug outputs are compatibility fallbacks.
    $candidates = @(
        (Join-Path $repoRoot "relay_proxy\x64\Release\relay_proxy.exe"),
        (Join-Path $repoRoot "x64\Release\relay_proxy.exe"),
        (Join-Path $repoRoot "relay_proxy\x64\Debug\relay_proxy.exe"),
        (Join-Path $repoRoot "x64\Debug\relay_proxy.exe")
    )
    $existingCandidates = @($candidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        ForEach-Object { Get-Item -LiteralPath $_ })
    $freshCandidates = @($existingCandidates | Where-Object {
        $null -eq $latestSource -or $_.LastWriteTimeUtc -ge $latestSource.LastWriteTimeUtc
    })
    # Choose the newest fresh output.  The candidate list still limits the
    # selection to Release first/familiar build locations, while timestamp
    # ordering prevents an older artifact from hiding a newer build.
    $selectedBinary = $freshCandidates |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $selectedBinary) {
        $selectedBinary = $existingCandidates | Select-Object -First 1
    }
    if ($null -ne $selectedBinary) {
        $RelayProxyPath = $selectedBinary.FullName
    }
}
if ([string]::IsNullOrWhiteSpace($RelayProxyPath) -or
    -not (Test-Path -LiteralPath $RelayProxyPath -PathType Leaf)) {
    throw "relay_proxy.exe not found. Build relay_proxy x64 Release before running this test."
}
$RelayProxyPath = (Resolve-Path -LiteralPath $RelayProxyPath).Path

$binary = Get-Item -LiteralPath $RelayProxyPath
if ($latestSource -and $binary.LastWriteTimeUtc -lt $latestSource.LastWriteTimeUtc) {
    throw "relay_proxy.exe is stale. Rebuild x64 Release. Binary=$($binary.LastWriteTimeUtc.ToString('o')); latest source=$($latestSource.FullName) $($latestSource.LastWriteTimeUtc.ToString('o'))"
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$blockMarker = [string]$manifest.expected.marker
$allowMarker = [string]$manifest.expected.allow_marker
$rule100Marker = [string]$manifest.expected.policy_keyword_100
$rule101Marker = [string]$manifest.expected.policy_keyword_101
if ([string]::IsNullOrWhiteSpace($blockMarker) -or
    [string]::IsNullOrWhiteSpace($allowMarker) -or
    [string]::IsNullOrWhiteSpace($rule100Marker) -or
    [string]::IsNullOrWhiteSpace($rule101Marker)) {
    throw "Manifest schema 2 policy markers are missing. Regenerate the test pack."
}

$tests = @(
    [pscustomobject]@{ Name="allow_text"; File="allow_public.txt"; Mime="text/plain"; Format="TEXT"; Exit=0; Action="ALLOW"; Rule=$null; Marker=$allowMarker },
    [pscustomobject]@{ Name="block_text"; File="block_confidential.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_cp949"; File="block_confidential_cp949.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf8_nobom"; File="block_confidential_utf8_nobom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf16le_nobom"; File="block_confidential_utf16le_nobom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf16le_bom"; File="block_confidential_utf16le_bom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf16be_bom"; File="block_confidential_utf16be_bom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf32le_bom"; File="block_confidential_utf32le_bom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_text_utf32be_bom"; File="block_confidential_utf32be_bom.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_policy_keyword_rule100"; File="policy_block_rule100.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=100; Marker=$rule100Marker },
    [pscustomobject]@{ Name="block_policy_keyword_rule101"; File="policy_block_rule101.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=101; Marker=$rule101Marker },
    [pscustomobject]@{ Name="block_policy_rrn_rule110"; File="policy_block_rule110_rrn.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=110; Marker="000101-3000008" },
    [pscustomobject]@{ Name="block_policy_card_rule111"; File="policy_block_rule111_card.txt"; Mime="text/plain"; Format="TEXT"; Exit=2; Action="BLOCK"; Rule=111; Marker="4111 1111 1111 1111" },
    [pscustomobject]@{ Name="allow_policy_invalid_rrn"; File="policy_allow_invalid_rrn.txt"; Mime="text/plain"; Format="TEXT"; Exit=0; Action="ALLOW"; Rule=$null; Marker="000101-3000009" },
    [pscustomobject]@{ Name="allow_policy_invalid_card"; File="policy_allow_invalid_card.txt"; Mime="text/plain"; Format="TEXT"; Exit=0; Action="ALLOW"; Rule=$null; Marker="9999 9999 9999 9999" },
    [pscustomobject]@{ Name="log_only_policy_email_rule112"; File="policy_log_only_email.txt"; Mime="text/plain"; Format="TEXT"; Exit=0; Action="ALLOW"; PolicyAction="LOG_ONLY"; Rule=112; Marker="dlp.synthetic@example.invalid" },
    [pscustomobject]@{ Name="log_only_policy_phone_rule113"; File="policy_log_only_phone.txt"; Mime="text/plain"; Format="TEXT"; Exit=0; Action="ALLOW"; PolicyAction="LOG_ONLY"; Rule=113; Marker="010-0000-0000" },
    [pscustomobject]@{ Name="block_docx"; File="safe_sample.docx"; Mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"; Format="DOCX/DOCM"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_xlsx"; File="safe_sample.xlsx"; Mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; Format="XLSX/XLSM"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_pptx"; File="safe_sample.pptx"; Mime="application/vnd.openxmlformats-officedocument.presentationml.presentation"; Format="PPTX/PPTM"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_hwpx"; File="safe_sample.hwpx"; Mime="application/hwp+zip"; Format="HWPX"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_zip"; File="safe_bundle.zip"; Mime="application/zip"; Format="ZIP"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_png"; File="safe_scan.png"; Mime="image/png"; Format="PNG"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_jpeg"; File="safe_scan.jpg"; Mime="image/jpeg"; Format="JPEG"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_gif"; File="safe_scan.gif"; Mime="image/gif"; Format="GIF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_gif_marker_frame_2"; File="marker_second_frame.gif"; Mime="image/gif"; Format="GIF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_bmp"; File="safe_scan.bmp"; Mime="image/bmp"; Format="BMP"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_tiff"; File="safe_scan.tiff"; Mime="image/tiff"; Format="TIFF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_tiff_marker_page_2"; File="marker_second_page.tiff"; Mime="image/tiff"; Format="TIFF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_native_pdf"; File="safe_text.pdf"; Mime="application/pdf"; Format="PDF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_scanned_pdf"; File="safe_scan.pdf"; Mime="application/pdf"; Format="PDF"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_encrypted_pdf"; File="encrypted_confidential.pdf"; Mime="application/pdf"; Format="PDF"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$null; RequireMarker=$false; ReasonPattern="encrypted PDF cannot be inspected" },
    [pscustomobject]@{ Name="block_hwp5"; File="minimal_hwp5_confidential.hwp"; Mime="application/x-hwp"; Format="HWP"; Exit=2; Action="BLOCK"; Rule=102; Marker=$blockMarker },
    [pscustomobject]@{ Name="block_synthetic_legacy_doc"; File="synthetic_legacy_confidential.doc"; Mime="application/msword"; Format="DOC"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_synthetic_legacy_xls"; File="synthetic_legacy_confidential.xls"; Mime="application/vnd.ms-excel"; Format="XLS"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_synthetic_legacy_ppt"; File="synthetic_legacy_confidential.ppt"; Mime="application/vnd.ms-powerpoint"; Format="PPT"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_encrypted_zip"; File="encrypted_confidential.zip"; Mime="application/zip"; Format="ZIP"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$null; RequireMarker=$false; ReasonPattern="encrypted archive entry" },
    [pscustomobject]@{ Name="block_docx_opaque_embedding"; File="embedded_opaque_payload.docx"; Mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"; Format="DOCX/DOCM"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$null; RequireMarker=$false; ReasonPattern="embedded package payload cannot be fully inspected" }
)

$optionalNativeTests = @(
    [pscustomobject]@{ Name="block_legacy_doc"; File="legacy_confidential.doc"; Mime="application/msword"; Format="DOC"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_legacy_xls"; File="legacy_confidential.xls"; Mime="application/vnd.ms-excel"; Format="XLS"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_legacy_ppt"; File="legacy_confidential.ppt"; Mime="application/vnd.ms-powerpoint"; Format="PPT"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$blockMarker; ReasonPattern="legacy OLE text evidence extracted partially" },
    [pscustomobject]@{ Name="block_encrypted_office"; File="encrypted_confidential.docx"; Mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"; Format="DOCX/DOCM"; Exit=2; Action="BLOCK"; Rule=$null; Marker=$null; RequireMarker=$false; ReasonPattern="encrypted|signature mismatch" }
)
foreach ($optionalTest in $optionalNativeTests) {
    if (Test-Path -LiteralPath (Join-Path $fixtures $optionalTest.File) -PathType Leaf) {
        $tests += $optionalTest
    }
}

function Normalize-ExtractedText {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $Value,
        "[^0-9A-Za-z\uAC00-\uD7A3]",
        ""
    ).ToLowerInvariant()
    # Match the same conservative OCR-confusable set enforced by the native
    # policy engine.  Windows OCR commonly renders capital I as lowercase l.
    return $normalized.Replace("l", "i").Replace("1", "i").Replace("0", "o")
}

function Get-FileSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            return (($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }) -join "")
        }
        finally {
            $algorithm.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-ExtractedSection {
    param([string]$Output)
    $beginToken = "----- EXTRACTED CONTENT BEGIN"
    $endToken = "----- EXTRACTED CONTENT END -----"
    $begin = $Output.IndexOf($beginToken, [System.StringComparison]::Ordinal)
    if ($begin -lt 0) { return $null }
    $begin = $Output.IndexOf("-----", $begin + $beginToken.Length, [System.StringComparison]::Ordinal)
    if ($begin -lt 0) { return $null }
    $begin += 5
    $end = $Output.IndexOf($endToken, $begin, [System.StringComparison]::Ordinal)
    if ($end -lt 0) { return $null }
    return $Output.Substring($begin, $end - $begin)
}

New-Item -ItemType Directory -Force -Path $resultDirectory, $rawOutputDirectory | Out-Null
$results = New-Object System.Collections.Generic.List[object]
$previousBlockUnscannable = $env:LOCAL_DLP_BLOCK_UNSCANNABLE
$previousMaximumText = $env:LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES
$originalOutputEncoding = [Console]::OutputEncoding

try {
    $env:LOCAL_DLP_BLOCK_UNSCANNABLE = "1"
    $env:LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES = "16777216"
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    Push-Location -LiteralPath $repoRoot
    try {
        foreach ($test in $tests) {
            $fixturePath = Join-Path $fixtures $test.File
            $failures = New-Object System.Collections.Generic.List[string]
            $outputText = ""
            $actualExit = -999

            if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
                $failures.Add("fixture missing")
            }
            else {
                $outputLines = @(& $RelayProxyPath --inspect-file $fixturePath $test.Mime 2>&1)
                $actualExit = $LASTEXITCODE
                $outputText = ($outputLines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
            }

            $logPath = Join-Path $rawOutputDirectory ($test.Name + ".log")
            [System.IO.File]::WriteAllText($logPath, $outputText, (New-Object System.Text.UTF8Encoding($false)))

            if ($actualExit -ne $test.Exit) {
                $failures.Add("exit expected=$($test.Exit) actual=$actualExit")
            }
            if ($outputText -notmatch ("(?m)^FILE ANALYSIS .*\bformat=" + [regex]::Escape($test.Format) + "(?:\s|$)")) {
                $failures.Add("format expected=$($test.Format)")
            }
            if ($outputText -notmatch ("(?m)^FILE ANALYSIS .*\baction=" + [regex]::Escape($test.Action) + "(?:\s|$)")) {
                $failures.Add("action expected=$($test.Action)")
            }

            $requireMarker = if ($null -eq $test.RequireMarker) { $true } else { [bool]$test.RequireMarker }
            if ($requireMarker) {
                $extracted = Get-ExtractedSection -Output $outputText
                if ($null -eq $extracted) {
                    $failures.Add("extracted content section missing")
                }
                elseif ((Normalize-ExtractedText $extracted) -notlike ("*" + (Normalize-ExtractedText $test.Marker) + "*")) {
                    $failures.Add("extracted marker missing=$($test.Marker)")
                }
            }

            if ($null -ne $test.Rule) {
                if ([string]$test.PolicyAction -eq "LOG_ONLY") {
                    $logOnlyPattern = "(?m)POLICY matched rule_id=" + $test.Rule +
                        ".*action=LOG_ONLY"
                    if ($outputText -notmatch $logOnlyPattern) {
                        $failures.Add("LOG_ONLY policy rule expected=$($test.Rule)")
                    }
                }
                elseif ($outputText -notmatch ("content policy rule\s+" + $test.Rule + ":")) {
                    $failures.Add("policy rule expected=$($test.Rule)")
                }
            }
            elseif ($test.Action -eq "ALLOW" -and $outputText -match "content policy rule\s+\d+:") {
                $failures.Add("ALLOW fixture unexpectedly matched a blocking content rule")
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$test.ReasonPattern) -and
                $outputText -notmatch [string]$test.ReasonPattern) {
                $failures.Add("reason pattern missing=$($test.ReasonPattern)")
            }

            $status = if ($failures.Count -eq 0) { "PASS" } else { "FAIL" }
            $analysisLine = ($outputText -split "\r?\n" | Where-Object { $_ -like "FILE ANALYSIS*" } | Select-Object -First 1)
            $results.Add([pscustomobject][ordered]@{
                name = $test.Name
                file = $test.File
                mime = $test.Mime
                expected_format = $test.Format
                expected_exit = $test.Exit
                actual_exit = $actualExit
                expected_action = $test.Action
                expected_policy_action = $test.PolicyAction
                expected_rule = $test.Rule
                expected_marker = $test.Marker
                status = $status
                failures = @($failures)
                analysis = [string]$analysisLine
                raw_output = $logPath
            })

            $color = if ($status -eq "PASS") { "Green" } else { "Red" }
            $detail = if ($failures.Count -eq 0) { "format/action/marker/rule verified" } else { $failures -join "; " }
            Write-Host ("[{0}] {1}: {2}" -f $status, $test.Name, $detail) -ForegroundColor $color
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    [Console]::OutputEncoding = $originalOutputEncoding
    if ($null -eq $previousBlockUnscannable) {
        Remove-Item Env:\LOCAL_DLP_BLOCK_UNSCANNABLE -ErrorAction SilentlyContinue
    }
    else {
        $env:LOCAL_DLP_BLOCK_UNSCANNABLE = $previousBlockUnscannable
    }
    if ($null -eq $previousMaximumText) {
        Remove-Item Env:\LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES -ErrorAction SilentlyContinue
    }
    else {
        $env:LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES = $previousMaximumText
    }
}

$resultArray = @($results | ForEach-Object { $_ })
$passCount = @($resultArray | Where-Object { $_.status -eq "PASS" }).Count
$failCount = @($resultArray | Where-Object { $_.status -eq "FAIL" }).Count
$summary = [pscustomobject][ordered]@{
    executed_utc = [DateTime]::UtcNow.ToString("o")
    selected_executable = $RelayProxyPath
    executable = $RelayProxyPath
    executable_sha256 = Get-FileSha256 -Path $RelayProxyPath
    policy_file = (Join-Path $repoRoot "relay_proxy\policy_rules.txt")
    environment = [pscustomobject]@{
        LOCAL_DLP_BLOCK_UNSCANNABLE = "1"
        LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES = "16777216"
    }
    counts = [pscustomobject]@{ PASS = $passCount; FAIL = $failCount }
    results = $resultArray
}

$relayResultPath = Join-Path $resultDirectory "relay_proxy_results.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $relayResultPath,
    ($summary | ConvertTo-Json -Depth 12),
    $utf8NoBom
)

$pythonSummaryPath = Join-Path $resultDirectory "summary.json"
if (Test-Path -LiteralPath $pythonSummaryPath -PathType Leaf) {
    $combined = Get-Content -LiteralPath $pythonSummaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $combined | Add-Member -MemberType NoteProperty -Name relay_proxy -Value $summary -Force
    [System.IO.File]::WriteAllText(
        $pythonSummaryPath,
        ($combined | ConvertTo-Json -Depth 14),
        $utf8NoBom
    )
}

Write-Host "relay_proxy.exe results: $relayResultPath"
Write-Host ("Native relay_proxy checks: PASS={0} FAIL={1}" -f $passCount, $failCount)
if ($failCount -gt 0) { exit 1 }
exit 0
