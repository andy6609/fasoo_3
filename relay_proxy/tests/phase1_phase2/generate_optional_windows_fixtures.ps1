[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$packDirectory = Split-Path -Parent $resolvedOutput
$manifestPath = Join-Path $packDirectory "manifest.json"
$marker = "DLP_TEST_CONFIDENTIAL_MARKER_2026"
$allText = @"
이 문서는 로컬 DLP 1차 2차 기능 검증용 문서입니다.
LOCAL DLP PHASE ONE TWO TEST DOCUMENT
$marker
"@
$password = "LocalDlp-Test-2026!"
$results = New-Object System.Collections.Generic.List[object]
$workerScript = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "generate_office_fixture_worker.ps1"

if ((Split-Path -Leaf $resolvedOutput) -ne "fixtures" -or
    (Split-Path -Leaf $packDirectory) -notmatch "AI_DLP") {
    throw "Unsafe optional fixture path: $resolvedOutput"
}
if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Container)) {
    throw "Fixture directory not found: $resolvedOutput"
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Manifest not found: $manifestPath"
}
if (-not (Test-Path -LiteralPath $workerScript -PathType Leaf)) {
    throw "Office fixture worker not found: $workerScript"
}

function Add-FixtureResult {
    param(
        [string]$Format,
        [string]$File,
        [string]$Kind,
        [string]$Status,
        [string]$Reason
    )
    $results.Add([pscustomobject][ordered]@{
        format = $Format
        file = $File
        kind = $Kind
        status = $Status
        reason = $Reason
    })
}

function Test-CfbMagic {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 8
        if ($stream.Read($header, 0, 8) -ne 8) { return $false }
        return ([BitConverter]::ToString($header) -eq "D0-CF-11-E0-A1-B1-1A-E1")
    }
    finally {
        $stream.Dispose()
    }
}

function Test-ProgId {
    param([string]$ProgId)
    try { return $null -ne [type]::GetTypeFromProgID($ProgId) }
    catch { return $false }
}

function Test-ApplicationRunning {
    param([string]$ProcessName)
    return $null -ne (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Invoke-OfficeFixtureWorker {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ApplicationProcess,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [int]$TimeoutSeconds = 20
    )

    $existingProcessIds = @(Get-Process -Name $ApplicationProcess -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Id })
    $stdoutPath = Join-Path $packDirectory (".office_worker_{0}_{1}.stdout.txt" -f $Mode, $PID)
    $stderrPath = Join-Path $packDirectory (".office_worker_{0}_{1}.stderr.txt" -f $Mode, $PID)
    $worker = $null
    $timedOut = $false
    try {
        # Avoid accepting a stale file from an earlier optional run.  The path
        # has already passed the dedicated AI_DLP/fixtures safety check above.
        if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
            [System.IO.File]::Delete($OutputPath)
        }
        $arguments = @(
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $workerScript),
            "-Mode", $Mode,
            "-OutputPath", ('"{0}"' -f $OutputPath),
            "-Password", ('"{0}"' -f $password)
        )
        $worker = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        if (-not $worker.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $worker.Kill() } catch {}
            [void]$worker.WaitForExit(5000)
            # Office sometimes finishes SaveAs but hangs in Quit because of a
            # COM add-in.  Preserve a completed, magic-validated fixture after
            # terminating that disposable worker; otherwise report a SKIP.
            if (Test-CfbMagic $OutputPath) {
                return [pscustomobject]@{
                    status = "GENERATED"
                    reason = "Office wrote a valid CFB; watchdog terminated hung COM cleanup"
                }
            }
            return [pscustomobject]@{
                status = "SKIP"
                reason = "Office COM exceeded the $TimeoutSeconds-second safety timeout"
            }
        }
        $worker.Refresh()
        if ($worker.ExitCode -ne 0) {
            $errorText = if (Test-Path -LiteralPath $stderrPath) {
                (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue).Trim()
            } else { "" }
            if ([string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = "Office worker exited with code $($worker.ExitCode)"
            }
            return [pscustomobject]@{ status = "SKIP"; reason = $errorText }
        }
        if (-not (Test-CfbMagic $OutputPath)) {
            return [pscustomobject]@{ status = "SKIP"; reason = "Office output is not a valid CFB file" }
        }
        return [pscustomobject]@{ status = "GENERATED"; reason = "Office COM worker completed" }
    }
    catch {
        return [pscustomobject]@{ status = "SKIP"; reason = $_.Exception.Message }
    }
    finally {
        if ($null -ne $worker -and -not $worker.HasExited) {
            try { $worker.Kill() } catch {}
        }

        # Clean up only a new, headless COM automation server.  Pre-existing
        # Office PIDs and any process with a visible document are never touched.
        foreach ($process in @(Get-Process -Name $ApplicationProcess -ErrorAction SilentlyContinue)) {
            if ($existingProcessIds -contains $process.Id -or
                -not [string]::IsNullOrWhiteSpace($process.MainWindowTitle)) {
                continue
            }
            $isAutomationServer = $false
            try {
                $cim = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $process.Id) -ErrorAction Stop
                $isAutomationServer = [string]$cim.CommandLine -match "(?i)(/automation|-embedding)"
            }
            catch {}
            if ($isAutomationServer) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($timedOut -and (Test-Path -LiteralPath $OutputPath -PathType Leaf) -and
            -not (Test-CfbMagic $OutputPath)) { [System.IO.File]::Delete($OutputPath) }
    }
}

function Generate-WordFixtures {
    $legacyName = "legacy_confidential.doc"
    $encryptedName = "encrypted_confidential.docx"
    $legacyPath = Join-Path $resolvedOutput $legacyName
    $encryptedPath = Join-Path $resolvedOutput $encryptedName

    if (-not (Test-ProgId "Word.Application")) {
        Add-FixtureResult "doc" $legacyName "legacy-office" "SKIP" "Word COM is not registered"
        Add-FixtureResult "encrypted office" $encryptedName "encrypted-office" "SKIP" "Word COM is not registered"
        return
    }
    if (Test-ApplicationRunning "WINWORD") {
        Add-FixtureResult "doc" $legacyName "legacy-office" "SKIP" "Word is already open; skipped to protect the user's active documents"
        Add-FixtureResult "encrypted office" $encryptedName "encrypted-office" "SKIP" "Word is already open; skipped to protect the user's active documents"
        return
    }

    $legacy = Invoke-OfficeFixtureWorker -Mode "LegacyDoc" -ApplicationProcess "WINWORD" -OutputPath $legacyPath
    Add-FixtureResult "doc" $legacyName "legacy-office" $legacy.status $legacy.reason
    if (Test-ApplicationRunning "WINWORD") {
        Add-FixtureResult "encrypted office" $encryptedName "encrypted-office" "SKIP" "Word remained open after the isolated worker; encrypted fixture skipped"
        return
    }
    $encrypted = Invoke-OfficeFixtureWorker -Mode "EncryptedDocx" -ApplicationProcess "WINWORD" -OutputPath $encryptedPath
    $encryptedReason = if ($encrypted.status -eq "GENERATED") {
        "Word password-protected DOCX; password=$password"
    } else { $encrypted.reason }
    Add-FixtureResult "encrypted office" $encryptedName "encrypted-office" $encrypted.status $encryptedReason
}

function Generate-ExcelFixture {
    $name = "legacy_confidential.xls"
    $path = Join-Path $resolvedOutput $name
    if (-not (Test-ProgId "Excel.Application")) {
        Add-FixtureResult "xls" $name "legacy-office" "SKIP" "Excel COM is not registered"
        return
    }
    if (Test-ApplicationRunning "EXCEL") {
        Add-FixtureResult "xls" $name "legacy-office" "SKIP" "Excel is already open; skipped to protect the user's active workbooks"
        return
    }

    $generated = Invoke-OfficeFixtureWorker -Mode "LegacyXls" -ApplicationProcess "EXCEL" -OutputPath $path
    $reason = if ($generated.status -eq "GENERATED") { "Excel SaveAs xlExcel8" } else { $generated.reason }
    Add-FixtureResult "xls" $name "legacy-office" $generated.status $reason
}

function Generate-PowerPointFixture {
    $name = "legacy_confidential.ppt"
    $path = Join-Path $resolvedOutput $name
    if (-not (Test-ProgId "PowerPoint.Application")) {
        Add-FixtureResult "ppt" $name "legacy-office" "SKIP" "PowerPoint COM is not registered"
        return
    }
    if (Test-ApplicationRunning "POWERPNT") {
        Add-FixtureResult "ppt" $name "legacy-office" "SKIP" "PowerPoint is already open; skipped to protect the user's active presentations"
        return
    }

    $generated = Invoke-OfficeFixtureWorker -Mode "LegacyPpt" -ApplicationProcess "POWERPNT" -OutputPath $path
    $reason = if ($generated.status -eq "GENERATED") { "PowerPoint SaveAs ppSaveAsPowerPoint8" } else { $generated.reason }
    Add-FixtureResult "ppt" $name "legacy-office" $generated.status $reason
}

Generate-WordFixtures
Generate-ExcelFixture
Generate-PowerPointFixture

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest | Add-Member -MemberType NoteProperty -Name windows_optional -Value ($results.ToArray()) -Force
$preserved = @($manifest.not_generated | Where-Object {
    $formats = @($_.formats)
    -not ($formats -contains "doc" -or $formats -contains "xls" -or
          $formats -contains "ppt" -or $formats -contains "encrypted office")
})
$notGenerated = New-Object System.Collections.Generic.List[object]
foreach ($item in $preserved) { $notGenerated.Add($item) }

$missingLegacy = @($results | Where-Object {
    $_.kind -eq "legacy-office" -and $_.status -ne "GENERATED"
} | ForEach-Object { $_.format })
if ($missingLegacy.Count -gt 0) {
    $notGenerated.Add([pscustomobject]@{
        formats = $missingLegacy
        reason = "Optional Office generation skipped or failed; see windows_optional in manifest.json"
    })
}
$missingEncrypted = @($results | Where-Object {
    $_.kind -eq "encrypted-office" -and $_.status -ne "GENERATED"
})
if ($missingEncrypted.Count -gt 0) {
    $notGenerated.Add([pscustomobject]@{
        formats = @("encrypted office")
        reason = "Optional Word encryption generation skipped or failed; see windows_optional in manifest.json"
    })
}
$manifest.not_generated = $notGenerated.ToArray()
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $manifestPath,
    ($manifest | ConvertTo-Json -Depth 12),
    $utf8NoBom
)

foreach ($item in $results) {
    $color = if ($item.status -eq "GENERATED") { "Green" } elseif ($item.status -eq "SKIP") { "Yellow" } else { "Red" }
    Write-Host ("[{0}] {1}: {2}" -f $item.status, $item.file, $item.reason) -ForegroundColor $color
}
if (@($results | Where-Object { $_.status -eq "FAIL" }).Count -gt 0) { exit 1 }
exit 0
