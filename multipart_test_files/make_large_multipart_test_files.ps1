$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function New-RepeatedFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][int]$MegaBytes,
        [Parameter(Mandatory=$true)][string]$ChunkText
    )

    $fullPath = Join-Path $Root $Path
    $bufferText = $ChunkText
    while ([System.Text.Encoding]::UTF8.GetByteCount($bufferText) -lt 1048576) {
        $bufferText += $bufferText
    }
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($bufferText.Substring(0, 1048576))

    $fs = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        for ($i = 0; $i -lt $MegaBytes; $i++) {
            $fs.Write($buffer, 0, $buffer.Length)
        }
    }
    finally {
        $fs.Close()
    }

    Write-Host "created $fullPath ($MegaBytes MB)"
}

New-RepeatedFile -Path "large_safe_5mb.txt" -MegaBytes 5 -ChunkText "safe upload data. no blocked keyword here. "
New-RepeatedFile -Path "large_too_big_11mb.txt" -MegaBytes 11 -ChunkText "large benign upload data. "

# secret appears near the beginning, so the 1MB streaming sample detects it quickly.
$secretPath = Join-Path $Root "large_secret_2mb.txt"
[System.IO.File]::WriteAllText($secretPath, "this uploaded file contains secret data near the beginning.`r`n", [System.Text.Encoding]::UTF8)
$fs = [System.IO.File]::Open($secretPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
try {
    $buffer = [System.Text.Encoding]::UTF8.GetBytes(("padding data. " * 8192))
    while ($fs.Length -lt (2 * 1024 * 1024)) {
        $fs.Write($buffer, 0, $buffer.Length)
    }
}
finally {
    $fs.Close()
}
Write-Host "created $secretPath (2 MB with secret sample)"
