[CmdletBinding(DefaultParameterSetName = "Recognize")]
param(
    [Parameter(ParameterSetName = "Probe", Mandatory = $true)]
    [switch]$Probe,

    [Parameter(ParameterSetName = "Recognize", Mandatory = $true)]
    [string]$InputPath,

    [Parameter(ParameterSetName = "Recognize")]
    [string]$Language = "ko"
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Initialize-WindowsOcr {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [void][Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Storage.FileAccessMode, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.SoftwareBitmap, Windows.Foundation, ContentType = WindowsRuntime]
}
function Await-WinRtResult {
    param(
        [Parameter(Mandatory = $true)]$Operation,
        [Parameter(Mandatory = $true)][Type]$ResultType
    )

    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq "AsTask" -and
            $_.IsGenericMethodDefinition -and
            $_.GetParameters().Count -eq 1
        } |
        Select-Object -First 1

    if (-not $asTask) {
        throw "System.WindowsRuntimeSystemExtensions.AsTask<T> was not found."
    }

    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    return $task.GetAwaiter().GetResult()
}

function Get-AvailableLanguages {
    return @([Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages |
        ForEach-Object { $_.LanguageTag })
}

try {
    Initialize-WindowsOcr
    $available = Get-AvailableLanguages

    if ($Probe) {
        [ordered]@{
            available = ($available.Count -gt 0)
            engine = "windows-media-ocr"
            languages = $available
            offline = $true
        } | ConvertTo-Json -Compress -Depth 4
        exit 0
    }

    $resolved = (Resolve-Path -LiteralPath $InputPath).Path
    $requested = $Language.Trim()
    $selected = $available | Where-Object {
        $_ -ieq $requested -or $_.StartsWith("$requested-", [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1

    if (-not $selected -and $requested -match "^(kor|ko)(\+eng)?$") {
        $selected = $available | Where-Object { $_ -ieq "ko" -or $_.StartsWith("ko-") } | Select-Object -First 1
    }
    if (-not $selected -and $requested -match "^(eng|en)(-.+)?$") {
        $selected = $available | Where-Object { $_ -ieq "en" -or $_.StartsWith("en-") } | Select-Object -First 1
    }
    if (-not $selected) {
        throw "Requested OCR language '$Language' is unavailable. Installed: $($available -join ', ')"
    }

    $languageObject = [Windows.Globalization.Language]::new($selected)
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($languageObject)
    if (-not $engine) {
        throw "Windows OCR engine could not be created for '$selected'."
    }

    $file = Await-WinRtResult ([Windows.Storage.StorageFile]::GetFileFromPathAsync($resolved)) ([Windows.Storage.StorageFile])
    $stream = Await-WinRtResult ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    try {
        $decoder = Await-WinRtResult ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $bitmap = Await-WinRtResult ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        try {
            $result = Await-WinRtResult ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
            $lines = @($result.Lines | ForEach-Object { $_.Text })
            [ordered]@{
                ok = $true
                engine = "windows-media-ocr"
                language = $selected
                text = $result.Text
                lines = $lines
            } | ConvertTo-Json -Compress -Depth 5
        }
        finally {
            if ($bitmap -is [System.IDisposable]) { $bitmap.Dispose() }
        }
    }
    finally {
        if ($stream -is [System.IDisposable]) { $stream.Dispose() }
    }
}
catch {
    [ordered]@{
        ok = $false
        engine = "windows-media-ocr"
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress -Depth 4
    exit 2
}
