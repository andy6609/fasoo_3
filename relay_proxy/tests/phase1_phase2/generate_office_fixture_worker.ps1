[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("LegacyDoc", "EncryptedDocx", "LegacyXls", "LegacyPpt")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$Password = "LocalDlp-Test-2026!"
)

# This script is intentionally launched in a disposable PowerShell process by
# generate_optional_windows_fixtures.ps1.  Office COM can block on a hidden
# add-in/dialog; isolating it lets the parent enforce a hard timeout without
# touching any Office process that existed before fixture generation.
$ErrorActionPreference = "Stop"
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$fixtureDirectory = Split-Path -Parent $resolvedOutput
$packDirectory = Split-Path -Parent $fixtureDirectory
if ((Split-Path -Leaf $fixtureDirectory) -ne "fixtures" -or
    (Split-Path -Leaf $packDirectory) -notmatch "AI_DLP") {
    throw "Unsafe Office fixture path: $resolvedOutput"
}

$marker = "DLP_TEST_CONFIDENTIAL_MARKER_2026"
$allText = @"
이 문서는 로컬 DLP 1차 2차 기능 검증용 문서입니다.
LOCAL DLP PHASE ONE TWO TEST DOCUMENT
$marker
"@

function Release-ComObjectSafely {
    param($Object)
    if ($null -ne $Object -and [System.Runtime.InteropServices.Marshal]::IsComObject($Object)) {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object)
    }
}

$application = $null
$document = $null
$workbook = $null
$worksheet = $null
$presentation = $null
$slide = $null
$shape = $null
try {
    switch ($Mode) {
        "LegacyDoc" {
            $application = New-Object -ComObject Word.Application
            $application.Visible = $false
            $application.DisplayAlerts = 0
            $document = $application.Documents.Add()
            $document.Content.Text = $allText
            $document.SaveAs2($resolvedOutput, 0)
            $document.Close(0)
            Release-ComObjectSafely $document
            $document = $null
        }
        "EncryptedDocx" {
            $application = New-Object -ComObject Word.Application
            $application.Visible = $false
            $application.DisplayAlerts = 0
            $document = $application.Documents.Add()
            $document.Content.Text = $allText
            # The fourth SaveAs2 argument is the password to open the document.
            # Password-protected OOXML is written as an OLE
            # EncryptionInfo/EncryptedPackage wrapper.
            $document.SaveAs2($resolvedOutput, 12, $false, $Password)
            $document.Close(0)
            Release-ComObjectSafely $document
            $document = $null
        }
        "LegacyXls" {
            $application = New-Object -ComObject Excel.Application
            $application.Visible = $false
            $application.DisplayAlerts = $false
            $workbook = $application.Workbooks.Add()
            $worksheet = $workbook.Worksheets.Item(1)
            $worksheet.Cells.Item(1, 1).Value2 = "Local DLP legacy XLS fixture"
            $worksheet.Cells.Item(2, 1).Value2 = $allText
            $worksheet.Cells.Item(3, 1).Value2 = $marker
            $workbook.SaveAs($resolvedOutput, 56)
            $workbook.Close($false)
            Release-ComObjectSafely $worksheet
            Release-ComObjectSafely $workbook
            $worksheet = $null
            $workbook = $null
        }
        "LegacyPpt" {
            $application = New-Object -ComObject PowerPoint.Application
            $application.DisplayAlerts = 1
            $presentation = $application.Presentations.Add(0)
            $slide = $presentation.Slides.Add(1, 12)
            $shape = $slide.Shapes.AddTextbox(1, 40, 50, 620, 360)
            $shape.TextFrame.TextRange.Text = $allText
            $presentation.SaveAs($resolvedOutput, 1)
            $presentation.Close()
            Release-ComObjectSafely $shape
            Release-ComObjectSafely $slide
            Release-ComObjectSafely $presentation
            $shape = $null
            $slide = $null
            $presentation = $null
        }
    }
    if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Leaf)) {
        throw "Office did not write the requested fixture"
    }
    Write-Output "GENERATED"
    exit 0
}
finally {
    if ($null -ne $document) { try { $document.Close(0) } catch {} }
    if ($null -ne $workbook) { try { $workbook.Close($false) } catch {} }
    if ($null -ne $presentation) { try { $presentation.Close() } catch {} }
    if ($null -ne $application) { try { $application.Quit() } catch {} }
    Release-ComObjectSafely $shape
    Release-ComObjectSafely $slide
    Release-ComObjectSafely $presentation
    Release-ComObjectSafely $worksheet
    Release-ComObjectSafely $workbook
    Release-ComObjectSafely $document
    Release-ComObjectSafely $application
}
