# Local DLP offline OCR worker

`offline_ocr.py` extracts Korean and English text from PNG, JPEG, GIF, BMP,
TIFF, and image-only PDF files without sending data to a cloud service.

Engine order:

1. Tesseract with `kor` language data, when installed.
2. Windows.Media.Ocr with the Korean Windows OCR language capability.
3. No compatible engine: exit code 2 and `NO_OCR_ENGINE`; no fabricated text.

## Probe

```powershell
.\run_offline_ocr.ps1 probe
```

## Extract one file

```powershell
.\run_offline_ocr.ps1 extract `
  --input "C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\fixtures\safe_scan.png" `
  --output "C:\Exception\ocr_content.txt" `
  --report "C:\Exception\ocr_report.json" `
  --language kor+eng
```

Exit codes:

- `0`: OCR complete; output and report written.
- `2`: compatible offline OCR engine unavailable.
- `3`: unsupported input or PDF renderer unavailable.
- `4`: OCR failed; the report contains the exact cause.

Optional environment variables:

- `LOCAL_DLP_PYTHON`: Python 3 executable used by the PowerShell launcher.
- `LOCAL_DLP_TESSERACT`: local `tesseract.exe` path.
- `LOCAL_DLP_PDFTOPPM`: local `pdftoppm.exe` path for scanned PDFs.

The worker processes the first frame of an animated GIF. OCR is probabilistic:
the caller should retain the original file and report, use normalized/fuzzy
matching for Korean prose, and use exact normalized matching for high-value
identifiers such as project codes and secret markers.
