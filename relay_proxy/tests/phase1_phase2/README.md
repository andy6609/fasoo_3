# Phase 1/2 Local DLP test pack

This folder creates a synthetic, offline test pack for the phase 1 document
parsers and phase 2 image OCR path. It contains no real confidential data.

The generated pack is intentionally written to:

```text
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack
```

Files generated inside the repository can be changed immediately to a Fasoo
`DRMONE` protected file, which makes parser tests invalid. The verifier checks
for that header and reports a specific failure instead of reporting a generic
PDF/ZIP parse error.

## One-click generation and verification

Run:

```powershell
cd C:\path\to\tcp_proxy_lab\relay_proxy\tests\phase1_phase2
.\RUN_ALL_TESTS.bat
```

Expected current result:

```text
Python fixture checks: PASS: 77, FAIL: 0, SKIP: 2
Native relay_proxy.exe checks: PASS: 38, FAIL: 0
Upload-record checks: PASS: 4, FAIL: 0
```

The two transparent SKIPs describe optional Microsoft Office vendor round-trip
DOC/XLS/PPT and password-protected Office generation on the current workstation.
They are not reported as passes. Deterministic parser-conformance fixtures still
verify HWP5, legacy CFB DOC/XLS/PPT, and encrypted ZIP paths in every run.
If Word, Excel, or PowerPoint is already open, optional COM generation is skipped
to protect the user's work. A disposable STA worker and 20-second watchdog prevent
hidden Office dialogs/add-ins from hanging the test run; only new headless
`/AUTOMATION` or `-Embedding` processes are eligible for cleanup.
The native checks execute the newest available `relay_proxy.exe`, preferring
`relay_proxy\x64\Release\relay_proxy.exe`, and fail if that executable is older
than a core C/C++ source file.

Machine-readable results:

```text
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\summary.json
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\relay_proxy_results.json
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\verification_results\upload_record_results.json
```

The first file contains both the Python result and an embedded `relay_proxy`
section. Per-case native stdout is retained below
`verification_results\relay_proxy_cli` for debugging.

## Generated coverage

- Plain text: UTF-8 with/without BOM, CP949, UTF-16LE/BE, UTF-32LE/BE, CSV,
  JSON, XML, and Python source
- OOXML: DOCX, XLSX, PPTX
- Korean document containers: HWPX and a minimal HWP5 CFB parser fixture
- Legacy Office fail-closed parser fixtures: DOC, XLS, PPT CFB streams
- PDF: text PDF, image-only scanned PDF, and genuine password-encrypted PDF
- Archive: ZIP containing text, JSON, and DOCX; genuine ZipCrypto encrypted ZIP
- Embedded package fail-closed: benign DOCX with `word/embeddings/opaque.bin`
- OCR: PNG, JPEG, GIF, BMP, TIFF, scanned PDF, plus marker-only-on-frame-2
  animated GIF and marker-only-on-page-2 TIFF
- Magic validation: PDF, OOXML/ZIP/HWPX, PNG, JPEG, GIF, BMP, TIFF
- DRM detection: Fasoo `DRMONE` prefix
- Policy rules: Korean keywords 100/101, checksum-valid synthetic resident ID
  110, Luhn-valid synthetic test card 111, invalid checksum ALLOW controls, and
  email/phone LOG_ONLY rules 112/113

The policy-sensitive format and OCR fixtures contain these synthetic markers:

```text
이 문서는 로컬 DLP 1차 2차 기능 검증용 문서입니다.
LOCAL DLP PHASE ONE TWO TEST DOCUMENT
DLP_TEST_CONFIDENTIAL_MARKER_2026
```

The historical `safe_sample.*` and `safe_scan.*` names mean that the files are
safe synthetic data, not that policy should allow them. They intentionally
contain `CONFIDENTIAL`, so a successful native content-policy test must return
exit code `2`, action `BLOCK`, and rule `102`.

Two explicit text controls avoid that ambiguity:

- `allow_public.txt` contains `DLP_TEST_PUBLIC_MARKER_2026` and must return
  exit code `0` with action `ALLOW`.
- `block_confidential.txt` contains `DLP_TEST_CONFIDENTIAL_MARKER_2026` and
  must return exit code `2` with action `BLOCK` and rule `102`.
- The CP949, UTF-8-no-BOM, UTF-16LE/BE, and UTF-32LE/BE controls must produce
  the same normalized marker and rule `102`, proving decoding is not UTF-8-only.

Policy-value fixtures are synthetic test data only:

- `000101-3000008` is fabricated with an all-zero serial area but intentionally
  passes the implemented date/checksum validator; it is not presented as a real
  person's identifier. `000101-3000009` is its failing-checksum control.
- `4111 1111 1111 1111` is the conventional non-active Luhn test-card value.
  `9999 9999 9999 9999` and every 13-16 digit suffix fail Luhn.
- `dlp.synthetic@example.invalid` uses the reserved `.invalid` domain, and
  `010-0000-0000` is used only as a format detector control.

For email and phone, the CLI's final enforcement action remains `ALLOW`, while
the SECURITY line must report `action=LOG_ONLY` and rule 112 or 113. The native
verifier asserts both parts so telemetry cannot silently disappear.

## Native C/C++ policy verification

After the Python structural/OCR verification, `RUN_ALL_TESTS.bat` invokes
`verify_relay_proxy.ps1`. It runs `relay_proxy.exe --inspect-file` against:

- UTF-8, CP949, UTF-16LE/BE, and UTF-32LE/BE TXT ALLOW/BLOCK controls
- Keyword, structured checksum, invalid-value, and LOG_ONLY policy controls
- DOCX, XLSX, PPTX, HWPX, and nested ZIP
- Minimal HWP5 and legacy DOC/XLS/PPT CFB fail-closed fixtures
- Encrypted ZIP/PDF and opaque embedded DOCX fail-closed fixtures
- PNG, JPEG, GIF, BMP, and TIFF through the proxy's native Windows OCR path,
  including marker-only-on-frame/page-2 regression cases
- Native-text PDF and image-only scanned PDF

Every sensitive case must simultaneously satisfy all of these assertions:

1. The process exits with code `2`.
2. `FILE ANALYSIS` reports the expected format and `action=BLOCK`.
3. The extracted-content section contains the normalized confidential marker
   (including the native engine's conservative OCR `I/l/1` tolerance).
4. The decision reason identifies content-policy rule `102`.

This is intentionally stricter than checking only a BLOCK exit code: a PDF
blocked as merely unscannable, or by an unrelated false-positive rule, fails.

## Browser upload test

1. Start `relay_proxy\start_ai_dlp_capture.bat`.
2. Fully close and reopen Chrome.
3. Upload files from the generated `fixtures` folder to ChatGPT, Gemini, and
   Claude one at a time.
4. Confirm each incident directory under `relay_proxy\upload_records` contains
   `original_*`, `content.txt`, and `metadata.txt`.
5. Confirm `metadata.txt` records service, local/UTC time, computer name,
   Windows user, client IP, process, original filename, SHA-256, and decision.
6. Compare `content.txt` with `manifest.json`. Image files and scanned PDFs are
   OCRed locally by the proxy through Windows.Media.Ocr; no cloud OCR API is used.
7. Stop with Ctrl+C. The capture wrapper restores the previous Windows proxy
   settings automatically; run `relay_proxy\unset_windows_proxy.bat` only as a
   fallback after an abnormal terminal/process shutdown.

## Separate commands

Generate only:

```powershell
.\generate_test_pack.ps1
```

Verify an existing pack and require a working OCR engine:

```powershell
.\verify_test_pack.ps1 -StrictOcr
```

Run only the native `relay_proxy.exe` analysis and policy assertions:

```powershell
.\verify_relay_proxy.ps1
```

Verify original/content/metadata storage for ChatGPT, Claude, and Gemini:

```powershell
.\verify_upload_records.ps1
```

To test a specific build explicitly:

```powershell
.\verify_relay_proxy.ps1 -RelayProxyPath "C:\path\to\relay_proxy.exe"
```

If an OCR engine is absent, verification reports `SKIP` by default. With
`-StrictOcr`, that condition is a failure. No cloud OCR API is used.

## Known limits

- The deterministic HWP5 and legacy DOC/XLS/PPT files are minimal CFB
  parser-conformance fixtures, not Hancom/Microsoft vendor round-trip documents.
  Keep a separate non-DRM production corpus before claiming broad real-world
  compatibility.
- DOC/XLS/PPT remain bounded best-effort OLE extraction and are blocked
  fail-closed. Optional Microsoft Office COM fixtures are generated only when
  the relevant application is installed, closed, and responsive within the
  watchdog window.
- Password-protected documents cannot yield plaintext without a password;
  encrypted ZIP and PDF are verified as blocked, while genuine
  password-protected Office generation remains conditional on an available,
  closed Word instance.
- Windows OCR may confuse similar glyphs (`차`/`자` and `I`/`l` occurred in testing).
  The verifier therefore requires at least 0.85 Korean similarity while still
  requiring the normalized English phrase and DLP marker with only the same
  narrowly-scoped confusable substitutions used by the native policy engine.
- Native Windows OCR enumerates up to 100 image frames/pages. The frame-2 GIF
  and page-2 TIFF cases fail if the implementation regresses to first-frame-only.
