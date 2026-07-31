# AI upload record storage

Run `start_ai_dlp_capture.bat` to enable explicit investigation mode. This
routes only configured ChatGPT, Gemini, and Claude hosts through the proxy and
saves decrypted upload evidence.

Each upload produces a directory under:

```text
upload_records\YYYYMMDD\HHMMSS_mmm_Service_sessionN_streamN_sequence\
```

Files in each record:

- `original_<filename>`: reconstructed original upload bytes.
- `content.txt`: extracted readable content. Plain text and source formats are
  decoded directly; DOCX/XLSX/PPTX/HWPX/ODF and nested ZIP entries are parsed;
  PDF pages and PNG/JPEG/GIF/BMP/TIFF images use local Windows OCR. HWP5 and
  legacy OLE Office files use bounded best-effort extraction.
- `metadata.txt`: local/UTC time, computer, Windows user, client IP, process,
  service, protocol, host/path, original filename, MIME, size, SHA-256, format,
  ALLOW/BLOCK decision, and reason.

The lower-level HTTP request body is also written under `upload_captures`. For
ChatGPT raw PUT this is normally the original file. For Claude/Gemini multipart
requests it includes boundaries and part headers; use `upload_records` for the
reconstructed file. The safe launcher limits one request/capture to 128 MiB and
the combined in-memory HTTP/1 request budget to 512 MiB. Larger or incomplete
uploads are rejected before upstream forwarding.

The event log includes `UPLOAD CONTENT SAVED` with the record directory. Text
preview logging is disabled by the safe start script; full content remains in
the protected `content.txt` rather than being duplicated into runtime logs.

Stop capture with Ctrl+C; the start wrapper restores the prior Windows proxy
settings automatically. Run `unset_windows_proxy.bat` as a fallback after an
abnormal terminal shutdown. If the proxy itself crashes, the wrapper
intentionally leaves the AI-only PAC enabled so AI uploads fail closed; Outlook
and non-AI destinations remain `DIRECT`. Diagnose the proxy and then run the
unset script. Upload records contain potentially sensitive company and personal
data. The current test launcher does not implement automatic retention or
encrypted/central evidence storage, so service ACLs and a retention policy are
required before company-wide deployment.
