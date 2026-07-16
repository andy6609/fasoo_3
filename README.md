# TCP Proxy Lab

## Overview

TCP Proxy Lab is a Windows-based C/C++ research proxy for file-only DLP on AI websites. Normal websites pass through without TLS decryption. Selected browser traffic for ChatGPT, Gemini, and Claude is decrypted, but only actual file-upload requests are inspected or blocked.

The main implementation lives in `relay_proxy`. Supporting projects provide echo servers, HTTP clients, TLS test clients, and standalone TLS MITM proof-of-concept code.

## Key Features

- Local TCP proxy running on `127.0.0.1:8000`
- Dynamic upstream resolution from HTTP `Host` headers
- HTTP request and response parsing
- HTTP `CONNECT` tunnel handling
- File-upload-only DLP inspection for selected AI websites
- Dangerous file-extension and file-signature validation
- Multipart/form-data upload parsing
- Ordinary chat JSON, telemetry, response bodies, and personal information are not DLP-inspected
- TLS MITM for selected HTTPS targets
- Dynamic per-host leaf certificate generation and caching
- Process-aware TLS intercept policy
- Audit logging for blocked, logged, and tunneled traffic
- Runtime policy reload through the command thread

## Repository Structure

| Path | Description |
| --- | --- |
| `tcp_proxy_lab.sln` | Visual Studio solution file |
| `tcp_proxy_lab/` | TCP echo server project |
| `echo_client/` | Simple TCP echo client |
| `simple_proxy/` | Basic fixed-upstream TCP proxy |
| `http_client/` | HTTP and CONNECT test clients |
| `relay_proxy/` | Main proxy implementation |
| `tls_mitm_proxy/` | Standalone TLS MITM proof-of-concept and TLS test servers |
| `tls_test_client/` | TLS CONNECT and keep-alive test clients |
| `multipart_test_files/` | Sample files for multipart upload testing |
| `windows_browser_tools/` | Helper scripts for local browser proxy tests |
| `docs/` | Development notes and TLS MITM documentation |

## Main Components

## relay_proxy

`relay_proxy` is the main local DLP proxy. It listens on `127.0.0.1:8000`, accepts HTTP proxy traffic, resolves upstream targets dynamically, applies DLP policies, and forwards or blocks traffic based on the inspection result.

Important modules include:

| File | Purpose |
| --- | --- |
| `relay_proxy.c` | Main proxy loop, client handling, CONNECT routing, HTTP relay flow |
| `http_parser.c` | HTTP request parsing |
| `http_response_parser.c` | HTTP response parsing |
| `policy_engine.c` | Rule loading and policy evaluation |
| `dlp_engine.c` | DLP pattern detection and body inspection |
| `multipart_parser.c` | Multipart upload parsing and file metadata extraction |
| `tls_mitm_engine.c` | HTTPS MITM session handling |
| `tls_intercept_policy.c` | Target/process-based HTTPS policy decisions |
| `cert_manager.c` | MITM CA and per-host leaf certificate handling |
| `audit_log.c` | Security and policy audit logging |
| `process_metadata.c` | Windows process metadata lookup for client connections |

## Requirements

- Windows
- Visual Studio with C/C++ build tools
- Windows SDK
- OpenSSL for TLS MITM certificate generation and TLS handling
- vcpkg packages `openssl:x64-windows`, `zlib:x64-windows`, and
  `nghttp2:x64-windows` (`nghttp2` provides HPACK decoding for HTTP/2)
- Winsock support through `Ws2_32.lib`
- IP Helper API support through `Iphlpapi.lib`

## Build

1. Open `tcp_proxy_lab.sln` in Visual Studio.
2. Select the desired build configuration, such as `Debug x64`.
3. Build the solution or build individual projects.
4. Use `relay_proxy` as the main executable for HTTP/HTTPS proxy testing.

Install the x64 native dependencies once if they are not already available:

```powershell
C:\vcpkg\vcpkg.exe install openssl:x64-windows zlib:x64-windows nghttp2:x64-windows
```

## Default Ports

| Component | Address |
| --- | --- |
| `relay_proxy` | `127.0.0.1:8000` |
| `echo_server` | `127.0.0.1:9000` |
| Local TLS test server | `127.0.0.1:9443` |

## File-only DLP behavior

The proxy deliberately ignores ordinary request bodies, including chat JSON,
telemetry, keywords, email addresses, phone numbers, resident IDs, and card-like
numbers. DLP is entered only when both conditions are true:

1. The destination is ChatGPT, Gemini, Claude, a local test host, or an exact
   confirmed host in `upload_capture_hosts.txt`.
2. The request is classified as a file upload from multipart metadata,
   `Content-Disposition`, a file MIME type, or an upload-style PUT request.

Safe text, Office, PDF, image, and ZIP files are allowed by the default policy.
Executable and script extensions are blocked. A known file signature that does
not match its declared extension is also blocked.

At the default `INFO` log level, per-request HTTP headers, static assets,
telemetry, Sentinel pings, TLS handshake details, session boundaries, and raw
tunnel summaries are hidden. The normal upload trail is intentionally compact:

```text
UPLOAD PREPARED  ... original file name and redacted storage target
UPLOAD INSPECTED ... hash, detected format, extracted text bytes, ALLOW/BLOCK
UPLOAD FORWARDED ... upstream status for an allowed upload
```

Set `LOCAL_DLP_LOG_LEVEL=DEBUG` only while diagnosing protocol details. Signed
upload URL query parameters are redacted at every log level.

ChatGPT metadata requests are correlated with the later raw PUT to
`*.oaiusercontent.com`, even when they use different TCP/TLS sessions. DOCX
containers, PDF content streams, and ZIP entries are inspected in memory. ZIP
path traversal, encrypted entries, excessive expansion, dangerous embedded
extensions, active/embedded PDF content, and declared-format signature
mismatches are blocked. Extracted document text is counted for policy use but is
not printed into the runtime log.

An individual file can be checked without enabling the Windows proxy:

```powershell
.\x64\Release\relay_proxy.exe --analyze-file .\sample.docx `
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
```

## Run CONNECT Tunnel Test

1. Start `relay_proxy.exe`.
2. Run `connect_test_client.exe`.

The test client connects to the proxy, sends an HTTP `CONNECT` request, waits for `200 Connection Established`, and then sends HTTP traffic through the tunnel.

## Run TLS MITM Test

Generate the local MITM root certificate:

```bat
relay_proxy\make_relay_proxy_certs.bat
```

Install the MITM root certificate into the current user's Windows Root store:

```bat
relay_proxy\install_mitm_root_ca_current_user.bat
```

Start a local TLS test server:

```bat
python tls_mitm_proxy\tls_browser_test_server.py
```

Start the proxy:

```bat
relay_proxy.exe
```

Run TLS test clients:

```bat
connect_tls_test_client.exe
connect_tls_keepalive_test_client.exe
```

For browser-based local testing:

```bat
windows_browser_tools\add_demo_local_to_hosts_ADMIN.bat
relay_proxy\set_windows_proxy_127_0_0_1_8000.bat
windows_browser_tools\open_browser_test_urls.bat
```

After testing, remove the local proxy settings and trusted test CA:

```bat
relay_proxy\unset_windows_proxy.bat
relay_proxy\remove_mitm_root_ca_current_user.bat
```

## DLP Policy Rules

DLP rules are configured in:

```text
relay_proxy/policy_rules.txt
```

Rule format:

```text
rule_id|action|type|pattern|reason
```

Supported actions:

| Action | Description |
| --- | --- |
| `ALLOW` | Allow matching traffic |
| `BLOCK` | Block matching traffic and return a local block response |
| `LOG_ONLY` | Allow traffic but write an audit event |

Supported rule types are intentionally limited to files:

| Type | Description |
| --- | --- |
| `FILE_UPLOAD` | Detect multipart file uploads |
| `FILE_EXT` | Match uploaded file extensions |

Example:

```text
1|BLOCK|FILE_EXT|.exe|Executable file upload blocked
4|BLOCK|FILE_EXT|.bat|Batch script upload blocked
10|LOG_ONLY|FILE_UPLOAD|-|File upload detected and allowed
```

## TLS Intercept Policy

HTTPS handling is configured in:

```text
relay_proxy/tls_intercept_policy.txt
```

Supported formats:

```text
<target> <action> [reason]
<process> <target> <action> [reason]
DEFAULT <action> [reason]
```

Supported actions:

| Action | Description |
| --- | --- |
| `MITM` | Decrypt selected AI HTTPS traffic; DLP still runs only for file-upload requests |
| `BYPASS` | Relay encrypted traffic without decryption |
| `AUDIT` | Relay encrypted traffic and write explicit audit metadata |
| `IGNORE` | Relay encrypted traffic while suppressing noisy tunnel logs |
| `BLOCK` | Reject the CONNECT request before connecting upstream |

Example:

```text
chrome.exe demo.local:9443 MITM local_browser_test
msedge.exe chatgpt.com:443 MITM ai_file_upload_only
chrome.exe gemini.google.com:443 MITM ai_file_upload_only
chrome.exe claude.ai:443 MITM ai_file_upload_only
DEFAULT IGNORE non_ai_passthrough
```

Rules are evaluated from top to bottom, and the first matching rule wins.
The default profile is browser-only and AI-only. Non-AI websites, non-browser
applications, authentication services, and unknown destinations use a silent
raw TLS tunnel without content inspection.

## Upload Host Discovery

When a browser sends an upload to a host that is currently covered by the
`IGNORE` default policy, enable metadata-only upload host discovery before
starting the proxy:

```powershell
$env:LOCAL_DLP_DISCOVER_UPLOAD_HOSTS = "1"
$env:LOCAL_DLP_DISCOVERY_MIN_UPLOAD_BYTES = "1024"
..\x64\Debug\relay_proxy.exe
```

In another PowerShell window, watch only discovery events:

```powershell
Get-Content .\relay_runtime.log -Wait | Select-String "UPLOAD_HOST_"
```

Then open the target website in a supported browser and upload one test file.
The proxy emits:

- `UPLOAD_HOST_DISCOVERY_BEGIN` when an encrypted `IGNORE` tunnel starts.
- `UPLOAD_HOST_CANDIDATE` when client-to-server traffic dominates a two-second
  window and crosses the configured byte threshold.
- `UPLOAD_HOST_DISCOVERY_SUMMARY` when the tunnel closes, including total
  outbound/inbound bytes and the candidate result.

Discovery does not decrypt or inspect the payload. It identifies candidates
from encrypted byte direction and timing, so background POST requests can be
false positives. Correlate the event time with the manual upload, then add only
the confirmed browser/host pair to `relay_proxy/upload_capture_hosts.txt`:

```text
chrome.exe confirmed-upload.example.com:443
```

Restart the proxy after changing these environment variables,
`upload_capture_hosts.txt`, or `tls_intercept_policy.txt`. The runtime `r`
command reloads only `policy_rules.txt`.

### Confirmed-host MITM and per-stream body capture

After correlating an `UPLOAD_HOST_CANDIDATE` event with one controlled upload,
add only that exact browser/host pair to:

```text
relay_proxy/upload_capture_hosts.txt
```

Rule format and example:

```text
<browser-process> <host>:<port>
chrome.exe confirmed-upload.example.com:443
```

Then restart the proxy with body capture enabled:

```powershell
cd C:\Users\wodbs0101_global\source\repos\tcp_proxy_lab\relay_proxy

$env:LOCAL_DLP_CAPTURE_UPLOAD_BODIES = "1"
$env:LOCAL_DLP_CAPTURE_MAX_BYTES = "268435456"
..\x64\Debug\relay_proxy.exe
```

A matching entry forces MITM on the next connection unless the normal TLS
policy explicitly returns `BLOCK`. Decrypted request bodies are written to
`relay_proxy/upload_captures`:

- HTTP/2: one `.bin` file per HTTP/2 stream ID, written directly from DATA
  frames up to the configured per-stream limit.
- HTTP/1.1: one `.bin` file per request exchange. Chunked bodies are dechunked
  when decoding succeeds.

Watch capture decisions and output paths with:

```powershell
Get-Content .\relay_runtime.log -Wait |
    Select-String "UPLOAD_CAPTURE_MITM_SELECTED|UPLOAD_BODY_CAPTURE_"
```

`UPLOAD_BODY_CAPTURE_BEGIN` includes the host, method, path, content type,
stream ID, and output path. `UPLOAD_BODY_CAPTURE_END` reports bytes written,
completion, truncation, and write status. Capture files contain decrypted raw
request bodies and may include credentials, conversation data, multipart
boundaries, or other sensitive information. Keep the allowlist exact, use only
controlled test files, and remove the capture files after analysis.

## Runtime Policy Reload

While `relay_proxy.exe` is running, enter:

```text
r
```

This reloads `policy_rules.txt` without restarting the proxy.

## Windows TLS Trust and HTTP Protocol Mode

For verified HTTPS interception, `relay_proxy` imports trusted roots from the
Windows Current User and Local Machine `ROOT` stores into its OpenSSL client
context. Public upstream certificates therefore remain verified without using
`LOCAL_DLP_ALLOW_INSECURE_UPSTREAM`.

HTTPS MITM follows ALPN negotiation. `http/1.1` uses the HTTP/1.1 parser while
`h2` uses HPACK header decoding, per-stream request reconstruction, DLP policy
evaluation, audit logging, upstream `RST_STREAM`, and a local HTTP/2 403 block
response. HTTP/2 file request bodies are inspected up to 32 MiB per active
stream. A file larger than the complete inspection buffer is blocked rather
than receiving a partial safety decision.

TLS itself is still normally TLS 1.2 or TLS 1.3. The HTTP application protocol
is selected inside that handshake by ALPN: `http/1.1` selects the existing
HTTP/1.1 engine and `h2` selects the HTTP/2 engine. At the default `INFO` level
this protocol detail is hidden. Set `LOCAL_DLP_LOG_LEVEL=DEBUG` and confirm the
choice with:

```text
TLS MITM ALPN selected. ... side=client alpn=h2
TLS MITM ALPN selected. ... side=upstream alpn=h2
TLS MITM HTTP/2 analysis and DLP enforcement started. ...
HTTP2_ANALYSIS direction=REQUEST ... stream_id=...
```

For a real ChatGPT browser test, keep `chatgpt.com` and `*.openai.com` as `MITM`
for the browser process in `tls_intercept_policy.txt`. The supplied policy does
not decrypt `ChatGPT.exe`, Codex, WebView, or other desktop applications. Restart
the proxy or press `r` after editing policy rules. Disable QUIC/HTTP/3 in the test
browser so the request
uses the configured TCP HTTP proxy; otherwise UDP/443 traffic does not pass
through this proxy.

Use `LOCAL_DLP_ALLOW_INSECURE_UPSTREAM=1` only for controlled local servers with
self-signed certificates, never for public-site testing.

## Certificate Safety Notes

This project creates a local testing CA for TLS MITM experiments. The generated private key is sensitive because it can sign leaf certificates for arbitrary hosts.

Important files:

```text
relay_proxy/certs/mitm.crt
relay_proxy/certs/mitm.key
relay_proxy/certs/generated/
```

Recommended cleanup after testing:

```bat
relay_proxy\remove_mitm_root_ca_current_user.bat
relay_proxy\reset_generated_certs.bat
```

Do not use the generated MITM CA outside a controlled local test environment.

## Current Development Status

Implemented:

- TCP proxy relay
- HTTP request parsing
- HTTP response parsing
- CONNECT tunnel support
- DLP policy engine
- Multipart upload detection
- Response DLP inspection
- TLS MITM for selected targets
- Dynamic certificate generation
- Process-aware TLS policy matching
- Security and audit logging

In progress:

- Upload file binary extraction
- Upload file hash and original-file comparison
- File signature and magic-number analysis
- More complete browser and AI-agent upload behavior testing
- Expanded test matrix and final report materials

## Notes

This project is intended for local learning, research, and controlled DLP proxy experiments. Use TLS MITM only on systems and traffic where you have permission to inspect the data.
