# TCP Proxy Lab

## Overview

TCP Proxy Lab is a Windows-based C/C++ proxy research project built with Visual Studio. It started as a simple TCP relay exercise and expanded into a local HTTP/HTTPS proxy with DLP inspection, policy-based blocking, TLS MITM support, multipart upload detection, and audit logging.

The main implementation lives in `relay_proxy`. Supporting projects provide echo servers, HTTP clients, TLS test clients, and standalone TLS MITM proof-of-concept code.

## Key Features

- Local TCP proxy running on `127.0.0.1:8000`
- Dynamic upstream resolution from HTTP `Host` headers
- HTTP request and response parsing
- HTTP `CONNECT` tunnel handling
- Policy-based DLP inspection
- Keyword, email, phone number, resident ID, credit card, file upload, and file extension detection
- Multipart/form-data upload parsing
- Response body inspection before forwarding data to the client
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
- Winsock support through `Ws2_32.lib`
- IP Helper API support through `Iphlpapi.lib`

## Build

1. Open `tcp_proxy_lab.sln` in Visual Studio.
2. Select the desired build configuration, such as `Debug x64`.
3. Build the solution or build individual projects.
4. Use `relay_proxy` as the main executable for HTTP/HTTPS proxy testing.

## Default Ports

| Component | Address |
| --- | --- |
| `relay_proxy` | `127.0.0.1:8000` |
| `echo_server` | `127.0.0.1:9000` |
| Local TLS test server | `127.0.0.1:9443` |

## Run Basic HTTP/DLP Test

1. Build the solution in Visual Studio.
2. Start `relay_proxy.exe`.
3. Run `http_client.exe`.
4. Modify the request body in the HTTP client to test different DLP rules.

Example payloads:

```text
message=secret
message=password
message=confidential
email=test@example.com
phone=010-1234-5678
```

Expected behavior:

- `secret` is blocked.
- `password` is blocked.
- `confidential` is logged only.
- Email-like content is blocked.
- Phone-number-like content is blocked.

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

Supported rule types:

| Type | Description |
| --- | --- |
| `KEYWORD` | Match a specific keyword |
| `EMAIL` | Detect email-like content |
| `PHONE` | Detect phone-number-like content |
| `RESIDENT_ID` | Detect resident-ID-like content |
| `CREDIT_CARD` | Detect credit-card-like content |
| `FILE_UPLOAD` | Detect multipart file uploads |
| `FILE_EXT` | Match uploaded file extensions |

Example:

```text
1|BLOCK|KEYWORD|secret|Sensitive keyword detected: secret
2|BLOCK|KEYWORD|password|Password keyword detected
3|LOG_ONLY|KEYWORD|confidential|Confidential keyword detected. log only
9|BLOCK|FILE_EXT|.zip|Zip file upload blocked
10|LOG_ONLY|FILE_UPLOAD|-|File upload detected. log only
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
| `MITM` | Decrypt HTTPS, inspect HTTP request/response data, and apply DLP rules |
| `BYPASS` | Relay encrypted traffic without decryption |
| `AUDIT` | Relay encrypted traffic and write explicit audit metadata |
| `IGNORE` | Relay encrypted traffic while suppressing noisy tunnel logs |
| `BLOCK` | Reject the CONNECT request before connecting upstream |

Example:

```text
demo.local:9443 MITM local_browser_test
127.0.0.1:9443 MITM loopback_tls_test
chrome.exe chatgpt.com:443 AUDIT chrome_ai_service_metadata_audit
chrome.exe accounts.google.com:443 BYPASS auth_service_exception
DEFAULT BYPASS safe_default_for_unknown_https
```

Rules are evaluated from top to bottom, and the first matching rule wins.

## Runtime Policy Reload

While `relay_proxy.exe` is running, enter:

```text
r
```

This reloads `policy_rules.txt` without restarting the proxy.

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
