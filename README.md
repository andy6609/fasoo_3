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
