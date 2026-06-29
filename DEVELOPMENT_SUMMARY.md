# TCP Proxy Lab 개발 정리

작성일: 2026-06-17

이 문서는 현재 저장소의 개발 사항, 실행 방법, 주요 모듈과 함수 사용법을 한 곳에 정리한 문서이다. 프로젝트는 Windows Winsock 기반 TCP/HTTP 프록시 실습에서 시작해, HTTP DLP 검사, CONNECT 터널 처리, TLS MITM, 정책 기반 차단/감사, 프로세스 메타데이터 로깅까지 확장되어 있다.

## 1. 전체 구성

### 솔루션

- `tcp_proxy_lab.sln`: Visual Studio 솔루션 파일
- 대상 플랫폼: Windows, Visual Studio C/C++
- 주요 라이브러리:
  - `Ws2_32.lib`: Winsock TCP 통신
  - `Iphlpapi.lib`: TCP 연결 소유 프로세스 조회
  - `libssl.lib`, `libcrypto.lib`: OpenSSL TLS/MITM 및 인증서 처리

### 프로젝트별 역할

| 경로 | 역할 |
| --- | --- |
| `tcp_proxy_lab/echo_server.c` | TCP echo 서버. 기본 upstream 테스트 서버 |
| `echo_client/echo_client.c` | echo 서버 또는 프록시로 문자열을 보내는 테스트 클라이언트 |
| `simple_proxy/simple_proxy.c` | 고정 upstream으로 데이터를 중계하는 초기 단순 TCP 프록시 |
| `http_client/http_client.c` | HTTP POST 요청을 프록시로 보내 DLP 정책을 테스트 |
| `http_client/connect_test_client.c` | HTTP CONNECT 터널 수립 후 터널 안에서 HTTP 요청 테스트 |
| `tls_mitm_proxy/tls_mitm_proxy.c` | 독립형 TLS MITM POC |
| `tls_test_client/*.c` | TLS/MITM 및 keep-alive 테스트용 클라이언트 |
| `relay_proxy/*.c`, `*.h` | 현재 핵심 프록시 구현. 동적 upstream, HTTP DLP, CONNECT, TLS MITM, 정책, 로깅 포함 |
| `windows_browser_tools/*.bat` | 브라우저 테스트용 hosts/URL 보조 스크립트 |

## 2. 현재 개발 상태 요약

### 10주차 계획 기준 현재 위치

현재 구현은 1~7주차 목표의 핵심 기능을 대부분 구현했고, 8~9주차의 일부 기반 기능까지 들어간 상태이다. 다만 8주차의 "업로드 파일 Binary 데이터 획득/원본 일치 검증"과 9주차의 "파일 시그니처 기반 분석, 다양한 브라우저/AI Agent 환경별 성공/실패 사례 정리"는 아직 PoC 수준을 넘어 체계적으로 완성해야 한다.

| 주차 | 목표 | 현재 상태 | 근거/구현 위치 | 남은 작업 |
| --- | --- | --- | --- | --- |
| 1주차 | 프로젝트 이해 및 기본 개념 학습 | 완료 | TCP/HTTP/HTTPS/TLS/MITM/DLP 방향으로 구조가 잡힘 | 최종 보고서에 개념 정리 보강 |
| 2주차 | 네트워크 통신 구조 및 Proxy 동작 방식 학습 | 완료 | `simple_proxy`, `relay_proxy`에서 explicit proxy 구조 구현 | transparent proxy 비교는 문서 중심으로 정리 필요 |
| 3주차 | Local Proxy 기본 구현 | 완료 | TCP listen, accept, upstream connect, 양방향 relay 구현 | 예외 케이스 테스트 로그 정리 |
| 4주차 | HTTP 요청/응답 분석 기능 구현 | 완료 | `http_parser`, `http_response_parser`, request/response buffer 구현 | header 전체 로깅, 더 많은 HTTP edge case는 개선 가능 |
| 5주차 | TLS 세션 암·복호화 구조 학습 및 적용 | 대부분 완료 | `tls_mitm_engine`, `cert_manager`, MITM CA/leaf cert 생성 | 인증서 신뢰 설치 절차와 보안 주의사항 보고서화 |
| 6주차 | HTTPS 트래픽 분석 기능 구현 | 대부분 완료 | CONNECT 정책, TLS MITM, HTTPS request/response DLP 검사 구현 | 브라우저별 실제 테스트 결과 정리 필요 |
| 7주차 | 파일 업로드 행위 식별 기능 구현 | 부분 완료 | `multipart_parser`, `FILE_UPLOAD`, `FILE_EXT`, filename 추출 | MIME type, 파일 크기, AI Agent별 업로드 패턴 정리 보강 |
| 8주차 | 업로드 파일 정보 및 바이너리 데이터 획득 | 진행 전/부분 기반 | multipart part body scan 기반은 있음 | 파일 binary 저장/해시/원본 비교 기능 필요 |
| 9주차 | 파일 분석 및 PoC 검증 | 진행 전/부분 기반 | 확장자 기반 `.zip`, `.xlsx` 판별은 있음 | magic number, signature, 성공/실패 사례 표 작성 필요 |
| 10주차 | 최종 보고서 작성 및 발표 | 문서 초안 진행 중 | 본 `DEVELOPMENT_SUMMARY.md` 작성 | 최종 보고서/발표 자료 형태로 재구성 필요 |

### 현재 구현 완료 범위

- Local TCP Proxy: 클라이언트 연결 수락, upstream 연결, 데이터 중계, 연결 종료 처리가 구현되어 있다.
- HTTP 분석: Method, Path, Version, Host, Content-Type, Content-Length, Body, 응답 Status/Content-Type/Transfer-Encoding/Body를 파싱한다.
- DLP 정책: keyword, email, phone, resident id, credit card, file upload, file extension 기반 정책 검사가 가능하다.
- HTTPS MITM: CONNECT 대상 정책에 따라 MITM/BYPASS/AUDIT/IGNORE/BLOCK 처리가 가능하고, MITM 대상은 TLS 복호화 후 HTTP request/response를 검사한다.
- 인증서 처리: MITM CA 인증서/키를 기반으로 host별 leaf certificate를 생성하고 `certs/generated`에 캐시한다.
- 프로세스 기반 정책: TCP 연결 소유 프로세스명을 조회하여 TLS intercept policy 판단과 audit log에 사용한다.
- Multipart 업로드 식별: `multipart/form-data` boundary, file part, filename, 일부 확장자와 업로드 파일 내부 keyword를 검사한다.
- Audit/Logging: request/response 차단, log-only, CONNECT raw tunnel summary, process metadata를 로그로 남긴다.

### 아직 완성해야 하는 핵심 범위

- 업로드 파일 binary 추출물을 별도 파일로 저장하거나 메모리 객체로 관리하는 기능.
- 업로드 파일의 원본 일치 검증을 위한 size/hash 계산.
- MIME Type, Content-Disposition field name, filename, 확장자, binary size를 구조화된 audit record로 남기는 기능.
- 파일 signature/magic number 기반 분석.
- 브라우저별, AI Agent별 파일 업로드 요청 차이 분석.
- 성공 사례/실패 사례 테스트 matrix 정리.
- 최종 보고서와 발표 자료용 아키텍처 다이어그램, 흐름도, 테스트 결과 표.

### 완료된 주요 기능

1. 기본 TCP echo 테스트
   - `echo_server`는 `127.0.0.1:9000`에서 대기한다.
   - `echo_client`는 `127.0.0.1:8000`으로 접속해 입력 문자열을 전송한다.

2. 단순 TCP 프록시
   - `simple_proxy`는 `127.0.0.1:8000`에서 클라이언트를 받고 `127.0.0.1:9000` upstream으로 고정 중계한다.
   - `send_all()`로 partial send 문제를 줄였다.

3. 동적 HTTP relay proxy
   - `relay_proxy`는 `127.0.0.1:8000`에서 대기한다.
   - 일반 HTTP 요청은 `Host` 헤더에서 upstream host/port를 동적으로 해석한다.
   - CONNECT 요청은 `host:port` target을 파싱하고 정책에 따라 MITM, BYPASS, AUDIT, IGNORE, BLOCK 중 하나로 처리한다.

4. HTTP 요청/응답 단위 버퍼링
   - 요청은 `request_buffer`로 `Content-Length` 기반 완성 여부를 판단한다.
   - 응답은 `response_buffer`로 `Content-Length`와 `Transfer-Encoding: chunked`를 처리한다.

5. DLP 정책 엔진
   - `policy_rules.txt`에서 룰을 로드한다.
   - 룰 포맷: `rule_id|action|type|pattern|reason`
   - 지원 action: `ALLOW`, `BLOCK`, `LOG_ONLY`
   - 지원 type: `KEYWORD`, `EMAIL`, `PHONE`, `RESIDENT_ID`, `CREDIT_CARD`, `FILE_UPLOAD`, `FILE_EXT`

6. Body decoding
   - `application/x-www-form-urlencoded`: `%xx`, `+` decoding
   - JSON 계열 content-type: escape sequence와 `\uXXXX` decoding
   - 그 외 content-type: raw body 복사

7. Multipart upload 검사
   - `multipart/form-data` boundary를 추출한다.
   - file part의 `filename`을 추출한다.
   - `.zip`, `.xlsx`, `secret`, `password`, email-like content 등을 검사한다.

8. 응답 DLP
   - upstream HTTP 응답 body도 정책 검사한다.
   - 응답 위반 시 원본 응답을 클라이언트로 보내지 않고 403 block response를 전송한다.

9. TLS intercept policy
   - `tls_intercept_policy.txt`에서 CONNECT 대상별 정책을 로드한다.
   - process-aware 규칙을 지원한다.
   - 기본값은 `DEFAULT BYPASS safe_default_for_unknown_https`이다.

10. TLS MITM
   - 정책이 `MITM`인 CONNECT 세션에서 클라이언트와 upstream 양쪽 TLS 세션을 각각 수립한다.
   - SNI callback으로 동적 leaf certificate를 생성/캐시한다.
   - TLS 안의 HTTP 요청/응답을 복호화해 기존 HTTP parser와 DLP 엔진으로 검사한다.
   - HTTP keep-alive에서 여러 request/response exchange를 순차 처리한다.

11. 프로세스 메타데이터
   - 클라이언트 TCP 연결의 owning PID를 조회한다.
   - `process_name`, `process_path`를 세션 컨텍스트와 audit log에 포함한다.

12. 로깅/Audit
   - 일반 로그: DEBUG, INFO, WARN, ERROR
   - 보안 로그: SECURITY
   - 차단/감사 이벤트는 `AUDIT ...` 형태로 세션, 프로세스, 요청/응답, 룰 정보를 남긴다.

13. 런타임 정책 reload
   - `command_thread`가 stdin 명령을 받아 `r` 입력 시 `policy_rules.txt`를 다시 로드한다.

## 3. 실행 방법

### 3.1 기본 HTTP/DLP 테스트

1. Visual Studio에서 `tcp_proxy_lab.sln`을 연다.
2. `relay_proxy`를 빌드한다.
3. 필요하면 `tcp_proxy_lab/echo_server.c`도 빌드해서 upstream 테스트 서버로 실행한다.
4. 실행 순서:

```text
1) echo_server.exe
2) relay_proxy.exe
3) http_client.exe
```

기본 포트:

| 컴포넌트 | 주소 |
| --- | --- |
| relay_proxy | `127.0.0.1:8000` |
| echo_server | `127.0.0.1:9000` |
| TLS test server | `127.0.0.1:9443` |

`http_client`의 body 값을 바꿔가며 DLP 결과를 확인할 수 있다.

예:

```c
const char* body = "message=sec%72et";
const char* body = "phone=010-1234-5678";
const char* body = "email=test%40example.com";
const char* body = "message=confidential";
```

### 3.2 CONNECT raw tunnel 테스트

```text
1) relay_proxy.exe
2) connect_test_client.exe
```

`connect_test_client`는 다음 순서로 동작한다.

1. `relay_proxy:8000`으로 TCP 접속
2. `CONNECT 127.0.0.1:9000 HTTP/1.1` 전송
3. `200 Connection Established` 확인
4. 터널 안에서 HTTP GET 요청 전송

### 3.3 TLS MITM 테스트

1. 인증서 생성:

```bat
relay_proxy\make_relay_proxy_certs.bat
```

2. 브라우저 테스트를 하려면 루트 CA 설치:

```bat
relay_proxy\install_mitm_root_ca_current_user.bat
```

3. 로컬 TLS 테스트 서버 실행:

```bat
python tls_mitm_proxy\tls_browser_test_server.py
```

4. relay proxy 실행:

```text
relay_proxy.exe
```

5. TLS 테스트 클라이언트 실행:

```text
connect_tls_test_client.exe
connect_tls_keepalive_test_client.exe
```

브라우저 테스트를 하려면:

```bat
windows_browser_tools\add_demo_local_to_hosts_ADMIN.bat
relay_proxy\set_windows_proxy_127_0_0_1_8000.bat
windows_browser_tools\open_browser_test_urls.bat
```

테스트 후 정리:

```bat
relay_proxy\unset_windows_proxy.bat
relay_proxy\remove_mitm_root_ca_current_user.bat
windows_browser_tools\remove_demo_local_from_hosts_ADMIN.bat
```

## 4. 정책 파일 사용법

### 4.1 `relay_proxy/policy_rules.txt`

포맷:

```text
rule_id|action|type|pattern|reason
```

예:

```text
1|BLOCK|KEYWORD|secret|Sensitive keyword detected: secret
3|LOG_ONLY|KEYWORD|confidential|Confidential keyword detected. log only
4|BLOCK|EMAIL|-|Email address detected
9|BLOCK|FILE_EXT|.zip|Zip file upload blocked
10|LOG_ONLY|FILE_UPLOAD|-|File upload detected. log only
```

동작:

- 룰은 위에서 아래로 검사된다.
- 처음 매칭되는 룰이 결과가 된다.
- `BLOCK`은 요청/응답을 차단하고 403을 전송한다.
- `LOG_ONLY`는 audit log만 남기고 원본 트래픽은 계속 전달한다.
- 파일이 없거나 유효 룰이 없으면 built-in default policy를 사용한다.
- `relay_proxy` 실행 중 콘솔에서 `r`을 입력하면 정책 reload가 수행된다.

### 4.2 `relay_proxy/tls_intercept_policy.txt`

지원 포맷:

```text
<target> <action> [reason]
<process> <target> <action> [reason]
DEFAULT <action> [reason]
```

지원 action:

| Action | 의미 |
| --- | --- |
| `MITM` | TLS 복호화 후 HTTP 요청/응답 DLP 검사 |
| `BYPASS` | 암호화된 CONNECT 터널을 그대로 중계 |
| `AUDIT` | raw tunnel로 중계하되 정책 결정 로그를 명시적으로 남김 |
| `IGNORE` | raw tunnel로 중계하고 noisy traffic 로그를 최대한 억제 |
| `BLOCK` | upstream 연결 전에 CONNECT 요청 차단 |

예:

```text
demo.local:9443 MITM local_browser_test
chrome.exe chatgpt.com:443 AUDIT chrome_ai_service_metadata_audit
chrome.exe accounts.google.com:443 BYPASS auth_service_exception
DEFAULT BYPASS safe_default_for_unknown_https
```

규칙은 위에서 아래로 평가되며 first match가 적용된다. `*.domain.com`, `*:443`, `*` 같은 wildcard를 사용할 수 있다.

## 5. 핵심 처리 흐름

### 5.1 일반 HTTP 요청/응답

```text
client
  -> relay_proxy accept
  -> session_context 생성
  -> process_metadata 조회
  -> relay_loop
  -> request_buffer에 client bytes 누적
  -> request_buffer_get_complete_request_length
  -> parse_http_request
  -> inspect_dlp_request
  -> inspect_multipart_upload_request
  -> BLOCK이면 send_block_response
  -> ALLOW/LOG_ONLY이면 Host 기반 upstream 연결
  -> upstream으로 원본 request forwarding
  -> response_buffer에 upstream bytes 누적
  -> response_buffer_get_complete_response_length
  -> parse_http_response
  -> inspect_dlp_response
  -> BLOCK이면 send_response_block_response
  -> ALLOW/LOG_ONLY이면 client로 원본 response forwarding
```

### 5.2 CONNECT 처리

```text
client CONNECT host:port
  -> parse_http_request
  -> upstream_resolve_from_connect_target
  -> tls_intercept_policy_decide_with_process
  -> BLOCK: send_block_response 후 종료
  -> MITM: upstream TCP 연결 후 200 응답, tls_mitm_handle_connect_session
  -> BYPASS/AUDIT/IGNORE: 200 응답 후 raw_tunnel_loop
```

### 5.3 TLS MITM 처리

```text
CONNECT MITM decision
  -> upstream TCP 연결
  -> client에게 200 Connection Established
  -> client-side SSL_CTX 생성
  -> SNI callback에서 host별 leaf cert 생성/적용
  -> client와 SSL_accept
  -> upstream-side SSL_CTX 생성
  -> upstream과 SSL_connect
  -> TLS 안의 HTTP request/response exchange 반복
  -> 각 exchange마다 request DLP, response DLP 검사
```

## 6. relay_proxy 모듈별 함수 정리

### 6.1 `relay_proxy.c`

#### `main(void)`

- Winsock 초기화, logger 초기화, 정책 엔진 로드, TLS intercept 정책 로드, command thread 시작, listener 생성을 수행한다.
- `PROXY_PORT`는 `8000`이다.
- accept 루프에서 클라이언트 연결마다 `proxy_session_context_t`를 할당하고 worker thread를 생성한다.

사용 위치:

```c
listen_sock = create_listener(PROXY_PORT);
client_sock = accept(listen_sock, ...);
session_context_init(session, client_sock, &client_addr, NULL, 0);
_beginthreadex(NULL, 0, client_thread_proc, session, 0, &thread_id);
```

#### `client_thread_proc(void* arg)`

- thread entry point.
- `arg`를 `proxy_session_context_t*`로 받아 thread id를 기록한다.
- `handle_client_session()`을 호출하고 세션 메모리를 해제한다.

#### `handle_client_session(proxy_session_context_t* session)`

- 세션 시작/종료 로그를 남긴다.
- `relay_loop()`를 실행한다.
- 종료 시 client socket을 닫고 byte counter를 포함한 summary를 남긴다.

#### `relay_loop(proxy_session_context_t* session)`

- 일반 HTTP, CONNECT, upstream 응답을 모두 처리하는 메인 relay loop.
- `select()`로 client socket과 upstream socket을 감시한다.
- client 방향:
  - `recv()`
  - `request_buffer_append()`
  - `request_buffer_get_complete_request_length()`
  - `parse_http_request()`
  - CONNECT이면 `handle_connect_request()`
  - 일반 HTTP이면 DLP 검사 후 upstream으로 전송
- upstream 방향:
  - `recv()`
  - `response_buffer_append()`
  - `response_buffer_get_complete_response_length()`
  - `parse_http_response()`
  - 응답 DLP 검사 후 client로 전송 또는 차단

#### `handle_connect_request(...)`

- CONNECT request 전용 처리 함수.
- CONNECT target을 `upstream_resolve_from_connect_target()`로 해석한다.
- TLS intercept policy를 조회한다.
- action별 처리:
  - `BLOCK`: 403 block response
  - `MITM`: upstream 연결, 200 응답, `tls_mitm_handle_connect_session()`
  - `BYPASS`, `AUDIT`, `IGNORE`: 200 응답, raw tunnel 중계
- 이미 버퍼에 들어온 CONNECT 이후 데이터가 있으면 `forward_buffered_connect_tunnel_data()`로 upstream에 전달한다.

#### `raw_tunnel_loop(...)`

- CONNECT BYPASS/AUDIT/IGNORE에서 암호화된 TCP byte stream을 그대로 양방향 중계한다.
- `select()`로 client/upstream 양쪽 socket을 감시한다.
- byte count, chunk count, duration, 종료 사유를 summary log로 남긴다.
- `IGNORE` 정책에서는 noisy log를 줄이기 위해 일부 로그를 생략한다.

#### `ensure_upstream_connected(...)`

- 일반 HTTP request의 `Host` 헤더를 기반으로 upstream을 동적으로 연결한다.
- 이미 upstream socket이 있으면 재사용한다.
- upstream이 proxy 자신을 가리키면 루프 방지를 위해 실패 처리한다.

#### `send_connect_established_response(SOCKET client_sock)`

- CONNECT 성공 응답을 전송한다.

```http
HTTP/1.1 200 Connection Established
Proxy-Agent: local-dlp-proxy
Connection: keep-alive
```

#### `is_same_endpoint(...)`

- IP 문자열과 port가 같은 endpoint인지 비교한다.
- proxy self-loop 방지에 사용한다.

#### `is_connect_request(const http_request_t* request)`

- HTTP method가 `CONNECT`인지 대소문자 무시로 확인한다.

#### `should_suppress_connect_policy_logs(...)`

- CONNECT 대상 정책이 `IGNORE`인지 silent decision으로 확인한다.
- noisy background traffic의 정책 로그 억제에 사용한다.

#### `forward_buffered_connect_tunnel_data(...)`

- CONNECT request 뒤에 같은 buffer로 이미 들어온 tunnel payload를 upstream으로 넘긴다.
- `request_buffer_consume()`으로 넘긴 만큼 제거한다.

### 6.2 `socket_utils.c`

#### `send_all(SOCKET sock, const char* buffer, int length)`

- `send()`가 일부만 전송할 수 있는 문제를 처리하기 위해 전체 length가 전송될 때까지 반복한다.
- 성공 시 총 전송 byte 수를 반환한다.
- 실패 시 `SOCKET_ERROR`를 반환한다.

사용 예:

```c
if (send_all(upstream_sock, request_data, complete_request_length) == SOCKET_ERROR) {
    // send failure
}
```

#### `close_socket_safe(SOCKET* sock)`

- `INVALID_SOCKET`이 아닌 socket만 닫고 포인터가 가리키는 값을 `INVALID_SOCKET`으로 바꾼다.

#### `create_listener(unsigned short port)`

- TCP listen socket을 생성한다.
- `SO_REUSEADDR` 설정, bind, listen까지 수행한다.
- 실패 시 `INVALID_SOCKET`을 반환한다.

#### `connect_upstream(const char* ip, unsigned short port)`

- IPv4 주소와 port로 upstream TCP 연결을 생성한다.
- DNS 이름이 아니라 IP 문자열을 받는다.

### 6.3 `session_context.c`

#### `session_context_init(...)`

- 세션 id를 증가시키고 client/proxy/upstream 주소, socket, process metadata 초기값을 설정한다.
- `getsockname()`으로 proxy local endpoint를 기록한다.

#### `session_context_set_thread_id(...)`

- worker thread id를 세션에 기록한다.

#### `session_context_set_upstream(...)`

- upstream IP/port를 세션에 기록한다.

#### `session_context_set_process_metadata(...)`

- 조회된 `process_metadata_t`를 세션에 복사한다.

#### byte counter 함수

- `session_context_add_bytes_from_client`
- `session_context_add_bytes_to_upstream`
- `session_context_add_bytes_from_upstream`
- `session_context_add_bytes_to_client`

각 방향별 byte count를 누적한다. relay와 TLS MITM 양쪽에서 audit summary에 사용한다.

#### log 함수

- `session_context_log_created`
- `session_context_log_started`
- `session_context_log_finished`

세션 생성, 시작, 종료 시점에 client/proxy/upstream, process, byte count를 로그로 남긴다.

### 6.4 `process_metadata.c`

#### `process_metadata_init(process_metadata_t* metadata)`

- `found=0`, `process_id=0`, name/path는 `-`로 초기화한다.

#### `process_metadata_lookup_tcp_owner(...)`

- `GetExtendedTcpTable()`로 현재 TCP table을 조회한다.
- client local endpoint와 proxy remote endpoint가 일치하는 row를 찾아 owning PID를 얻는다.
- PID로 `QueryFullProcessImageNameA()`를 호출해 process path와 name을 채운다.

사용 예:

```c
process_metadata_t process_metadata;
process_metadata_init(&process_metadata);
process_metadata_lookup_tcp_owner(
    session->client_ip,
    session->client_port,
    session->proxy_ip,
    session->proxy_port,
    &process_metadata
);
```

#### `process_metadata_log(...)`

- PID, process name, process path를 로그로 남긴다.

### 6.5 `upstream_resolver.c`

#### `upstream_target_init(upstream_target_t* target)`

- host/ip를 `-`, port를 `0`으로 초기화한다.

#### `upstream_resolve_from_host_header(const char* host_header, upstream_target_t* target)`

- 일반 HTTP `Host` 헤더를 파싱한다.
- port가 없으면 기본값 `80`을 사용한다.
- DNS를 IPv4 주소로 resolve한다.

#### `upstream_resolve_from_connect_target(const char* connect_target, upstream_target_t* target)`

- CONNECT target을 파싱한다.
- port가 없으면 기본값 `443`을 사용한다.

#### `upstream_target_log(...)`, `upstream_target_log_connect(...)`

- resolve 결과를 일반 HTTP/CONNECT 용도로 구분해 로그에 남긴다.

주의:

- 현재 IPv4/domain 중심이다.
- IPv6 authority는 아직 지원하지 않고 warn 후 실패 처리한다.

### 6.6 `request_buffer.c`

#### `request_buffer_init(request_buffer_t* buffer)`

- 요청 버퍼를 0으로 초기화한다.

#### `request_buffer_append(...)`

- 새로 수신한 client bytes를 버퍼 뒤에 붙인다.
- 최대 크기 `REQUEST_BUFFER_MAX_SIZE`는 65536이다.

#### `request_buffer_get_complete_request_length(...)`

- `\r\n\r\n` header end를 찾는다.
- `Content-Length`를 읽어 전체 request 길이를 계산한다.
- 반환값:
  - `1`: 완성된 HTTP request가 있음
  - `0`: 아직 불완전함
  - `-1`: 오류

#### `request_buffer_data(...)`, `request_buffer_length(...)`

- 내부 data pointer와 현재 길이를 읽는다.

#### `request_buffer_consume(...)`

- 처리한 길이만큼 버퍼 앞부분을 제거한다.
- 남은 데이터가 있으면 앞으로 당긴다.

### 6.7 `response_buffer.c`

#### `response_buffer_init(...)`, `response_buffer_append(...)`

- upstream 응답 bytes를 누적한다.
- 최대 크기 `RESPONSE_BUFFER_MAX_SIZE`는 131072이다.

#### `response_buffer_get_complete_response_length(...)`

- HTTP response header end를 찾는다.
- `Transfer-Encoding: chunked`이면 chunk framing을 끝까지 읽어 완성 여부를 판단한다.
- chunked가 아니면 `Content-Length` 기반으로 판단한다.
- 반환값은 request buffer와 동일하게 `1`, `0`, `-1`이다.

#### `response_buffer_data(...)`, `response_buffer_length(...)`, `response_buffer_consume(...)`

- request buffer와 같은 방식으로 data 접근, 길이 조회, 소비 처리를 한다.

### 6.8 `http_parser.c`

#### `parse_http_request(const char* buffer, int length, http_request_t* request)`

- HTTP request line에서 method, path, version을 추출한다.
- header에서 `Host`, `Content-Length`, `Content-Type`을 추출한다.
- body는 최대 `HTTP_BODY_SIZE - 1`만큼 복사한다.
- 성공 시 `1`, 실패 시 `0`.

사용 예:

```c
http_request_t request;
if (parse_http_request(data, length, &request)) {
    dlp_result_t result = inspect_dlp_request(&request);
}
```

#### `print_http_request(const http_request_t* request)`

- request 구조체 내용을 stdout에 출력한다.
- 디버깅용이다.

### 6.9 `http_response_parser.c`

#### `parse_http_response(const char* buffer, int length, http_response_t* response)`

- status line에서 version, status code, reason phrase를 추출한다.
- `Content-Length`, `Content-Type`, `Transfer-Encoding`을 추출한다.
- chunked body는 decoded body로 변환해 `response->body`에 저장한다.
- 성공 시 `1`, 실패 시 `0`.

#### `print_http_response(const http_response_t* response)`

- response 구조체를 stdout에 출력한다.

### 6.10 `body_decoder.c`

#### `decode_body_for_inspection(...)`

- DLP 검사 전에 body를 사람이 읽는 형태에 가깝게 변환한다.
- content-type에 따라 다음 중 하나를 수행한다.
  - form-urlencoded: `%xx`, `+` decoding
  - JSON: `\"`, `\\`, `\n`, `\t`, `\uXXXX` decoding
  - 기타: raw copy
- 성공 시 `0`, 실패 시 `-1`.

사용 예:

```c
char inspection_body[8192];
int inspection_length = 0;
decode_body_for_inspection(
    request->content_type,
    request->body,
    request->body_length,
    inspection_body,
    sizeof(inspection_body),
    &inspection_length
);
```

### 6.11 `policy_engine.c`

#### `policy_engine_init(const char* policy_file_path)`

- 정책 파일을 읽어 전역 룰 배열에 로드한다.
- 파일이 없거나 유효 룰이 없으면 built-in default rules를 로드한다.
- 내부적으로 critical section을 사용해 reload와 inspect를 보호한다.

#### `policy_engine_reload(const char* policy_file_path)`

- 정책 reload entry point.
- 현재 구현은 `policy_engine_init()`을 다시 호출한다.

#### `policy_engine_cleanup(void)`

- 룰 배열을 비우고 critical section을 삭제한다.

#### `inspect_policy_text(const char* data, int length)`

- 로드된 정책 룰을 순서대로 검사한다.
- 첫 매칭 결과를 `policy_result_t`로 반환한다.
- 매칭이 없으면 `POLICY_ACTION_ALLOW`.

룰 타입별 검사:

| Type | 검사 함수 |
| --- | --- |
| `KEYWORD` | case-insensitive substring |
| `EMAIL` | `detect_email_pattern` |
| `PHONE` | `detect_phone_pattern` |
| `RESIDENT_ID` | `detect_resident_id_pattern` |
| `CREDIT_CARD` | `detect_credit_card_pattern` |
| `FILE_UPLOAD` | `detect_file_upload_pattern` |
| `FILE_EXT` | `detect_file_extension_pattern` |

### 6.12 `dlp_engine.c`

#### `inspect_dlp_request(const http_request_t* request)`

- request body가 없으면 allow.
- body가 있으면 `decode_body_for_inspection()` 후 `inspect_policy_text()`를 호출한다.
- 결과를 `dlp_result_t`로 변환한다.

#### `inspect_dlp_response(const http_response_t* response)`

- response body를 같은 방식으로 검사한다.

### 6.13 `pattern_detector.c`

#### `detect_email_pattern(const char* data, int length)`

- local-part, `@`, domain, dot 형태를 검사한다.
- 간단한 email-like pattern 감지용이다.

#### `detect_phone_pattern(const char* data, int length)`

- 숫자와 optional separator 기반 전화번호 패턴을 검사한다.
- 예: `010-1234-5678`

#### `detect_resident_id_pattern(const char* data, int length)`

- 주민등록번호 형태를 검사한다.
- 숫자 6자리, optional separator, 뒤 7자리 형태를 기준으로 한다.

#### `detect_credit_card_pattern(const char* data, int length)`

- 카드번호 후보 숫자를 추출하고 Luhn check를 수행한다.

#### `detect_file_upload_pattern(const char* data, int length)`

- `filename=`, multipart 관련 token 등 파일 업로드 흔적을 찾는다.

#### `detect_file_extension_pattern(const char* data, int length, const char* extension)`

- filename 주변에서 특정 확장자를 찾는다.
- 정책의 `FILE_EXT` 타입에서 사용한다.

### 6.14 `multipart_parser.c`

#### `inspect_multipart_upload_request(const http_request_t* request, dlp_result_t* result)`

- `Content-Type`에서 `multipart/form-data`와 boundary를 확인한다.
- 각 part header에서 `filename` parameter를 추출한다.
- file part만 검사한다.
- 기존 `result`가 이미 `BLOCK`이면 변경하지 않는다.
- multipart 검사 결과:
  - `.zip`: BLOCK, rule id 9
  - file content에 `secret`: BLOCK, rule id 1
  - file content에 `password`: BLOCK, rule id 2
  - file content에 email-like pattern: BLOCK, rule id 4
  - `.xlsx`: LOG_ONLY, rule id 8
  - 그 외 file upload: LOG_ONLY, rule id 10

사용 예:

```c
dlp_result_t result = inspect_dlp_request(&request);
inspect_multipart_upload_request(&request, &result);
if (result.action == DLP_ACTION_BLOCK) {
    send_block_response(client_sock, result.reason);
}
```

### 6.15 `http_block_response.c`

#### `send_block_response(SOCKET client_sock, const char* reason)`

- 요청 차단용 403 HTTP 응답을 보낸다.
- body title은 `DLP policy blocked this request.`이다.

#### `send_response_block_response(SOCKET client_sock, const char* reason)`

- 응답 차단용 403 HTTP 응답을 보낸다.
- body title은 `DLP policy blocked this response.`이다.

### 6.16 `logger.c`

#### `logger_init(const char* log_file_path)`

- 로그 파일을 append mode로 연다.
- critical section을 초기화한다.

#### `logger_close(void)`

- 로그 파일을 닫고 lock을 정리한다.

#### 로그 함수

- `log_debug`
- `log_info`
- `log_warn`
- `log_error`
- `log_security`

모두 `printf`와 log file에 동시에 기록한다.

### 6.17 `audit_log.c`

#### `audit_log_block_event(...)`

- HTTP request BLOCK 이벤트를 SECURITY 로그로 남긴다.
- 세션, 프로세스, method/path/host, rule id, keyword, reason 포함.

#### `audit_log_log_only_event(...)`

- HTTP request LOG_ONLY 이벤트를 남긴다.

#### `audit_log_response_block_event(...)`

- HTTP response BLOCK 이벤트를 남긴다.
- status, content-type, rule 정보 포함.

#### `audit_log_response_log_only_event(...)`

- HTTP response LOG_ONLY 이벤트를 남긴다.

#### `audit_log_connect_tunnel_event(...)`

- CONNECT raw tunnel 이벤트를 남긴다.

### 6.18 `command_thread.c`

#### `command_thread_start(const char* policy_file_path)`

- stdin command thread를 시작한다.
- 중복 시작은 방지한다.
- 실행 중 입력:
  - `r`: policy reload
  - `h`, `?`: help

### 6.19 `tls_intercept_policy.c`

#### `tls_intercept_policy_load(const char* path)`

- TLS intercept policy 파일을 로드한다.
- 실패 시 safe default를 적용한다.
- safe default:
  - `demo.local:9443 MITM`
  - `127.0.0.1:9443 MITM`
  - `localhost:9443 MITM`
  - 나머지 BYPASS

#### `tls_intercept_policy_decide(...)`

- host/port만으로 정책을 결정한다.
- process 정보가 없을 때 사용한다.

#### `tls_intercept_policy_decide_with_process(...)`

- host/port/process name을 기준으로 정책을 결정한다.
- process-specific rule이 broad rule보다 앞에 있으면 우선 적용된다.

#### `tls_intercept_policy_decide_with_process_silent(...)`

- decision은 동일하지만 verbose policy decision log를 줄이는 용도이다.
- `IGNORE` 로그 억제 판단에 사용한다.

#### `tls_intercept_policy_action_to_string(...)`

- enum action을 문자열로 변환한다.

#### `tls_intercept_policy_cleanup(void)`

- 로드된 룰을 비운다.

### 6.20 `tls_mitm_engine.c`

#### `tls_mitm_handle_connect_session(...)`

- CONNECT가 MITM 정책으로 결정된 세션의 전체 TLS MITM 처리를 담당한다.
- 처리 순서:
  1. CONNECT host 추출
  2. client-side `SSL_CTX` 생성
  3. SNI callback 등록
  4. upstream-side `SSL_CTX` 생성
  5. client와 `SSL_accept`
  6. upstream과 `SSL_connect`
  7. HTTP request/response exchange 반복

#### `tls_mitm_sni_callback(...)`

- 클라이언트 TLS ClientHello의 SNI를 읽는다.
- `cert_manager_get_or_create_leaf_certificate()`로 host별 leaf cert/key를 준비한다.
- 해당 인증서를 현재 SSL context에 적용한다.

#### `tls_mitm_process_one_http_request_response(...)`

- TLS 안에서 HTTP request 하나와 response 하나를 처리한다.
- request:
  - `tls_read_complete_http_request`
  - `parse_http_request`
  - `inspect_dlp_request`
  - `inspect_multipart_upload_request`
  - block/log/forward
- response:
  - `tls_read_complete_http_response`
  - `parse_http_response`
  - `inspect_dlp_response`
  - block/log/forward
- keep-alive 여부를 판단해:
  - `1`: 다음 exchange 계속
  - `0`: 정상 종료
  - `-1`: 오류

#### `tls_read_complete_http_request(...)`

- `SSL_read()`로 decrypted HTTP request를 읽고 `request_buffer`에 누적한다.
- 완성된 request 길이를 반환한다.

#### `tls_read_complete_http_response(...)`

- `SSL_read()`로 decrypted HTTP response를 읽고 `response_buffer`에 누적한다.
- chunked/content-length 모두 `response_buffer`가 판단한다.

#### `tls_mitm_should_close_after_exchange(...)`

- request/response의 `Connection: close`, HTTP/1.0 keep-alive 여부를 보고 TLS MITM loop 종료 여부를 결정한다.

#### `tls_mitm_send_block_response(...)`

- TLS 연결 안에서 HTTP 403 block response를 보낸다.

### 6.21 `cert_manager.c`

#### `cert_manager_get_or_create_leaf_certificate(...)`

- host별 leaf certificate와 private key 경로를 만든다.
- `certs/generated/<host>.crt`, `<host>.key`가 있으면 cache hit로 재사용한다.
- 없으면 `certs/mitm.crt`, `certs/mitm.key`를 CA로 사용해 새 leaf cert를 생성한다.

사용 예:

```c
char cert_path[512];
char key_path[512];
cert_manager_get_or_create_leaf_certificate(
    host,
    cert_path,
    sizeof(cert_path),
    key_path,
    sizeof(key_path)
);
```

#### `cert_manager_is_ip_literal(const char* host)`

- host가 IPv4 또는 IPv6 literal인지 확인한다.
- SNI를 upstream에 설정할지 결정할 때 사용한다.

### 6.22 `mitm_target_policy.c`

현재 `relay_proxy`의 최신 CONNECT 정책은 `tls_intercept_policy` 중심으로 사용된다. `mitm_target_policy`는 별도 allowlist 기반 MITM 정책 모듈로 남아 있다.

#### `mitm_target_policy_load(const char* path)`

- `mitm_targets.txt`를 로드한다.
- host, host:port, wildcard suffix 형식을 지원한다.

#### `mitm_target_policy_is_allowed(const char* host, int port)`

- 주어진 host/port가 MITM allowlist에 포함되는지 확인한다.

#### `mitm_target_policy_cleanup(void)`

- 로드된 룰을 정리한다.

## 7. 테스트 클라이언트/POC 함수 정리

### 7.1 `echo_server.c`

#### `main(void)`

- `127.0.0.1:9000`에서 TCP listen.
- 클라이언트 하나를 accept.
- 받은 데이터를 그대로 다시 send한다.

### 7.2 `echo_client.c`

#### `main(void)`

- `127.0.0.1:8000`에 접속.
- stdin에서 문자열을 읽어 전송.
- 서버/프록시로부터 받은 echo를 출력.
- `quit` 입력 시 종료.

### 7.3 `simple_proxy.c`

#### `send_all(...)`

- 전체 byte를 upstream/client로 전송한다.

#### `main(void)`

- `127.0.0.1:8000`에서 listen.
- upstream `127.0.0.1:9000`에 고정 연결.
- client -> upstream -> client 순서로 단순 중계한다.

### 7.4 `http_client.c`

#### `send_all(...)`

- HTTP request를 proxy에 완전히 전송한다.

#### `main(void)`

- `relay_proxy:8000`으로 TCP 연결.
- POST `/upload` 요청을 만든다.
- body와 content-type을 바꿔 DLP 검사 결과를 확인한다.

### 7.5 `connect_test_client.c`

#### `send_all_local(...)`

- CONNECT request와 tunneled HTTP request를 전송한다.

#### `connect_to_proxy(void)`

- `127.0.0.1:8000`으로 TCP 연결한다.

#### `main(void)`

- CONNECT 요청을 보내고 `200 Connection Established`를 확인한다.
- 같은 TCP 연결 안에서 HTTP GET을 보내 터널 중계를 검증한다.

### 7.6 TLS 테스트 클라이언트

공통 보조 함수:

- `print_openssl_error`: OpenSSL error queue 출력
- `send_all`: TCP 전체 전송
- `ssl_write_all`: TLS 전체 전송
- `connect_tcp`: TCP 연결 생성
- `recv_connect_response`: CONNECT 응답 수신
- `read_one_http_response`: TLS 안의 HTTP response 하나를 읽음
- `build_get_request`, `build_post_request`: keep-alive 테스트 요청 생성
- `send_request_and_print_response`: 요청 전송 후 응답 출력

주요 시나리오:

- `connect_tls_test_client`: CONNECT 후 TLS handshake, 단일 HTTPS 요청 테스트
- `connect_tls_keepalive_test_client`: 하나의 TLS 세션 안에서 여러 HTTP request/response exchange 테스트
- 마지막 `/secret` 요청은 response DLP BLOCK을 기대한다.

### 7.7 `tls_mitm_proxy.c`

독립형 TLS MITM POC이다. 현재 `relay_proxy`에 통합된 TLS MITM과 별도로, 개념 검증용으로 볼 수 있다.

주요 함수:

- `init_winsock`: Winsock 초기화
- `create_listener`: `8443`에서 listen
- `connect_tcp`: upstream `127.0.0.1:9443` 연결
- `create_server_ctx`: client-facing TLS server context 생성
- `create_client_ctx`: upstream-facing TLS client context 생성
- `handle_tls_mitm_session`: client TLS accept, upstream TLS connect, decrypted HTTP 중계/차단
- `send_tls_block_response`: TLS 안에서 403 block response 전송
- `contains_ignore_case`: POC용 keyword 검사

## 8. 로그 확인 포인트

`relay_proxy` 실행 시 로그 파일:

```text
relay_runtime.log
```

중요 로그 키워드:

| 키워드 | 의미 |
| --- | --- |
| `session created` | 클라이언트 연결 수락 및 세션 생성 |
| `process metadata found` | 연결 소유 프로세스 조회 성공 |
| `POLICY matched` | DLP 정책 룰 매칭 |
| `AUDIT` | 보안 감사 이벤트 |
| `CONNECT TLS policy decision` | CONNECT 대상 TLS 정책 결정 |
| `TLS MITM session started` | MITM 처리 시작 |
| `TLS MITM request blocked` | HTTPS request 차단 |
| `TLS MITM response blocked` | HTTPS response 차단 |
| `CONNECT raw tunnel summary` | BYPASS/AUDIT/IGNORE 터널 summary |

## 9. 현재 제약/주의 사항

1. HTTP parser는 실습/POC 수준이다.
   - 모든 HTTP edge case를 처리하지 않는다.
   - header folding, gzip/br 압축 body, HTTP/2는 처리하지 않는다.

2. IPv6 upstream authority는 아직 제한적이다.
   - resolver와 policy parser 일부에서 IPv6 authority를 실패 처리한다.

3. TLS MITM은 HTTP/1.1 중심이다.
   - ALPN callback은 HTTP/1.1을 선택하도록 구성되어 있지만, 실제 서비스별 pinning/HTTP2/압축 대응은 별도 작업이 필요하다.

4. 인증서 신뢰 설정이 필요하다.
   - 브라우저 테스트 시 `mitm.crt`를 현재 사용자 루트 CA로 설치해야 한다.
   - 테스트 후 반드시 제거하는 것이 좋다.

5. 실제 외부 서비스 MITM은 신중해야 한다.
   - `tls_intercept_policy.txt` 기본값은 BYPASS이다.
   - MITM 대상은 로컬 테스트 target 위주로 유지하는 것이 안전하다.

## 10. 향후 개선 후보

### 10주차 완성을 위한 개발 우선순위

1. 8주차 목표 완성: 업로드 파일 메타데이터와 binary 획득
   - `multipart_parser`에서 file part를 발견했을 때 filename, extension, part content-type, body size를 구조체로 추출한다.
   - 파일 binary를 안전한 테스트 디렉터리에 저장하거나, 최소한 SHA-256/hash와 size를 계산해 audit log에 남긴다.
   - 원본 파일과 추출 파일의 크기/hash를 비교하는 테스트 절차를 만든다.

2. 9주차 목표 완성: 파일 분석 기능
   - 확장자만 보지 않고 magic number를 검사한다.
   - 예: ZIP 계열 `50 4B`, PDF `%PDF`, PNG `89 50 4E 47`, JPEG `FF D8 FF`.
   - 확장자와 실제 signature가 다를 때 mismatch로 기록한다.

3. 브라우저/AI Agent 환경별 검증
   - Chrome/Edge 브라우저 업로드 테스트.
   - ChatGPT, Notion, 웹메일, 기타 AI Agent 또는 WebView 기반 앱에서 업로드 요청이 어떤 host/process/content-type으로 나오는지 정리한다.
   - MITM이 어려운 서비스는 BYPASS/AUDIT로 metadata만 남기고 한계점으로 기록한다.

4. 정책/로그 정리
   - 파일 업로드 전용 audit log 포맷을 추가한다.
   - 예: `AUDIT direction=REQUEST action=FILE_UPLOAD filename=... extension=... mime=... size=... sha256=... signature=...`
   - `policy_rules.txt`에 파일 업로드 테스트용 룰을 명확히 분리한다.

5. 최종 보고서/발표 자료 작성
   - 프로젝트 목적, 전체 구조, Proxy 흐름, TLS MITM 구조, 파일 업로드 식별 흐름, 테스트 결과, 한계점, 개선 방향을 정리한다.
   - 본 문서는 개발 인수인계/기술 정리 문서이고, 최종 발표 자료는 더 짧고 시각적으로 재구성하면 된다.

### 기술 개선 후보

- gzip/br response decompression 후 DLP 검사.
- HTTP/2 CONNECT/MITM 처리.
- IPv6 authority parsing 지원.
- policy reload 시 TLS intercept policy도 reload하는 command 추가.
- 정책 룰 match 우선순위/복수 match report.
- JSON parser 기반 field-level 검사.
- multipart 대용량 파일 streaming 검사.
- unit test 추가.
- log rotation.
- 설정 파일로 port/path 상수 분리.

## 11. 10주차 계획별 산출물 체크리스트

| 주차 | 산출물 | 현재 준비 상태 |
| --- | --- | --- |
| 1주차 | 개념 학습 정리 | 본 문서에 요약 필요, 최종 보고서에서 보강 |
| 2주차 | Proxy 구조 설명 | 구현과 문서 기반 준비됨 |
| 3주차 | Local Proxy 기본 동작 코드/테스트 | 준비됨 |
| 4주차 | HTTP parsing 로그/결과 | 준비됨 |
| 5주차 | TLS MITM 구조 설명/인증서 절차 | 코드 준비됨, 설명 자료 보강 필요 |
| 6주차 | HTTPS 분석 테스트 결과 | 기능 준비됨, 브라우저 테스트 결과 수집 필요 |
| 7주차 | 파일 업로드 식별 로그 | 부분 준비됨 |
| 8주차 | 파일 binary 추출/원본 비교 결과 | 추가 개발 필요 |
| 9주차 | 파일 signature 분석/PoC 검증표 | 추가 개발 및 테스트 필요 |
| 10주차 | 최종 보고서/발표 자료 | 본 문서를 기반으로 작성 필요 |

## 12. 최종 보고서 권장 목차

1. 프로젝트 개요
   - Local Proxy 기반 네트워크 패킷 분석 PoC 목적
   - 왜 HTTP/HTTPS 분석과 파일 업로드 식별이 필요한지

2. 배경 지식
   - TCP 통신 흐름
   - Explicit Proxy와 Transparent Proxy 차이
   - HTTP 요청/응답 구조
   - HTTPS, TLS, 인증서, MITM 구조
   - multipart/form-data 파일 업로드 구조

3. 시스템 구조
   - 전체 아키텍처
   - `relay_proxy` 중심 모듈 구성
   - 정책 엔진, DLP 엔진, TLS MITM 엔진, multipart parser 관계

4. 구현 내용
   - TCP proxy
   - HTTP parser
   - CONNECT tunnel
   - TLS MITM
   - DLP policy
   - 파일 업로드 식별
   - audit logging

5. 테스트 및 검증
   - 일반 HTTP DLP 테스트
   - HTTPS MITM 분석 테스트
   - 파일 업로드 식별 테스트
   - 브라우저/AI Agent별 테스트 결과
   - 성공/실패 사례

6. 한계점
   - HTTP/2, compression, certificate pinning, 대용량 파일 streaming, IPv6, 실제 서비스별 예외

7. 향후 개선 방향
   - binary 추출 안정화
   - 파일 signature 분석
   - 정책 고도화
   - 운영형 로그/설정 구조

8. 결론
   - PoC로 검증한 범위
   - 실서비스 수준으로 가기 위해 필요한 작업
