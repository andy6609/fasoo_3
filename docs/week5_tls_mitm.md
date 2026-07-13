# 5주차 TLS MITM 구조 정리

이 문서는 현재 `relay_proxy` 구현을 기준으로 Proxy Root CA, Host별 Leaf Certificate 동적 생성, TLS MITM 동작 흐름, 클라이언트-Proxy TLS 세션과 Proxy-서버 TLS 세션 구조, Certificate Pinning의 한계를 정리한다.

## 1. 범위

현재 코드에서 TLS MITM은 `relay_proxy`의 HTTPS `CONNECT` 처리 위에 구현되어 있다. 클라이언트가 `CONNECT host:port HTTP/1.1` 요청을 보내면 프록시는 `tls_intercept_policy.txt` 정책을 확인한다.

정책 결과에 따라 동작은 다음 중 하나로 나뉜다.

| 정책 | 동작 |
| --- | --- |
| `MITM` | HTTPS를 복호화하여 HTTP request/response를 분석하고 DLP 정책을 적용한다. |
| `BYPASS` | 암호화된 TCP tunnel을 그대로 중계한다. |
| `AUDIT` | 암호화된 TCP tunnel을 그대로 중계하되 감사 로그를 남긴다. |
| `IGNORE` | 암호화된 TCP tunnel을 중계하되 개발 중 노이즈성 로그를 줄인다. |
| `BLOCK` | upstream 연결 전에 CONNECT 요청 자체를 차단한다. |

관련 구현:

- `relay_proxy/relay_proxy.c`: CONNECT 요청 수신, 정책 판단, MITM/BYPASS/BLOCK 분기
- `relay_proxy/tls_intercept_policy.c`: TLS intercept 정책 로드 및 매칭
- `relay_proxy/tls_mitm_engine.c`: TLS MITM 세션 처리
- `relay_proxy/cert_manager.c`: Host별 Leaf Certificate 생성 및 캐시

## 2. Proxy Root CA 생성 및 설치 구조

### 2.1 Root CA의 역할

일반 HTTPS 통신에서 클라이언트는 서버가 제시한 인증서를 신뢰할 수 있는 Root CA 체인으로 검증한다. TLS MITM 프록시는 실제 서버 인증서를 그대로 사용할 수 없다. 프록시가 클라이언트에게는 서버처럼 동작해야 하므로, 접속 대상 host 이름에 맞는 인증서를 직접 만들어 클라이언트에게 제시해야 한다.

이때 프록시가 만든 인증서를 클라이언트가 신뢰하려면, 프록시 인증서를 서명한 Root CA가 클라이언트의 신뢰 저장소에 설치되어 있어야 한다. 이 프로젝트에서는 `Local DLP MITM Root CA`라는 로컬 테스트용 Root CA를 생성하고 Windows Current User Root store에 설치한다.

### 2.2 Root CA 생성

Root CA 생성 스크립트는 다음 파일이다.

```text
relay_proxy/make_relay_proxy_certs.bat
```

이 스크립트는 OpenSSL을 사용해 다음 파일을 생성한다.

```text
relay_proxy/certs/mitm.crt
relay_proxy/certs/mitm.key
relay_proxy/certs/openssl_ca.cnf
```

`mitm.crt`는 클라이언트가 신뢰해야 하는 Root CA 인증서이고, `mitm.key`는 Host별 Leaf Certificate를 서명할 때 사용하는 개인키다.

스크립트에서 설정하는 주요 CA 확장은 다음과 같다.

```text
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
```

즉, 이 인증서는 일반 서버 인증서가 아니라 다른 인증서를 서명할 수 있는 CA 인증서로 생성된다.

### 2.3 Root CA 설치

Root CA 설치 스크립트는 다음 파일이다.

```text
relay_proxy/install_mitm_root_ca_current_user.bat
```

이 스크립트는 `certutil`을 사용해 `certs/mitm.crt`를 현재 사용자 인증서 저장소의 Root store에 추가한다.

```text
certutil -user -addstore Root "%CERT_FILE%"
```

설치 대상은 Current User Root store이므로, 같은 Windows 장비라도 다른 사용자 계정에는 자동으로 적용되지 않는다.

### 2.4 보안 주의사항

`mitm.key`는 매우 민감한 파일이다. 이 키를 가진 사람은 해당 Root CA로 임의의 서버 인증서를 만들 수 있다. 테스트가 끝나면 Root CA를 제거하고, 필요하면 생성된 인증서와 개인키를 폐기해야 한다.

관련 제거 스크립트:

```text
relay_proxy/remove_mitm_root_ca_current_user.bat
relay_proxy/reset_generated_certs.bat
```

## 3. Host별 Leaf Certificate 동적 생성 구조

### 3.1 Leaf Certificate가 필요한 이유

브라우저가 `https://demo.local:9443`에 접속하면 인증서의 Subject 또는 Subject Alternative Name이 `demo.local`과 일치해야 한다. `https://chatgpt.com`에 접속하면 `chatgpt.com`에 맞는 인증서가 필요하다.

따라서 프록시는 하나의 고정 서버 인증서만 사용할 수 없다. 접속 대상 host별로 다른 Leaf Certificate를 만들어야 한다.

### 3.2 현재 코드의 생성 흐름

동적 인증서 생성은 `cert_manager_get_or_create_leaf_certificate()`가 담당한다.

```c
int cert_manager_get_or_create_leaf_certificate(
    const char* host,
    char* cert_path,
    int cert_path_size,
    char* key_path,
    int key_path_size
);
```

처리 흐름은 다음과 같다.

1. SNI 또는 CONNECT target에서 대상 host를 결정한다.
2. `certs/generated` 아래에 해당 host용 인증서와 키가 이미 있는지 확인한다.
3. 없으면 `certs/mitm.crt`, `certs/mitm.key`를 로드한다.
4. 새 RSA key pair와 X.509 Leaf Certificate를 생성한다.
5. Leaf Certificate의 CN/SAN을 대상 host에 맞춘다.
6. MITM Root CA private key로 Leaf Certificate에 서명한다.
7. 생성된 인증서와 키를 `certs/generated`에 저장한다.
8. 이후 같은 host 접속에서는 캐시된 인증서와 키를 재사용한다.

생성 예시는 다음과 같다.

```text
relay_proxy/certs/generated/demo.local.crt
relay_proxy/certs/generated/demo.local.key
relay_proxy/certs/generated/www.google.com.crt
relay_proxy/certs/generated/www.google.com.key
```

### 3.3 SNI callback과 인증서 선택

TLS MITM에서는 클라이언트가 TLS ClientHello에 SNI를 담아 보낸다. 현재 코드는 `tls_mitm_sni_callback()`에서 이 SNI를 읽고, 해당 host용 인증서를 준비한 뒤 현재 TLS 세션에 적용한다.

관련 흐름:

```text
client TLS ClientHello
  -> SNI 추출
  -> cert_manager_get_or_create_leaf_certificate(host)
  -> SSL_use_certificate_file()
  -> SSL_use_PrivateKey_file()
  -> SSL_check_private_key()
```

SNI가 없으면 CONNECT target에서 얻은 host를 fallback host로 사용한다. fallback host도 없으면 기본 MITM 인증서를 사용한다.

## 4. TLS MITM 동작 원리

### 4.1 일반 HTTPS 흐름

프록시가 없거나 단순 tunnel만 수행하는 경우 HTTPS 흐름은 다음과 같다.

```text
Client
  -> TCP connect to Proxy
  -> CONNECT target.example:443
Proxy
  -> TCP connect to target.example:443
  -> HTTP/1.1 200 Connection Established
Client <================ encrypted TLS tunnel ================> Server
```

이 구조에서는 Proxy가 TLS 내부의 HTTP request/response를 볼 수 없다. Proxy가 볼 수 있는 것은 CONNECT target, 포트, 바이트 수, 연결 시간 같은 메타데이터뿐이다.

### 4.2 MITM HTTPS 흐름

MITM 정책이 적용되면 프록시는 하나의 TLS tunnel을 그대로 중계하지 않는다. 대신 TLS 세션을 두 개로 나눈다.

```text
Client
  <==== TLS session A ====>
Proxy
  <==== TLS session B ====>
Destination Server
```

세션 A에서 Proxy는 서버 역할을 한다. 클라이언트에게 동적 Leaf Certificate를 제시하고 `SSL_accept()`로 handshake를 완료한다.

세션 B에서 Proxy는 클라이언트 역할을 한다. 실제 서버에 접속하고 `SSL_connect()`로 handshake를 완료한다.

그 결과 Proxy 내부에서는 다음 처리가 가능해진다.

```text
Client TLS record
  -> Proxy SSL_read()
  -> decrypted HTTP request
  -> HTTP parser / DLP engine
  -> Proxy SSL_write()
  -> Server TLS record
```

반대 방향도 동일하다.

```text
Server TLS record
  -> Proxy SSL_read()
  -> decrypted HTTP response
  -> HTTP response parser / DLP engine
  -> Proxy SSL_write()
  -> Client TLS record
```

### 4.3 현재 코드의 MITM 처리 순서

현재 `relay_proxy` 기준 MITM 처리 순서는 다음과 같다.

1. 클라이언트가 Proxy에 TCP 연결한다.
2. 클라이언트가 `CONNECT host:port HTTP/1.1` 요청을 보낸다.
3. `relay_proxy.c`가 CONNECT target을 파싱한다.
4. `tls_intercept_policy.txt`를 기준으로 MITM/BYPASS/AUDIT/IGNORE/BLOCK을 결정한다.
5. `MITM`이면 Proxy가 upstream 서버에 TCP 연결한다.
6. Proxy가 클라이언트에게 `HTTP/1.1 200 Connection Established`를 보낸다.
7. Proxy가 클라이언트 쪽 TLS context를 준비한다.
8. SNI callback에서 host별 Leaf Certificate를 생성하거나 캐시에서 읽는다.
9. Proxy가 클라이언트와 `SSL_accept()`를 수행한다.
10. Proxy가 upstream 서버 쪽 TLS context를 준비한다.
11. Proxy가 upstream 서버에 SNI를 설정한다.
12. Proxy가 upstream 서버와 `SSL_connect()`를 수행한다.
13. upstream 서버 인증서를 검증한다.
14. 복호화된 HTTP request/response를 파싱하고 DLP 정책을 적용한다.
15. 허용이면 반대편 TLS 세션으로 다시 암호화해 전달한다.
16. 차단이면 원본 데이터를 전달하지 않고 block response를 전송한다.

## 5. 클라이언트-Proxy TLS 세션과 Proxy-서버 TLS 세션 구조

### 5.1 클라이언트-Proxy TLS 세션

이 세션에서 Proxy는 서버처럼 동작한다.

| 항목 | 내용 |
| --- | --- |
| TLS 역할 | Proxy가 TLS server |
| OpenSSL 함수 | `SSL_accept()` |
| 인증서 | Proxy가 생성한 host별 Leaf Certificate |
| 인증서 서명자 | `Local DLP MITM Root CA` |
| 클라이언트 검증 기준 | Root CA가 신뢰 저장소에 설치되어 있고 host 이름이 일치해야 함 |
| Proxy가 얻는 데이터 | 복호화된 HTTP request |

클라이언트 입장에서는 실제 서버와 직접 TLS를 맺는 것처럼 보이지만, 실제로는 Proxy와 TLS를 맺는다.

### 5.2 Proxy-서버 TLS 세션

이 세션에서 Proxy는 클라이언트처럼 동작한다.

| 항목 | 내용 |
| --- | --- |
| TLS 역할 | Proxy가 TLS client |
| OpenSSL 함수 | `SSL_connect()` |
| SNI | CONNECT target 또는 클라이언트 SNI 기반 host |
| 서버 인증서 | 실제 destination server가 제시하는 인증서 |
| 검증 방식 | 기본 신뢰 경로와 host 이름 검증 |
| Proxy가 얻는 데이터 | 복호화된 HTTP response |

현재 코드는 upstream 인증서 검증을 활성화한다. 로컬 테스트 편의를 위해 `LOCAL_DLP_ALLOW_INSECURE_UPSTREAM` 환경 변수를 사용하면 upstream 검증을 끌 수 있지만, 이는 테스트 환경에서만 사용해야 한다.

### 5.3 두 TLS 세션이 독립적인 이유

두 세션은 암호키, handshake, 인증서, ALPN 선택이 서로 독립적이다. Proxy는 클라이언트 쪽에서는 서버 인증서를 제시하고, 서버 쪽에서는 클라이언트로 접속한다.

따라서 프록시 내부에서만 HTTP 평문이 존재한다. 네트워크 구간에서는 여전히 각각 TLS로 암호화되어 이동한다.

```text
Client --encrypted--> Proxy --encrypted--> Server
          session A       plain HTTP       session B
```

## 6. ALPN, HTTP/1.1, HTTP/2

ALPN은 TLS handshake 중에 애플리케이션 프로토콜을 협상하는 기능이다. 브라우저와 서버는 ALPN을 통해 `h2` 또는 `http/1.1`을 선택할 수 있다.

현재 코드에는 다음 기반이 있다.

- 클라이언트/서버 TLS 세션에서 ALPN 선택 결과를 로그로 남긴다.
- upstream에 `h2` 또는 `http/1.1` ALPN을 설정한다.
- `http2_engine.c`에서 HTTP/2 frame relay와 기본 frame 관찰 로직이 있다.
- HTTP/1.1 request/response는 기존 parser와 DLP 엔진으로 분석한다.

주의할 점은 HTTP/2는 HTTP/1.1과 달리 header compression, stream multiplexing, binary frame 구조를 사용한다. 따라서 HTTP/2 traffic을 완전한 DLP 분석 대상으로 만들려면 HPACK/QPACK, stream별 body 조립, multipart 재구성 같은 추가 작업이 필요하다.

## 7. Certificate Pinning 개념과 한계

### 7.1 Certificate Pinning이란

Certificate Pinning은 애플리케이션이 운영체제의 일반 신뢰 저장소만 믿지 않고, 특정 서버 인증서 또는 공개키를 코드나 설정에 고정해 검증하는 방식이다.

일반 브라우저 HTTPS 검증은 다음 조건을 주로 본다.

```text
서버 인증서가 신뢰된 Root CA 체인으로 이어지는가?
인증서의 host 이름이 접속 host와 일치하는가?
인증서가 만료되지 않았는가?
```

Certificate Pinning이 적용된 앱은 여기에 추가 조건을 둔다.

```text
이 인증서 또는 공개키가 앱이 미리 알고 있는 값과 일치하는가?
```

### 7.2 MITM에서 문제가 되는 이유

TLS MITM Proxy가 만든 Leaf Certificate는 OS 신뢰 저장소 기준으로는 정상일 수 있다. 하지만 Certificate Pinning을 사용하는 앱은 이 인증서가 실제 서버의 인증서 또는 공개키와 다르다는 것을 감지할 수 있다.

그 결과 다음 문제가 발생한다.

| 현상 | 설명 |
| --- | --- |
| TLS handshake 실패 | 앱이 프록시 인증서를 거부한다. |
| 앱 내부 오류 | 네트워크 오류, 보안 오류, 로그인 실패처럼 보일 수 있다. |
| 서비스 기능 저하 | 인증, 결제, 보안 API, 업데이트 체크 등이 실패할 수 있다. |

### 7.3 현재 프로젝트에서의 처리 방향

현재 프로젝트는 Certificate Pinning을 우회하지 않는다. 대신 정책 파일에서 민감하거나 실패 가능성이 높은 대상은 `BYPASS`, `AUDIT`, `IGNORE`로 처리한다.

예를 들어 `tls_intercept_policy.txt`에는 인증/브라우저 시스템 트래픽을 우회하는 규칙이 있다.

```text
chrome.exe accounts.google.com:443 BYPASS auth_service_exception
chrome.exe safebrowsing.google.com:443 BYPASS browser_safety_service_exception
DEFAULT BYPASS safe_default_for_unknown_https
```

이 설계는 PoC 안정성을 높인다. 모든 HTTPS를 무조건 MITM하면 인증서 pinning, HTTP/2, 압축, 인증 서비스, 브라우저 백그라운드 트래픽 때문에 테스트가 쉽게 깨질 수 있다. 그래서 현재 구조는 명시적으로 허용한 대상만 MITM하고, 나머지는 기본적으로 BYPASS한다.

## 8. 테스트 절차

### 8.1 인증서 준비

```bat
cd relay_proxy
make_relay_proxy_certs.bat
install_mitm_root_ca_current_user.bat
```

### 8.2 로컬 HTTPS 테스트 서버 실행

```bat
python tls_mitm_proxy\tls_browser_test_server.py
```

### 8.3 Proxy 실행

Visual Studio에서 `relay_proxy`를 빌드한 뒤 실행한다. 기본 listen port는 `8000`이다.

### 8.4 브라우저/클라이언트 테스트

Windows proxy를 `127.0.0.1:8000`으로 설정한 뒤 `demo.local:9443` 같은 MITM 정책 대상에 접속한다.

관련 보조 스크립트:

```text
relay_proxy/set_windows_proxy_127_0_0_1_8000.bat
windows_browser_tools/add_demo_local_to_hosts_ADMIN.bat
windows_browser_tools/open_browser_test_urls.bat
```

### 8.5 기대 로그

성공 시 다음과 같은 로그 흐름을 기대할 수 있다.

```text
CONNECT TLS MITM mode selected by policy
TLS MITM SNI callback enabled
TLS MITM SNI selected dynamic certificate
TLS MITM client TLS handshake complete
TLS MITM upstream certificate verified
TLS MITM upstream TLS handshake complete
TLS MITM decrypted HTTP request
TLS MITM decrypted HTTP response
```

## 9. 현재 구현의 한계

현재 코드는 TLS MITM의 핵심 구조를 갖추고 있지만, 실서비스 전체 트래픽을 안정적으로 분석하기에는 아직 한계가 있다.

| 항목 | 현재 상태 | 남은 과제 |
| --- | --- | --- |
| Root CA 생성/설치 | 구현됨 | 설치/제거 절차 문서화와 안전 관리 필요 |
| Host별 Leaf Certificate | 구현됨 | SAN, wildcard, IP literal edge case 추가 검증 필요 |
| HTTP/1.1 HTTPS 분석 | 구현됨 | 압축, chunked, keep-alive edge case 지속 보강 |
| HTTP/2 | frame relay/관찰 기반 있음 | HPACK, stream 재조립, DLP 분석 고도화 필요 |
| Certificate Pinning | 우회하지 않음 | 정책 기반 BYPASS 예외 관리 필요 |
| 브라우저/앱 호환성 | 로컬 테스트 중심 | 실제 서비스별 성공/실패 matrix 필요 |

## 10. 요약

현재 프로젝트의 TLS MITM은 다음 구조로 정리할 수 있다.

```text
1. Local Proxy가 CONNECT 요청 수신
2. tls_intercept_policy.txt로 MITM 여부 결정
3. MITM 대상이면 클라이언트에 200 Connection Established 응답
4. SNI 또는 CONNECT target 기반으로 host별 Leaf Certificate 생성
5. 클라이언트와 Proxy 사이 TLS 세션 수립
6. Proxy와 실제 서버 사이 별도 TLS 세션 수립
7. Proxy 내부에서 HTTP request/response 복호화 및 DLP 검사
8. 허용 시 다시 TLS로 암호화해 전달, 위반 시 차단 응답 전송
```

핵심은 TLS를 깨뜨리는 것이 아니라, 클라이언트 기준 TLS 세션과 서버 기준 TLS 세션을 프록시가 각각 별도로 맺는다는 점이다. 그래서 프록시 내부에서만 HTTP 평문 분석이 가능하며, 외부 네트워크 구간은 계속 TLS로 암호화된다.
