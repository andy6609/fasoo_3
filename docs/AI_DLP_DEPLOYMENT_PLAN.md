# AI DLP 엔드포인트 배포 및 안정화 계획

## 1. 제품 목표

각 사내 PC에 로컬 프록시를 배포하고 사용자가 ChatGPT, Gemini, Claude에
접속하거나 파일을 업로드할 때만 보안 이벤트를 생성한다. 일반 웹 탐색,
브라우저 업데이트, 정적 리소스, telemetry는 분석 이벤트로 저장하지 않는다.
확실하게 식별된 위험 파일만 차단하며 분석기 장애가 사용자 웹 접속 장애로
전파되지 않도록 한다.

## 2. 운영 원칙

1. 대상 최소화: 최상위 AI UI 호스트와 확인된 업로드/API 호스트만 MITM한다.
2. 이벤트 최소화: 사용자 행위 분석에는 `relay_events.log`만 사용한다.
3. 진단 분리: `relay_runtime.log`는 경고·오류만 저장하고 DEBUG는 현장 장애
   조사 때만 일시적으로 켠다.
4. 통신 가용성: HPACK 또는 부가 분석 실패 시 해당 분석 방향을 fail-open으로
   전환하고 원본 frame 전달은 지속한다.
5. 차단 보수성: 완전한 업로드 식별과 정책 위반이 모두 성립할 때만 차단한다.
6. 인증서 일관성: 하나의 CA, 하나의 private key, 하나의 leaf cache만 사용한다.

## 3. 이번 안정화에서 구현한 내용

### 로그

- AI 접속은 `chatgpt.com`, `gemini.google.com`, `claude.ai`에서만 `AI ACCESS`로 기록한다.
- 동일 브라우저 프로세스와 서비스의 60초 내 TLS 재연결은 중복 접속 이벤트로
  기록하지 않는다.
- 업로드 준비·검사·전달과 정책 감사 이벤트는 `relay_events.log`에 저장한다.
- INFO 모드의 진단 메시지, 일반 HTTP 요청, discovery begin, candidate=NO는
  분석 이벤트에서 제외한다.
- discovery는 명시적으로 환경변수를 켠 개발 모드에서만 동작한다.

### 인증서

- 실행 위치와 무관하게 `relay_proxy/certs`의 CA와 key를 우선 사용한다.
- Windows Current User Root에 설치되는 CA와 프록시 서명 CA를 일치시켰다.
- cached leaf 인증서의 유효 기간, private key, CA signature, hostname을 검증한다.
- 오래되거나 다른 CA로 서명된 leaf는 자동으로 폐기하고 재생성한다.
- 동시 TLS 세션이 같은 hostname leaf를 동시에 생성하지 못하도록 전역 단일
  writer lock을 적용했다.

### HTTP/2

- 브라우저 ClientHello의 ALPN 목록을 읽은 뒤 handshake를 일시 중지한다.
- 브라우저가 지원하는 `h2`, `http/1.1`만 실제 서버에 제시하고 서버 선택 결과를
  확인한 뒤 브라우저 측도 동일한 프로토콜로 handshake를 완료한다.
- 서버가 ALPN을 보내지 않으면 HTTP/1.1로 처리하며 양쪽 프로토콜이 다른 상태로
  분석 엔진을 시작하지 않는다.
- HPACK response decode 실패가 발생해도 raw HTTP/2 frame forwarding을 계속한다.
- response 분석만 비활성화하고 request 방향 파일 업로드 분석은 유지한다.
- 같은 분석 우회 경고는 프로세스 실행 중 최초 한 번만 WARN으로 기록한다.
- 브라우저 종료 시 발생하는 정상 socket reset/abort를 오류로 저장하지 않는다.

## 4. 검증 결과

- Debug x64 `relay_proxy` 프로젝트 빌드 성공.
- 안전 TXT와 DOCX fixture는 ALLOW.
- BAT와 위험 파일 포함 ZIP fixture는 BLOCK.
- Chrome HTTP/2를 통한 ChatGPT, Gemini, Claude HTML 수신 성공.
- `h2,http/1.1`을 제시한 Chrome과 HTTP/1.1 전용 로컬 TLS 서버 사이에서 양쪽
  `http/1.1` 선택 및 HTTP/1.1 응답 분석 성공.
- 실제 Gemini에서 양쪽 `h2` 선택, HTTP/2 request stream 분석 및 HTML 수신 성공.
- Gemini HPACK response decode 실패 상황에서도 페이지 수신 성공.
- Claude 동시 세션에서 leaf PEM 경쟁 조건 재현 후 직렬화 적용, 재검증 성공.
- 기본 INFO 모드에서 AI 접속 이벤트만 `relay_events.log`에 생성되고 신규
  runtime noise가 없는 것을 확인했다.

## 5. 배포 기본 설정

```powershell
$env:LOCAL_DLP_LOG_LEVEL = "INFO"
Remove-Item Env:\LOCAL_DLP_DISCOVER_UPLOAD_HOSTS -ErrorAction SilentlyContinue
Remove-Item Env:\LOCAL_DLP_CAPTURE_UPLOAD_BODIES -ErrorAction SilentlyContinue
.\x64\Debug\relay_proxy.exe
```

동일한 설정은 저장소 루트에서 다음 스크립트로 실행할 수 있다. 스크립트는 이전
시험에서 남은 discovery, body capture, insecure upstream 환경변수를 실행 범위
안에서 명시적으로 제거한다.

```powershell
.\relay_proxy\start_ai_dlp_info.bat
```

중앙 수집 대상은 `relay_events.log` 하나로 제한한다. `relay_runtime.log`는 로컬
보관 기간을 짧게 설정하고 WARN/ERROR 장애 분석에만 사용한다.

## 6. 다음 개발 단계

### P0: 실제 로그인 업로드 회귀

- ChatGPT, Gemini, Claude에서 동일한 안전·차단 fixture를 업로드한다.
- 서비스별 실제 method, host, path, content-type을 확정한다.
- UI host가 아닌 저장소 host는 수동 검증 후 정확한 host 규칙만 추가한다.
- 정상 채팅·정적 리소스가 `relay_events.log`에 들어오지 않는지 함께 검증한다.

### P0: 설치 패키지

- CA 설치, 프록시 실행 파일, 정책 파일을 하나의 서명된 설치 패키지로 묶는다.
- 설치·제거·CA rotation을 idempotent하게 만든다.
- CA private key 접근 권한을 서비스 계정과 관리자만 읽도록 제한한다.

### P1: 중앙 이벤트 수집

- 파일 tail 방식 대신 구조화 JSONL 또는 Windows Event Log 출력을 추가한다.
- endpoint ID, 사용자/프로세스, AI 서비스, 파일 hash, action, rule ID를
  표준 schema로 정의한다.
- 전송 실패 시 bounded local queue와 재시도 정책을 적용한다.

### P1: 개인정보 및 보존

- query, token, cookie, 대화 본문은 저장하지 않는다.
- 파일 본문 capture는 기본 비활성화하고 승인된 시험 장비에서만 사용한다.
- 이벤트 log rotation, 최대 크기, 보존 기간, 접근 권한을 정책으로 고정한다.

### P2: 자동화 테스트

- HTTP/1.1 multipart, chunked, raw PUT, HTTP/2 DATA/CONTINUATION fixture를 자동화한다.
- 인증서 동시 생성, CA rotation, stale leaf, 32 MiB 상한을 회귀 테스트한다.
- AI 사이트 변경을 탐지하는 일일 synthetic access test를 운영한다.

## 7. 완료 기준

- 일반 Chrome 실행만으로 분석 이벤트가 생성되지 않는다.
- AI UI 접속 시 서비스별 접속 이벤트가 한 번 생성된다.
- 안전 파일은 허용되고 위험 파일은 차단되며 동일한 audit schema가 남는다.
- 인증서 경고 없이 세 AI 서비스가 연속·동시에 접속된다.
- 분석기 오류가 발생해도 사이트 연결은 유지되고 운영 경고만 남는다.
- 중앙 분석 시스템은 일반 네트워크 로그를 수집하지 않고 AI 보안 이벤트만
  처리한다.
