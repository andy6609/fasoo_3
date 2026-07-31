# AI 파일 DLP 1·2차 테스트 가이드

## 1. 자동 회귀 테스트

저장소 루트에서 다음 파일을 실행한다.

```powershell
.\relay_proxy\RUN_PHASE1_PHASE2_TESTS.bat
```

이 배치는 Visual Studio의 MSBuild를 찾아 `Release|x64` 최신 소스를 먼저
빌드한 다음 fixture 생성, 구조·OCR 검증, 네이티브 정책 검증, 증적 저장 검증을
차례로 수행한다.

정상 기준은 다음과 같다.

- 구조·본문·OCR fixture: `PASS 77 / FAIL 0 / SKIP 2`
- 실제 `relay_proxy.exe` 정책: `PASS 38 / FAIL 0`
- 원본·본문·메타데이터 저장: `PASS 4 / FAIL 0`

결과와 합성 테스트 파일은 DRM 영향을 피하기 위해 아래에 생성된다.

```text
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack
```

SKIP 2건은 실패를 숨긴 것이 아니다. Microsoft Office가 직접 저장한 레거시
DOC/XLS/PPT와 암호화 Office fixture의 선택 생성 상태다. 사용자가 Word, Excel,
PowerPoint를 열어 둔 경우 문서를 보호하기 위해 자동으로 SKIP하며, 숨은 COM
창은 20초 watchdog으로 중단한다. 테스트가 새로 만든 무창 Office 자동화 PID만
정리하고 기존 Office 프로세스는 종료하지 않는다.

필수 경로는 SKIP과 별개로 항상 검증한다. 최소 HWP5 CFB, 최소 legacy
DOC/XLS/PPT CFB, 실제 ZipCrypto 암호화 ZIP, CP949·UTF-16·UTF-32 텍스트,
2번째 프레임/페이지에만 표식이 있는 GIF/TIFF, 임베디드 바이너리 DOCX가
`relay_proxy.exe`에서 추출 또는 fail-closed 되는지 검사한다. 최소 CFB 파일은
파서 회귀용 합성물이며 Hancom/Microsoft가 저장한 호환성 corpus를 대신하지는
않는다.

암호화 PDF도 실제 password-encrypted 파일을 생성해 암호로 평문 marker가
복구되는지 구조 검증하고, 프록시는 암호 없이 `encrypted PDF cannot be
inspected` 사유로 차단하는지 확인한다.

정책 값도 모두 합성 대조군이다. `000101-3000008`은 구현된 날짜·체크섬만
통과하도록 만든 all-zero serial 테스트 값이고 실제 개인 식별자로 제시하지
않는다. `4111 1111 1111 1111`은 비활성 Luhn 테스트 카드 값이다. 무효 체크섬
대조군은 ALLOW, `.invalid` 이메일과 `010-0000-0000`은 최종 전송 ALLOW와 함께
SECURITY 로그의 rule 112/113 `LOG_ONLY`까지 검증한다.

## 2. 최초 1회 인증서 준비

Chrome/Edge가 프록시가 발급한 사이트 인증서를 신뢰하려면 현재 사용자 인증서
저장소에 테스트 CA를 설치해야 한다.

```powershell
.\relay_proxy\make_relay_proxy_certs.bat
.\relay_proxy\install_mitm_root_ca_current_user.bat
```

CA와 key가 이미 있으면 생성 배치는 기존 쌍을 덮어쓰지 않는다.

## 3. 실브라우저 업로드 테스트 시작

```powershell
.\relay_proxy\start_ai_dlp_capture.bat
```

스크립트는 다음 순서로 동작한다.

1. 최신 Release 빌드 및 CA 파일·Windows 신뢰 여부 확인
2. Release 프록시 실행 및 정책·업로드 캡처 초기화 확인
3. 로컬 PAC endpoint 준비 확인
4. ChatGPT/Gemini/Claude 도메인만 `127.0.0.1:8000`으로 라우팅
5. 나머지 사이트, Outlook, Microsoft 365는 `DIRECT`
6. Ctrl+C 종료 시 기존 Windows 프록시 설정 자동 복원

비정상 종료로 자동 복원이 실행되지 않았을 때만 다음을 실행한다.

```powershell
.\relay_proxy\unset_windows_proxy.bat
```

Chrome은 완전히 종료한 뒤 다시 실행한다. 테스트 중에는 HTTP/3가 TCP 프록시를
우회하지 않도록 QUIC를 끈다.

```powershell
& "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" --disable-quic
```

## 4. 서비스별 업로드

아래 폴더에서 먼저 두 파일을 각 서비스에 한 번씩 업로드한다.

```text
C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack\fixtures
```

| 파일 | 기대 결과 |
|---|---|
| `allow_public.txt` | ALLOW, 원본·본문·메타데이터 저장 |
| `block_confidential.txt` | BLOCK, 규칙 102, 증적 저장 |

그다음 `safe_sample.docx`, `safe_sample.xlsx`, `safe_sample.pptx`,
`safe_sample.hwpx`, `safe_text.pdf`, `safe_scan.pdf`, 이미지 파일을 올린다.
이 파일들은 안전한 합성 파일이지만 `CONFIDENTIAL` 테스트 표식이 들어 있으므로
기대 결과는 BLOCK이다.

- ChatGPT: metadata 요청과 후속 raw PUT을 상관분석한다.
- Claude: multipart의 파일 part를 분리해 원본을 복원한다.
- Gemini: 일반·resumable 업로드 헤더와 finalize 요청을 인식한다.

브라우저 UI가 변경되어 요청 구조가 달라지면 fail-closed 이벤트 또는
`unknown` 파일명이 남을 수 있다. 이 경우 해당 서비스의 `host`, `method`,
query를 제거한 `path`, `content-type`, 업로드 헤더를 확인해 규칙을 갱신해야
하며 토큰이 포함된 전체 URL은 로그에 남기지 않는다.

## 5. 결과 확인

보안 이벤트 감시:

```powershell
Get-Content .\relay_proxy\relay_events.log -Wait |
    Select-String 'AI ACCESS|UPLOAD|POLICY|BLOCK|ALLOW'
```

장애 로그 감시:

```powershell
Get-Content .\relay_proxy\relay_runtime.log -Wait |
    Select-String '\[WARN\]|\[ERROR\]'
```

업로드 한 건마다 다음 구조가 생긴다.

```text
relay_proxy\upload_records\YYYYMMDD\...\
  original_<원본파일명>
  content.txt
  metadata.txt
```

`metadata.txt`에서 `captured_local`, `captured_utc`, `computer`,
`windows_user`, `client_ip`, `process_name`, `service`, `host`, `filename`,
`sha256`, `format`, `action`, `reason`을 확인한다.

## 6. 예방 차단 모드의 HTTP 처리

안전 시작 배치는 `LOCAL_DLP_FORCE_HTTP1_UPLOAD_INSPECTION=1`을 사용한다.
브라우저와 서버 양쪽에서 HTTP/1.1을 협상하고 요청 전체를 건당 최대 128 MiB까지
버퍼링한 뒤 검사 결과가 ALLOW일 때만 서버로 보낸다. 따라서 이 모드가 현재의
예방 차단 기준이다. 동시 연결의 HTTP/1 요청 버퍼 합계도 512 MiB로 제한하며,
어느 한도를 넘으면 서버로 보내기 전에 fail-closed 처리한다.

이 환경변수를 끄면 ALPN에 따라 HTTP/1.1 또는 HTTP/2가 자동 선택된다. HTTP/2
경로도 stream 재조립·분석·기록·차단 응답을 구현하지만, END_STREAM 전에 이미
전달된 DATA를 회수할 수 없으므로 현재는 무유출 예방 경계가 아니라 감사/탐지
경로로 취급한다.

## 7. 현재 범위 밖

- 음성·영상 음성인식/전사
- RAR/7Z/TAR/GZIP 내부 해제(형식 식별 후 fail-closed)
- 암호를 모르는 암호화 문서의 평문 추출
- DRM 해제 자체(인가된 복호화 연동 전에는 탐지 후 fail-closed)
- HTTP/3/QUIC 복호화
- 128 MiB를 넘는 단일 업로드(현재 안전 한도에서 차단)
- 업로드 기록의 장기 보존·중앙 전송·자동 삭제 정책

이 항목들은 원본 식별과 차단은 가능하지만 본문 전체 추출을 성공으로 기록하지
않는다.
