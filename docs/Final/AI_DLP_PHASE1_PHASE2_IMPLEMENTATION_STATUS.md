# AI 파일 DLP 1·2차 구현 현황

> 기준 브랜치: `codex/ai-dlp-phase1-phase2`
>
> 기준 커밋: `60abac8` (`Implement AI upload DLP phase 1 and 2`)

## 1. AI 사이트별 업로드 처리

| 서비스 | 현재 구현 방식 |
|---|---|
| ChatGPT | 파일 metadata 요청과 후속 raw PUT 업로드를 연결해 원본을 복원한다. |
| Claude | `multipart/form-data`의 파일 Part를 분리해 원본을 복원한다. |
| Gemini | 일반 업로드 및 resumable upload의 offset/finalize 요청을 추적해 파일을 재조립한다. |

POST, PUT, PATCH 기반 업로드를 지원하며 다음 항목을 분석한다.

- `Content-Type`
- `Content-Disposition`
- multipart boundary
- 파일명과 `filename*`
- `Content-Length` 및 chunked body
- Binary Stream
- Gemini 분할 업로드의 offset과 전체 크기
- 파일 확장자와 실제 Magic Byte 일치 여부

주요 코드:

- [`multipart_parser.c`](../../relay_proxy/multipart_parser.c)
- [`upload_tracker.c`](../../relay_proxy/upload_tracker.c)
- [`upload_capture.c`](../../relay_proxy/upload_capture.c)

## 2. 파일 원본·본문 추출

### 2.1 본문 추출이 구현된 형식

- TXT, CSV, JSON, XML
- UTF-8, CP949, UTF-16, UTF-32
- DOCX, XLSX, PPTX
- HWPX
- HWP5 일부 구조
- 일반 텍스트 PDF
- 스캔 PDF OCR
- ZIP 및 중첩 ZIP 내부 문서
- PNG, JPEG, GIF, BMP, TIFF OCR
- 다중 프레임 GIF/TIFF의 최대 100개 프레임

DOCX 내부 XML뿐 아니라 문서에 포함된 이미지와 임베디드 파일도 검사한다.

주요 코드:

- [`file_analyzer.c`](../../relay_proxy/file_analyzer.c)
- [`windows_ocr.cpp`](../../relay_proxy/windows_ocr.cpp)
- [`offline_ocr.py`](../../relay_proxy/tools/offline_ocr.py)

### 2.2 본문을 추출할 수 없는 경우

다음 형식은 내용을 안전하게 검사할 수 없으면 기본적으로 차단하는 fail-closed 방식으로 처리한다.

- 암호화된 PDF·ZIP·Office 문서
- DRM 문서
- 복잡한 레거시 DOC/XLS/PPT
- 실행 파일이나 불투명 바이너리가 포함된 문서
- 손상된 ZIP·PDF
- 지원하지 않는 압축·미디어 형식

원본이 정상적으로 캡처됐다면 본문 추출에 실패하더라도 원본 파일과 실패 사유를 저장한다.

## 3. 보안 정책 판단

현재 다음 기준으로 ALLOW/BLOCK을 판단한다.

- 기밀 키워드
- 테스트 기밀 표식
- 주민등록번호 날짜·체크섬 검증
- 카드번호 Luhn 검증
- 이메일·전화번호 LOG_ONLY 규칙
- 확장자와 Magic Byte 불일치
- 실행 파일 및 스크립트
- 암호화·DRM·분석 불가능 문서
- ZIP Bomb 및 과도한 중첩 구조
- 문서 내부 OLE, Package, Script, BinData

주요 코드:

- [`policy_engine.c`](../../relay_proxy/policy_engine.c)
- [`policy_rules.txt`](../../relay_proxy/policy_rules.txt)
- [`dlp_engine.c`](../../relay_proxy/dlp_engine.c)

## 4. 업로드 증적 저장

업로드마다 다음 구조로 증적을 저장한다.

```text
relay_proxy\upload_records\YYYYMMDD\...\
  original_원본파일명
  content.txt
  metadata.txt
```

`metadata.txt`에는 다음 정보가 포함된다.

- 업로드 로컬·UTC 시간
- PC 이름
- Windows 사용자
- 클라이언트 IP
- 프로세스 이름
- AI 서비스
- 대상 호스트와 경로
- HTTP Method
- 파일명과 Content-Type
- 파일 크기
- SHA-256
- 분석된 파일 형식
- ALLOW/BLOCK
- 적용된 정책과 사유
- 증적 저장 완료 여부

자세한 구조는 [`UPLOAD_RECORDS_README.md`](../../relay_proxy/UPLOAD_RECORDS_README.md)를 참고한다.

## 5. HTTP/TLS 처리 상태

현재 다음 기능을 구현했다.

- TLS 인증서 동적 발급 및 캐싱
- ChatGPT, Gemini, Claude 인증서 처리
- ALPN 기반 HTTP/1.1·HTTP/2 선택
- HTTP/1.1 전체 요청 버퍼링 후 검사
- HTTP/2 stream 및 DATA frame 재조립·분석
- HTTP/3 우회를 막기 위한 QUIC 비활성화 테스트 방식
- 인증서·정책 초기화 실패 시 fail-closed

예방 차단 실행 모드는 HTTP/1.1로 강제한다. 서버로 파일을 보내기 전에 단일 요청 기준 최대 128 MiB까지 전체를 수집하고, 검사 결과가 ALLOW인 요청만 서버에 전송한다.

HTTP/2 분석도 구현돼 있지만 파일 전체 분석 전에 일부 DATA가 서버로 전달될 수 있으므로 현재는 탐지·감사용이다. 회사 기밀의 완전한 사전 차단 기준은 HTTP/1.1 예방 모드다.

주요 코드:

- [`tls_mitm_engine.c`](../../relay_proxy/tls_mitm_engine.c)
- [`http2_engine.c`](../../relay_proxy/http2_engine.c)
- [`request_buffer.c`](../../relay_proxy/request_buffer.c)

## 6. 일반 업무 프로그램 보호

현재 PAC 설정은 다음과 같다.

- ChatGPT, Gemini, Claude 관련 도메인 → 로컬 프록시
- Outlook, Microsoft 365, 일반 웹사이트 → DIRECT

Outlook 로그인이 로컬 프록시 인증서 문제로 차단되지 않도록 AI 서비스 관련 트래픽만 선택적으로 프록시한다.

관련 파일:

- [`ai_only_proxy.pac`](../../relay_proxy/ai_only_proxy.pac)
- [`start_ai_dlp_capture.ps1`](../../relay_proxy/start_ai_dlp_capture.ps1)

## 7. 검증 완료 상태

자동 테스트 결과는 다음과 같다.

| 검증 항목 | 결과 |
|---|---|
| Release x64 빌드 | 경고 0 / 오류 0 |
| 업로드 저장 안전성 | 19 PASS / 0 FAIL |
| 파일 구조·본문·OCR | 77 PASS / 0 FAIL / 2 선택 SKIP |
| 실제 네이티브 정책 | 38 PASS / 0 FAIL |
| 원본·본문·메타데이터 저장 | 4 PASS / 0 FAIL |
| AI 전용 PAC 및 Outlook DIRECT smoke test | PASS |
| 종료 후 프록시 프로세스·8000 포트 정리 | PASS |

실행 방법은 [`TESTING_GUIDE_KO.md`](../../relay_proxy/TESTING_GUIDE_KO.md)를 참고한다.

## 8. 아직 남은 부분

현재 코드는 기능 검증 단계까지 완료됐지만 전사 배포 제품 단계는 아니다. 다음 작업이 추가로 필요하다.

- 로그인된 실제 ChatGPT·Gemini·Claude UI 반복 회귀 테스트
- AI 서비스 요청 URL 변경에 대한 자동 업데이트
- Windows Service와 watchdog
- 서명된 설치·제거 패키지
- 중앙 보안 서버로 이벤트 전송
- 증적 파일 ACL·암호화·보존 기간·자동 삭제
- HTTP/2 완전 사전 차단 구조
- HTTP/3/QUIC 분석
- RAR, 7Z, TAR, GZIP 내부 해제
- 음성·영상 전사
- DRM 솔루션의 인가된 복호화 연동
- 실제 Hancom·구버전 Office 파일 corpus 확대

## 9. 현재 단계 요약

현재 구현은 로컬 PC에서 ChatGPT, Gemini, Claude 파일 업로드를 식별하고, 가능한 문서는 본문과 OCR 결과까지 분석하며, 위험 문서를 차단하고, 원본·본문·PC 정보를 증적으로 저장하는 1·2차 기능 검증 단계까지 완료된 상태다.
