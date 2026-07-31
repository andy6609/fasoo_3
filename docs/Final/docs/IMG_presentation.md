# 2차 발표 시각자료(로그·스크린샷) 준비 목록

> 슬라이드에 넣을 로그·표를 **바로 복붙할 수 있게** 박제해 둔다.
> - **실시간 프록시 로그는 임시 파일(`tasks/*.output`)이라 사라질 수 있다.**
>   그래서 아래에 실제 로그를 박제했고, **안 사라지는 원본 위치**도 같이 적었다.
>   (원본: `Infinity_v2/docs/test_results/<서비스>_web/file_*.md` 안 코드블록)
> - 로그를 새로 깨끗하게 뽑고 싶으면 맨 아래 **부록: 재추출 명령어** 참고.
> - 슬라이드에선 `magic=OK/MISMATCH`, `hash=...` 부분을 색으로 강조하면 효과 큼.

---

## 자료 1 — 세 가지 전송 방식 (대본 7-①)

> 슬라이드 의도: "같은 파일 하나 올리는데 서비스마다 이렇게 다르게 생겼다."
> 로그 3개를 나란히 놓으면 '방식이 제각각'이 한눈에 보인다.
> 원본: `test_results/claude_web/file_A.md`, `gemini_web/file_A.md`, `chatgpt_web/file_A.md`

**① multipart — Claude/Grok/DeepSeek (한 번에)**
```
[Observe] POST claude.ai/.../wiggle/upload-file
          ct=[multipart/form-data; boundary=----WebKitFormBoundary...]  bodylen=2288
[Upload]  service=claude handler=Multipart  file="A_기밀_설계문서.pdf"
          magic=OK  hash=e1625535be12246f
```

**② Google Resumable — Gemini (이름 먼저 → 내용 나중, 2번)**
```
[Observe] POST push.clients6.google.com/upload/   X-Goog-Upload-Command=start
          bodylen=36  head=File name: A_기밀_설계문서.pdf      ← 이름만
[Upload:pending] handler=Resumable
[Observe] POST push.clients6.google.com/upload/?upload_id=...  X-Goog-Upload-Command=upload, finalize
          bodylen=2084  head=%PDF-1.4...                        ← 내용만
[Upload]  service=gemini handler=Resumable  file="A_기밀_설계문서.pdf"
          magic=OK  hash=e1625535be12246f
```

**③ Presigned URL — ChatGPT (클라우드로 직송)**
```
[Observe] POST chatgpt.com/backend-api/files   ct=[application/json]
          head={"file_name":"A_기밀_설계문서.pdf","file_s...          ← 자사엔 쪽지만
[Upload:pending] handler=Presigned
[Observe] PUT sdmntprjapaneast.oaiusercontent.com/files/.../raw?...   ← 딴 서버(Azure)로 파일
          ct=[application/pdf]  bodylen=2084  head=%PDF-1.4...
[Upload]  service=chatgpt handler=Presigned  file="A_기밀_설계문서.pdf"
          magic=OK  hash=e1625535be12246f
```

---

## 자료 2 — 같은 파일, 다른 서비스, 같은 해시 (대본 7-③, ★ 제일 강력)

> 슬라이드 의도: "전송 방식은 5개 제각각인데, 우리가 복원한 결과 지문은 하나로 똑같다."
> 원본: 각 `test_results/*/file_A.md`

```
Claude     [Upload] service=claude   handler=Multipart   magic=OK  hash=e1625535be12246f
Gemini     [Upload] service=gemini   handler=Resumable   magic=OK  hash=e1625535be12246f
ChatGPT    [Upload] service=chatgpt  handler=Presigned   magic=OK  hash=e1625535be12246f
Grok       [Upload] service=generic  handler=Multipart   magic=OK  hash=e1625535be12246f
DeepSeek   [Upload] service=generic  handler=Multipart   magic=OK  hash=e1625535be12246f
                                                                    └─ 다섯 개 다 동일 ─┘
```

---

## 자료 3 — 발견 → 수정 (대본 7-④, before/after 3쌍)

> 슬라이드 의도: "새 형식 넣을 때마다 버그 나왔고, 하나씩 고쳤다." before/after 대비가 핵심.

**(가) 오피스 위조 탐지 — 처음엔 못 잡음 → 고침 (파일 E)**
> 원본: `test_results/claude_web/file_E.md` §0, §5
```
[수정 전]  file="E_고객데이터_원본.xlsx"
           type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet(declared)
           magic=UNKNOWN          ← 위조인데 그냥 통과

[수정 후]  file="E_고객데이터_원본.xlsx"
           type=application/zip(declared)
           magic=MISMATCH         ← 위조 정확히 탐지
```

**(나) 대용량 절단 — 잘려도 흔적은 남김 (파일 C)**
> 원본: `test_results/deepseek_web/file_C.md`
```
[Upload]  file="C_대용량_고객리스트.pdf"
          size=261980/?  reqlen=618952           ← 618KB 중 26만B만 캡처(상한)
          magic=OK  hash=skipped(truncated)
          saved=captured_files/..._PARTIAL_C_...  ← '잘림'을 파일명에 표시
```

**(다) IPv6 — 파일이 서버에 안 올라가던 것 → 고침 (DeepSeek)**
> 원본: `Infinity_v2/docs/ipv6-upstream-fix.md`, `test_results/deepseek_web/file_B.md`
```
[수정 전]  [ERROR] Failed to connect to upstream: hif-dliq.deepseek.com   ← 반복
                                                     (IPv6 전용 호스트, 못 감)

[수정 후]  [INFO]  ALPN Negotiated: h2 for hif-dliq.deepseek.com
           [INFO]  H2Bridge running for hif-dliq.deepseek.com             ← 정상 연결
```

---

## 자료 4 — 웹 말고 앱 (대본 7-2, MSIX 예외 전/후)

> 슬라이드 의도: "앱은 처음엔 0건 → 예외 한 줄 → 웹과 100% 동일."
> 원본: `proxy_ToInfinity/docs/noDRM/logs/claude-app/claude-app-upload.md`
> (앱 실험은 v1에서 해서 로그 형식이 `[Parser]`/`[Verifier]`임 — 슬라이드엔 상관없음)
```
[예외 등록 전]  탐지 0건  (윈도우가 앱→127.0.0.1 프록시 연결을 차단)

[예외 등록 후]  [Observe] POST claude.ai/.../wiggle/upload-file  bodylen=2288
               [Parser]  파일명: A_기밀_설계문서.pdf, 크기: 2084 bytes 추출 완료
               [Verifier] 매직넘버 일치 확인 (application/pdf)
               [Verifier] 추출된 파일 해시: e1625535be12246f   ← 웹과 동일
```
- 예외 등록 명령(슬라이드에 한 줄 보여주면 좋음): `CheckNetIsolation LoopbackExempt -a -n=<패키지이름>`

---

## 자료 5 — Grok: 파일은 됨 / 채팅은 안 됨 (대본 8-0)

> 슬라이드 의도: "파일 업로드는 Grok도 잘 잡힘. 못 잡는 건 그 뒤의 실시간 채팅(WebSocket)."
> 원본(파일): `test_results/grok_web/file_A.md` / (한계): `grok-websocket-limitation.md`

**파일 업로드 — ✅ 성공 (2026-07-29 실측)**
```
[Observe] POST grok.com/http/upload-file-v2/direct
          ct=[multipart/form-data; boundary=----WebKitFormBoundary...]  bodylen=2288
[Upload]  service=generic handler=Multipart
          endpoint=grok.com/http/upload-file-v2/direct  file="A_기밀_설계문서.pdf"
          magic=OK  hash=e1625535be12246f  saved=captured_files/9_A_기밀_설계문서.pdf
```

**채팅 시작 — ❌ 실패 (WebSocket 전환에서 끊김)**
```
[INFO] ALPN Negotiated: http/1.1 for grok.com
[Observe] POST grok.com/_data/v1/a/t/...  head=...gateway_new_conversation...   ← 대화 시작 시도
[Observe] POST grok.com/api/log_metric    head=[{"type":"client_application_error"...  ← 에러
           → 브라우저 화면: "Connection failed. Please try again."
```
- 주의: 채팅 실패는 딱 떨어지는 `[ERROR]` 한 줄이 아니라 **"연결이 그냥 끊기는" 형태**라,
  슬라이드엔 위 (파일 성공 로그) + (브라우저의 connection failed 스크린샷)을 나란히 놓는 게
  제일 명확하다. 원리 설명은 `grok-websocket-limitation.md`의 전화→문자 비유 사용.

---

## 준비물 체크리스트 (슬라이드용)

- [ ] 자료1: 전송 방식 3종 로그 (multipart / resumable / presigned)
- [ ] 자료2: 5개 서비스 같은 해시 로그
- [ ] 자료3: before/after 3쌍 (오피스위조 / 절단 / IPv6)
- [ ] 자료4: 앱 MSIX 전/후 + `CheckNetIsolation` 명령 한 줄
- [ ] 자료5: Grok 파일성공 로그 + 브라우저 "connection failed" **스크린샷 직접 찍기**
- [ ] (선택) `captured_files/` 폴더에 실제로 복원된 파일들 보여주는 스크린샷

---

## 부록 — 로그 재추출 명령어

**A. 지금 돌고 있는 프록시가 어느 로그 파일에 쓰는지 찾기**
```bash
DIR="C:/Users/ANDYLE~1/AppData/Local/Temp/claude/c--Users-AndyLee-global-source-repos-local-proxy-lab/dc82aa8e-fe8f-437b-89ab-df06d19a1009/tasks"
ls -t "$DIR"/*.output | head -3    # 가장 최근 수정된 것이 현재 로그
```

**B. 특정 자료만 뽑기 (LOG=위에서 찾은 파일 경로)**
```bash
# 자료2 — 모든 [Upload] 성공 줄 (해시 비교용)
grep -E "\[Upload\] service=" "$LOG" | grep "magic=OK"

# 자료3(가) — 오피스 위조 전/후
grep -E "xlsx.*magic=(UNKNOWN|MISMATCH)" "$LOG"

# 자료3(다) — IPv6 전/후
grep -E "hif-dliq|Failed to connect to upstream" "$LOG"

# 자료5 — Grok 파일 업로드 + 채팅 에러
grep -iE "grok.*upload-file|\[Upload\].*grok|gateway_new_conversation|client_application_error" "$LOG"
```

**C. 로그가 다 사라졌을 때 (원본에서 뽑기)**
> `test_results/` 안 md 파일들에 로그가 코드블록으로 이미 박제돼 있다. 거기서 복사하면 됨.
```bash
# 예: 5개 서비스 A 업로드 로그가 있는 문서들
ls Infinity_v2/docs/test_results/*/file_A.md
```

**D. 완전 새로 깨끗하게 재현하고 싶으면**
1. 프록시 실행: `Infinity_v2/build/Debug/Infinity_v2.exe`
2. 크롬: `--proxy-server="http://127.0.0.1:18080" --disable-quic --user-data-dir=<임시>`
3. `C:\Exception\testfiles\`에서 A~E 업로드 (git 폴더 사본은 DRM 오염이라 안 됨)

---

# 슬라이드별 생성 프롬프트 (팀원 GPT에 넘긴 것 — 기록용)

> 팀원이 학습시켜둔 슬라이드 생성 GPT에 넘긴 프롬프트를 그대로 보관한다.
> 스타일(색·폰트·레이아웃)은 GPT가 이미 학습했으므로 프롬프트에선 **내용·구조만** 지정한다.
> 슬라이드 번호는 실제 덱 기준(5번=팀원 "파일 업로드 식별 중요"에 이어짐).

## 슬라이드 06 — AI 서비스는 파일을 어떻게 주고받는가 (개념 다리)

**대본 대응:** presentation-2-script.md §6
**확정 배너 문구:** `⚠️ QUIC(UDP)은 프록시 미경유 — TCP 강제 전환으로 해결`

```
6번 슬라이드를 만들어줘. 기존 발표 스타일(색·폰트·카드·레이아웃) 그대로 유지해줘.

슬라이드 번호: 06
제목: AI 서비스는 파일을 어떻게 주고받는가

■ 상단: 전송 방식 카드 3개 (가로 나란히)
  카드 1 — 아이콘: 상자/패키지
    큰 라벨: 한 번에 통째로 / 설명: multipart 방식 · 파일과 이름을 한 요청에
    예시(작게): Claude · Grok · DeepSeek
  카드 2 — 아이콘: 둘로 쪼개짐/두 화살표
    큰 라벨: 두 번에 쪼개서 / 설명: Resumable 방식 · 이름 먼저 → 내용 나중
    예시(작게): Gemini
  카드 3 — 아이콘: 구름(클라우드)
    큰 라벨: 클라우드로 직송 / 설명: Presigned 방식 · 자사 서버 말고 외부 저장소로
    예시(작게): ChatGPT

■ 하단: 강조 배너 1개
    ⚠️ QUIC(UDP)은 프록시 미경유 — TCP 강제 전환으로 해결

[주의]
- 카드는 정확히 3개.
- 로그 코드나 긴 문장은 넣지 마 (다음 슬라이드에서 다룸).
- 영어 용어(multipart/Resumable/Presigned/QUIC)는 그대로, 한글 설명 곁들여서.
```

**설계 메모:** 5번(카드 나열 + 하단 보라 배너 = 위조 예시)의 자매 슬라이드가 되게 동일 구조.
로그는 6번에 안 넣고 7번에서 증거로 크게.

---

## 슬라이드 07 — 서비스마다 방식이 다르다 (표 + 실제 로그가 주인공)

**대본 대응:** presentation-2-script.md §7-①
**핵심:** 표는 위에 작게(5→3 요약), **실제 캡처 로그 3박스가 주인공**. 화살표 주석 필수.

```
7번 슬라이드를 만들어줘. 기존 발표 스타일(색·폰트·카드·레이아웃) 그대로 유지해줘.

슬라이드 번호: 07
제목: 서비스마다 파일 올리는 방식이 다르다 — 실제 캡처 로그

■ 상단(작게): 요약 한 줄 표
  | Claude · Grok · DeepSeek | 표준 multipart |
  | Gemini                   | Resumable (2번에 쪼갬) |
  | ChatGPT                  | Presigned (클라우드 직송) |

■ 중앙(크게, 주인공): 실제 캡처 로그 3박스 — 짙은 배경 + 고정폭(monospace), 가로 3칸

  ① multipart (Claude 계열)
     POST claude.ai/.../wiggle/upload-file
     Content-Type: multipart/form-data; boundary=----…
     head=----… Content-Disposition: filename="A_기밀_설계문서.pdf"
     → 파일 + 이름이 한 요청에 통째로

  ② Resumable (Gemini)
     POST push.clients6.google.com/upload/   X-Goog-Upload-Command: start
       head=File name: A_기밀_설계문서.pdf     ← 이름만
     POST push.clients6.google.com/upload/?upload_id=…  X-Goog-Upload-Command: upload, finalize
       head=%PDF-1.4...                        ← 내용만
     → 이름과 내용을 2번에 나눠서

  ③ Presigned (ChatGPT)
     POST chatgpt.com/backend-api/files
       head={"file_name":"A_기밀_설계문서.pdf", …}   ← 자사엔 쪽지만
     PUT  sdmntpr***.oaiusercontent.com/.../raw
       head=%PDF-1.4...                              ← 실제 파일은 Azure로
     → 파일은 외부 클라우드로 직송

■ 하단: 강조 배너 1개
    5개 안에서만도 방식이 3가지 — 표준 파서 하나로는 다 못 잡는다

[각 로그 박스에서 색으로 강조]
- ①: "multipart/form-data" 와 filename="..."
- ②: "start" 와 "finalize" + "File name:" / "%PDF"
- ③: 호스트가 "chatgpt.com" → "oaiusercontent.com" 으로 바뀌는 것

[주의]
- 로그가 주인공. 표는 위에 작게 요약용으로만.
- boundary·upload_id·긴 토큰 값은 "…" 로 줄여. head=/호스트/Command 는 남겨.
- "← 이름만 / ← 내용만 / ← 쪽지만 / ← Azure로" 화살표 주석 꼭 넣어(이해 포인트).
```

**설계 메모:** 로그(증거) + 화살표(해석) 세트가 핵심. Resumable의 start/finalize,
Presigned의 호스트 바뀜이 "쪼갠다 / 딴 데로 보낸다"를 눈으로 증명.

---

## 슬라이드 08 — 우리 프록시가 파일을 처리하는 4단계 (파이프라인)

**대본 대응:** presentation-2-script.md §7-② (핸들러) — "분류기"가 아니라 "처리 시스템"임을 보여줌
**핵심:** 라우터→파서만이 아니라 **상관저장소(③) + 검증·저장(④)까지** 넣어야 깊이가 산다.
④ 위조탐지는 **5번 슬라이드(위조 예시)와 이어지는** 부분.

```
8번 슬라이드를 만들어줘. 기존 발표 스타일 그대로 유지해줘.

슬라이드 번호: 08
제목: 우리 프록시가 파일을 처리하는 4단계

■ 중앙: 위 → 아래로 흐르는 파이프라인 다이어그램

  [파일 업로드 요청]
        │
  ① [라우터]        — 어느 전송 방식인지 판별
        │  (3갈래로 갈라짐)
  ② [파서(핸들러) 3개]  — 방식대로 파일 실물을 뜯어냄
        - Multipart 파서  → Claude · Grok · DeepSeek
        - Resumable 파서  → Gemini
        - Presigned 파서  → ChatGPT
        │  (Gemini·ChatGPT의 쪼개진 2요청은 옆에서 합쳐짐)
  ③ [상관 저장소]   — 이름/내용으로 쪼개져 온 요청을 이어붙임
        │
  ④ [검증·저장]     — 위조 탐지(매직넘버) · 해시 · 저장

■ 하단: 강조 배너 1개
    새 서비스가 표준(multipart)을 쓰면 → 코드 수정 없이 자동으로 잡힌다

[주의]
- ①→②→③→④가 위에서 아래로 흐르는 게 한눈에 보이게 (파이프라인).
- ②의 파서 3개는 가로로, ③④는 다시 한 줄기로 모이게.
- ④의 "위조 탐지"는 앞 5번 슬라이드(위조 예시)와 이어지는 부분이라 살짝 강조.
- 로그·코드는 넣지 마.
```

**4단계 요약:**
| 단계 | 이름 | 하는 일 |
|---|---|---|
| ① | 라우터 | 어느 전송 방식인지 판별해 알맞은 파서로 넘김 |
| ② | 핸들러=파서 | 그 방식 규칙대로 요청을 뜯어 파일 실물을 꺼냄 |
| ③ | 상관 저장소 | Gemini·ChatGPT의 쪼개진 2요청(이름/내용)을 짝지어 이어붙임 |
| ④ | 검증·저장 | 위조 탐지(매직넘버) · 해시 · captured_files 저장 |

**대본 추가 문장(권장):** "...알맞은 파서로 넘겨지는 구조죠. 그리고 Gemini나 ChatGPT처럼
쪼개서 오는 건 상관 저장소에서 이름이랑 내용을 다시 이어 붙이고요. 마지막에 꺼낸 파일로
아까 말한 위조 탐지랑 해시 검사를 해서 저장합니다."

---

## 슬라이드 진행 현황 (체크)

- [x] 06 — 전송 방식 3종 카드 + QUIC 배너 (프롬프트 확정)
- [x] 07 — 5→3 요약표 + 실제 로그 3박스 (프롬프트 확정)
- [x] 08 — 처리 4단계 파이프라인 (프롬프트 확정)
- [ ] A~E 테스트 파일 설계 (7-③) 슬라이드
- [ ] "같은 파일 다른 서비스 같은 해시" (7-③) 슬라이드 — 자료2 활용
- [ ] 발견→수정 before/after (7-④) 슬라이드 — 자료3 활용
- [ ] 앱 MSIX (7-2) 슬라이드 — 자료4 활용
- [ ] Grok 파일OK/채팅fail (8-0) 슬라이드 — 자료5 활용
- [ ] 앞으로 로드맵 (8 마무리) 슬라이드
