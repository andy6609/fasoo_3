# Infinity_v2

> **상태:** 설계 단계 — 코드 미포팅
> **목적:** `proxy_ToInfinity`의 업로드 라우팅을 **다중 전송 규격을 다룰 수 있는 구조**로 재설계한다.

---

## 왜 v2인가

3사(claude.ai / Gemini / ChatGPT) 업로드를 실측한 결과 **전송 규격이 셋 다 달랐다.**

| 서비스 | 규격 | 요청 수 | 파일 본문 위치 |
|---|---|---|---|
| claude.ai | 표준 `multipart/form-data` | 1 | 같은 요청 |
| Gemini | Google Resumable | 2 | finalize 요청 본문 전체 |
| ChatGPT | Presigned URL (Azure Blob 직송) | 3 | **다른 호스트로 PUT** |

v1의 라우팅(`if` 체인 + URL 부분 문자열 매칭)으로는 이 셋을 다룰 수 없다는 것이
수치로 드러났다 — ChatGPT 캡처에서 **오탐 9건 / 미탐 3건 / 추출 0건**.

실측 근거: `../proxy_ToInfinity/docs/noDRM/logs/`

---

## 문서

| 문서 | 내용 |
|---|---|
| `docs/architecture.md` | 라우팅 구조 설계 — v1 문제 진단, 공통 데이터 모델, 파이프라인, 탐지 신호, 상관 전략 |
| `docs/handler-interface.md` | 핸들러 계약 — 인터페이스, 자료구조, 3사 처리 명세, 구현 순서 |
| `docs/design-summary-7-27.md` | 위 둘의 **요지 요약** — "왜 이렇게 설계했는가"를 빠르게 훑는 용도 |

처음 읽는다면 `design-summary-7-27.md` → `architecture.md` → `handler-interface.md` 순서를 권장한다.

---

## 설계 요지

1. **탐지를 URL이 아니라 구조적 신호로** — Content-Type / 업로드 헤더 / 호스트 접미사+메서드.
   오탐이 구조적으로 사라지고, `MultipartHandler`가 호스트를 안 봐서 **미조사 서비스도 자동 포착**된다.
2. **모든 핸들러가 같은 `UploadRecord`를 채운다** — 검증·해시·저장은 규격을 모른 채 한 번만 구현.
3. **`Ignored` 반환으로 조기 `return` 문제 제거** — 미구현 핸들러가 범용 처리를 막을 수 없다.
4. **요청 간 상태(`CorrelationStore`)** — 파일명과 본문이 다른 요청에 있는 규격을 다룬다.
   ChatGPT는 `file_size`로 **크기 매칭**(강), Gemini는 순서 기반(약).
5. **MIME은 조건부 신뢰 + 확장자 폴백** — Gemini의 Content-Type은 파일과 무관한 고정값이다.

---

## 진행

- [x] 아키텍처 설계
- [x] 핸들러 계약 정의
- [ ] `src/` 포팅
- [ ] `MultipartHandler` → **claude.ai A/B/C로 회귀 검증 (v1과 동일 결과여야 함)**
- [ ] `CorrelationStore` + `PresignedHandler` → ChatGPT 검증
- [ ] `ResumableHandler` → Gemini 검증
- [ ] 동시 업로드 적대적 테스트

---

## 관련
- `../proxy_ToInfinity/` — v1 (현재 동작하는 트랙)
- `../proxy_ToInfinity/docs/service-specific-parser-decision.md` — 전용 파서 판단 기준
- `../proxy_ToInfinity/docs/upload-channel-and-transport-analysis.md` — 매체별 한계 분류
