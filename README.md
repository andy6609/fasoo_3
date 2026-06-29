# 🔐 HTTPS 트래픽 분석 PoC — 인턴 프로젝트

> Local Proxy를 직접 구현하여 HTTPS 트래픽을 복호화하고,  
> 파일 업로드 행위를 탐지·분석하는 PoC(Proof of Concept)를 개발합니다.

---

## 프로젝트 목적

- 클라이언트 ↔ 서버 간 HTTPS 통신 구조를 직접 구현하며 이해
- TLS 중간자(MITM) 구조를 활용한 트래픽 복호화 환경 구성
- 파일 업로드 요청을 Proxy 레벨에서 식별·추출·검증
- 브라우저 및 AI Agent 환경에서의 동작 검증

---

## 커리큘럼 (10주)

| 주차 | 주제 | 핵심 구현 / 학습 |
|:----:|------|----------------|
| W1 | 프로젝트 이해 · 기본 개념 | PoC 목적/방향, 패킷 분석, Proxy, HTTP/HTTPS, TLS, 인증서, 파일 업로드 요청 구조 |
| W2 | 통신 구조 · Proxy 동작 | 클라↔서버 흐름, Explicit vs Transparent Proxy 차이, Local Proxy 수신·중계 구조 |
| W3 | Local Proxy 기본 구현 | TCP 프록시: 연결 수락 → 대상 서버 연결 → 요청/응답 중계 → 연결 종료, 테스트 |
| W4 | HTTP 요청/응답 분석 | Method / URL / Host / Header / Content-Type / Body 파싱 + 로그 기록 |
| W5 | TLS 암·복호화 구조 + 적용 | Root CA, Host별 Leaf 인증서, 클라-Proxy / Proxy-서버 이중 TLS 세션, 복호화 환경 구성 |
| W6 | HTTPS 트래픽 분석 | 복호화된 HTTPS의 URL / Header / Body 확인, "암호문 → Proxy 내부 평문" 검증 (브라우저 대상) |
| W7 | 파일 업로드 행위 식별 | Multipart/Form-Data, Content-Disposition, 파일명, Content-Type, 파일 크기로 업로드 탐지 |
| W8 | 업로드 파일 정보 · 바이너리 획득 | 파일명 / 확장자 / MIME / 크기 / Binary 추출, 원본 파일 일치 검증 |
| W9 | 파일 분석 + PoC 검증 | 파일 유형 분석, 확장자 검증, 파일 시그니처(매직넘버) 확인, 다양한 환경 테스트, 성공/실패 정리 |
| W10 | 최종 보고서 · 발표 | 목적 / 구조 / 구현 / 테스트 결과 / 한계 / 개선 방향 정리 + 발표 |
