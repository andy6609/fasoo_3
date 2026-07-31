# 업스트림 IPv4 고정 → IPv6 전용 호스트 도달 불가 (발견 + 수정)

> **발견일:** 2026-07-29
> **경위:** DeepSeek 파일 업로드 실험 중, 파일 처리 백엔드 호스트로의 연결이 반복 실패
>   (`[ERROR] Failed to connect to upstream: hif-dliq.deepseek.com`)하는 것을 보고 추적.
> **상태:** 원인 확인 + **수정 완료**. 실측 재검증은 진행 중.

---

## 요약 (한눈에 보기)

우리 프록시가 업스트림(진짜 서버)에 연결할 때 **IPv4(`AF_INET`)만** 쓰도록 하드코딩돼
있었다. 그런데 서비스 중에는 **IPv6 주소만 가진 호스트**가 있다 — 이런 호스트에는 우리
프록시가 아예 도달할 수 없어서, 그 호스트를 거치는 기능(DeepSeek의 경우 파일 처리)이
통째로 실패했다.

| 호스트 | 인프라 | 주소 | IPv4 고정 프록시로 도달? |
|---|---|---|---|
| `chat.deepseek.com` (메인) | AWS CloudFront | IPv4 `3.173.21.63` | ✅ 됨 |
| `hif-dliq.deepseek.com` (파일 처리) | Huawei Cloud WAF | **IPv6만** (`2407:c080:...`, A 레코드 없음) | ❌ **안 됨** |

`AF_INET` → `AF_UNSPEC`로 바꾸고 주소 리스트를 순회하도록 고쳤다.

---

## 1. 증상

DeepSeek에서 파일 A/B를 올리면 **우리 프록시는 파일을 정상 캡처**하는데
(`[Upload] service=generic handler=Multipart ... magic=OK/MISMATCH`), 브라우저 화면에서는
업로드가 실패한 것처럼 보였다. 로그에 아래 에러가 반복됐다:

```
[ERROR] Failed to connect to upstream: hif-dliq.deepseek.com
```

즉 파일 본문 자체는 우리 프록시 눈앞을 완전히 지나갔지만(DLP 관점 성공), DeepSeek 서버가
그 파일을 받아 처리하는 단계에서 실패했다.

---

## 2. 원인 진단 — 위조가 아니라 IPv6

처음엔 "B가 위조(PNG-as-pdf)라서 서버가 거부한 것 아니냐"는 가설이 있었으나 **틀렸다.**
A(정상 PDF)도 같은 `hif-*` 연결 실패를 겪었기 때문에, 파일 내용과 무관한 문제다.

DNS/직결 테스트로 확정:

```
$ nslookup hif-dliq.deepseek.com
  → b5b249a2....vip1.huaweicloudwaf.com
  → 2407:c080:802:1ce8:...   (IPv6 주소만, A 레코드 없음)

$ curl -v https://hif-dliq.deepseek.com
  * IPv4: (none)
  * Trying [2407:c080:802:1ce8:...]:443...
  * Established connection   ← 직결(프록시 없이)로는 IPv6로 정상 연결됨
```

**직결로는 IPv6로 잘 되는데 우리 프록시만 실패했다** → 프록시의 업스트림 연결이 IPv6를
못 쓴다는 뜻. 코드를 보니 원인이 명확했다.

---

## 3. 원인 코드 (`Http1Engine.cpp` `connectUpstreamTcp`)

### 수정 전
```cpp
static SOCKET connectUpstreamTcp(const std::string& host, int port) {
    struct addrinfo hints = {}, *info = nullptr;
    hints.ai_family = AF_INET;          // ← IPv4만 요청
    hints.ai_socktype = SOCK_STREAM;
    ...
    if (getaddrinfo(host, portStr, &hints, &info) != 0) return INVALID_SOCKET;
    SOCKET sock = socket(info->ai_family, ...);   // ← 첫 결과만 사용
    ...
}
```

두 가지 문제가 겹쳐 있었다:
1. **`AF_INET`(IPv4 전용)** — IPv6만 있는 호스트는 `getaddrinfo`가 주소를 하나도 못 줘서
   그 자리에서 `INVALID_SOCKET` 반환.
2. **첫 번째 주소만 시도** — 설령 여러 주소를 받아도 첫 게 실패하면 나머지를 안 써봤다.

### 수정 후
```cpp
hints.ai_family = AF_UNSPEC;   // IPv4·IPv6 둘 다 허용
...
// 여러 주소를 리스트로 받아, 연결될 때까지 순회
for (struct addrinfo* p = info; p != nullptr; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock == INVALID_SOCKET) continue;
    if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) break;  // 성공
    closesocket(sock); sock = INVALID_SOCKET;
}
```

- `AF_UNSPEC`로 IPv4/IPv6 주소를 모두 받는다.
- 리스트를 순회하며 **처음 성공하는 주소로 연결**한다(IPv6가 먼저 오고 실패하면 IPv4로,
  또는 그 반대로 자연스럽게 폴백).

**리슨 소켓(`ProxyServer.cpp`)은 안 건드렸다** — 그건 브라우저가 `127.0.0.1`(IPv4)로
붙는 로컬 소켓이라 IPv4로 두는 게 맞다. 바뀌어야 하는 건 "우리 → 바깥 서버" 방향뿐이다.

---

## 4. 왜 지금까지 안 걸렸나

claude.ai/Gemini/ChatGPT/Grok, 그리고 DeepSeek의 메인 호스트(`chat.deepseek.com`)까지
전부 IPv4 주소를 가지고 있어서 IPv4 고정으로도 문제가 없었다. **IPv6 전용 호스트를 쓰는
서비스가 DeepSeek의 파일 백엔드가 처음**이었다. 새 서비스로 표본을 넓히자 드러난 문제라는
점에서, D/E(포맷 확장)·Grok(WebSocket) 때와 같은 성격이다 — "실제로 넓혀봐야 나오는 버그".

---

## 5. 분류

기존 한계 유형(A 전송우회 / B 인증서고정 / C 파서한계 / D OS샌드박스)과 다르다. 이건
**우리 프록시 자체의 구현 결함**이라 유형 C(파서·구현 한계)에 가깝지만, "디코딩은 되는데
못 읽는" 게 아니라 **아예 연결을 못 맺는** 형태다. 그리고 C의 다른 사례들과 달리 **우리가
고칠 수 있고, 실제로 고쳤다.**

---

## 관련
- `../src/Protocol/Http1Engine.cpp` — `connectUpstreamTcp`(수정 위치)
- `test_results/deepseek_web/file_A.md`, `file_B.md` — DeepSeek 캡처 기록
- `grok-websocket-limitation.md` — 같은 "새 서비스에서 드러난 구현 한계" 계열
