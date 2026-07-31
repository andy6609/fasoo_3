#ifndef PROXY_V2_UPLOAD_ROUTER_H
#define PROXY_V2_UPLOAD_ROUTER_H

#include "Inspector/UploadTypes.h"
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace proxy {
namespace v2 {

// ─────────────────────────────────────────────────────────────
//  상관(correlation) 저장소
//
//  Gemini·ChatGPT는 파일명과 파일 본문이 서로 다른 요청에 들어 있다.
//  선행 메타 요청을 여기 보관했다가 후행 본문 요청이 꺼내 쓴다.
//
//  정확한 키(upload_id, presigned URL)는 메타 요청의 *응답* 에 있는데
//  현재 h2 응답을 분석기로 넘기지 않아 쓸 수 없다. 그래서 차선책을 쓰되
//  서비스마다 강도가 다르다 (docs/architecture.md §5).
// ─────────────────────────────────────────────────────────────
struct PendingUpload {
    std::string filename;
    long long   declaredSize;   // 모르면 -1
    std::string endpoint;
    std::chrono::steady_clock::time_point ts;
};

class CorrelationStore {
public:
    void put(const std::string& service, PendingUpload p);

    // size >= 0 이면 declaredSize == size 인 항목을 먼저 찾고(강한 매칭),
    // 없으면 가장 오래된 항목으로 폴백한다(순서 기반).
    //
    // 폴백이 필요한 이유: 파일이 캡처 상한을 넘으면 본문 크기가 상한값으로
    // 잘려 실제 크기와 달라진다. 이때 크기 매칭은 반드시 실패한다.
    bool take(const std::string& service, long long size, PendingUpload& out);

private:
    void expireLocked();

    static const int  kTtlSeconds     = 300;  // ChatGPT SAS 토큰 수명(~5분)에 맞춤
    static const size_t kMaxPerService = 32;  // 본문 요청이 끝내 안 올 때 무한 축적 방지

    std::mutex mu_;
    std::map<std::string, std::deque<PendingUpload>> byService_;  // 서비스별 분리
};

// ─────────────────────────────────────────────────────────────
//  핸들러 인터페이스
// ─────────────────────────────────────────────────────────────
class IUploadHandler {
public:
    virtual ~IUploadHandler() {}

    virtual const char* name() const = 0;

    // 이 요청이 내가 처리할 전송 규격인가? (부작용 없이 판별만)
    virtual bool matches(const RequestContext& ctx) const = 0;

    // 실제 처리. matches()가 true여도 Ignored를 반환할 수 있다
    // (규격은 맞지만 이 요청은 파일이 아닌 제어 요청인 경우 등).
    virtual HandlerResult handle(const RequestContext& ctx, CorrelationStore& store) = 0;
};

// ─────────────────────────────────────────────────────────────
//  라우터
// ─────────────────────────────────────────────────────────────
class UploadRouter {
public:
    void registerHandler(std::unique_ptr<IUploadHandler> h);
    void route(const RequestContext& ctx);

    // 등록 순서 = 우선순위 (구체적 신호 → 범용)
    static UploadRouter& instance();

private:
    std::vector<std::unique_ptr<IUploadHandler>> handlers_;
    CorrelationStore store_;
};

// Complete 로 올라온 레코드의 공통 후처리 (규격 무관):
// 절단 판정 → 기대 타입 결정 → 매직넘버 → 해시 → 저장 → 로깅
void processUpload(UploadRecord& rec);

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_UPLOAD_ROUTER_H
