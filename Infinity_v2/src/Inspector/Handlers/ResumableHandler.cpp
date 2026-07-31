#include "Inspector/Handlers/ResumableHandler.h"
#include "Inspector/HeaderUtil.h"

namespace proxy {
namespace v2 {

bool ResumableHandler::matches(const RequestContext& ctx) const {
    // X-Goog-Upload-Command가 있으면 Google resumable 프로토콜이다.
    // (start / "upload, finalize" / query 등 모든 단계가 이 헤더를 단다)
    return !getHeaderValue(ctx.headers, "X-Goog-Upload-Command").empty();
}

HandlerResult ResumableHandler::handle(const RequestContext& ctx, CorrelationStore& store) {
    const std::string cmd = getHeaderValue(ctx.headers, "X-Goog-Upload-Command");

    // ── start: 메타데이터만 (파일명) ──────────────────────────────
    // 본문 형식은 실측으로 확정: "File name: " + UTF-8 파일명. JSON 아니고,
    // 후행 개행 없음(A: 파일명 25 B + 접두어 11 B = bodylen 36).
    if (cmd.find("start") != std::string::npos) {
        static const std::string kPrefix = "File name: ";
        const std::string& b = ctx.body;
        if (b.size() < kPrefix.size() || b.compare(0, kPrefix.size(), kPrefix) != 0) {
            // start인데 형식이 다르면 우리가 아는 규격이 아니다 → 넘긴다.
            return HandlerResult::ignored();
        }
        PendingUpload p;
        p.filename    = b.substr(kPrefix.size());
        p.declaredSize = -1;                 // start 본문엔 크기가 없다 → 순서 기반 상관
        p.endpoint    = ctx.host + ctx.path;
        store.put("gemini", std::move(p));
        return HandlerResult::pending();
    }

    // ── finalize: 본문 전체가 파일 ────────────────────────────────
    // "upload, finalize"처럼 finalize를 포함한다. (중간 "upload"만 있는 청크는
    // 대상 파일이 작아 한 번에 끝나므로 실측에선 관측되지 않았지만, finalize를
    // 포함하는지로 완결 요청만 집는다)
    if (cmd.find("finalize") != std::string::npos) {
        UploadRecord rec;
        rec.service  = "gemini";
        rec.endpoint = ctx.host + ctx.path;

        PendingUpload p;
        if (store.take("gemini", -1, p)) {   // 크기를 모르므로 순서 기반 폴백
            rec.filename = p.filename;
        }
        // start를 못 봤어도(순서 어긋남·프록시 늦게 붙음) 내용은 살린다.
        // 파일명이 비면 공통 후처리가 확장자 없이 저장하되 본문은 보존된다.

        // Gemini의 Content-Type은 application/x-www-form-urlencoded 고정값이라
        // 파일과 무관하다 → 비워 두고 타입 판정을 확장자 폴백에 맡긴다.
        rec.declaredType = "";
        // finalize 본문은 래핑 0바이트라 Content-Length가 곧 파일 크기다(실측 확정).
        rec.declaredSize = ctx.declaredLen;
        rec.requestLen   = ctx.declaredLen;
        rec.content      = ctx.body;
        rec.truncated    = (ctx.declaredLen >= 0 &&
                            ctx.body.size() < static_cast<size_t>(ctx.declaredLen));
        return HandlerResult::complete(std::move(rec));
    }

    // query 등 제어 요청은 파일이 아니다 → 다른 핸들러에게 넘긴다.
    return HandlerResult::ignored();
}

} // namespace v2
} // namespace proxy
