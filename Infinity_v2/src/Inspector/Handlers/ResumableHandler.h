#ifndef PROXY_V2_RESUMABLE_HANDLER_H
#define PROXY_V2_RESUMABLE_HANDLER_H

#include "Inspector/UploadRouter.h"

namespace proxy {
namespace v2 {

// Google resumable 업로드 처리 (Gemini).
//
// 파일명과 파일 내용이 서로 다른 HTTP 요청에 나뉘어 온다.
//   start    → 본문 "File name: <파일명>"  (파일명만, 오버헤드 11 B)
//   finalize → 본문 전체가 파일           (내용만, 파일명 없음)
// 그래서 상태가 필요하다 — start를 CorrelationStore에 넣고 finalize에서 꺼낸다.
//
// 판별 신호는 X-Goog-Upload-Command 헤더 하나다(호스트를 보지 않는다).
// start 응답 헤더로 오는 upload_id를 아직 읽지 못하므로(Http2Engine이 응답을
// 분석기로 넘기지 않음) 상관은 순서 기반 — 동시 업로드에서 파일명이 뒤바뀔 수 있다.
class ResumableHandler : public IUploadHandler {
public:
    const char* name() const override { return "Resumable"; }
    bool matches(const RequestContext& ctx) const override;
    HandlerResult handle(const RequestContext& ctx, CorrelationStore& store) override;
};

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_RESUMABLE_HANDLER_H
