#ifndef PROXY_V2_PRESIGNED_HANDLER_H
#define PROXY_V2_PRESIGNED_HANDLER_H

#include "Inspector/UploadRouter.h"

namespace proxy {
namespace v2 {

// Presigned URL(클라우드 직송) 업로드 처리 (ChatGPT).
//
// 두 요청으로 나뉜다.
//   (나) 메타데이터  POST chatgpt.com/backend-api/files  JSON{file_name,file_size}
//   (가) 파일 본문   PUT  *.oaiusercontent.com/...       본문 전체가 파일(래핑 0 B)
//
// 메타 요청에 진짜 파일 크기(file_size)가 있어 3사 중 유일하게 크기 기반 상관이
// 가능하다 → 동시 업로드에도 견딘다. 스토리지 호스트는 세션 중 바뀌므로
// (sdmntprwestus2 → sdmntprnznorth) 반드시 접미사 매칭한다.
class PresignedHandler : public IUploadHandler {
public:
    const char* name() const override { return "Presigned"; }
    bool matches(const RequestContext& ctx) const override;
    HandlerResult handle(const RequestContext& ctx, CorrelationStore& store) override;
};

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_PRESIGNED_HANDLER_H
