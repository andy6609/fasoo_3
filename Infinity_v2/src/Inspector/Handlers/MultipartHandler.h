#ifndef PROXY_V2_MULTIPART_HANDLER_H
#define PROXY_V2_MULTIPART_HANDLER_H

#include "Inspector/UploadRouter.h"

namespace proxy {
namespace v2 {

// 표준 multipart/form-data 처리.
//
// 판별 신호는 Content-Type 하나뿐이고 **호스트를 보지 않는다.**
// 그래서 아직 조사하지 않은 서비스라도 표준 multipart를 쓰면 자동으로 잡히고,
// service가 "generic"으로 찍혀 새 서비스를 발견했다는 신호가 된다.
class MultipartHandler : public IUploadHandler {
public:
    const char* name() const override { return "Multipart"; }
    bool matches(const RequestContext& ctx) const override;
    HandlerResult handle(const RequestContext& ctx, CorrelationStore& store) override;
};

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_MULTIPART_HANDLER_H
