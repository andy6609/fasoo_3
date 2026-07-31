#include "Inspector/Handlers/MultipartHandler.h"
#include "Inspector/HeaderUtil.h"

namespace proxy {
namespace v2 {

bool MultipartHandler::matches(const RequestContext& ctx) const {
    std::string ct = getHeaderValue(ctx.headers, "Content-Type");
    return ct.find("multipart/form-data") != std::string::npos;
}

HandlerResult MultipartHandler::handle(const RequestContext& ctx, CorrelationStore&) {
    std::string ct = getHeaderValue(ctx.headers, "Content-Type");

    size_t bp = ct.find("boundary=");
    if (bp == std::string::npos) return HandlerResult::ignored();

    std::string boundary = ct.substr(bp + 9);
    if (!boundary.empty() && boundary.front() == '"') boundary.erase(0, 1);
    size_t cut = boundary.find_first_of(";, ");
    if (cut != std::string::npos) boundary = boundary.substr(0, cut);
    if (!boundary.empty() && boundary.back() == '"') boundary.pop_back();
    if (boundary.empty()) return HandlerResult::ignored();

    const std::string& body = ctx.body;
    const std::string full = "--" + boundary;

    // 본문이 업로드 캡처 상한에 걸려 잘렸는가.
    // 잘렸다면 마지막 파트의 닫는 boundary가 캡처 범위 밖으로 밀려나 존재하지 않는다.
    const bool bodyTruncated =
        (ctx.declaredLen >= 0 && static_cast<unsigned long long>(ctx.declaredLen) > body.size());

    size_t pos = body.find(full);
    while (pos != std::string::npos) {
        size_t nextPos = body.find(full, pos + full.length());

        // 닫는 boundary가 없는 경우는 둘이다.
        //  (1) 본문이 온전함 → 여기가 정상 종료 지점(마지막 "--boundary--" 뒤)
        //  (2) 본문이 절단됨 → 마지막 파트가 통째로 남아 있다. 버리면 파일명조차
        //      기록되지 않아 탐지가 완전히 누락된다(v1의 256KB 문제).
        const bool tailPart = (nextPos == std::string::npos);
        if (tailPart && !bodyTruncated) break;

        size_t partStart = pos + full.length();
        if (partStart + 2 <= body.length() && body.compare(partStart, 2, "\r\n") == 0)
            partStart += 2;

        size_t partEnd;
        if (tailPart) {
            partEnd = body.length();          // 절단본: 남은 전부가 파일 내용의 앞부분
        } else {
            partEnd = nextPos;
            if (partEnd >= 2 && body.compare(partEnd - 2, 2, "\r\n") == 0) partEnd -= 2;
        }
        if (partStart >= partEnd) break;

        std::string part = body.substr(partStart, partEnd - partStart);

        size_t headerEnd = part.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string partHeaders = part.substr(0, headerEnd) + "\r\n";
            std::string partBody    = part.substr(headerEnd + 4);

            std::string disp = getHeaderValue(partHeaders, "Content-Disposition");
            size_t fp = disp.find("filename=\"");
            if (fp != std::string::npos) {
                size_t fe = disp.find('"', fp + 10);
                if (fe != std::string::npos) {
                    UploadRecord rec;
                    rec.service      = (ctx.host.find("claude") != std::string::npos)
                                           ? "claude" : "generic";
                    rec.endpoint     = ctx.host + ctx.path;
                    rec.filename     = disp.substr(fp + 10, fe - (fp + 10));
                    rec.declaredType = getHeaderValue(partHeaders, "Content-Type");
                    // multipart는 파일 크기를 알려주지 않는다. Content-Length는
                    // boundary·파트 헤더를 포함한 래퍼 전체 크기라 파일 크기가 아니다.
                    rec.declaredSize = -1;
                    rec.requestLen   = ctx.declaredLen;   // 로깅 맥락용
                    rec.content      = partBody;
                    // 절단 여부는 여기서 판정한다. 요청 전체가 캡처 상한에 걸렸고
                    // 지금 파트가 닫는 boundary 없이 끝났다면 그 파트가 잘린 것이다.
                    rec.truncated    = tailPart;
                    return HandlerResult::complete(std::move(rec));
                }
            }
        }

        if (tailPart) break;
        pos = nextPos;
    }

    // multipart이긴 한데 파일 파트가 없었다 (순수 폼 필드 등).
    // Ignored를 반환해 다른 핸들러에게 기회를 넘긴다.
    return HandlerResult::ignored();
}

} // namespace v2
} // namespace proxy
