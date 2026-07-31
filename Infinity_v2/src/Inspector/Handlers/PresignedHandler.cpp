#include "Inspector/Handlers/PresignedHandler.h"
#include "Inspector/HeaderUtil.h"

#include <cctype>

namespace proxy {
namespace v2 {

namespace {

// host가 suffix로 끝나는가. 스토리지 호스트가 세션 중 바뀌므로 접미사로만 판별한다.
bool hostEndsWith(const std::string& host, const std::string& suffix) {
    return host.size() >= suffix.size() &&
           host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// 메타 JSON은 작고(≈420 B) 절단되지 않으므로 정식 파서 없이 필드만 뽑는다.
// "key" 뒤 첫 따옴표 문자열 값을 반환한다. 못 찾으면 빈 문자열.
std::string jsonString(const std::string& body, const std::string& key) {
    const std::string k = "\"" + key + "\"";
    size_t kp = body.find(k);
    if (kp == std::string::npos) return "";
    size_t colon = body.find(':', kp + k.size());
    if (colon == std::string::npos) return "";
    size_t q1 = body.find('"', colon + 1);
    if (q1 == std::string::npos) return "";
    // 이스케이프된 따옴표는 파일명에 사실상 없으므로 단순 종료 따옴표를 찾는다.
    size_t q2 = body.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return body.substr(q1 + 1, q2 - q1 - 1);
}

// "key": 12345 형태의 정수 값. 못 찾으면 -1.
long long jsonNumber(const std::string& body, const std::string& key) {
    const std::string k = "\"" + key + "\"";
    size_t kp = body.find(k);
    if (kp == std::string::npos) return -1;
    size_t colon = body.find(':', kp + k.size());
    if (colon == std::string::npos) return -1;
    size_t i = colon + 1;
    while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i]))) ++i;
    // 값이 정수(file_size:2084)인지 문자열(file_size:"2084")인지 실측 미확인
    // (chatgpt-web-upload.md §3.5: 로그 head가 48 B에서 잘려 값 형식 미관측).
    // 둘 다 받아들인다 — 선행 따옴표는 건너뛴다. 형식이 또 다르면 -1로 떨어져
    // 순서 기반 상관으로 우아하게 강등된다.
    if (i < body.size() && body[i] == '"') ++i;
    size_t start = i;
    while (i < body.size() && std::isdigit(static_cast<unsigned char>(body[i]))) ++i;
    if (i == start) return -1;
    return parseLenValue(body.substr(start, i - start));
}

} // namespace

bool PresignedHandler::matches(const RequestContext& ctx) const {
    // (가) 파일 본문: 스토리지 호스트 접미사 + PUT
    if (ctx.method == "PUT" && hostEndsWith(ctx.host, "oaiusercontent.com"))
        return true;

    // (나) 메타데이터: chatgpt.com 의 /backend-api/files (완전 일치) + JSON
    //   부분 일치로 하면 /files/library, /files/process_upload_stream 등이
    //   오탐된다(v1 오탐 9건의 원인) → 반드시 완전 일치.
    if (ctx.host == "chatgpt.com" && ctx.path == "/backend-api/files") {
        std::string ct = getHeaderValue(ctx.headers, "Content-Type");
        if (ct.find("application/json") != std::string::npos) return true;
    }
    return false;
}

HandlerResult PresignedHandler::handle(const RequestContext& ctx, CorrelationStore& store) {
    // ── (나) 메타데이터 요청 ──────────────────────────────────────
    if (ctx.host == "chatgpt.com" && ctx.path == "/backend-api/files") {
        std::string filename = jsonString(ctx.body, "file_name");
        long long   fsize    = jsonNumber(ctx.body, "file_size");
        if (filename.empty()) return HandlerResult::ignored();  // 파일 생성 요청이 아님

        PendingUpload p;
        p.filename     = filename;
        p.declaredSize = fsize;              // 진짜 파일 크기 → 크기 매칭 가능(강한 상관)
        p.endpoint     = ctx.host + ctx.path;
        store.put("chatgpt", std::move(p));
        return HandlerResult::pending();
    }

    // ── (가) 파일 본문 요청 (PUT to *.oaiusercontent.com) ─────────
    UploadRecord rec;
    rec.service  = "chatgpt";
    rec.endpoint = ctx.host + ctx.path;

    PendingUpload p;
    // 크기 매칭 우선. 파일이 캡처 상한을 넘어 body가 잘리면 크기가 어긋나
    // 순서 기반 폴백으로 내려간다(take 내부에서 처리).
    long long declaredSize = -1;
    if (store.take("chatgpt", static_cast<long long>(ctx.body.size()), p)) {
        rec.filename = p.filename;
        declaredSize = p.declaredSize;       // 메타의 file_size(진짜 파일 크기)
    }

    // ChatGPT의 PUT Content-Type은 확장자에서 유도된 값이라 비교 대상으로 유효하다.
    rec.declaredType = getHeaderValue(ctx.headers, "Content-Type");
    rec.declaredSize = declaredSize;
    rec.requestLen   = ctx.declaredLen;
    rec.content      = ctx.body;
    rec.truncated    = (declaredSize >= 0 &&
                        ctx.body.size() < static_cast<size_t>(declaredSize));
    return HandlerResult::complete(std::move(rec));
}

} // namespace v2
} // namespace proxy
