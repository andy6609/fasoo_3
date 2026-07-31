#ifndef PROXY_V2_UPLOAD_TYPES_H
#define PROXY_V2_UPLOAD_TYPES_H

#include <string>

namespace proxy {
namespace v2 {

// 라우터가 핸들러에 넘기는 요청 컨텍스트. 핸들러는 이것만 본다.
// (host/path/query를 미리 분해해 두어, 핸들러가 URL 문자열을 다시 파싱하지 않게 한다)
struct RequestContext {
    std::string method;       // "POST" | "PUT" | "PATCH"
    std::string host;         // "chatgpt.com"
    std::string path;         // "/backend-api/files"  (쿼리 제외)
    std::string query;        // "upload_id=...&upload_protocol=resumable"
    std::string headers;      // 원본 헤더 블록
    std::string body;         // 캡처된 본문 (업로드 캡처 상한에 걸려 잘렸을 수 있음)
    long long   declaredLen;  // 요청 Content-Length. 없으면 -1
};

// 전송 규격이 무엇이든 모든 핸들러가 채우는 공통 결과.
// 검증·해시·저장은 이 타입만 보고 동작하므로 규격을 알 필요가 없다.
struct UploadRecord {
    std::string service;      // "claude" | "gemini" | "chatgpt" | "generic"
    std::string handler;      // 어느 핸들러가 만들었는지 (로깅용)
    std::string endpoint;     // host + path (증거용)
    std::string filename;
    std::string declaredType; // 클라이언트가 주장한 MIME. 신뢰할 수 없으면 빈 값

    // 실제 "파일" 크기를 알 때만 채운다. 모르면 -1.
    //
    // 주의: 요청의 Content-Length를 그대로 넣으면 안 된다. multipart는
    // Content-Length가 boundary·파트 헤더까지 포함한 래퍼 전체 크기여서
    // 파일 크기보다 항상 크고, 그것을 파일 크기로 오인하면 절단되지 않은
    // 업로드까지 절단으로 판정된다.
    //   - multipart : 알 수 없음 → -1
    //   - Gemini    : finalize 본문이 곧 파일이므로 Content-Length가 파일 크기
    //   - ChatGPT   : 메타 요청의 file_size가 진짜 파일 크기
    long long   declaredSize;

    // 요청 Content-Length. 로깅 맥락용이며 절단 판정에는 쓰지 않는다.
    long long   requestLen;

    std::string content;      // 파일 본문
    bool        truncated;    // 캡처 상한에 걸렸는가 (핸들러가 판정해 채운다)

    UploadRecord() : declaredSize(-1), requestLen(-1), truncated(false) {}
};

// 핸들러가 요청을 어떻게 처리했는지.
//
// Ignored 가 이 설계의 핵심이다. v1에서는 ChatGPT 전용 분기가 스텁이면서도
// return 으로 요청을 삼켜, 표준 multipart 파서가 처리할 수 있었던 업로드까지
// 놓쳤다. v2에서는 처리하지 못하면 반드시 Ignored 를 반환해야 하고,
// 라우터는 그때 다음 핸들러에게 기회를 넘긴다.
enum class Disposition {
    Ignored,    // 내 것이 아님 → 라우터가 다음 핸들러로
    Pending,    // 메타데이터만 확보. 후행 본문 요청을 기다림
    Complete    // 파일 확보. 검증·저장 파이프로
};

struct HandlerResult {
    Disposition  disposition;
    UploadRecord record;      // Complete 일 때만 유효

    HandlerResult() : disposition(Disposition::Ignored) {}
    static HandlerResult ignored() { return HandlerResult(); }
    static HandlerResult pending() {
        HandlerResult r; r.disposition = Disposition::Pending; return r;
    }
    static HandlerResult complete(UploadRecord rec) {
        HandlerResult r; r.disposition = Disposition::Complete; r.record = std::move(rec); return r;
    }
};

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_UPLOAD_TYPES_H
