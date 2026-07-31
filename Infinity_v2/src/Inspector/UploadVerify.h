#ifndef PROXY_V2_UPLOAD_VERIFY_H
#define PROXY_V2_UPLOAD_VERIFY_H

#include <string>

namespace proxy {
namespace v2 {

enum class MagicResult {
    Ok,        // 기대 타입과 실제 매직바이트가 일치
    Mismatch,  // 불일치 — 확장자 위조 의심
    Unknown    // 기대 타입을 모르거나 검사 규칙이 없음
};

const char* magicResultName(MagicResult r);

// 기대 타입이 어디서 왔는가. 로그에 출처를 정확히 남기기 위해 필요하다.
// (선언된 MIME을 그대로 쓴 것과, 그것을 못 믿어 확장자로 유도한 것은 의미가 다르다)
enum class TypeSource {
    Declared,   // 클라이언트가 선언한 MIME을 그대로 사용
    Extension,  // 선언된 MIME이 타입 정보를 담지 않아 파일명 확장자에서 유도
    None        // 어느 쪽으로도 정하지 못함
};

const char* typeSourceName(TypeSource s);

// 기대 타입을 정한다.
//
// declaredMime이 실제로 "파일 타입"을 담고 있을 때만 그것을 쓰고,
// 아니면 파일명 확장자에서 유도한다.
//
// 폴백이 필요한 이유:
//   - Gemini는 Content-Type이 application/x-www-form-urlencoded 고정값이라
//     파일에 대해 아무것도 말해주지 않는다.
//   - claude.ai에서도 .go 파일이 application/octet-stream으로 와서
//     매직 검증이 무의미하게 통과한 적이 있다.
// 즉 이 폴백은 특정 서비스용이 아니라 전반적인 개선이다.
std::string resolveExpectedType(const std::string& declaredMime, const std::string& filename,
                                TypeSource* source = nullptr);

// 매직바이트 검증. 매직바이트는 본문 선두에 있으므로 절단본에서도 유효하다.
MagicResult verifyMagicNumber(const std::string& data, const std::string& expectedMime);

// djb2 계열 의사 해시 (데모용, SHA-256 아님)
std::string calculateHash(const std::string& data);

// 업로드 파일명을 안전한 basename으로 정규화
// (경로 탈출 "../", 드라이브 구분자, 제어문자 차단. 유니코드는 보존)
std::string sanitizeFilename(const std::string& raw);

} // namespace v2
} // namespace proxy

#endif // PROXY_V2_UPLOAD_VERIFY_H
