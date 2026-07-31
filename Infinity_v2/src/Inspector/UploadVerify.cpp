#include "Inspector/UploadVerify.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace proxy {
namespace v2 {

const char* magicResultName(MagicResult r) {
    switch (r) {
        case MagicResult::Ok:       return "OK";
        case MagicResult::Mismatch: return "MISMATCH";
        default:                    return "UNKNOWN";
    }
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// MIME이 "파일 타입"을 담고 있는가.
// 아래 값들은 전송 규격이나 "알 수 없는 바이트열"을 뜻할 뿐 타입 정보가 아니다.
static bool mimeCarriesType(const std::string& lowerMime) {
    if (lowerMime.empty()) return false;
    if (lowerMime.find("x-www-form-urlencoded") != std::string::npos) return false;  // Gemini
    if (lowerMime.find("octet-stream") != std::string::npos)          return false;
    if (lowerMime.find("application/binary") != std::string::npos)    return false;
    return true;
}

static std::string extensionOf(const std::string& filename) {
    size_t dot = filename.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= filename.size()) return "";
    return toLower(filename.substr(dot + 1));
}

static std::string extensionToMime(const std::string& ext) {
    if (ext == "pdf")                    return "application/pdf";
    if (ext == "png")                    return "image/png";
    if (ext == "jpg" || ext == "jpeg")   return "image/jpeg";
    if (ext == "gif")                    return "image/gif";
    if (ext == "zip")                    return "application/zip";
    if (ext == "docx" || ext == "xlsx" || ext == "pptx")
        return "application/zip";        // OOXML은 실체가 ZIP(PK)이다
    return "";
}

const char* typeSourceName(TypeSource s) {
    switch (s) {
        case TypeSource::Declared:  return "declared";
        case TypeSource::Extension: return "from-ext";
        default:                    return "unknown";
    }
}

std::string resolveExpectedType(const std::string& declaredMime, const std::string& filename,
                                TypeSource* source) {
    std::string lower = toLower(declaredMime);
    // "application/pdf; charset=..." 같은 파라미터 제거
    size_t semi = lower.find(';');
    if (semi != std::string::npos) lower = lower.substr(0, semi);
    while (!lower.empty() && (lower.back() == ' ' || lower.back() == '\t')) lower.pop_back();

    if (mimeCarriesType(lower)) {
        if (source) *source = TypeSource::Declared;
        // OOXML(docx/xlsx/pptx)의 declared MIME은 이 접두어로 시작하고 실체는 ZIP이다.
        // verifyMagicNumber는 정확한 문자열 일치만 보므로, 정규화 없이는 claude.ai/ChatGPT
        // 실측에서 항상 magic=UNKNOWN이 나왔다(test_results/*/file_D.md, file_E.md).
        if (lower.rfind("application/vnd.openxmlformats-officedocument.", 0) == 0)
            return "application/zip";
        return lower;
    }

    std::string byExt = extensionToMime(extensionOf(filename));
    if (source) *source = byExt.empty() ? TypeSource::None : TypeSource::Extension;
    return byExt;
}

MagicResult verifyMagicNumber(const std::string& data, const std::string& expectedMime) {
    if (expectedMime.empty()) return MagicResult::Unknown;
    if (data.size() < 8)      return MagicResult::Unknown;

    const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());

    if (expectedMime == "application/pdf")
        return data.compare(0, 5, "%PDF-") == 0 ? MagicResult::Ok : MagicResult::Mismatch;

    if (expectedMime == "image/png")
        return (p[0] == 0x89 && data.compare(1, 3, "PNG") == 0)
                   ? MagicResult::Ok : MagicResult::Mismatch;

    if (expectedMime == "image/jpeg")
        return (p[0] == 0xFF && p[1] == 0xD8) ? MagicResult::Ok : MagicResult::Mismatch;

    if (expectedMime == "image/gif")
        return data.compare(0, 3, "GIF") == 0 ? MagicResult::Ok : MagicResult::Mismatch;

    // ZIP 계열 (docx/xlsx/pptx 포함). 빈 아카이브 변형도 허용한다.
    if (expectedMime == "application/zip")
        return (p[0] == 'P' && p[1] == 'K' &&
                (p[2] == 0x03 || p[2] == 0x05 || p[2] == 0x07))
                   ? MagicResult::Ok : MagicResult::Mismatch;

    return MagicResult::Unknown;
}

std::string calculateHash(const std::string& data) {
    unsigned long long hash = 5381;
    for (char c : data) hash = ((hash << 5) + hash) + c;
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

std::string sanitizeFilename(const std::string& raw) {
    size_t slash = raw.find_last_of("/\\");                 // 디렉터리 성분 제거 → basename
    std::string name = (slash == std::string::npos) ? raw : raw.substr(slash + 1);
    std::string safe;
    for (char c : name) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20) continue;                            // 제어문자
        if (c == '/' || c == '\\' || c == ':') continue;    // 잔여 경로/드라이브 구분자
        safe.push_back(c);
    }
    if (safe.empty() || safe == "." || safe == "..") safe = "unnamed_upload";
    return safe;
}

} // namespace v2
} // namespace proxy
