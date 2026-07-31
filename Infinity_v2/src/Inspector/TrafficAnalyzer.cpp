#include "Inspector/TrafficAnalyzer.h"
#include "Inspector/UploadRouter.h"
#include "Inspector/HeaderUtil.h"
#include "Core/Logger.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <exception>
#include <zlib.h>
#include <brotli/decode.h>

namespace proxy {

// 저장 파일명 유니크화용 시퀀스 (동시 업로드가 같은 파일명에 겹쳐써서 깨지던 문제 방지)
static std::atomic<unsigned> g_captureSeq{ 0 };

// ============================================================
//  Content-Encoding 실해제 (gzip/deflate=zlib, br=brotli)
//  캡처 상한으로 스트림이 잘려도 여기까지 풀린 평문은 유효하다.
// ============================================================
static bool inflateGzipOrZlib(const std::string& in, std::string& out) {
    if (in.empty()) return false;
    z_stream zs{};
    // windowBits = 15+32 → gzip(1f 8b)과 zlib(78 xx) 헤더를 자동 감지
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return false;
    zs.next_in = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();
    char buf[16384];
    int ret;
    do {
        zs.next_out = (Bytef*)buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) { inflateEnd(&zs); return !out.empty(); }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (zs.avail_out == 0 && ret != Z_STREAM_END);
    inflateEnd(&zs);
    return !out.empty();
}
static bool brotliDecompress(const std::string& in, std::string& out) {
    if (in.empty()) return false;
    BrotliDecoderState* st = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!st) return false;
    const uint8_t* next_in = (const uint8_t*)in.data();
    size_t avail_in = in.size();
    char buf[16384];
    BrotliDecoderResult r;
    do {
        uint8_t* next_out = (uint8_t*)buf;
        size_t avail_out = sizeof(buf);
        r = BrotliDecoderDecompressStream(st, &avail_in, &next_in, &avail_out, &next_out, nullptr);
        out.append(buf, sizeof(buf) - avail_out);
    } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
    BrotliDecoderDestroyInstance(st);
    return !out.empty();
}
// Content-Encoding 값에 따라 해제. 실패/미지원이면 빈 문자열.
static std::string decodeBody(const std::string& encoding, const std::string& in) {
    std::string enc = encoding;
    std::transform(enc.begin(), enc.end(), enc.begin(), ::tolower);
    std::string out;
    if (enc.find("br") != std::string::npos) { if (brotliDecompress(in, out)) return out; }
    else if (enc.find("gzip") != std::string::npos || enc.find("deflate") != std::string::npos) {
        if (inflateGzipOrZlib(in, out)) return out;
    }
    return "";
}

// 업로드 파일명을 안전한 basename 으로 정규화 (경로 탈출 "../", 드라이브(:), 제어문자 차단).
// 유니코드(한글 등 >=0x80 바이트)는 보존한다.
static std::string sanitizeFilename(const std::string& raw) {
    size_t slash = raw.find_last_of("/\\");                 // 디렉터리 성분 제거 → basename
    std::string name = (slash == std::string::npos) ? raw : raw.substr(slash + 1);
    std::string safe;
    for (char c : name) {
        unsigned char uc = (unsigned char)c;
        if (uc < 0x20) continue;                            // 제어문자
        if (c == '/' || c == '\\' || c == ':') continue;    // 잔여 경로/드라이브 구분자
        safe.push_back(c);
    }
    if (safe.empty() || safe == "." || safe == "..") safe = "unnamed_upload";
    return safe;
}

std::string TrafficAnalyzer::getHeaderValue(const std::string& headers, const std::string& key) {
    std::string lowerHeaders = headers;
    std::transform(lowerHeaders.begin(), lowerHeaders.end(), lowerHeaders.begin(), ::tolower);
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    
    size_t pos = lowerHeaders.find(lowerKey + ":");
    if (pos == std::string::npos) return "";
    pos += key.length() + 1;
    while (pos < headers.length() && (headers[pos] == ' ' || headers[pos] == '\t')) pos++;
    
    size_t endPos = headers.find("\r\n", pos);
    if (endPos == std::string::npos) endPos = headers.length();
    
    return headers.substr(pos, endPos - pos);
}

// 헤더 값 문자열을 안전하게 정수로 읽는다 (비었거나 비정상이면 -1).
// std::stoll은 비정상 입력에 예외를 던져 스레드를 죽이므로 쓰지 않는다.
static long long parseLenValue(const std::string& v) {
    if (v.empty()) return -1;
    long long n = 0;
    for (char c : v) {
        if (c == ' ' || c == '\t') continue;
        if (c < '0' || c > '9') return -1;
        if (n > (9223372036854775807LL - (c - '0')) / 10) return -1;  // 오버플로 방지
        n = n * 10 + (c - '0');
    }
    return n;
}

// [W8] 간단한 해시 함수 (데모 목적의 의사 SHA-256 또는 해시 합)
std::string TrafficAnalyzer::calculateHash(const std::string& data) {
    unsigned long long hash = 5381;
    for (char c : data) {
        hash = ((hash << 5) + hash) + c;
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

// [W9] 매직넘버 검증 로직
bool TrafficAnalyzer::verifyMagicNumber(const std::string& data, const std::string& mimeType) {
    if (data.size() < 8) return false;
    
    std::string lowerMime = mimeType;
    std::transform(lowerMime.begin(), lowerMime.end(), lowerMime.begin(), ::tolower);
    
    if (lowerMime == "application/pdf") {
        return data.substr(0, 5) == "%PDF-";
    } else if (lowerMime == "image/png") {
        return (unsigned char)data[0] == 0x89 && data.substr(1, 3) == "PNG";
    } else if (lowerMime == "image/jpeg" || lowerMime == "image/jpg") {
        return (unsigned char)data[0] == 0xFF && (unsigned char)data[1] == 0xD8;
    }
    // 기본적으로 알 수 없는 타입은 경고 없이 넘어감
    return true; 
}

void TrafficAnalyzer::analyzeRequest(const std::string& method, 
                                     const std::string& url, 
                                     const std::string& headers, 
                                     const std::string& body) {
    if (method != "POST" && method != "PUT" && method != "PATCH") return;

    std::string host = getHeaderValue(headers, "Host");
    std::string contentType = getHeaderValue(headers, "Content-Type");

    // [Observe] 업로드성 요청(POST/PUT/PATCH)을 전부 남긴다 — multipart가 아닌 방식
    // (구글 resumable, JSON+base64 등)까지 보이게 해서 서비스별 업로드 지문을 조사한다.
    std::string up1 = getHeaderValue(headers, "X-Goog-Upload-Protocol");
    std::string up2 = getHeaderValue(headers, "X-Goog-Upload-Command");
    std::string extra;
    if (!up1.empty()) extra += "  X-Goog-Upload-Protocol=" + up1;
    if (!up2.empty()) extra += "  X-Goog-Upload-Command=" + up2;
    std::string head;
    if (!body.empty()) {
        head = body.substr(0, 48);
        for (char& c : head) if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7f) c = '.';
    }
    Logger::info("[Observe] " + method + " " + host + url + "  ct=[" + contentType + "]  bodylen=" +
                 std::to_string(body.size()) + extra + (head.empty() ? "" : ("  head=" + head)));

    // [v2] 업로드 처리는 UploadRouter로 넘긴다.
    //
    // v1의 routeToParser는 host/url 부분 문자열로 판별해 오탐이 났고
    // (ChatGPT 캡처에서 오탐 9 / 미탐 3 / 추출 0), 스텁이 return으로 요청을
    // 삼켜 범용 파서를 막았다. v2는 구조적 신호로 판별하고, 처리 못 한
    // 핸들러는 Ignored를 반환해 다음 핸들러에게 기회를 넘긴다.
    //
    // contentType이 비어 있어도 라우팅한다 — ChatGPT의 Azure PUT처럼
    // Content-Type만으로는 판별되지 않는 규격이 있기 때문이다.
    v2::RequestContext ctx;
    ctx.method = method;
    ctx.host   = host;
    size_t q   = url.find('?');
    ctx.path   = (q == std::string::npos) ? url : url.substr(0, q);
    ctx.query  = (q == std::string::npos) ? ""  : url.substr(q + 1);
    ctx.headers     = headers;
    ctx.body        = body;
    ctx.declaredLen = v2::parseLenValue(getHeaderValue(headers, "Content-Length"));

    v2::UploadRouter::instance().route(ctx);
}

void TrafficAnalyzer::routeToParser(const std::string& host, const std::string& url, const std::string& contentType, const std::string& headers, const std::string& body) {
    
    // AI 서비스 전용 핑거프린트 확인
    if (host.find("chatgpt.com") != std::string::npos && url.find("/backend-api/files") != std::string::npos) {
        Logger::info("[Router] 업로드(ChatGPT 전용) 엔드포인트: " + host + url);
        parseChatGPTUpload(body, contentType);
        return;
    }
    
    // 기본 멀티파트 파서로 라우팅
    if (contentType.find("multipart/form-data") != std::string::npos) {
        size_t boundaryPos = contentType.find("boundary=");
        if (boundaryPos != std::string::npos) {
            std::string boundary = contentType.substr(boundaryPos + 9);
            if (!boundary.empty() && boundary.front() == '"') boundary.erase(0, 1);
            if (!boundary.empty() && boundary.back() == '"') boundary.pop_back();
            
            Logger::info("[Router] 업로드(표준 multipart) 엔드포인트: " + host + url);
            // 요청이 선언한 Content-Length를 함께 넘긴다. 분석기가 받는 body는 업로드 캡처
            // 상한(256KB)에 걸려 잘렸을 수 있는데, 이 둘을 비교해야 절단 여부를 알 수 있다.
            parseStandardMultipart(body, boundary, parseLenValue(getHeaderValue(headers, "Content-Length")));
        }
    }
}

void TrafficAnalyzer::parseChatGPTUpload(const std::string& body, const std::string& contentType) {
    Logger::info("[Parser] ChatGPT 파일 파싱은 아직 미구현입니다. 추가 트래픽 캡처 후 적용 예정");
}

void TrafficAnalyzer::parseStandardMultipart(const std::string& body, const std::string& boundary,
                                             long long declaredLen) {
    std::string fullBoundary = "--" + boundary;
    size_t pos = body.find(fullBoundary);

    std::error_code ec;
    std::filesystem::create_directories("captured_files", ec);

    // 업로드 캡처 상한(Http1Engine/Http2Engine의 256KB)에 걸려 본문이 잘렸는가.
    // 잘렸다면 마지막 파트의 닫는 boundary가 캡처 범위 밖으로 밀려나 존재하지 않는다.
    const bool bodyTruncated = (declaredLen >= 0 && (unsigned long long)declaredLen > body.size());
    if (bodyTruncated) {
        Logger::warn("[Parser] 업로드 본문이 캡처 상한에 걸려 절단됨 — 캡처 " +
                     std::to_string(body.size()) + " bytes / 요청 선언 " +
                     std::to_string(declaredLen) + " bytes. 메타데이터만 복구를 시도한다.");
    }

    while (pos != std::string::npos) {
        size_t nextPos = body.find(fullBoundary, pos + fullBoundary.length());

        // 닫는 boundary가 없는 경우는 두 가지다.
        //  (1) 본문이 온전함  → 여기가 정상 종료 지점(마지막 "--boundary--" 뒤). 그대로 종료.
        //  (2) 본문이 절단됨  → 마지막 파트가 통째로 남아 있다. 예전에는 이걸 break로 버려서
        //      256KB 초과 업로드가 파일명조차 남기지 못하고 탐지가 완전히 누락됐다.
        //      이제는 "절단된 파트"로 처리해 헤더(파일명/타입)와 선두 매직바이트는 살린다.
        const bool tailPart = (nextPos == std::string::npos);
        if (tailPart && !bodyTruncated) break;

        size_t partStart = pos + fullBoundary.length();
        if (partStart + 2 <= body.length() && body.compare(partStart, 2, "\r\n") == 0) {
            partStart += 2;
        }

        size_t partEnd;
        if (tailPart) {
            partEnd = body.length();          // 절단본: 남은 전부가 파일 내용의 앞부분
        } else {
            partEnd = nextPos;
            if (partEnd >= 2 && body.compare(partEnd - 2, 2, "\r\n") == 0) {
                partEnd -= 2;
            }
        }
        if (partStart >= partEnd) break;

        std::string part = body.substr(partStart, partEnd - partStart);

        size_t headerEnd = part.find("\r\n\r\n");
        if (headerEnd == std::string::npos && tailPart) {
            // 헤더 도중에 잘린 경우 — 파일명조차 복구할 수 없다 (상한이 극단적으로 작을 때)
            Logger::warn("[Parser] 절단된 파트의 헤더가 불완전해 메타데이터를 복구하지 못했다.");
        }
        if (headerEnd != std::string::npos) {
            std::string partHeaders = part.substr(0, headerEnd) + "\r\n";
            std::string partBody = part.substr(headerEnd + 4);

            std::string disp = getHeaderValue(partHeaders, "Content-Disposition");
            std::string mime = getHeaderValue(partHeaders, "Content-Type");
            size_t filenamePos = disp.find("filename=\"");
            
            if (filenamePos != std::string::npos) {
                size_t filenameEnd = disp.find("\"", filenamePos + 10);
                if (filenameEnd != std::string::npos) {
                    std::string filename = disp.substr(filenamePos + 10, filenameEnd - (filenamePos + 10));
                    if (tailPart) {
                        // 절단본: 실제 파일 크기는 알 수 없다. 캡처량과 요청 전체 크기를 함께 남겨
                        // "무엇이, 어디로, 대략 얼마나" 나갔는지는 추적 가능하게 한다.
                        Logger::warn("[Parser] 파일명: " + filename + " — 본문 절단됨(캡처 상한 초과). "
                                     "캡처 " + std::to_string(partBody.size()) + " bytes. 실제 파일 크기 불명");
                    } else {
                        Logger::info("[Parser] 파일명: " + filename + ", 크기: " + std::to_string(partBody.size()) + " bytes 추출 완료");
                    }

                    // [W9] 매직넘버 검증 — 매직바이트는 본문 선두에 있으므로 절단본에서도 유효하다
                    if (!mime.empty()) {
                        bool magicOk = verifyMagicNumber(partBody, mime);
                        if (magicOk) {
                            Logger::info("[Verifier] 매직넘버 일치 확인 (" + mime + ")");
                        } else {
                            Logger::warn("[Verifier] 경고! MIME 타입과 실제 매직넘버 불일치 의심 (" + mime + ")");
                        }
                    }

                    // [W8] 해시 검증 — 절단본의 해시는 원본과 비교할 수 없다.
                    // 파일 해시인 것처럼 남기면 대조 시 거짓 불일치로 오독되므로 계산하지 않는다.
                    if (tailPart) {
                        Logger::warn("[Verifier] 해시 생략 — 절단본이라 원본과 비교 불가");
                    } else {
                        std::string fileHash = calculateHash(partBody);
                        Logger::info("[Verifier] 추출된 파일 해시: " + fileHash + " (원본과 비교 요망)");
                    }

                    std::string safeName = sanitizeFilename(filename);
                    if (safeName != filename)
                        Logger::warn("[Parser] 파일명 경로 안전화: \"" + filename + "\" -> \"" + safeName + "\"");
                    // 캡처마다 유니크 접두어(순번) → 동시 업로드(예: claude.ai upload-file +
                    // convert_document)가 같은 파일명에 겹쳐써서 저장본이 깨지던 레이스 제거.
                    // 절단본은 PARTIAL_ 접두어로 구분 — 온전한 추출본과 섞이면 대조 검증이 오염된다.
                    unsigned seq = ++g_captureSeq;
                    std::string filepath = "captured_files/" + std::to_string(seq) +
                                           (tailPart ? "_PARTIAL_" : "_") + safeName;
                    // UTF-8 파일명(한글 등)을 u8path로 열어 Windows narrow-경로 저장 실패를 막는다.
                    //
                    // 단, u8path는 인자가 유효한 UTF-8이 아니면 예외를 던진다. 클라이언트가 보내는
                    // Content-Disposition의 filename은 신뢰할 수 없는 입력이고(예: curl이
                    // 로컬 ANSI 코드페이지로 보낸 한글 파일명) 실제로 여기서 예외가 터져
                    // 스레드가 죽고 프로세스 전체가 종료되는 것을 관측했다.
                    // 탐지 시스템이 죽으면 이후 트래픽이 통째로 무감시 통과(fail-open)하므로,
                    // 저장 실패는 반드시 이 요청 하나의 실패로 국한시킨다.
                    bool saved = false;
                    try {
                        std::ofstream ofs(std::filesystem::u8path(filepath), std::ios::binary);
                        if (ofs) {
                            ofs.write(partBody.data(), partBody.size());
                            ofs.close();
                            saved = true;
                            Logger::info(std::string("[Parser] 파일 저장 완료") +
                                         (tailPart ? "(절단본)" : "") + ": " + filepath);
                        }
                    } catch (const std::exception& e) {
                        Logger::warn(std::string("[Parser] 유니코드 경로 저장 실패(") + e.what() +
                                     ") — ASCII 대체 파일명으로 재시도한다.");
                    }

                    if (!saved) {
                        // 파일명이 어떤 인코딩이든 저장 자체는 성공해야 한다. 탐지 기록을 잃는 것이
                        // 파일명을 잃는 것보다 나쁘므로, 이름을 포기하고 내용을 남긴다.
                        std::string fallback = "captured_files/" + std::to_string(seq) +
                                               (tailPart ? "_PARTIAL_" : "_") + "unnamed.bin";
                        std::ofstream ofs2(fallback, std::ios::binary);
                        if (ofs2) {
                            ofs2.write(partBody.data(), partBody.size());
                            ofs2.close();
                            Logger::warn("[Parser] 파일 저장 완료(대체 이름): " + fallback +
                                         "  원래 파일명(비-UTF-8 가능성): " + filename);
                        } else {
                            Logger::error("[Parser] 파일 저장 실패: " + filepath);
                        }
                    }
                }
            }
        }
        pos = nextPos;
    }
}

void TrafficAnalyzer::analyzeResponse(int statusCode,
                                      const std::string& headers,
                                      const std::string& body) {
    std::string encoding = getHeaderValue(headers, "Content-Encoding");
    if (encoding.empty() || encoding == "identity" || body.empty()) return;

    // [9번] Content-Encoding 실해제 — 응답 본문을 우리도 평문으로 읽는다
    std::string decoded = decodeBody(encoding, body);
    if (!decoded.empty()) {
        Logger::info("[Decode] Content-Encoding=" + encoding + ": " +
                     std::to_string(body.size()) + "B(compressed) -> " +
                     std::to_string(decoded.size()) + "B(plain)");
    } else {
        Logger::warn("[Decode] 해제 실패/미지원: " + encoding +
                     " (" + std::to_string(body.size()) + "B; 캡처가 잘렸을 수 있음)");
    }
}

} // namespace proxy
