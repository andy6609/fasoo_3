#include "Inspector/UploadRouter.h"
#include "Inspector/UploadVerify.h"
#include "Core/Logger.h"

#include <atomic>
#include <exception>
#include <filesystem>
#include <fstream>

namespace proxy {
namespace v2 {

// 저장 파일명 유니크화용 시퀀스.
// 한 업로드가 여러 엔드포인트로 동시에 나갈 때 같은 파일명에 겹쳐써서
// 저장본이 깨지던 문제(v1 이슈3)를 막는다.
static std::atomic<unsigned> g_captureSeq(0);

// ─────────────────────────────────────────────────────────────
//  CorrelationStore
// ─────────────────────────────────────────────────────────────
void CorrelationStore::put(const std::string& service, PendingUpload p) {
    std::lock_guard<std::mutex> lk(mu_);
    expireLocked();
    auto& q = byService_[service];
    if (q.size() >= kMaxPerService) q.pop_front();
    p.ts = std::chrono::steady_clock::now();
    q.push_back(std::move(p));
}

bool CorrelationStore::take(const std::string& service, long long size, PendingUpload& out) {
    std::lock_guard<std::mutex> lk(mu_);
    expireLocked();
    auto it = byService_.find(service);
    if (it == byService_.end() || it->second.empty()) return false;
    auto& q = it->second;

    // 1) 크기 매칭 — 동시 업로드에도 견딘다 (ChatGPT: 메타 요청에 file_size가 있음)
    if (size >= 0) {
        for (auto i = q.begin(); i != q.end(); ++i) {
            if (i->declaredSize == size) {
                out = *i;
                q.erase(i);
                return true;
            }
        }
    }

    // 2) 순서 기반 폴백 — 크기를 모르거나(Gemini), 본문이 상한에 잘려
    //    크기가 실제와 달라진 경우(대용량 ChatGPT)
    out = q.front();
    q.pop_front();
    return true;
}

void CorrelationStore::expireLocked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto& kv : byService_) {
        auto& q = kv.second;
        while (!q.empty()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - q.front().ts).count();
            if (age < kTtlSeconds) break;
            Logger::warn("[Upload:expire] service=" + kv.first +
                         " file=\"" + q.front().filename + "\" — 본문 요청이 오지 않아 폐기");
            q.pop_front();
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  UploadRouter
// ─────────────────────────────────────────────────────────────
UploadRouter& UploadRouter::instance() {
    static UploadRouter r;
    return r;
}

void UploadRouter::registerHandler(std::unique_ptr<IUploadHandler> h) {
    handlers_.push_back(std::move(h));
}

void UploadRouter::route(const RequestContext& ctx) {
    for (auto& h : handlers_) {
        if (!h->matches(ctx)) continue;

        HandlerResult r = h->handle(ctx, store_);

        // 규격은 맞았지만 이 요청은 처리 대상이 아니었다 → 다음 핸들러에게 기회를 준다.
        // (v1에서 스텁이 return으로 요청을 삼켜 범용 파서를 막던 문제를 구조적으로 차단)
        if (r.disposition == Disposition::Ignored) continue;

        if (r.disposition == Disposition::Pending) {
            Logger::info(std::string("[Upload:pending] handler=") + h->name() +
                         " endpoint=" + ctx.host + ctx.path);
            return;
        }

        r.record.handler = h->name();
        processUpload(r.record);
        return;
    }
    // 아무도 집지 않으면 조용히 종료한다 (오탐 로그를 남기지 않는다)
}

// ─────────────────────────────────────────────────────────────
//  공통 후처리 — 여기서부터는 전송 규격을 모른다
// ─────────────────────────────────────────────────────────────
void processUpload(UploadRecord& rec) {
    // 1) 절단 판정
    //
    // 핸들러가 이미 판정했으면 그것을 존중한다. 핸들러만이 자기 규격의 프레이밍을
    // 알기 때문이다(multipart는 파트 경계로, 나머지는 본문 길이로 판정).
    // 여기서는 "진짜 파일 크기를 아는" 규격에 한해 추가로 확인만 한다.
    if (!rec.truncated && rec.declaredSize >= 0 &&
        rec.content.size() < static_cast<size_t>(rec.declaredSize)) {
        rec.truncated = true;
    }

    // 2) 기대 타입 결정 — MIME이 타입 정보를 담고 있을 때만 신뢰하고,
    //    아니면 파일명 확장자로 폴백한다.
    //    (Gemini의 Content-Type은 파일과 무관한 프로토콜 고정값이고,
    //     octet-stream 류도 타입 정보가 없다)
    TypeSource typeSrc = TypeSource::None;
    std::string expected = resolveExpectedType(rec.declaredType, rec.filename, &typeSrc);

    // 3) 매직넘버 — 매직바이트는 본문 선두에 있으므로 절단본에서도 유효하다
    MagicResult magic = verifyMagicNumber(rec.content, expected);

    // 4) 해시 — 절단본은 원본과 비교할 수 없다. 파일 해시인 것처럼 남기면
    //    대조 시 거짓 불일치로 오독되므로 계산하지 않는다.
    std::string hash = rec.truncated ? "" : calculateHash(rec.content);

    // 5) 저장
    std::error_code ec;
    std::filesystem::create_directories("captured_files", ec);

    std::string safeName = sanitizeFilename(rec.filename);
    unsigned seq = ++g_captureSeq;
    std::string filepath = "captured_files/" + std::to_string(seq) +
                           (rec.truncated ? "_PARTIAL_" : "_") + safeName;

    // 파일명은 클라이언트가 보낸 비신뢰 입력이다. u8path는 유효한 UTF-8이
    // 아니면 예외를 던지고, 그것이 스레드를 빠져나가면 프로세스가 죽는다.
    // 탐지 기록을 잃는 것이 파일명을 잃는 것보다 나쁘므로, 실패 시 이름을
    // 포기하고 내용을 남긴다.
    std::string saved;
    try {
        std::ofstream ofs(std::filesystem::u8path(filepath), std::ios::binary);
        if (ofs) {
            ofs.write(rec.content.data(), rec.content.size());
            ofs.close();
            saved = filepath;
        }
    } catch (const std::exception&) {
        // 아래 폴백에서 처리
    }
    if (saved.empty()) {
        std::string fallback = "captured_files/" + std::to_string(seq) +
                               (rec.truncated ? "_PARTIAL_" : "_") + "unnamed.bin";
        std::ofstream ofs2(fallback, std::ios::binary);
        if (ofs2) {
            ofs2.write(rec.content.data(), rec.content.size());
            ofs2.close();
            saved = fallback + " (원래 파일명 저장 실패)";
        } else {
            saved = "(저장 실패)";
        }
    }

    // 6) 로깅 — 업로드 1건 = 로그 1줄.
    //    v1은 [Router]/[Parser]/[Verifier]가 여러 줄로 흩어져 grep -c 가
    //    요청 수가 아니라 줄 수를 세는 함정이 있었다.
    // size=<캡처된 파일 바이트>/<실제 파일 크기>
    //   실제 크기를 모르는 규격(multipart)은 "?"로 두고, 대신 요청 전체 길이를
    //   reqlen= 으로 따로 보여준다. 둘을 같은 자리에 섞으면 오독된다.
    std::string sizeField = std::to_string(rec.content.size()) + "/" +
                            (rec.declaredSize >= 0 ? std::to_string(rec.declaredSize) : "?");
    if (rec.requestLen >= 0) sizeField += " reqlen=" + std::to_string(rec.requestLen);

    std::string line = "[Upload] service=" + rec.service +
                       " handler=" + rec.handler +
                       " endpoint=" + rec.endpoint +
                       " file=\"" + rec.filename + "\"" +
                       " size=" + sizeField +
                       " type=" + (expected.empty() ? "?" : expected) +
                       "(" + typeSourceName(typeSrc) + ")" +
                       " magic=" + magicResultName(magic) +
                       " hash=" + (hash.empty() ? "skipped(truncated)" : hash) +
                       " saved=" + saved;

    if (rec.truncated || magic == MagicResult::Mismatch) Logger::warn(line);
    else                                                 Logger::info(line);
}

} // namespace v2
} // namespace proxy
