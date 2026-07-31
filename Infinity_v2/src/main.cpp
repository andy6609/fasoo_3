#include <iostream>
#include <memory>
#include "Core/Logger.h"
#include "Core/ProxyServer.h"
#include "Crypto/TlsManager.h"
#include "Inspector/UploadRouter.h"
#include "Inspector/Handlers/ResumableHandler.h"
#include "Inspector/Handlers/PresignedHandler.h"
#include "Inspector/Handlers/MultipartHandler.h"

int main() {
    proxy::Logger::init(proxy::Logger::Level::DEBUG);
    proxy::Logger::info("Infinity_v2 starting...");

    if (!proxy::TlsManager::init()) {
        proxy::Logger::error("TlsManager init failed");
        return 1;
    }

    // 업로드 핸들러 등록. 등록 순서 = 우선순위이며, 구체적인 신호부터 본다.
    //   1. ResumableHandler  (X-Goog-Upload-Command 헤더)      — Gemini
    //   2. PresignedHandler  (스토리지 호스트 접미사 + PUT)     — ChatGPT
    //   3. MultipartHandler  (Content-Type, 범용 폴백)          — claude.ai/기타
    //
    // 구체적 신호(전용 헤더·호스트)를 먼저 보고, 아무도 안 집으면 범용
    // multipart 폴백으로 내려간다. 각 핸들러는 자기 것이 아니면 Ignored를
    // 반환하므로 미구현·판별실패가 범용 처리를 막지 못한다
    // (docs/handler-interface.md §3, §5).
    auto& router = proxy::v2::UploadRouter::instance();
    router.registerHandler(std::make_unique<proxy::v2::ResumableHandler>());
    router.registerHandler(std::make_unique<proxy::v2::PresignedHandler>());
    router.registerHandler(std::make_unique<proxy::v2::MultipartHandler>());
    proxy::Logger::info("UploadRouter: 3 handlers registered (Resumable, Presigned, Multipart)");

    proxy::ProxyServer server(18080);
    server.start();

    proxy::TlsManager::cleanup();
    proxy::Logger::info("Server stopped.");
    return 0;
}
