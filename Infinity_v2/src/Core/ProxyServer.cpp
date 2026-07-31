#include "Core/ProxyServer.h"
#include "Core/Logger.h"
#include "Core/Context.h"
#include "Protocol/Http1Engine.h"

#include <thread>
#include <exception>
#include <ws2tcpip.h>

namespace proxy {

ProxyServer::ProxyServer(int port) : port_(port) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

ProxyServer::~ProxyServer() {
    stop();
    WSACleanup();
}

void ProxyServer::start() {
    listenSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket_ == INVALID_SOCKET) {
        Logger::error("Failed to create listen socket");
        return;
    }

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(listenSocket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        Logger::error("Failed to bind port " + std::to_string(port_));
        closesocket(listenSocket_);
        return;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Listen failed");
        closesocket(listenSocket_);
        return;
    }

    isRunning_ = true;
    Logger::info("ProxyServer listening on port " + std::to_string(port_));

    acceptLoop();
}

void ProxyServer::stop() {
    if (isRunning_) {
        isRunning_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
        }
    }
}

void ProxyServer::acceptLoop() {
    while (isRunning_) {
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
        
        if (!isRunning_) break;

        if (clientSock == INVALID_SOCKET) {
            Logger::warn("Accept failed");
            continue;
        }

        // cpp-httplib의 스레드 모델 벤치마킹: 1연결 = 1스레드 분리
        //
        // 스레드 경계에서 예외를 반드시 흡수한다. 분리(detach)된 스레드에서 예외가 빠져나가면
        // std::terminate가 호출되어 프록시 프로세스 전체가 죽는다. 실제로 비-UTF-8 파일명이
        // std::filesystem::u8path에서 예외를 던져 프록시가 통째로 종료된 사례를 관측했다.
        // 탐지 시스템이 죽으면 이후 트래픽이 전부 무감시로 통과(fail-open)하므로,
        // 어떤 요청 하나도 프록시 전체를 무너뜨릴 수 없어야 한다.
        std::thread([this, clientSock]() {
            try {
                handleConnection(clientSock);
            } catch (const std::exception& e) {
                Logger::error(std::string("연결 처리 중 예외 — 해당 연결만 종료: ") + e.what());
            } catch (...) {
                Logger::error("연결 처리 중 알 수 없는 예외 — 해당 연결만 종료");
            }
        }).detach();
    }
}

void ProxyServer::handleConnection(SOCKET clientSock) {
    // 1. 소켓만 감싼 빈 Context 생성
    Context ctx;
    ctx.clientSock = clientSock;

    // 2. HTTP/1.1 엔진으로 넘겨서 CONNECT 파싱, TLS 핸드셰이크(TlsManager 사용),
    //    그리고 통신 루프까지 수행하도록 위임
    Http1Engine::process(ctx);
}

} // namespace proxy
