#ifndef TLS_MITM_ENGINE_H
#define TLS_MITM_ENGINE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "http_parser.h"
#include "session_context.h"

int tls_mitm_handle_connect_session(
    proxy_session_context_t* session,
    SOCKET upstream_sock,
    const http_request_t* connect_request
);

#endif
