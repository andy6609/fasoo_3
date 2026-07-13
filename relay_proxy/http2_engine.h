#ifndef HTTP2_ENGINE_H
#define HTTP2_ENGINE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <openssl/ssl.h>

#include "session_context.h"

int http2_engine_relay_loop(
    proxy_session_context_t* session,
    SSL* client_ssl,
    SSL* upstream_ssl,
    SOCKET upstream_sock
);

#endif /* HTTP2_ENGINE_H */
