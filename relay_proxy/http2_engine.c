#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <string.h>

#include <WinSock2.h>
#include <Windows.h>

#include "http2_engine.h"
#include "logger.h"

#define HTTP2_ENGINE_BUFFER_SIZE 8192
#define HTTP2_ENGINE_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_ENGINE_PREFACE_LENGTH 24
#define HTTP2_ENGINE_INSPECT_BUFFER_SIZE (256 * 1024)
#define HTTP2_ENGINE_PREVIEW_SIZE 256

typedef struct http2_engine_inspector {
    unsigned char buffer[HTTP2_ENGINE_INSPECT_BUFFER_SIZE];
    int length;
    int preface_consumed;
    const char* direction;
} http2_engine_inspector_t;

static int http2_engine_ssl_write_all(SSL* ssl, const char* data, int length)
{
    int total_sent = 0;

    if (ssl == NULL || data == NULL || length <= 0) {
        return -1;
    }

    while (total_sent < length) {
        int sent = SSL_write(ssl, data + total_sent, length - total_sent);

        if (sent <= 0) {
            log_error("HTTP/2 SSL_write() failed");
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

static void http2_engine_inspector_init(
    http2_engine_inspector_t* inspector,
    const char* direction,
    int expect_client_preface
)
{
    if (inspector == NULL) {
        return;
    }

    memset(inspector, 0, sizeof(*inspector));
    inspector->direction = direction != NULL ? direction : "-";
    inspector->preface_consumed = expect_client_preface ? 0 : 1;
}

static unsigned int http2_engine_read_u24(const unsigned char* data)
{
    return ((unsigned int)data[0] << 16) |
        ((unsigned int)data[1] << 8) |
        (unsigned int)data[2];
}

static unsigned int http2_engine_read_u31(const unsigned char* data)
{
    return (((unsigned int)data[0] & 0x7f) << 24) |
        ((unsigned int)data[1] << 16) |
        ((unsigned int)data[2] << 8) |
        (unsigned int)data[3];
}

static const char* http2_engine_frame_type_name(unsigned char type)
{
    switch (type) {
    case 0x0: return "DATA";
    case 0x1: return "HEADERS";
    case 0x2: return "PRIORITY";
    case 0x3: return "RST_STREAM";
    case 0x4: return "SETTINGS";
    case 0x5: return "PUSH_PROMISE";
    case 0x6: return "PING";
    case 0x7: return "GOAWAY";
    case 0x8: return "WINDOW_UPDATE";
    case 0x9: return "CONTINUATION";
    default: return "UNKNOWN";
    }
}

static void http2_engine_make_binary_preview(
    const unsigned char* data,
    int data_length,
    char* preview,
    int preview_size
)
{
    int i;
    int limit;

    if (preview == NULL || preview_size <= 0) {
        return;
    }

    preview[0] = '\0';

    if (data == NULL || data_length <= 0) {
        return;
    }

    limit = data_length;
    if (limit > preview_size - 1) {
        limit = preview_size - 1;
    }

    for (i = 0; i < limit; i++) {
        unsigned char ch = data[i];
        preview[i] = (ch >= 32 && ch < 127) ? (char)ch : ' ';
    }

    preview[limit] = '\0';
}

static void http2_engine_log_frame(
    proxy_session_context_t* session,
    const http2_engine_inspector_t* inspector,
    unsigned char type,
    unsigned char flags,
    unsigned int stream_id,
    const unsigned char* payload,
    unsigned int payload_length
)
{
    if (session == NULL || inspector == NULL) {
        return;
    }

    log_debug(
        "HTTP2_FRAME session_id=%lu direction=%s type=%s stream_id=%u flags=0x%02x payload_bytes=%u",
        session->session_id,
        inspector->direction,
        http2_engine_frame_type_name(type),
        stream_id,
        flags,
        payload_length
    );

    if (type == 0x1) {
        log_info(
            "HTTP2_ANALYSIS direction=%s session_id=%lu frame=HEADERS stream_id=%u header_block_bytes=%u end_headers=%s end_stream=%s",
            inspector->direction,
            session->session_id,
            stream_id,
            payload_length,
            (flags & 0x4) ? "true" : "false",
            (flags & 0x1) ? "true" : "false"
        );
    }
    else if (type == 0x0) {
        const unsigned char* body = payload;
        unsigned int body_length = payload_length;
        char preview[HTTP2_ENGINE_PREVIEW_SIZE];

        if ((flags & 0x8) && body_length > 0) {
            unsigned int padding_length = body[0];
            body++;
            body_length--;

            if (padding_length <= body_length) {
                body_length -= padding_length;
            }
            else {
                body_length = 0;
            }
        }

        http2_engine_make_binary_preview(
            body,
            (int)body_length,
            preview,
            sizeof(preview)
        );

        log_info(
            "HTTP2_ANALYSIS direction=%s session_id=%lu frame=DATA stream_id=%u body_bytes=%u end_stream=%s body_preview=%s%s",
            inspector->direction,
            session->session_id,
            stream_id,
            body_length,
            (flags & 0x1) ? "true" : "false",
            body_length > 0 ? preview : "-",
            body_length >= sizeof(preview) ? " [truncated]" : ""
        );
    }
}

static int http2_engine_inspector_append(
    http2_engine_inspector_t* inspector,
    proxy_session_context_t* session,
    const unsigned char* data,
    int data_length
)
{
    int pos;

    if (inspector == NULL || data == NULL || data_length < 0) {
        return -1;
    }

    if (data_length == 0) {
        return 0;
    }

    if (data_length > HTTP2_ENGINE_INSPECT_BUFFER_SIZE - inspector->length) {
        log_warn(
            "HTTP2 inspector buffer full. session_id=%lu direction=%s buffered=%d incoming=%d. Dropping buffered parse state.",
            session != NULL ? session->session_id : 0,
            inspector->direction,
            inspector->length,
            data_length
        );
        inspector->length = 0;
        inspector->preface_consumed = 1;
    }

    if (data_length > HTTP2_ENGINE_INSPECT_BUFFER_SIZE - inspector->length) {
        return -1;
    }

    memcpy(inspector->buffer + inspector->length, data, data_length);
    inspector->length += data_length;

    pos = 0;

    if (!inspector->preface_consumed) {
        if (inspector->length < HTTP2_ENGINE_PREFACE_LENGTH) {
            return 0;
        }

        if (memcmp(inspector->buffer, HTTP2_ENGINE_PREFACE, HTTP2_ENGINE_PREFACE_LENGTH) != 0) {
            log_error(
                "HTTP2 client preface mismatch. session_id=%lu direction=%s",
                session != NULL ? session->session_id : 0,
                inspector->direction
            );
            return -1;
        }

        log_info(
            "HTTP2_ANALYSIS direction=%s session_id=%lu client_preface=ok",
            inspector->direction,
            session != NULL ? session->session_id : 0
        );
        pos = HTTP2_ENGINE_PREFACE_LENGTH;
        inspector->preface_consumed = 1;
    }

    while (inspector->length - pos >= 9) {
        unsigned int payload_length = http2_engine_read_u24(inspector->buffer + pos);
        unsigned char type = inspector->buffer[pos + 3];
        unsigned char flags = inspector->buffer[pos + 4];
        unsigned int stream_id = http2_engine_read_u31(inspector->buffer + pos + 5);
        int frame_length;

        if (payload_length > HTTP2_ENGINE_INSPECT_BUFFER_SIZE - 9) {
            log_error(
                "HTTP2 frame too large. session_id=%lu direction=%s payload_bytes=%u",
                session != NULL ? session->session_id : 0,
                inspector->direction,
                payload_length
            );
            return -1;
        }

        frame_length = 9 + (int)payload_length;
        if (inspector->length - pos < frame_length) {
            break;
        }

        http2_engine_log_frame(
            session,
            inspector,
            type,
            flags,
            stream_id,
            inspector->buffer + pos + 9,
            payload_length
        );

        pos += frame_length;
    }

    if (pos > 0) {
        if (pos < inspector->length) {
            memmove(inspector->buffer, inspector->buffer + pos, inspector->length - pos);
            inspector->length -= pos;
        }
        else {
            inspector->length = 0;
        }
    }

    return 0;
}

int http2_engine_relay_loop(
    proxy_session_context_t* session,
    SSL* client_ssl,
    SSL* upstream_ssl,
    SOCKET upstream_sock
)
{
    http2_engine_inspector_t client_to_upstream;
    http2_engine_inspector_t upstream_to_client;
    char buffer[HTTP2_ENGINE_BUFFER_SIZE];
    int result = 0;

    if (session == NULL || client_ssl == NULL || upstream_ssl == NULL ||
        upstream_sock == INVALID_SOCKET) {
        return -1;
    }

    http2_engine_inspector_init(&client_to_upstream, "REQUEST", 1);
    http2_engine_inspector_init(&upstream_to_client, "RESPONSE", 0);

    log_info(
        "TLS MITM HTTP/2 relay loop started. session_id=%lu",
        session->session_id
    );

    while (1) {
        fd_set read_fds;
        struct timeval timeout;
        int select_result;
        SOCKET client_sock;

        client_sock = session->client_sock;
        if (client_sock == INVALID_SOCKET) {
            result = -1;
            break;
        }

        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(upstream_sock, &read_fds);

        timeout.tv_sec = 300;
        timeout.tv_usec = 0;

        select_result = select(0, &read_fds, NULL, NULL, &timeout);
        if (select_result == SOCKET_ERROR) {
            log_error(
                "TLS MITM HTTP/2 select() failed. session_id=%lu error=%d",
                session->session_id,
                WSAGetLastError()
            );
            result = -1;
            break;
        }

        if (select_result == 0) {
            log_info(
                "TLS MITM HTTP/2 idle timeout. session_id=%lu",
                session->session_id
            );
            break;
        }

        if (FD_ISSET(client_sock, &read_fds) || SSL_pending(client_ssl) > 0) {
            int read_len = SSL_read(client_ssl, buffer, sizeof(buffer));

            if (read_len <= 0) {
                int ssl_error = SSL_get_error(client_ssl, read_len);

                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    log_info(
                        "TLS MITM HTTP/2 client closed TLS connection. session_id=%lu",
                        session->session_id
                    );
                    break;
                }

                log_error(
                    "TLS MITM HTTP/2 SSL_read() from client failed. session_id=%lu ssl_error=%d",
                    session->session_id,
                    ssl_error
                );
                result = -1;
                break;
            }

            session_context_add_bytes_from_client(session, read_len);

            if (http2_engine_inspector_append(
                &client_to_upstream,
                session,
                (const unsigned char*)buffer,
                read_len
            ) != 0) {
                result = -1;
                break;
            }

            if (http2_engine_ssl_write_all(upstream_ssl, buffer, read_len) < 0) {
                result = -1;
                break;
            }

            session_context_add_bytes_to_upstream(session, read_len);
        }

        if (FD_ISSET(upstream_sock, &read_fds) || SSL_pending(upstream_ssl) > 0) {
            int read_len = SSL_read(upstream_ssl, buffer, sizeof(buffer));

            if (read_len <= 0) {
                int ssl_error = SSL_get_error(upstream_ssl, read_len);

                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    log_info(
                        "TLS MITM HTTP/2 upstream closed TLS connection. session_id=%lu",
                        session->session_id
                    );
                    break;
                }

                log_error(
                    "TLS MITM HTTP/2 SSL_read() from upstream failed. session_id=%lu ssl_error=%d",
                    session->session_id,
                    ssl_error
                );
                result = -1;
                break;
            }

            session_context_add_bytes_from_upstream(session, read_len);

            if (http2_engine_inspector_append(
                &upstream_to_client,
                session,
                (const unsigned char*)buffer,
                read_len
            ) != 0) {
                result = -1;
                break;
            }

            if (http2_engine_ssl_write_all(client_ssl, buffer, read_len) < 0) {
                result = -1;
                break;
            }

            session_context_add_bytes_to_client(session, read_len);
        }
    }

    if (result == 0) {
        log_info("TLS MITM HTTP/2 relay loop finished normally. session_id=%lu", session->session_id);
    }
    else {
        log_error("TLS MITM HTTP/2 relay loop finished with error. session_id=%lu", session->session_id);
    }

    return result;
}
