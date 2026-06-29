#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls_mitm_engine.h"
#include "logger.h"
#include "request_buffer.h"
#include "response_buffer.h"
#include "http_parser.h"
#include "http_response_parser.h"
#include "dlp_engine.h"
#include "audit_log.h"
#include "cert_manager.h"
#include "multipart_parser.h"
#include "content_decoder.h"
#include "chunked_decoder.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define TLS_MITM_CERT_FILE "certs\\mitm.crt"
#define TLS_MITM_KEY_FILE  "certs\\mitm.key"
#define TLS_MITM_BUFFER_SIZE 8192
#define TLS_MITM_MAX_HOSTNAME 256

typedef struct tls_mitm_sni_context {
    proxy_session_context_t* session;
    char fallback_host[TLS_MITM_MAX_HOSTNAME];
    char selected_sni[TLS_MITM_MAX_HOSTNAME];
} tls_mitm_sni_context_t;

static volatile LONG g_tls_mitm_initialized = 0;

static void tls_mitm_init_openssl_once(void)
{
    if (InterlockedCompareExchange(&g_tls_mitm_initialized, 1, 0) == 0) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
}

static void tls_mitm_log_openssl_error(const char* message)
{
    unsigned long err;
    int has_error = 0;

    if (message == NULL) {
        message = "OpenSSL error";
    }

    while ((err = ERR_get_error()) != 0) {
        char error_text[256];

        memset(error_text, 0, sizeof(error_text));
        ERR_error_string_n(err, error_text, sizeof(error_text));

        log_error("%s: %s", message, error_text);
        has_error = 1;
    }

    if (!has_error) {
        log_error("%s", message);
    }
}


static void tls_mitm_copy_string(
    char* dst,
    int dst_size,
    const char* src
)
{
    if (dst == NULL || dst_size <= 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    _snprintf_s(dst, dst_size, _TRUNCATE, "%s", src);
}

static void tls_mitm_extract_connect_host(
    const http_request_t* connect_request,
    char* host,
    int host_size
)
{
    const char* source;
    const char* start;
    const char* end;
    int len;

    if (host == NULL || host_size <= 0) {
        return;
    }

    host[0] = '\0';

    if (connect_request == NULL) {
        return;
    }

    if (connect_request->path[0] != '\0') {
        source = connect_request->path;
    }
    else if (connect_request->host[0] != '\0') {
        source = connect_request->host;
    }
    else {
        return;
    }

    start = source;

    while (*start == ' ' || *start == '\t') {
        start++;
    }

    if (*start == '[') {
        const char* close_bracket = strchr(start, ']');

        if (close_bracket != NULL) {
            len = (int)(close_bracket - start + 1);

            if (len >= host_size) {
                len = host_size - 1;
            }

            memcpy(host, start, len);
            host[len] = '\0';
            return;
        }
    }

    end = start;

    while (*end != '\0' &&
        *end != ':' &&
        *end != '/' &&
        *end != ' ' &&
        *end != '\t' &&
        *end != '\r' &&
        *end != '\n') {
        end++;
    }

    len = (int)(end - start);

    if (len <= 0) {
        return;
    }

    if (len >= host_size) {
        len = host_size - 1;
    }

    memcpy(host, start, len);
    host[len] = '\0';
}

static int tls_mitm_sni_callback(
    SSL* ssl,
    int* ad,
    void* arg
)
{
    const char* sni_name;
    const char* cert_host;
    tls_mitm_sni_context_t* context;

    char cert_path[CERT_MANAGER_PATH_SIZE];
    char key_path[CERT_MANAGER_PATH_SIZE];

    (void)ad;

    if (ssl == NULL) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    context = (tls_mitm_sni_context_t*)arg;

    sni_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (sni_name != NULL && sni_name[0] != '\0') {
        cert_host = sni_name;
    }
    else if (context != NULL && context->fallback_host[0] != '\0') {
        cert_host = context->fallback_host;
    }
    else {
        log_info("TLS MITM SNI not provided and no fallback host. using default MITM certificate.");
        return SSL_TLSEXT_ERR_OK;
    }

    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));

    if (cert_manager_get_or_create_leaf_certificate(
        cert_host,
        cert_path,
        sizeof(cert_path),
        key_path,
        sizeof(key_path)
    ) != 0) {
        log_error(
            "TLS MITM failed to prepare dynamic certificate. host=%s",
            cert_host
        );

        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (SSL_use_certificate_file(ssl, cert_path, SSL_FILETYPE_PEM) != 1) {
        tls_mitm_log_openssl_error("SSL_use_certificate_file() failed in SNI callback");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (SSL_use_PrivateKey_file(ssl, key_path, SSL_FILETYPE_PEM) != 1) {
        tls_mitm_log_openssl_error("SSL_use_PrivateKey_file() failed in SNI callback");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (SSL_check_private_key(ssl) != 1) {
        tls_mitm_log_openssl_error("SSL_check_private_key() failed in SNI callback");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (context != NULL) {
        tls_mitm_copy_string(
            context->selected_sni,
            sizeof(context->selected_sni),
            cert_host
        );
    }

    log_info(
        "TLS MITM SNI selected dynamic certificate. session_id=%lu sni=%s cert=%s",
        context != NULL && context->session != NULL ? context->session->session_id : 0,
        cert_host,
        cert_path
    );

    return SSL_TLSEXT_ERR_OK;
}


static int tls_mitm_alpn_select_http11_cb(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg
)
{
    static const unsigned char http11_proto[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    int select_result;

    (void)ssl;
    (void)arg;

    if (out == NULL || outlen == NULL || in == NULL || inlen == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    select_result = SSL_select_next_proto(
        (unsigned char**)out,
        outlen,
        http11_proto,
        sizeof(http11_proto),
        in,
        inlen
    );

    if (select_result == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

static void tls_mitm_log_selected_alpn(
    proxy_session_context_t* session,
    SSL* ssl,
    const char* side
)
{
    const unsigned char* selected = NULL;
    unsigned int selected_len = 0;
    char alpn_text[64];

    if (session == NULL || ssl == NULL) {
        return;
    }

    if (side == NULL) {
        side = "unknown";
    }

    SSL_get0_alpn_selected(ssl, &selected, &selected_len);

    if (selected != NULL && selected_len > 0) {
        if (selected_len >= sizeof(alpn_text)) {
            selected_len = sizeof(alpn_text) - 1;
        }

        memcpy(alpn_text, selected, selected_len);
        alpn_text[selected_len] = '\0';

        log_info(
            "TLS MITM ALPN selected. session_id=%lu side=%s alpn=%s",
            session->session_id,
            side,
            alpn_text
        );
    }
    else {
        log_info(
            "TLS MITM ALPN not selected. session_id=%lu side=%s defaulting to HTTP/1.1 parser",
            session->session_id,
            side
        );
    }
}

static SSL_CTX* tls_mitm_create_server_ctx(void)
{
    SSL_CTX* ctx;

    tls_mitm_init_openssl_once();

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        tls_mitm_log_openssl_error("SSL_CTX_new(TLS_server_method) failed");
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, TLS_MITM_CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        tls_mitm_log_openssl_error("SSL_CTX_use_certificate_file() failed. certs\\mitm.crt not found or invalid");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, TLS_MITM_KEY_FILE, SSL_FILETYPE_PEM) != 1) {
        tls_mitm_log_openssl_error("SSL_CTX_use_PrivateKey_file() failed. certs\\mitm.key not found or invalid");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        tls_mitm_log_openssl_error("SSL_CTX_check_private_key() failed");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /*
        Browser test mode:
        Modern browsers may offer h2 and http/1.1 through ALPN.
        Our parser handles HTTP/1.1, so explicitly select http/1.1 when offered.
    */
    SSL_CTX_set_alpn_select_cb(ctx, tls_mitm_alpn_select_http11_cb, NULL);

    return ctx;
}

static SSL_CTX* tls_mitm_create_client_ctx(void)
{
    SSL_CTX* ctx;

    tls_mitm_init_openssl_once();

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        tls_mitm_log_openssl_error("SSL_CTX_new(TLS_client_method) failed");
        return NULL;
    }

    /*
        POC note: the upstream test server uses a self-signed certificate,
        so certificate verification is disabled here.
        In a production design, verification and exception handling should be policy-driven.
    */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /*
        Upstream browser-test mode:
        Offer http/1.1 to the upstream server. If the upstream does not support ALPN,
        the TLS handshake can still continue and the HTTP/1.1 parser remains valid for this POC.
    */
    {
        static const unsigned char http11_proto[] = {
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };

        if (SSL_CTX_set_alpn_protos(ctx, http11_proto, sizeof(http11_proto)) != 0) {
            log_error("SSL_CTX_set_alpn_protos() failed. upstream ALPN will be omitted.");
        }
    }

    return ctx;
}

static int ssl_write_all(SSL* ssl, const char* data, int length)
{
    int total_sent = 0;

    if (ssl == NULL || data == NULL || length <= 0) {
        return -1;
    }

    while (total_sent < length) {
        int sent = SSL_write(ssl, data + total_sent, length - total_sent);

        if (sent <= 0) {
            tls_mitm_log_openssl_error("SSL_write() failed");
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

static int build_tls_block_response(
    char* response,
    int response_size,
    const char* title,
    const char* reason
)
{
    char body[1024];
    int body_length;
    int response_length;

    if (response == NULL || response_size <= 0) {
        return -1;
    }

    if (title == NULL || title[0] == '\0') {
        title = "TLS MITM DLP blocked this traffic.";
    }

    if (reason == NULL || reason[0] == '\0') {
        reason = "DLP policy violation";
    }

    _snprintf_s(
        body,
        sizeof(body),
        _TRUNCATE,
        "[BLOCKED] %s\n"
        "Reason: %s\n",
        title,
        reason
    );

    body_length = (int)strlen(body);

    _snprintf_s(
        response,
        response_size,
        _TRUNCATE,
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_length,
        body
    );

    response_length = (int)strlen(response);

    return response_length;
}

static int tls_mitm_send_block_response(
    proxy_session_context_t* session,
    SSL* client_ssl,
    const char* title,
    const char* reason
)
{
    char response[2048];
    int response_length;
    int sent;

    response_length = build_tls_block_response(
        response,
        sizeof(response),
        title,
        reason
    );

    if (response_length <= 0) {
        return -1;
    }

    sent = ssl_write_all(client_ssl, response, response_length);
    if (sent < 0) {
        return -1;
    }

    session_context_add_bytes_to_client(session, sent);

    return sent;
}

static int tls_read_complete_http_request(
    proxy_session_context_t* session,
    SSL* client_ssl,
    request_buffer_t* request_buffer,
    int* complete_request_length
)
{
    char buffer[TLS_MITM_BUFFER_SIZE];

    if (session == NULL || client_ssl == NULL || request_buffer == NULL || complete_request_length == NULL) {
        return -1;
    }

    *complete_request_length = 0;

    while (1) {
        int complete_result;
        int read_len;

        complete_result = request_buffer_get_complete_request_length(
            request_buffer,
            complete_request_length
        );

        if (complete_result < 0) {
            log_error(
                "TLS MITM request_buffer_get_complete_request_length() failed. session_id=%lu",
                session->session_id
            );
            return -1;
        }

        if (complete_result > 0) {
            return 1;
        }

        memset(buffer, 0, sizeof(buffer));

        read_len = SSL_read(client_ssl, buffer, sizeof(buffer));
        if (read_len <= 0) {
            int ssl_error = SSL_get_error(client_ssl, read_len);

            log_error(
                "TLS MITM SSL_read() from client failed. session_id=%lu ssl_error=%d",
                session->session_id,
                ssl_error
            );
            tls_mitm_log_openssl_error("TLS MITM SSL_read() from client failed");
            return -1;
        }

        session_context_add_bytes_from_client(session, read_len);

        log_debug(
            "TLS MITM decrypted CLIENT -> PROXY: session_id=%lu %d bytes received",
            session->session_id,
            read_len
        );

        if (request_buffer_append(request_buffer, buffer, read_len) != 0) {
            log_error(
                "TLS MITM request_buffer_append() failed. session_id=%lu",
                session->session_id
            );
            return -1;
        }
    }
}

static int tls_read_complete_http_response(
    proxy_session_context_t* session,
    SSL* upstream_ssl,
    response_buffer_t* response_buffer,
    int* complete_response_length
)
{
    char buffer[TLS_MITM_BUFFER_SIZE];

    if (session == NULL || upstream_ssl == NULL || response_buffer == NULL || complete_response_length == NULL) {
        return -1;
    }

    *complete_response_length = 0;

    while (1) {
        int complete_result;
        int read_len;

        complete_result = response_buffer_get_complete_response_length(
            response_buffer,
            complete_response_length
        );

        if (complete_result < 0) {
            log_error(
                "TLS MITM response_buffer_get_complete_response_length() failed. session_id=%lu",
                session->session_id
            );
            return -1;
        }

        if (complete_result > 0) {
            return 1;
        }

        memset(buffer, 0, sizeof(buffer));

        read_len = SSL_read(upstream_ssl, buffer, sizeof(buffer));
        if (read_len <= 0) {
            int ssl_error = SSL_get_error(upstream_ssl, read_len);

            log_error(
                "TLS MITM SSL_read() from upstream failed. session_id=%lu ssl_error=%d",
                session->session_id,
                ssl_error
            );
            tls_mitm_log_openssl_error("TLS MITM SSL_read() from upstream failed");
            return -1;
        }

        session_context_add_bytes_from_upstream(session, read_len);

        log_debug(
            "TLS MITM decrypted UPSTREAM -> PROXY: session_id=%lu %d bytes received",
            session->session_id,
            read_len
        );

        if (response_buffer_append(response_buffer, buffer, read_len) != 0) {
            log_error(
                "TLS MITM response_buffer_append() failed. session_id=%lu",
                session->session_id
            );
            return -1;
        }
    }
}


static int tls_mitm_find_header_token_ci(
    const char* data,
    int length,
    const char* header_name,
    const char* token
)
{
    int pos = 0;
    int header_name_len;
    int token_len;

    if (data == NULL || length <= 0 || header_name == NULL || token == NULL) {
        return 0;
    }

    header_name_len = (int)strlen(header_name);
    token_len = (int)strlen(token);

    while (pos < length) {
        int line_start = pos;
        int line_end = pos;
        int line_len;
        int value_start;

        while (line_end < length) {
            if (data[line_end] == '\r' && line_end + 1 < length && data[line_end + 1] == '\n') {
                break;
            }
            line_end++;
        }

        line_len = line_end - line_start;

        if (line_len == 0) {
            break;
        }

        if (line_len > header_name_len &&
            _strnicmp(data + line_start, header_name, header_name_len) == 0 &&
            data[line_start + header_name_len] == ':') {

            value_start = line_start + header_name_len + 1;
            while (value_start < line_end &&
                (data[value_start] == ' ' || data[value_start] == '\t')) {
                value_start++;
            }

            {
                int i;

                for (i = value_start; i + token_len <= line_end; i++) {
                    if (_strnicmp(data + i, token, token_len) == 0) {
                        return 1;
                    }
                }
            }
        }

        if (line_end + 2 <= length) {
            pos = line_end + 2;
        }
        else {
            break;
        }
    }

    return 0;
}

static int tls_mitm_is_http10(const char* data, int length)
{
    if (data == NULL || length <= 0) {
        return 0;
    }

    {
        int i;

        for (i = 0; i + 8 <= length; i++) {
            if (data[i] == '\r' && i + 1 < length && data[i + 1] == '\n') {
                break;
            }

            if (_strnicmp(data + i, "HTTP/1.0", 8) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

static int tls_mitm_should_close_after_exchange(
    const char* request_data,
    int request_length,
    const char* response_data,
    int response_length
)
{
    int request_connection_close;
    int response_connection_close;
    int request_http10;
    int response_http10;
    int request_keep_alive;
    int response_keep_alive;

    request_connection_close = tls_mitm_find_header_token_ci(
        request_data,
        request_length,
        "Connection",
        "close"
    );

    response_connection_close = tls_mitm_find_header_token_ci(
        response_data,
        response_length,
        "Connection",
        "close"
    );

    request_http10 = tls_mitm_is_http10(request_data, request_length);
    response_http10 = tls_mitm_is_http10(response_data, response_length);

    request_keep_alive = tls_mitm_find_header_token_ci(
        request_data,
        request_length,
        "Connection",
        "keep-alive"
    );

    response_keep_alive = tls_mitm_find_header_token_ci(
        response_data,
        response_length,
        "Connection",
        "keep-alive"
    );

    if (request_connection_close || response_connection_close) {
        return 1;
    }

    if (request_http10 && !request_keep_alive) {
        return 1;
    }

    if (response_http10 && !response_keep_alive) {
        return 1;
    }

    return 0;
}

static int tls_mitm_process_one_http_request_response(
    proxy_session_context_t* session,
    SSL* client_ssl,
    SSL* upstream_ssl,
    int exchange_index
)
{
    request_buffer_t* request_buffer = NULL;
    response_buffer_t* response_buffer = NULL;

    int complete_request_length = 0;
    int complete_response_length = 0;
    int should_close_after_exchange = 0;
    int function_result = -1;

    const char* request_data;
    const char* response_data;

    http_request_t request;
    http_response_t response;
    dlp_result_t dlp_result;

    request_buffer = (request_buffer_t*)malloc(sizeof(request_buffer_t));
    response_buffer = (response_buffer_t*)malloc(sizeof(response_buffer_t));

    if (request_buffer == NULL || response_buffer == NULL) {
        log_error(
            "TLS MITM failed to allocate HTTP buffers. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );
        function_result = -1;
        goto cleanup;
    }

    request_buffer_init(request_buffer);
    response_buffer_init(response_buffer);

    log_info(
        "TLS MITM waiting for HTTPS request. session_id=%lu exchange_index=%d",
        session->session_id,
        exchange_index
    );

    if (tls_read_complete_http_request(
        session,
        client_ssl,
        request_buffer,
        &complete_request_length
    ) != 1) {
        function_result = -1;
        goto cleanup;
    }

    request_data = request_buffer_data(request_buffer);

    memset(&request, 0, sizeof(request));

    if (!parse_http_request(request_data, complete_request_length, &request)) {
        log_error(
            "TLS MITM failed to parse decrypted HTTP request. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );
        function_result = -1;
        goto cleanup;
    }

    log_info(
        "TLS MITM decrypted HTTP request. session_id=%lu exchange_index=%d length=%d method=%s path=%s host=%s",
        session->session_id,
        exchange_index,
        complete_request_length,
        request.method,
        request.path,
        request.host
    );

    print_http_request(&request);
    log_http_request_analysis(&request, session->session_id, "HTTPS_MITM");

    {
        http_request_t decoded_request_for_dlp;
        const http_request_t* request_for_dlp;
        int chunked_decode_result;

        memset(&decoded_request_for_dlp, 0, sizeof(decoded_request_for_dlp));
        request_for_dlp = &request;

        chunked_decode_result = chunked_decoder_prepare_request_for_dlp(
            &request,
            request_data,
            complete_request_length,
            &decoded_request_for_dlp,
            "TLS MITM REQUEST"
        );

        if (chunked_decode_result == 1) {
            request_for_dlp = &decoded_request_for_dlp;
            log_debug(
                "TLS MITM request DLP will inspect dechunked body. session_id=%lu exchange_index=%d",
                session->session_id,
                exchange_index
            );
        }
        else if (chunked_decode_result < 0) {
            log_warn(
                "TLS MITM request chunk decoding failed. session_id=%lu exchange_index=%d DLP will inspect original request body.",
                session->session_id,
                exchange_index
            );
        }

        dlp_result = inspect_dlp_request(request_for_dlp);
        inspect_multipart_upload_request(request_for_dlp, &dlp_result);

    if (dlp_result.action == DLP_ACTION_BLOCK) {
        log_security(
            "TLS MITM request blocked. session_id=%lu exchange_index=%d Not forwarding to upstream.",
            session->session_id,
            exchange_index
        );
        log_security(
            "Matched rule id: session_id=%lu rule_id=%d",
            session->session_id,
            dlp_result.matched_rule_id
        );
        log_security(
            "Matched keyword: session_id=%lu keyword=%s",
            session->session_id,
            dlp_result.keyword
        );
        log_security(
            "Block reason: session_id=%lu reason=%s",
            session->session_id,
            dlp_result.reason
        );

        audit_log_block_event(session, request_for_dlp, &dlp_result);

        if (tls_mitm_send_block_response(
            session,
            client_ssl,
            "TLS MITM DLP blocked this request.",
            dlp_result.reason
        ) < 0) {
            function_result = -1;
        goto cleanup;
        }

        function_result = 0;
        goto cleanup;
    }
    else if (dlp_result.action == DLP_ACTION_LOG_ONLY) {
        log_security(
            "TLS MITM request log-only rule matched. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );

        audit_log_log_only_event(session, request_for_dlp, &dlp_result);
    }

    }

    if (ssl_write_all(upstream_ssl, request_data, complete_request_length) < 0) {
        log_error(
            "TLS MITM SSL_write() request to upstream failed. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );
        function_result = -1;
        goto cleanup;
    }

    session_context_add_bytes_to_upstream(session, complete_request_length);

    log_debug(
        "TLS MITM PROXY -> UPSTREAM decrypted request forwarded. session_id=%lu exchange_index=%d length=%d",
        session->session_id,
        exchange_index,
        complete_request_length
    );

    while (1) {
        if (tls_read_complete_http_response(
            session,
            upstream_ssl,
            response_buffer,
            &complete_response_length
        ) != 1) {
            function_result = -1;
            goto cleanup;
        }

        response_data = response_buffer_data(response_buffer);

        memset(&response, 0, sizeof(response));

        if (!parse_http_response(response_data, complete_response_length, &response)) {
            log_error(
                "TLS MITM failed to parse decrypted HTTP response. session_id=%lu exchange_index=%d",
                session->session_id,
                exchange_index
            );
            function_result = -1;
            goto cleanup;
        }

        log_info(
            "TLS MITM decrypted HTTP response. session_id=%lu exchange_index=%d length=%d status=%d content_type=%s",
            session->session_id,
            exchange_index,
            complete_response_length,
            response.status_code,
            response.content_type[0] != '\0' ? response.content_type : "-"
        );

        print_http_response(&response);
        log_http_response_analysis(&response, session->session_id, "HTTPS_MITM");

        if (response.status_code >= 100 && response.status_code < 200 && response.status_code != 101) {
            log_info(
                "TLS MITM interim HTTP response detected. session_id=%lu exchange_index=%d status=%d forwarding interim response and waiting for final response.",
                session->session_id,
                exchange_index,
                response.status_code
            );

            if (ssl_write_all(client_ssl, response_data, complete_response_length) < 0) {
                log_error(
                    "TLS MITM SSL_write() interim response to client failed. session_id=%lu exchange_index=%d status=%d",
                    session->session_id,
                    exchange_index,
                    response.status_code
                );
                function_result = -1;
                goto cleanup;
            }

            session_context_add_bytes_to_client(session, complete_response_length);
            response_buffer_consume(response_buffer, complete_response_length);
            complete_response_length = 0;
            continue;
        }

        break;
    }

    {
        http_response_t decoded_response_for_dlp;
        const http_response_t* response_for_dlp;
        int decode_result;

        memset(&decoded_response_for_dlp, 0, sizeof(decoded_response_for_dlp));
        response_for_dlp = &response;

        decode_result = content_decoder_prepare_response_for_dlp(
            &response,
            response_data,
            complete_response_length,
            &decoded_response_for_dlp,
            "TLS MITM RESPONSE"
        );

        if (decode_result == 1) {
            response_for_dlp = &decoded_response_for_dlp;
            log_debug(
                "TLS MITM response DLP will inspect decompressed body. session_id=%lu exchange_index=%d",
                session->session_id,
                exchange_index
            );
        }
        else if (decode_result < 0) {
            log_warn(
                "TLS MITM response decompression failed. session_id=%lu exchange_index=%d DLP will inspect original response body.",
                session->session_id,
                exchange_index
            );
        }

        dlp_result = inspect_dlp_response(response_for_dlp);

        if (dlp_result.action == DLP_ACTION_BLOCK) {
        log_security(
            "TLS MITM response blocked. session_id=%lu exchange_index=%d Not forwarding original response to client.",
            session->session_id,
            exchange_index
        );
        log_security(
            "Matched rule id: session_id=%lu rule_id=%d",
            session->session_id,
            dlp_result.matched_rule_id
        );
        log_security(
            "Matched keyword: session_id=%lu keyword=%s",
            session->session_id,
            dlp_result.keyword
        );
        log_security(
            "Block reason: session_id=%lu reason=%s",
            session->session_id,
            dlp_result.reason
        );

            audit_log_response_block_event(session, response_for_dlp, &dlp_result);

        if (tls_mitm_send_block_response(
            session,
            client_ssl,
            "TLS MITM DLP blocked this response.",
            dlp_result.reason
        ) < 0) {
            function_result = -1;
        goto cleanup;
        }

            function_result = 0;
        goto cleanup;
        }
        else if (dlp_result.action == DLP_ACTION_LOG_ONLY) {
            log_security(
                "TLS MITM response log-only rule matched. session_id=%lu exchange_index=%d",
                session->session_id,
                exchange_index
            );

            audit_log_response_log_only_event(session, response_for_dlp, &dlp_result);
        }
    }

    if (ssl_write_all(client_ssl, response_data, complete_response_length) < 0) {
        log_error(
            "TLS MITM SSL_write() response to client failed. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );
        function_result = -1;
        goto cleanup;
    }

    session_context_add_bytes_to_client(session, complete_response_length);

    log_debug(
        "TLS MITM PROXY -> CLIENT decrypted response forwarded through TLS. session_id=%lu exchange_index=%d length=%d",
        session->session_id,
        exchange_index,
        complete_response_length
    );

    should_close_after_exchange = tls_mitm_should_close_after_exchange(
        request_data,
        complete_request_length,
        response_data,
        complete_response_length
    );

    if (should_close_after_exchange) {
        log_info(
            "TLS MITM HTTP exchange completed and connection will close. session_id=%lu exchange_index=%d",
            session->session_id,
            exchange_index
        );
        function_result = 0;
        goto cleanup;
    }

    log_info(
        "TLS MITM HTTP exchange completed. keep-alive continues. session_id=%lu exchange_index=%d",
        session->session_id,
        exchange_index
    );

    function_result = 1;
    goto cleanup;

cleanup:
    if (request_buffer != NULL) {
        free(request_buffer);
        request_buffer = NULL;
    }
    if (response_buffer != NULL) {
        free(response_buffer);
        response_buffer = NULL;
    }

    return function_result;
}


int tls_mitm_handle_connect_session(
    proxy_session_context_t* session,
    SOCKET upstream_sock,
    const http_request_t* connect_request
)
{
    SSL_CTX* client_side_ctx = NULL;
    SSL_CTX* upstream_side_ctx = NULL;
    SSL* client_ssl = NULL;
    SSL* upstream_ssl = NULL;
    int result = -1;

    char connect_host[TLS_MITM_MAX_HOSTNAME];
    char client_sni[TLS_MITM_MAX_HOSTNAME];
    char upstream_sni[TLS_MITM_MAX_HOSTNAME];

    tls_mitm_sni_context_t sni_context;

    memset(connect_host, 0, sizeof(connect_host));
    memset(client_sni, 0, sizeof(client_sni));
    memset(upstream_sni, 0, sizeof(upstream_sni));
    memset(&sni_context, 0, sizeof(sni_context));

    if (session == NULL || upstream_sock == INVALID_SOCKET) {
        return -1;
    }

    tls_mitm_extract_connect_host(
        connect_request,
        connect_host,
        sizeof(connect_host)
    );

    if (connect_host[0] == '\0' && session->upstream_ip[0] != '\0') {
        tls_mitm_copy_string(
            connect_host,
            sizeof(connect_host),
            session->upstream_ip
        );
    }

    log_info(
        "TLS MITM session started. session_id=%lu client=%s:%d upstream=%s:%d",
        session->session_id,
        session->client_ip,
        session->client_port,
        session->upstream_ip,
        session->upstream_port
    );

    client_side_ctx = tls_mitm_create_server_ctx();
    if (client_side_ctx == NULL) {
        goto cleanup;
    }

    sni_context.session = session;
    tls_mitm_copy_string(
        sni_context.fallback_host,
        sizeof(sni_context.fallback_host),
        connect_host
    );

    SSL_CTX_set_tlsext_servername_callback(
        client_side_ctx,
        tls_mitm_sni_callback
    );

    SSL_CTX_set_tlsext_servername_arg(
        client_side_ctx,
        &sni_context
    );

    log_info(
        "TLS MITM SNI callback enabled. session_id=%lu fallback_host=%s",
        session->session_id,
        sni_context.fallback_host[0] != '\0' ? sni_context.fallback_host : "-"
    );

    upstream_side_ctx = tls_mitm_create_client_ctx();
    if (upstream_side_ctx == NULL) {
        goto cleanup;
    }

    client_ssl = SSL_new(client_side_ctx);
    if (client_ssl == NULL) {
        tls_mitm_log_openssl_error("SSL_new(client_side_ctx) failed");
        goto cleanup;
    }

    if (SSL_set_fd(client_ssl, (int)session->client_sock) != 1) {
        tls_mitm_log_openssl_error("SSL_set_fd(client_ssl) failed");
        goto cleanup;
    }

    if (SSL_accept(client_ssl) != 1) {
        tls_mitm_log_openssl_error("SSL_accept() from client failed");
        goto cleanup;
    }

    log_info(
        "TLS MITM client TLS handshake complete. session_id=%lu",
        session->session_id
    );

    log_info(
        "TLS MITM client TLS details. session_id=%lu protocol=%s cipher=%s",
        session->session_id,
        SSL_get_version(client_ssl),
        SSL_get_cipher(client_ssl)
    );

    tls_mitm_log_selected_alpn(session, client_ssl, "client");

    if (sni_context.selected_sni[0] != '\0') {
        tls_mitm_copy_string(
            client_sni,
            sizeof(client_sni),
            sni_context.selected_sni
        );
    }
    else {
        const char* accepted_sni;

        accepted_sni = SSL_get_servername(client_ssl, TLSEXT_NAMETYPE_host_name);

        if (accepted_sni != NULL && accepted_sni[0] != '\0') {
            tls_mitm_copy_string(
                client_sni,
                sizeof(client_sni),
                accepted_sni
            );
        }
    }

    if (client_sni[0] != '\0') {
        log_info(
            "TLS MITM client SNI extracted. session_id=%lu sni=%s",
            session->session_id,
            client_sni
        );
    }
    else {
        log_info(
            "TLS MITM client did not provide SNI. session_id=%lu fallback_host=%s",
            session->session_id,
            connect_host[0] != '\0' ? connect_host : "-"
        );
    }

    upstream_ssl = SSL_new(upstream_side_ctx);
    if (upstream_ssl == NULL) {
        tls_mitm_log_openssl_error("SSL_new(upstream_side_ctx) failed");
        goto cleanup;
    }

    if (SSL_set_fd(upstream_ssl, (int)upstream_sock) != 1) {
        tls_mitm_log_openssl_error("SSL_set_fd(upstream_ssl) failed");
        goto cleanup;
    }

    if (client_sni[0] != '\0') {
        tls_mitm_copy_string(
            upstream_sni,
            sizeof(upstream_sni),
            client_sni
        );
    }
    else if (connect_host[0] != '\0' && !cert_manager_is_ip_literal(connect_host)) {
        tls_mitm_copy_string(
            upstream_sni,
            sizeof(upstream_sni),
            connect_host
        );
    }

    if (upstream_sni[0] != '\0') {
        if (SSL_set_tlsext_host_name(upstream_ssl, upstream_sni) != 1) {
            tls_mitm_log_openssl_error("SSL_set_tlsext_host_name() to upstream failed");
            goto cleanup;
        }

        log_info(
            "TLS MITM upstream SNI set. session_id=%lu sni=%s",
            session->session_id,
            upstream_sni
        );
    }
    else {
        log_info(
            "TLS MITM upstream SNI omitted. session_id=%lu connect_host=%s",
            session->session_id,
            connect_host[0] != '\0' ? connect_host : "-"
        );
    }

    if (SSL_connect(upstream_ssl) != 1) {
        tls_mitm_log_openssl_error("SSL_connect() to upstream failed");
        goto cleanup;
    }

    log_info(
        "TLS MITM upstream TLS handshake complete. session_id=%lu upstream=%s:%d",
        session->session_id,
        session->upstream_ip,
        session->upstream_port
    );

    log_info(
        "TLS MITM upstream TLS details. session_id=%lu protocol=%s cipher=%s",
        session->session_id,
        SSL_get_version(upstream_ssl),
        SSL_get_cipher(upstream_ssl)
    );

    tls_mitm_log_selected_alpn(session, upstream_ssl, "upstream");

    {
        int exchange_index = 1;

        while (1) {
            int exchange_result;

            exchange_result = tls_mitm_process_one_http_request_response(
                session,
                client_ssl,
                upstream_ssl,
                exchange_index
            );

            if (exchange_result < 0) {
                result = -1;
                break;
            }

            if (exchange_result == 0) {
                result = 0;
                break;
            }

            exchange_index++;

            log_info(
                "TLS MITM keep-alive waiting for next HTTPS request. session_id=%lu next_exchange_index=%d",
                session->session_id,
                exchange_index
            );
        }
    }

cleanup:
    if (upstream_ssl != NULL) {
        SSL_shutdown(upstream_ssl);
        SSL_free(upstream_ssl);
        upstream_ssl = NULL;
    }

    if (client_ssl != NULL) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        client_ssl = NULL;
    }

    if (upstream_side_ctx != NULL) {
        SSL_CTX_free(upstream_side_ctx);
        upstream_side_ctx = NULL;
    }

    if (client_side_ctx != NULL) {
        SSL_CTX_free(client_side_ctx);
        client_side_ctx = NULL;
    }

    if (result == 0) {
        log_info(
            "TLS MITM session finished normally. session_id=%lu",
            session->session_id
        );
    }
    else {
        log_error(
            "TLS MITM session finished with error. session_id=%lu",
            session->session_id
        );
    }

    return result;
}
