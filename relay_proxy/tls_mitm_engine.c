#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Wincrypt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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
#include "http2_engine.h"
#include "upload_capture.h"
#include "upload_tracker.h"
#include "file_analyzer.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")

#define TLS_MITM_CERT_FILE "certs\\mitm.crt"
#define TLS_MITM_KEY_FILE  "certs\\mitm.key"
#define TLS_MITM_BUFFER_SIZE 8192
#define TLS_MITM_MAX_HOSTNAME 256
#define TLS_MITM_INSECURE_UPSTREAM_ENV "LOCAL_DLP_ALLOW_INSECURE_UPSTREAM"
#define TLS_MITM_FORCE_HTTP1_UPLOAD_ENV "LOCAL_DLP_FORCE_HTTP1_UPLOAD_INSPECTION"
#define DLP_BLOCK_UNSCANNABLE_ENV "LOCAL_DLP_BLOCK_UNSCANNABLE"
#define TLS_MITM_HTTP1_REQUEST_TIMEOUT_ENV "LOCAL_DLP_HTTP1_REQUEST_TIMEOUT_MS"
#define TLS_MITM_HTTP1_IDLE_TIMEOUT_ENV "LOCAL_DLP_HTTP1_IDLE_TIMEOUT_MS"
#define TLS_MITM_HTTP1_REQUEST_TIMEOUT_DEFAULT_MS 300000ULL
#define TLS_MITM_HTTP1_IDLE_TIMEOUT_DEFAULT_MS 30000ULL
#define AI_ACCESS_DEDUP_WINDOW_MS 60000ULL
#define AI_ACCESS_TRACKER_SIZE 32

typedef struct ai_access_event_entry {
    unsigned long process_id;
    char host[TLS_MITM_MAX_HOSTNAME];
    ULONGLONG last_logged_ms;
} ai_access_event_entry_t;

static SRWLOCK g_ai_access_event_lock = SRWLOCK_INIT;
static ai_access_event_entry_t g_ai_access_events[AI_ACCESS_TRACKER_SIZE];

static const char* tls_mitm_ai_service_for_entry_host(const char* host)
{
    if (host == NULL) return NULL;
    if (_stricmp(host, "chatgpt.com") == 0 || _stricmp(host, "www.chatgpt.com") == 0) {
        return "ChatGPT";
    }
    if (_stricmp(host, "gemini.google.com") == 0) return "Gemini";
    if (_stricmp(host, "claude.ai") == 0 || _stricmp(host, "www.claude.ai") == 0) {
        return "Claude";
    }
    return NULL;
}

static int tls_mitm_should_log_ai_access(unsigned long process_id, const char* host)
{
    ULONGLONG now = GetTickCount64();
    int i;
    int replacement = 0;
    ULONGLONG oldest = ULLONG_MAX;
    int should_log = 1;

    AcquireSRWLockExclusive(&g_ai_access_event_lock);
    for (i = 0; i < AI_ACCESS_TRACKER_SIZE; ++i) {
        ai_access_event_entry_t* entry = &g_ai_access_events[i];
        if (entry->last_logged_ms == 0) {
            replacement = i;
            oldest = 0;
            continue;
        }
        if (entry->process_id == process_id && _stricmp(entry->host, host) == 0) {
            if (now - entry->last_logged_ms < AI_ACCESS_DEDUP_WINDOW_MS) {
                should_log = 0;
            }
            else {
                entry->last_logged_ms = now;
            }
            ReleaseSRWLockExclusive(&g_ai_access_event_lock);
            return should_log;
        }
        if (entry->last_logged_ms < oldest) {
            oldest = entry->last_logged_ms;
            replacement = i;
        }
    }

    g_ai_access_events[replacement].process_id = process_id;
    strcpy_s(g_ai_access_events[replacement].host, sizeof(g_ai_access_events[replacement].host), host);
    g_ai_access_events[replacement].last_logged_ms = now;
    ReleaseSRWLockExclusive(&g_ai_access_event_lock);
    return 1;
}

static void tls_mitm_resolve_runtime_path(
    const char* relative_path,
    char* resolved,
    size_t resolved_size
)
{
    char repository_path[MAX_PATH];

    if (resolved == NULL || resolved_size == 0) return;
    resolved[0] = '\0';
    if (relative_path == NULL || relative_path[0] == '\0') return;

    _snprintf_s(
        repository_path,
        sizeof(repository_path),
        _TRUNCATE,
        "relay_proxy\\%s",
        relative_path
    );
    if (GetFileAttributesA(repository_path) != INVALID_FILE_ATTRIBUTES) {
        strcpy_s(resolved, resolved_size, repository_path);
        return;
    }

    strcpy_s(resolved, resolved_size, relative_path);
}

typedef enum tls_mitm_app_protocol {
    TLS_MITM_APP_PROTOCOL_HTTP11 = 0,
    TLS_MITM_APP_PROTOCOL_HTTP2 = 1
} tls_mitm_app_protocol_t;

typedef struct tls_mitm_sni_context {
    proxy_session_context_t* session;
    char fallback_host[TLS_MITM_MAX_HOSTNAME];
    char selected_sni[TLS_MITM_MAX_HOSTNAME];
    char client_hello_sni[TLS_MITM_MAX_HOSTNAME];
    int client_hello_captured;
    int client_offers_h2;
    int client_offers_http11;
    int upstream_handshake_ready;
    tls_mitm_app_protocol_t negotiated_protocol;
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

/*
 * Browsers keep several speculative TLS connections open.  When the proxy is
 * restarted those sockets can disappear between CONNECT and SSL_accept().
 * OpenSSL reports that as an error even though it is only a client reconnect.
 */
static int tls_mitm_is_expected_client_handshake_close(
    SSL* ssl,
    int accept_result,
    int* ssl_error_out,
    int* socket_error_out
)
{
    int ssl_error;
    int socket_error;
    unsigned long openssl_error;

    ssl_error = SSL_get_error(ssl, accept_result);
    socket_error = WSAGetLastError();
    openssl_error = ERR_peek_error();

    if (ssl_error_out != NULL) {
        *ssl_error_out = ssl_error;
    }
    if (socket_error_out != NULL) {
        *socket_error_out = socket_error;
    }

    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        ERR_clear_error();
        return 1;
    }

    if (ssl_error == SSL_ERROR_SYSCALL &&
        (openssl_error == 0 ||
            socket_error == WSAECONNRESET ||
            socket_error == WSAECONNABORTED ||
            socket_error == WSAENOTCONN)) {
        ERR_clear_error();
        return 1;
    }

#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    if (ssl_error == SSL_ERROR_SSL &&
        openssl_error != 0 &&
        ERR_GET_REASON(openssl_error) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        ERR_clear_error();
        return 1;
    }
#endif

    return 0;
}

static int tls_mitm_env_flag_enabled(const char* name)
{
    char value[16];
    size_t required_size = 0;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    value[0] = '\0';

    if (getenv_s(&required_size, value, sizeof(value), name) != 0 || required_size == 0) {
        return 0;
    }

    return _stricmp(value, "1") == 0 ||
        _stricmp(value, "true") == 0 ||
        _stricmp(value, "yes") == 0 ||
        _stricmp(value, "on") == 0;
}

static int tls_mitm_add_windows_store_to_openssl(
    X509_STORE* openssl_store,
    DWORD store_location,
    const char* location_name
)
{
    HCERTSTORE windows_store;
    PCCERT_CONTEXT cert_context = NULL;
    int added = 0;

    if (openssl_store == NULL) {
        return 0;
    }

    windows_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        0,
        store_location | CERT_STORE_READONLY_FLAG,
        "ROOT"
    );
    if (windows_store == NULL) {
        log_warn(
            "failed to open Windows ROOT certificate store. location=%s win32_error=%lu",
            location_name != NULL ? location_name : "-",
            (unsigned long)GetLastError()
        );
        return 0;
    }

    while ((cert_context = CertEnumCertificatesInStore(windows_store, cert_context)) != NULL) {
        const unsigned char* encoded = cert_context->pbCertEncoded;
        X509* certificate = d2i_X509(NULL, &encoded, (long)cert_context->cbCertEncoded);

        if (certificate == NULL) {
            ERR_clear_error();
            continue;
        }

        if (X509_STORE_add_cert(openssl_store, certificate) != 1) {
            /* Duplicate roots are expected across OpenSSL and Windows stores. */
            ERR_clear_error();
        }

        /* Parsed certificates count as available even when already present. */
        added++;

        X509_free(certificate);
    }

    CertCloseStore(windows_store, 0);
    return added;
}

static int tls_mitm_load_windows_trust_roots(SSL_CTX* ctx)
{
    X509_STORE* store;
    int current_user_count;
    int local_machine_count;

    if (ctx == NULL) {
        return -1;
    }

    store = SSL_CTX_get_cert_store(ctx);
    if (store == NULL) {
        log_error("TLS MITM failed to get OpenSSL certificate store");
        return -1;
    }

    current_user_count = tls_mitm_add_windows_store_to_openssl(
        store,
        CERT_SYSTEM_STORE_CURRENT_USER,
        "CurrentUser"
    );
    local_machine_count = tls_mitm_add_windows_store_to_openssl(
        store,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        "LocalMachine"
    );

    if (current_user_count + local_machine_count <= 0) {
        log_error("TLS MITM did not load any Windows trusted root certificates");
        return -1;
    }

    log_debug(
        "TLS MITM Windows trust roots loaded. current_user=%d local_machine=%d",
        current_user_count,
        local_machine_count
    );
    return 0;
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


static int tls_mitm_alpn_select_supported_cb(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg
)
{
    static const unsigned char supported_protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    static const unsigned char h2_proto[] = {
        2, 'h', '2'
    };
    static const unsigned char http11_proto[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    const unsigned char* selectable = supported_protos;
    unsigned int selectable_len = sizeof(supported_protos);
    tls_mitm_sni_context_t* context = (tls_mitm_sni_context_t*)arg;
    int select_result;

    (void)ssl;

    if (out == NULL || outlen == NULL || in == NULL || inlen == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /*
     * The first ClientHello pass is paused while the proxy negotiates ALPN
     * with the real upstream server.  On resume, advertise exactly that
     * protocol to the browser so both TLS legs always use the same parser.
     */
    if (context != NULL && context->upstream_handshake_ready) {
        if (context->negotiated_protocol == TLS_MITM_APP_PROTOCOL_HTTP2) {
            selectable = h2_proto;
            selectable_len = sizeof(h2_proto);
        }
        else {
            selectable = http11_proto;
            selectable_len = sizeof(http11_proto);
        }
    }

    select_result = SSL_select_next_proto(
        (unsigned char**)out,
        outlen,
        selectable,
        selectable_len,
        in,
        inlen
    );

    if (select_result == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

static unsigned long long tls_mitm_env_timeout_ms(
    const char* name,
    unsigned long long default_value
)
{
    const char* value;
    char* end = NULL;
    unsigned __int64 parsed;
    if (name == NULL) return default_value;
    value = getenv(name);
    if (value == NULL || value[0] == '\0') return default_value;
    parsed = _strtoui64(value, &end, 10);
    if (end == value || end == NULL || *end != '\0' || parsed < 1000ULL ||
        parsed > 3600000ULL) return default_value;
    return (unsigned long long)parsed;
}

static void tls_mitm_capture_client_hello_sni(
    SSL* ssl,
    tls_mitm_sni_context_t* context
)
{
    const unsigned char* extension = NULL;
    size_t extension_len = 0;
    size_t name_len;

    if (ssl == NULL || context == NULL) return;

    if (SSL_client_hello_get0_ext(
        ssl,
        TLSEXT_TYPE_server_name,
        &extension,
        &extension_len
    ) != 1 || extension == NULL || extension_len < 5) {
        return;
    }

    /* ServerNameList length (2), name type (1), hostname length (2). */
    if (extension[2] != TLSEXT_NAMETYPE_host_name) return;

    name_len = ((size_t)extension[3] << 8) | extension[4];
    if (name_len == 0 || name_len > extension_len - 5) return;
    if (name_len >= sizeof(context->client_hello_sni)) {
        name_len = sizeof(context->client_hello_sni) - 1;
    }

    memcpy(context->client_hello_sni, extension + 5, name_len);
    context->client_hello_sni[name_len] = '\0';
}

static void tls_mitm_capture_client_hello_alpn(
    SSL* ssl,
    tls_mitm_sni_context_t* context
)
{
    const unsigned char* extension = NULL;
    size_t extension_len = 0;
    size_t list_len;
    size_t offset;

    if (ssl == NULL || context == NULL) return;

    context->client_offers_h2 = 0;
    context->client_offers_http11 = 0;

    if (SSL_client_hello_get0_ext(
        ssl,
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        &extension,
        &extension_len
    ) != 1 || extension == NULL || extension_len < 2) {
        /* A TLS client without ALPN is an implicit HTTP/1.1 client. */
        context->client_offers_http11 = 1;
        return;
    }

    list_len = ((size_t)extension[0] << 8) | extension[1];
    if (list_len > extension_len - 2) {
        list_len = extension_len - 2;
    }

    offset = 2;
    while (offset < 2 + list_len) {
        size_t protocol_len = extension[offset++];

        if (protocol_len == 0 || protocol_len > 2 + list_len - offset) break;

        if (protocol_len == 2 && memcmp(extension + offset, "h2", 2) == 0) {
            context->client_offers_h2 = 1;
        }
        else if (protocol_len == 8 &&
            memcmp(extension + offset, "http/1.1", 8) == 0) {
            context->client_offers_http11 = 1;
        }

        offset += protocol_len;
    }
}

static int tls_mitm_client_hello_cb(SSL* ssl, int* alert, void* arg)
{
    tls_mitm_sni_context_t* context = (tls_mitm_sni_context_t*)arg;

    (void)alert;

    if (context == NULL) return SSL_CLIENT_HELLO_SUCCESS;

    if (!context->client_hello_captured) {
        tls_mitm_capture_client_hello_sni(ssl, context);
        tls_mitm_capture_client_hello_alpn(ssl, context);
        context->client_hello_captured = 1;
    }

    if (!context->upstream_handshake_ready) {
        return SSL_CLIENT_HELLO_RETRY;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

static tls_mitm_app_protocol_t tls_mitm_get_selected_app_protocol(SSL* ssl)
{
    const unsigned char* selected = NULL;
    unsigned int selected_len = 0;

    if (ssl == NULL) {
        return TLS_MITM_APP_PROTOCOL_HTTP11;
    }

    SSL_get0_alpn_selected(ssl, &selected, &selected_len);

    if (selected != NULL && selected_len == 2 && memcmp(selected, "h2", 2) == 0) {
        return TLS_MITM_APP_PROTOCOL_HTTP2;
    }

    return TLS_MITM_APP_PROTOCOL_HTTP11;
}

static int tls_mitm_set_upstream_alpn(
    SSL* upstream_ssl,
    int client_offers_h2,
    int client_offers_http11
)
{
    static const unsigned char h2_and_http11_protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    static const unsigned char h2_proto[] = {
        2, 'h', '2'
    };
    static const unsigned char http11_proto[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };

    if (upstream_ssl == NULL) {
        return -1;
    }

    if (client_offers_h2 && client_offers_http11) {
        if (SSL_set_alpn_protos(
            upstream_ssl,
            h2_and_http11_protos,
            sizeof(h2_and_http11_protos)
        ) != 0) {
            log_error("SSL_set_alpn_protos() failed. requested upstream ALPN=h2,http/1.1");
            return -1;
        }
        return 0;
    }

    if (client_offers_h2) {
        if (SSL_set_alpn_protos(upstream_ssl, h2_proto, sizeof(h2_proto)) != 0) {
            log_error("SSL_set_alpn_protos() failed. requested upstream ALPN=h2");
            return -1;
        }
        return 0;
    }

    if (!client_offers_http11) {
        log_error("TLS MITM client offered no supported ALPN protocol");
        return -1;
    }

    if (SSL_set_alpn_protos(upstream_ssl, http11_proto, sizeof(http11_proto)) != 0) {
        log_error("SSL_set_alpn_protos() failed. requested upstream ALPN=http/1.1");
        return -1;
    }

    return 0;
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
    char cert_path[MAX_PATH];
    char key_path[MAX_PATH];

    tls_mitm_init_openssl_once();

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        tls_mitm_log_openssl_error("SSL_CTX_new(TLS_server_method) failed");
        return NULL;
    }

    tls_mitm_resolve_runtime_path(TLS_MITM_CERT_FILE, cert_path, sizeof(cert_path));
    tls_mitm_resolve_runtime_path(TLS_MITM_KEY_FILE, key_path, sizeof(key_path));

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        tls_mitm_log_openssl_error("SSL_CTX_use_certificate_file() failed. certs\\mitm.crt not found or invalid");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
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
        Select the best protocol offered by the browser. HTTP/1.1 uses the
        existing request parser and HTTP/2 uses the HPACK/stream DLP engine.
    */
    SSL_CTX_set_alpn_select_cb(ctx, tls_mitm_alpn_select_supported_cb, NULL);

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

    if (tls_mitm_env_flag_enabled(TLS_MITM_INSECURE_UPSTREAM_ENV)) {
        log_warn(
            "TLS MITM upstream certificate verification is disabled by %s. Use only in local test environments.",
            TLS_MITM_INSECURE_UPSTREAM_ENV
        );
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        /* OpenSSL on Windows does not automatically use the Windows trust stores. */
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            ERR_clear_error();
            log_debug("OpenSSL default verify paths are unavailable; using Windows trust stores");
        }

        if (tls_mitm_load_windows_trust_roots(ctx) != 0) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

static int tls_mitm_configure_upstream_hostname_verification(
    SSL* upstream_ssl,
    const char* host
)
{
    X509_VERIFY_PARAM* verify_param;

    if (upstream_ssl == NULL || host == NULL || host[0] == '\0') {
        return -1;
    }

    if (tls_mitm_env_flag_enabled(TLS_MITM_INSECURE_UPSTREAM_ENV)) {
        return 0;
    }

    verify_param = SSL_get0_param(upstream_ssl);
    if (verify_param == NULL) {
        log_error("TLS MITM failed to get upstream verification parameters. host=%s", host);
        return -1;
    }

    X509_VERIFY_PARAM_set_hostflags(verify_param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    if (cert_manager_is_ip_literal(host)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(verify_param, host) != 1) {
            log_error("TLS MITM failed to configure upstream IP certificate verification. host=%s", host);
            return -1;
        }
    }
    else {
        if (X509_VERIFY_PARAM_set1_host(verify_param, host, 0) != 1) {
            log_error("TLS MITM failed to configure upstream hostname certificate verification. host=%s", host);
            return -1;
        }
    }

    log_info("TLS MITM upstream certificate verification enabled. host=%s", host);
    return 0;
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

static int tls_mitm_request_expects_continue(const char* data, int length)
{
    int cursor;
    int header_end = -1;
    if (data == NULL || length <= 0) return 0;
    for (cursor = 0; cursor + 3 < length; ++cursor) {
        if (memcmp(data + cursor, "\r\n\r\n", 4) == 0) {
            header_end = cursor + 2;
            break;
        }
    }
    if (header_end < 0) return 0;

    for (cursor = 0; cursor + 2 < header_end; ++cursor) {
        int value_start;
        int value_end;
        if (cursor > 0 && !(data[cursor - 1] == '\n')) continue;
        if (cursor + 7 >= header_end || _strnicmp(data + cursor, "Expect:", 7) != 0) continue;
        value_start = cursor + 7;
        while (value_start < header_end &&
            (data[value_start] == ' ' || data[value_start] == '\t')) ++value_start;
        value_end = value_start;
        while (value_end < header_end && data[value_end] != '\r' && data[value_end] != '\n')
            ++value_end;
        while (value_end > value_start &&
            (data[value_end - 1] == ' ' || data[value_end - 1] == '\t')) --value_end;
        return value_end - value_start == 12 &&
            _strnicmp(data + value_start, "100-continue", 12) == 0;
    }
    return 0;
}

static int tls_read_complete_http_request(
    proxy_session_context_t* session,
    SSL* client_ssl,
    request_buffer_t* request_buffer,
    int* complete_request_length
)
{
    char buffer[TLS_MITM_BUFFER_SIZE];
    ULONGLONG started_at;
    ULONGLONG last_progress_at;
    unsigned long long request_timeout_ms;
    unsigned long long idle_timeout_ms;
    SOCKET client_socket;
    int continue_sent = 0;

    if (session == NULL || client_ssl == NULL || request_buffer == NULL || complete_request_length == NULL) {
        return -1;
    }

    *complete_request_length = 0;
    started_at = GetTickCount64();
    last_progress_at = started_at;
    request_timeout_ms = tls_mitm_env_timeout_ms(
        TLS_MITM_HTTP1_REQUEST_TIMEOUT_ENV,
        TLS_MITM_HTTP1_REQUEST_TIMEOUT_DEFAULT_MS);
    idle_timeout_ms = tls_mitm_env_timeout_ms(
        TLS_MITM_HTTP1_IDLE_TIMEOUT_ENV,
        TLS_MITM_HTTP1_IDLE_TIMEOUT_DEFAULT_MS);
    client_socket = (SOCKET)SSL_get_fd(client_ssl);

    while (1) {
        int complete_result;
        int read_len;

        complete_result = request_buffer_get_complete_request_length(
            request_buffer,
            complete_request_length
        );

        if (complete_result == -2) {
            log_security(
                "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=request_size_limit buffered_bytes=%d max_request_bytes=%d",
                session->session_id, request_buffer_length(request_buffer),
                request_buffer_max_capacity(request_buffer));
            return -1;
        }
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

        if (SSL_pending(client_ssl) <= 0) {
            ULONGLONG now = GetTickCount64();
            unsigned long long total_elapsed = now - started_at;
            unsigned long long idle_elapsed = now - last_progress_at;
            unsigned long long total_remaining;
            unsigned long long idle_remaining;
            unsigned long long wait_ms;
            fd_set read_fds;
            struct timeval timeout;
            int select_result;

            if (total_elapsed >= request_timeout_ms || idle_elapsed >= idle_timeout_ms) {
                log_security(
                    "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=request_receive_timeout buffered_bytes=%d total_elapsed_ms=%llu idle_elapsed_ms=%llu",
                    session->session_id, request_buffer_length(request_buffer),
                    total_elapsed, idle_elapsed);
                return -1;
            }
            total_remaining = request_timeout_ms - total_elapsed;
            idle_remaining = idle_timeout_ms - idle_elapsed;
            wait_ms = total_remaining < idle_remaining ? total_remaining : idle_remaining;
            FD_ZERO(&read_fds);
            FD_SET(client_socket, &read_fds);
            timeout.tv_sec = (long)(wait_ms / 1000ULL);
            timeout.tv_usec = (long)((wait_ms % 1000ULL) * 1000ULL);
            select_result = select(0, &read_fds, NULL, NULL, &timeout);
            if (select_result == 0) {
                log_security(
                    "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=request_receive_timeout buffered_bytes=%d wait_ms=%llu",
                    session->session_id, request_buffer_length(request_buffer), wait_ms);
                return -1;
            }
            if (select_result == SOCKET_ERROR) {
                log_error(
                    "HTTP/1.1 request receive select failed. session_id=%lu error=%d",
                    session->session_id, WSAGetLastError());
                return -1;
            }
        }

        read_len = SSL_read(client_ssl, buffer, sizeof(buffer));
        if (read_len <= 0) {
            int ssl_error = SSL_get_error(client_ssl, read_len);

            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                log_info(
                    "TLS MITM client closed TLS connection cleanly. session_id=%lu",
                    session->session_id
                );
                return 0;
            }

            log_error(
                "TLS MITM SSL_read() from client failed. session_id=%lu ssl_error=%d",
                session->session_id,
                ssl_error
            );
            tls_mitm_log_openssl_error("TLS MITM SSL_read() from client failed");
            return -1;
        }

        session_context_add_bytes_from_client(session, read_len);
        last_progress_at = GetTickCount64();

        log_debug(
            "TLS MITM decrypted CLIENT -> PROXY: session_id=%lu %d bytes received",
            session->session_id,
            read_len
        );

        {
            int append_result = request_buffer_append(request_buffer, buffer, read_len);
            if (append_result == -2) {
                log_security(
                    "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=request_size_limit buffered_bytes=%d incoming_bytes=%d max_request_bytes=%d",
                    session->session_id, request_buffer_length(request_buffer), read_len,
                    request_buffer_max_capacity(request_buffer));
                return -1;
            }
            if (append_result == -3) {
                log_security(
                    "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=global_request_buffer_budget_exhausted buffered_bytes=%d incoming_bytes=%d",
                    session->session_id, request_buffer_length(request_buffer), read_len);
                return -1;
            }
            if (append_result != 0) {
                log_error(
                    "TLS MITM request_buffer_append() failed. session_id=%lu",
                    session->session_id
                );
                return -1;
            }
        }

        if (!continue_sent && tls_mitm_request_expects_continue(
            request_buffer_data(request_buffer), request_buffer_length(request_buffer))) {
            int post_append_complete_length = 0;
            int post_append_result = request_buffer_get_complete_request_length(
                request_buffer, &post_append_complete_length);
            if (post_append_result == -2) {
                log_security(
                    "HTTP1_UPLOAD_FAIL_CLOSED session_id=%lu reason=request_size_limit_before_continue buffered_bytes=%d max_request_bytes=%d",
                    session->session_id, request_buffer_length(request_buffer),
                    request_buffer_max_capacity(request_buffer));
                return -1;
            }
            if (post_append_result == 0) {
                static const char continue_response[] = "HTTP/1.1 100 Continue\r\n\r\n";
                int sent = ssl_write_all(client_ssl, continue_response,
                    (int)(sizeof(continue_response) - 1));
                if (sent < 0) {
                    log_error("HTTP/1.1 100 Continue send failed. session_id=%lu",
                        session->session_id);
                    return -1;
                }
                session_context_add_bytes_to_client(session, sent);
                continue_sent = 1;
            }
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
    unsigned long metadata_upload_id = 0;
    upload_tracking_info_t upload_info;
    file_analysis_result_t file_analysis;
    int file_analysis_complete = 0;
    upload_capture_writer_t upload_capture;
    upload_capture_view_t upload_capture_view;

    memset(&upload_info, 0, sizeof(upload_info));
    memset(&file_analysis, 0, sizeof(file_analysis));
    memset(&upload_capture, 0, sizeof(upload_capture));
    memset(&upload_capture_view, 0, sizeof(upload_capture_view));

    request_buffer = (request_buffer_t*)calloc(1, sizeof(request_buffer_t));
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

    {
        int request_read_result = tls_read_complete_http_request(
            session,
            client_ssl,
            request_buffer,
            &complete_request_length
        );
        if (request_read_result != 1) {
            function_result = request_read_result == 0 ? 0 : -1;
            goto cleanup;
        }
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

    {
        char sanitized_path[UPLOAD_TRACKER_PATH_SIZE];
        upload_tracker_sanitize_path(request.path, sanitized_path, sizeof(sanitized_path));
        log_info(
            "TLS MITM decrypted HTTP request. session_id=%lu exchange_index=%d length=%d method=%s path=%s host=%s",
            session->session_id,
            exchange_index,
            complete_request_length,
            request.method,
            sanitized_path,
            request.host
        );
    }

    if (logger_is_debug_enabled()) {
        print_http_request(&request);
    }
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

        if (request.body_data != NULL && request.body_data_length > 0) {
            const void* capture_body = request.body_data;
            size_t capture_body_length = (size_t)request.body_data_length;
            unsigned char* decoded_capture_body = NULL;
            int decoded_capture_body_length = 0;

            if (chunked_decode_result == 1 &&
                chunked_decode_http_message_body(
                    request_data,
                    complete_request_length,
                    &decoded_capture_body,
                    &decoded_capture_body_length
                ) == 0) {
                capture_body = decoded_capture_body;
                capture_body_length = (size_t)decoded_capture_body_length;
            }

            if (upload_capture_begin(
                &upload_capture,
                session,
                &request,
                443,
                "http1",
                (unsigned int)exchange_index
            ) > 0) {
                upload_capture_append(&upload_capture, capture_body, capture_body_length);
                upload_capture_finish(&upload_capture, 1);
                if (upload_capture_open_complete_view(
                    &upload_capture,
                    &upload_capture_view
                ) < 0) {
                    log_warn(
                        "HTTP/1.1 complete upload capture could not be mapped. session_id=%lu exchange_index=%d file=\"%s\"",
                        session->session_id,
                        exchange_index,
                        upload_capture.file_path
                    );
                }
            }

            free(decoded_capture_body);
        }

        dlp_result = inspect_dlp_request(request_for_dlp);
        if (dlp_request_should_inspect(request_for_dlp)) {
            inspect_multipart_upload_request_with_context(
                request_for_dlp,
                &dlp_result,
                session,
                NULL,
                "http1",
                (unsigned int)exchange_index
            );
        }

        if (upload_tracker_is_metadata_request(
            request_for_dlp->method,
            request_for_dlp->host,
            request_for_dlp->path
        )) {
            const char* metadata_body = request_for_dlp->body_data != NULL
                ? request_for_dlp->body_data : request_for_dlp->body;
            size_t metadata_body_length = request_for_dlp->body_data != NULL
                ? (size_t)request_for_dlp->body_data_length : (size_t)request_for_dlp->body_length;
            metadata_upload_id = upload_tracker_record_metadata_request(
                session->session_id,
                (unsigned int)exchange_index,
                metadata_body,
                metadata_body_length
            );
        }
        else {
            const char* metadata_body = request_for_dlp->body_data != NULL
                ? request_for_dlp->body_data : request_for_dlp->body;
            size_t metadata_body_length = request_for_dlp->body_data != NULL
                ? (size_t)request_for_dlp->body_data_length : (size_t)request_for_dlp->body_length;
            metadata_upload_id = upload_tracker_record_resumable_start(
                session->session_id,
                (unsigned int)exchange_index,
                request_for_dlp,
                metadata_body,
                metadata_body_length
            );
        }

        if (dlp_request_should_inspect(request_for_dlp) &&
            strstr(request_for_dlp->content_type, "multipart/form-data") == NULL) {
            const unsigned char* file_body = (const unsigned char*)(request_for_dlp->body_data != NULL
                ? request_for_dlp->body_data : request_for_dlp->body);
            size_t file_body_length = request_for_dlp->body_data != NULL
                ? (size_t)request_for_dlp->body_data_length : (size_t)request_for_dlp->body_length;
            unsigned long long observed_file_length;
            int original_complete;
            char sanitized_path[UPLOAD_TRACKER_PATH_SIZE];
            const char* filename;
            http_request_t effective_request;
            const http_request_t* record_request;
            const char* effective_content_type;

            if (upload_capture_view.data != NULL) {
                file_body = upload_capture_view.data;
                file_body_length = upload_capture_view.length;
            }
            original_complete = upload_capture.is_fragment
                ? upload_capture.reassembly_complete : 1;
            observed_file_length = upload_capture.is_fragment && upload_capture.fragment_total_known
                ? upload_capture.fragment_total : (unsigned long long)file_body_length;

            if (!upload_tracker_match_resumable_finalize(
                session->session_id,
                request_for_dlp,
                request_for_dlp->content_length > 0
                    ? (unsigned long long)request_for_dlp->content_length
                    : (unsigned long long)file_body_length,
                &upload_info
            )) {
                upload_tracker_match_raw_put(
                    request_for_dlp->host,
                    request_for_dlp->path,
                    request_for_dlp->content_type,
                    request_for_dlp->content_length > 0
                        ? (unsigned long long)request_for_dlp->content_length
                        : (unsigned long long)file_body_length,
                    &upload_info
                );
            }
            filename = upload_info.filename[0] ? upload_info.filename : "unknown";
            effective_request = *request_for_dlp;
            if (upload_info.content_type[0]) {
                strncpy_s(effective_request.content_type, sizeof(effective_request.content_type),
                    upload_info.content_type, _TRUNCATE);
            }
            record_request = &effective_request;
            effective_content_type = record_request->content_type;
            if (upload_capture.is_fragment && !upload_capture.reassembly_complete) {
                memset(&file_analysis, 0, sizeof(file_analysis));
                file_analysis.action = FILE_ANALYSIS_BLOCK;
                strcpy_s(file_analysis.format, sizeof(file_analysis.format), "FRAGMENT");
                strcpy_s(file_analysis.reason, sizeof(file_analysis.reason),
                    "resumable upload is incomplete; fail closed before upstream release");
            }
            else if (file_analyzer_inspect(
                filename,
                effective_content_type,
                file_body,
                file_body_length,
                &file_analysis
            ) != 0) {
                memset(&file_analysis, 0, sizeof(file_analysis));
                file_analysis.action = FILE_ANALYSIS_BLOCK;
                strcpy_s(file_analysis.format, sizeof(file_analysis.format), "UNKNOWN");
                strcpy_s(file_analysis.reason, sizeof(file_analysis.reason), "file analyzer failed");
            }
            if (original_complete && file_analysis.action != FILE_ANALYSIS_BLOCK) {
                dlp_result_t content_policy = inspect_dlp_file_content(
                    filename,
                    effective_content_type,
                    file_body,
                    file_body_length,
                    &file_analysis);
                if (content_policy.action == DLP_ACTION_BLOCK) {
                    file_analysis.action = FILE_ANALYSIS_BLOCK;
                    _snprintf_s(file_analysis.reason, sizeof(file_analysis.reason), _TRUNCATE,
                        "content policy rule %d: %s", content_policy.matched_rule_id,
                        content_policy.reason[0] ? content_policy.reason : "blocked");
                    dlp_result.action = DLP_ACTION_BLOCK;
                    dlp_result.matched_rule_id = content_policy.matched_rule_id;
                    strncpy_s(dlp_result.keyword, sizeof(dlp_result.keyword),
                        content_policy.keyword[0] ? content_policy.keyword : "DOCUMENT_CONTENT", _TRUNCATE);
                    strncpy_s(dlp_result.reason, sizeof(dlp_result.reason),
                        file_analysis.reason, _TRUNCATE);
                }
            }
            file_analysis_complete = 1;
            if (upload_record_store_file_ex(
                session,
                record_request,
                NULL,
                "http1",
                (unsigned int)exchange_index,
                filename,
                file_body,
                file_body_length,
                observed_file_length,
                original_complete,
                &file_analysis
            ) < 0) {
                file_analysis.action = FILE_ANALYSIS_BLOCK;
                file_analysis.extraction_complete = 0;
                file_analysis.extraction_status = FILE_EXTRACTION_PARTIAL;
                strcpy_s(file_analysis.reason, sizeof(file_analysis.reason),
                    "upload evidence could not be stored; fail closed");
                dlp_result.action = DLP_ACTION_BLOCK;
                dlp_result.matched_rule_id = 9300;
                strcpy_s(dlp_result.keyword, sizeof(dlp_result.keyword), "AUDIT_STORAGE_FAILURE");
                strcpy_s(dlp_result.reason, sizeof(dlp_result.reason), file_analysis.reason);
            }
            if (file_analysis.action == FILE_ANALYSIS_BLOCK) {
                if (dlp_result.action != DLP_ACTION_BLOCK) {
                    dlp_result.action = DLP_ACTION_BLOCK;
                    dlp_result.matched_rule_id = 9001;
                    strncpy_s(dlp_result.keyword, sizeof(dlp_result.keyword), file_analysis.format, _TRUNCATE);
                    strncpy_s(dlp_result.reason, sizeof(dlp_result.reason), file_analysis.reason, _TRUNCATE);
                }
            }
            upload_tracker_sanitize_path(request_for_dlp->path, sanitized_path, sizeof(sanitized_path));
            log_event(
                "UPLOAD INSPECTED id=%lu session=%lu exchange=%d file=\"%s\" bytes=%llu type=%s format=%s entries=%u extracted_text_bytes=%llu sha256=%s action=%s reason=\"%s\" target=%s%s",
                upload_info.upload_id,
                session->session_id,
                exchange_index,
                filename,
                (unsigned long long)file_body_length,
                effective_content_type[0] ? effective_content_type : "unknown",
                file_analysis.format[0] ? file_analysis.format : "UNKNOWN",
                file_analysis.archive_entries,
                file_analysis.extracted_text_bytes,
                file_analysis.sha256[0] ? file_analysis.sha256 : "unavailable",
                file_analysis.action == FILE_ANALYSIS_BLOCK ? "BLOCK" : "ALLOW",
                file_analysis.reason[0] ? file_analysis.reason : "-",
                request_for_dlp->host[0] ? request_for_dlp->host : "-",
                sanitized_path
            );
        }

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

        if (logger_is_debug_enabled()) {
            print_http_response(&response);
        }
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

    if (metadata_upload_id != 0 && response.body_length > 0) {
        upload_tracker_record_metadata_response(
            metadata_upload_id,
            response.body,
            (size_t)response.body_length
        );
    }

    if (file_analysis_complete) {
        log_event(
            "UPLOAD FORWARDED id=%lu session=%lu exchange=%d file=\"%s\" upstream_status=%d",
            upload_info.upload_id,
            session->session_id,
            exchange_index,
            upload_info.filename[0] ? upload_info.filename : "unknown",
            response.status_code
        );
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
    upload_capture_close_view(&upload_capture_view);
    if (upload_capture.attempted && !upload_capture.finished) {
        upload_capture_finish(&upload_capture, 0);
    }
    if (request_buffer != NULL) {
        request_buffer_cleanup(request_buffer);
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
    tls_mitm_app_protocol_t app_protocol = TLS_MITM_APP_PROTOCOL_HTTP11;

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

    /*
     * Pause the browser handshake after parsing ClientHello.  This lets the
     * proxy offer only the browser-supported protocols upstream, observe the
     * server's real ALPN choice, and then resume with that exact protocol.
     */
    SSL_CTX_set_client_hello_cb(
        client_side_ctx,
        tls_mitm_client_hello_cb,
        &sni_context
    );
    SSL_CTX_set_alpn_select_cb(
        client_side_ctx,
        tls_mitm_alpn_select_supported_cb,
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

    {
        int accept_result;
        int ssl_error;

        accept_result = SSL_accept(client_ssl);
        ssl_error = SSL_get_error(client_ssl, accept_result);

        if (accept_result == 1 || ssl_error != SSL_ERROR_WANT_CLIENT_HELLO_CB) {
            int ssl_error = 0;
            int socket_error = 0;

            if (tls_mitm_is_expected_client_handshake_close(
                client_ssl,
                accept_result,
                &ssl_error,
                &socket_error
            )) {
                log_debug(
                    "TLS client disconnected during handshake; browser may reconnect. session_id=%lu host=%s ssl_error=%d socket_error=%d",
                    session->session_id,
                    connect_host[0] != '\0' ? connect_host : "-",
                    ssl_error,
                    socket_error
                );
                result = 0;
                goto cleanup;
            }

            log_error(
                "SSL_accept() from client failed. session_id=%lu host=%s ssl_error=%d socket_error=%d",
                session->session_id,
                connect_host[0] != '\0' ? connect_host : "-",
                ssl_error,
                socket_error
            );
            tls_mitm_log_openssl_error("OpenSSL client handshake detail");
            goto cleanup;
        }
    }

    log_debug(
        "TLS MITM ClientHello captured. session_id=%lu sni=%s offers_h2=%s offers_http11=%s",
        session->session_id,
        sni_context.client_hello_sni[0] ? sni_context.client_hello_sni : "-",
        sni_context.client_offers_h2 ? "true" : "false",
        sni_context.client_offers_http11 ? "true" : "false"
    );

    if (sni_context.client_hello_sni[0] != '\0') {
        tls_mitm_copy_string(
            client_sni,
            sizeof(client_sni),
            sni_context.client_hello_sni
        );
    }
    else if (connect_host[0] != '\0' && !cert_manager_is_ip_literal(connect_host)) {
        tls_mitm_copy_string(
            client_sni,
            sizeof(client_sni),
            connect_host
        );
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

    {
        int force_http1_upload_inspection =
            tls_mitm_env_flag_enabled(TLS_MITM_FORCE_HTTP1_UPLOAD_ENV) ||
            (upload_capture_is_enabled() &&
                tls_mitm_env_flag_enabled(DLP_BLOCK_UNSCANNABLE_ENV));
        int offer_h2_upstream = sni_context.client_offers_h2;

        if (force_http1_upload_inspection) {
            if (!sni_context.client_offers_http11) {
                log_security(
                    "AI_UPLOAD_FAIL_CLOSED session_id=%lu reason=client_does_not_offer_http1_1 h2_not_used_for_preventive_upload_dlp=true",
                    session->session_id);
                goto cleanup;
            }
            offer_h2_upstream = 0;
            log_security(
                "AI_UPLOAD_PREVENTIVE_MODE session_id=%lu protocol=http/1.1 reason=full_request_must_be_inspected_before_upstream_forward h2_buffering_not_enabled=true",
                session->session_id);
        }

        if (tls_mitm_set_upstream_alpn(
            upstream_ssl,
            offer_h2_upstream,
            sni_context.client_offers_http11
        ) != 0) {
            goto cleanup;
        }
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

    if (upstream_sni[0] != '\0') {
        if (tls_mitm_configure_upstream_hostname_verification(upstream_ssl, upstream_sni) != 0) {
            goto cleanup;
        }
    }
    else if (connect_host[0] != '\0') {
        if (tls_mitm_configure_upstream_hostname_verification(upstream_ssl, connect_host) != 0) {
            goto cleanup;
        }
    }
    else if (!tls_mitm_env_flag_enabled(TLS_MITM_INSECURE_UPSTREAM_ENV)) {
        log_error(
            "TLS MITM upstream certificate verification failed before handshake. session_id=%lu reason=no hostname",
            session->session_id
        );
        goto cleanup;
    }

    if (SSL_connect(upstream_ssl) != 1) {
        long verify_result = SSL_get_verify_result(upstream_ssl);
        log_error(
            "TLS MITM upstream handshake failed. session_id=%lu host=%s verify_result=%ld verify_error=\"%s\"",
            session->session_id,
            upstream_sni[0] != '\0' ? upstream_sni : connect_host,
            verify_result,
            X509_verify_cert_error_string(verify_result)
        );
        tls_mitm_log_openssl_error("SSL_connect() to upstream failed");
        goto cleanup;
    }

    if (!tls_mitm_env_flag_enabled(TLS_MITM_INSECURE_UPSTREAM_ENV)) {
        long verify_result = SSL_get_verify_result(upstream_ssl);

        if (verify_result != X509_V_OK) {
            log_error(
                "TLS MITM upstream certificate verification failed. session_id=%lu host=%s verify_result=%ld error=%s",
                session->session_id,
                upstream_sni[0] != '\0' ? upstream_sni : connect_host,
                verify_result,
                X509_verify_cert_error_string(verify_result)
            );
            goto cleanup;
        }

        log_info(
            "TLS MITM upstream certificate verified. session_id=%lu host=%s",
            session->session_id,
            upstream_sni[0] != '\0' ? upstream_sni : connect_host
        );
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
        const unsigned char* selected = NULL;
        unsigned int selected_len = 0;

        SSL_get0_alpn_selected(upstream_ssl, &selected, &selected_len);

        if (selected != NULL && selected_len == 2 && memcmp(selected, "h2", 2) == 0) {
            app_protocol = TLS_MITM_APP_PROTOCOL_HTTP2;
        }
        else if (selected != NULL && selected_len == 8 &&
            memcmp(selected, "http/1.1", 8) == 0) {
            app_protocol = TLS_MITM_APP_PROTOCOL_HTTP11;
        }
        else if (selected_len == 0 && sni_context.client_offers_http11) {
            /* Servers without ALPN are treated as HTTP/1.1 only. */
            app_protocol = TLS_MITM_APP_PROTOCOL_HTTP11;
        }
        else {
            log_error(
                "TLS MITM no common HTTP protocol with upstream. session_id=%lu client_h2=%s client_http11=%s upstream_alpn_length=%u",
                session->session_id,
                sni_context.client_offers_h2 ? "true" : "false",
                sni_context.client_offers_http11 ? "true" : "false",
                selected_len
            );
            goto cleanup;
        }
    }

    sni_context.negotiated_protocol = app_protocol;
    sni_context.upstream_handshake_ready = 1;

    {
        int accept_result;

        accept_result = SSL_accept(client_ssl);
        if (accept_result != 1) {
            int ssl_error = 0;
            int socket_error = 0;

            if (tls_mitm_is_expected_client_handshake_close(
                client_ssl,
                accept_result,
                &ssl_error,
                &socket_error
            )) {
                log_debug(
                    "TLS client disconnected while completing handshake; browser may reconnect. session_id=%lu host=%s ssl_error=%d socket_error=%d",
                    session->session_id,
                    connect_host[0] != '\0' ? connect_host : "-",
                    ssl_error,
                    socket_error
                );
                result = 0;
                goto cleanup;
            }

            log_error(
                "SSL_accept() completion from client failed. session_id=%lu host=%s ssl_error=%d socket_error=%d",
                session->session_id,
                connect_host[0] != '\0' ? connect_host : "-",
                ssl_error,
                socket_error
            );
            tls_mitm_log_openssl_error("OpenSSL client handshake completion detail");
            goto cleanup;
        }
    }

    if (tls_mitm_get_selected_app_protocol(client_ssl) != app_protocol) {
        log_error(
            "TLS MITM ALPN mismatch after common negotiation. session_id=%lu expected=%s client=%s",
            session->session_id,
            app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2 ? "h2" : "http/1.1",
            tls_mitm_get_selected_app_protocol(client_ssl) == TLS_MITM_APP_PROTOCOL_HTTP2
                ? "h2" : "http/1.1"
        );
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

    log_debug(
        "TLS MITM common application protocol selected. session_id=%lu protocol=%s",
        session->session_id,
        app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2 ? "h2" : "http/1.1"
    );

    {
        const char* ready_host = upstream_sni[0] != '\0' ? upstream_sni : connect_host;
        const char* service = tls_mitm_ai_service_for_entry_host(ready_host);
        if (service != NULL && tls_mitm_should_log_ai_access(
            (unsigned long)session->process.process_id,
            ready_host
        )) {
            log_event(
                "AI ACCESS service=%s process=%s process_id=%lu host=%s protocol=%s",
                service,
                session->process.process_name[0] ? session->process.process_name : "-",
                (unsigned long)session->process.process_id,
                ready_host,
                app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2 ? "h2" : "http/1.1"
            );
        }
        log_debug(
            "AI TLS READY session=%lu host=%s protocol=%s",
            session->session_id,
            ready_host,
            app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2 ? "h2" : "http/1.1"
        );
    }

    if (app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2 &&
        tls_mitm_get_selected_app_protocol(upstream_ssl) == TLS_MITM_APP_PROTOCOL_HTTP2) {
        result = http2_engine_relay_loop(
            session,
            client_ssl,
            upstream_ssl,
            upstream_sock
        );
    }
    else if (app_protocol == TLS_MITM_APP_PROTOCOL_HTTP2) {
        log_error(
            "TLS MITM HTTP/2 was selected by client but upstream did not negotiate h2. session_id=%lu",
            session->session_id
        );
        result = -1;
    }
    else {
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
