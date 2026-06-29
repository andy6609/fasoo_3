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

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define MITM_LISTEN_PORT 8443
#define UPSTREAM_HOST "127.0.0.1"
#define UPSTREAM_PORT 9443

#define MITM_CERT_FILE "certs/mitm.crt"
#define MITM_KEY_FILE  "certs/mitm.key"

#define BUFFER_SIZE 8192
#define RESPONSE_MAX_SIZE 65536
#define SELECT_TIMEOUT_SEC 10

static void print_openssl_error(const char* message)
{
    unsigned long err;

    printf("[ERROR] %s\n", message);

    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("        OpenSSL: %s\n", err_buf);
    }
}

static void close_socket_safe(SOCKET* sock)
{
    if (sock == NULL) {
        return;
    }

    if (*sock != INVALID_SOCKET) {
        closesocket(*sock);
        *sock = INVALID_SOCKET;
    }
}

static int init_winsock(void)
{
    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return -1;
    }

    return 0;
}

static SOCKET create_listener(int port)
{
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    int opt = 1;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    setsockopt(
        listen_sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char*)&opt,
        sizeof(opt)
    );

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[ERROR] bind() failed: %d\n", WSAGetLastError());
        close_socket_safe(&listen_sock);
        return INVALID_SOCKET;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        printf("[ERROR] listen() failed: %d\n", WSAGetLastError());
        close_socket_safe(&listen_sock);
        return INVALID_SOCKET;
    }

    return listen_sock;
}

static SOCKET connect_tcp(const char* host, int port)
{
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* ptr;
    char port_text[16];
    int gai_result;
    DWORD timeout_ms = 3000;

    if (host == NULL || port <= 0) {
        return INVALID_SOCKET;
    }

    _snprintf_s(port_text, sizeof(port_text), _TRUNCATE, "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    gai_result = getaddrinfo(host, port_text, &hints, &result);
    if (gai_result != 0) {
        printf("[ERROR] getaddrinfo() failed for %s:%d\n", host, port);
        return INVALID_SOCKET;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            break;
        }

        close_socket_safe(&sock);
    }

    freeaddrinfo(result);

    if (sock != INVALID_SOCKET) {
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    }

    return sock;
}

static int contains_ignore_case(const char* data, int length, const char* keyword)
{
    int i;
    int keyword_length;

    if (data == NULL || keyword == NULL || length <= 0 || keyword[0] == '\0') {
        return 0;
    }

    keyword_length = (int)strlen(keyword);
    if (keyword_length <= 0 || length < keyword_length) {
        return 0;
    }

    for (i = 0; i <= length - keyword_length; i++) {
        if (_strnicmp(data + i, keyword, keyword_length) == 0) {
            return 1;
        }
    }

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
            int ssl_error = SSL_get_error(ssl, sent);
            printf("[ERROR] SSL_write failed. ssl_error=%d\n", ssl_error);
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

static SSL_CTX* create_server_ctx(void)
{
    SSL_CTX* ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        print_openssl_error("SSL_CTX_new(TLS_server_method) failed");
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, MITM_CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        print_openssl_error("failed to load MITM certificate file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, MITM_KEY_FILE, SSL_FILETYPE_PEM) != 1) {
        print_openssl_error("failed to load MITM private key file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        print_openssl_error("MITM certificate/private key mismatch");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static SSL_CTX* create_client_ctx(void)
{
    SSL_CTX* ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        print_openssl_error("SSL_CTX_new(TLS_client_method) failed");
        return NULL;
    }

    /*
        POC 전용 설정.
        테스트 서버가 self-signed cert를 쓰기 때문에 검증을 끈다.
        실제 제품에서는 서버 인증서 검증 정책을 별도로 설계해야 한다.
    */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

static int read_upstream_response(SSL* upstream_ssl, char* response, int response_size)
{
    int total = 0;

    if (upstream_ssl == NULL || response == NULL || response_size <= 1) {
        return -1;
    }

    response[0] = '\0';

    while (total < response_size - 1) {
        int read_len;

        read_len = SSL_read(upstream_ssl, response + total, response_size - 1 - total);
        if (read_len > 0) {
            total += read_len;
            response[total] = '\0';
            continue;
        }
        else {
            int ssl_error = SSL_get_error(upstream_ssl, read_len);

            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                break;
            }

            /*
                테스트 서버가 응답 후 close하면 정상적으로 끝난다.
                timeout/syscall 계열은 이미 일부 응답을 받은 경우 종료로 처리한다.
            */
            if (total > 0) {
                break;
            }

            printf("[ERROR] SSL_read(upstream) failed. ssl_error=%d\n", ssl_error);
            return -1;
        }
    }

    response[total] = '\0';
    return total;
}

static int send_tls_block_response(SSL* client_ssl, const char* reason)
{
    char body[1024];
    char response[2048];
    int body_length;
    int response_length;

    if (reason == NULL || reason[0] == '\0') {
        reason = "DLP policy violation";
    }

    _snprintf_s(
        body,
        sizeof(body),
        _TRUNCATE,
        "[BLOCKED] TLS MITM DLP blocked this response.\n"
        "Reason: %s\n",
        reason
    );

    body_length = (int)strlen(body);

    _snprintf_s(
        response,
        sizeof(response),
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

    return ssl_write_all(client_ssl, response, response_length);
}

static int handle_tls_mitm_session(SSL_CTX* server_ctx, SSL_CTX* client_ctx, SOCKET client_sock)
{
    SSL* client_ssl = NULL;
    SSL* upstream_ssl = NULL;
    SOCKET upstream_sock = INVALID_SOCKET;

    char request[BUFFER_SIZE];
    int request_length;

    char response[RESPONSE_MAX_SIZE];
    int response_length;

    int result = -1;

    client_ssl = SSL_new(server_ctx);
    if (client_ssl == NULL) {
        print_openssl_error("SSL_new(client side) failed");
        goto cleanup;
    }

    SSL_set_fd(client_ssl, (int)client_sock);

    if (SSL_accept(client_ssl) != 1) {
        print_openssl_error("SSL_accept() from client failed");
        goto cleanup;
    }

    printf("[MITM] client TLS handshake complete\n");

    upstream_sock = connect_tcp(UPSTREAM_HOST, UPSTREAM_PORT);
    if (upstream_sock == INVALID_SOCKET) {
        printf("[ERROR] failed to connect upstream %s:%d\n", UPSTREAM_HOST, UPSTREAM_PORT);
        goto cleanup;
    }

    upstream_ssl = SSL_new(client_ctx);
    if (upstream_ssl == NULL) {
        print_openssl_error("SSL_new(upstream side) failed");
        goto cleanup;
    }

    SSL_set_fd(upstream_ssl, (int)upstream_sock);
    SSL_set_tlsext_host_name(upstream_ssl, UPSTREAM_HOST);

    if (SSL_connect(upstream_ssl) != 1) {
        print_openssl_error("SSL_connect() to upstream failed");
        goto cleanup;
    }

    printf("[MITM] upstream TLS handshake complete. upstream=%s:%d\n", UPSTREAM_HOST, UPSTREAM_PORT);

    memset(request, 0, sizeof(request));
    request_length = SSL_read(client_ssl, request, sizeof(request) - 1);
    if (request_length <= 0) {
        int ssl_error = SSL_get_error(client_ssl, request_length);
        printf("[ERROR] SSL_read(client request) failed. ssl_error=%d\n", ssl_error);
        goto cleanup;
    }

    request[request_length] = '\0';

    printf("\n[MITM] decrypted client request (%d bytes)\n", request_length);
    printf("------------------------------------------------------------\n");
    printf("%s\n", request);
    printf("------------------------------------------------------------\n");

    if (ssl_write_all(upstream_ssl, request, request_length) < 0) {
        goto cleanup;
    }

    memset(response, 0, sizeof(response));
    response_length = read_upstream_response(upstream_ssl, response, sizeof(response));
    if (response_length <= 0) {
        printf("[ERROR] failed to read upstream response\n");
        goto cleanup;
    }

    printf("\n[MITM] decrypted upstream response (%d bytes)\n", response_length);
    printf("------------------------------------------------------------\n");
    printf("%s\n", response);
    printf("------------------------------------------------------------\n");

    if (contains_ignore_case(response, response_length, "secret")) {
        printf("[MITM][SECURITY] keyword detected in decrypted TLS response: secret\n");
        printf("[MITM][SECURITY] sending TLS block response to client\n");

        if (send_tls_block_response(client_ssl, "Sensitive keyword detected: secret") < 0) {
            goto cleanup;
        }
    }
    else {
        if (ssl_write_all(client_ssl, response, response_length) < 0) {
            goto cleanup;
        }
    }

    result = 0;

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

    close_socket_safe(&upstream_sock);
    close_socket_safe(&client_sock);

    return result;
}

int main(void)
{
    SSL_CTX* server_ctx = NULL;
    SSL_CTX* client_ctx = NULL;
    SOCKET listen_sock = INVALID_SOCKET;

    printf("[MITM] TLS MITM POC starting...\n");
    printf("[MITM] listen      : 127.0.0.1:%d\n", MITM_LISTEN_PORT);
    printf("[MITM] upstream    : %s:%d\n", UPSTREAM_HOST, UPSTREAM_PORT);
    printf("[MITM] cert        : %s\n", MITM_CERT_FILE);
    printf("[MITM] private key : %s\n", MITM_KEY_FILE);

    if (init_winsock() != 0) {
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    server_ctx = create_server_ctx();
    if (server_ctx == NULL) {
        WSACleanup();
        return 1;
    }

    client_ctx = create_client_ctx();
    if (client_ctx == NULL) {
        SSL_CTX_free(server_ctx);
        WSACleanup();
        return 1;
    }

    listen_sock = create_listener(MITM_LISTEN_PORT);
    if (listen_sock == INVALID_SOCKET) {
        SSL_CTX_free(client_ctx);
        SSL_CTX_free(server_ctx);
        WSACleanup();
        return 1;
    }

    printf("[MITM] listening...\n");

    while (1) {
        SOCKET client_sock;
        struct sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        char client_ip[64];

        memset(&client_addr, 0, sizeof(client_addr));
        memset(client_ip, 0, sizeof(client_ip));

        client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock == INVALID_SOCKET) {
            printf("[ERROR] accept() failed: %d\n", WSAGetLastError());
            continue;
        }

        InetNtopA(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        printf("\n[MITM] client connected: %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        if (handle_tls_mitm_session(server_ctx, client_ctx, client_sock) == 0) {
            printf("[MITM] session finished normally\n");
        }
        else {
            printf("[MITM] session finished with error\n");
        }
    }

    close_socket_safe(&listen_sock);

    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    EVP_cleanup();
    WSACleanup();

    return 0;
}
