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

#define PROXY_IP "127.0.0.1"
#define PROXY_PORT 8000
#define CONNECT_TARGET "127.0.0.1:9443"
#define TLS_SNI_NAME "demo.local"
#define BUFFER_SIZE 8192
#define REQUEST_BUFFER_SIZE 4096
#define RESPONSE_BUFFER_SIZE 16384

/*
    connect_tls_keepalive_test_client.c

    Purpose:
    - Send a CONNECT request to relay_proxy:8000.
    - Perform a TLS handshake after CONNECT succeeds.
    - Send multiple HTTP requests inside the same TLS session.

    Test sequence:
    1) GET  /safe    Connection: keep-alive  -> allow
    2) POST /upload  Connection: keep-alive  -> allow
    3) GET  /secret  Connection: close       -> response DLP BLOCK

    Expected relay_proxy logs:
    - exchange_index=1 then keep-alive continues
    - exchange_index=2 then keep-alive continues
    - exchange_index=3 detects secret and blocks the response
*/

static void print_openssl_error(const char* message)
{
    unsigned long err;
    int has_error = 0;

    if (message == NULL) {
        message = "OpenSSL error";
    }

    while ((err = ERR_get_error()) != 0) {
        char text[256];
        memset(text, 0, sizeof(text));
        ERR_error_string_n(err, text, sizeof(text));
        printf("%s: %s\n", message, text);
        has_error = 1;
    }

    if (!has_error) {
        printf("%s\n", message);
    }
}

static int send_all(SOCKET sock, const char* data, int length)
{
    int total_sent = 0;

    if (data == NULL || length <= 0) {
        return SOCKET_ERROR;
    }

    while (total_sent < length) {
        int sent = send(sock, data + total_sent, length - total_sent, 0);

        if (sent == SOCKET_ERROR) {
            return SOCKET_ERROR;
        }

        if (sent == 0) {
            break;
        }

        total_sent += sent;
    }

    return total_sent;
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
            printf("[CLIENT] SSL_write() failed. ssl_error=%d\n", ssl_error);
            print_openssl_error("[CLIENT] SSL_write() OpenSSL error");
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

static SOCKET connect_tcp(const char* ip, int port)
{
    SOCKET sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[CLIENT] socket() failed. error=%d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (InetPtonA(AF_INET, ip, &addr.sin_addr) != 1) {
        printf("[CLIENT] InetPtonA() failed. ip=%s\n", ip);
        closesocket(sock);
        return INVALID_SOCKET;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[CLIENT] connect() failed. error=%d\n", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

static int recv_connect_response(SOCKET sock)
{
    char buffer[BUFFER_SIZE];
    int total = 0;

    memset(buffer, 0, sizeof(buffer));

    while (total < BUFFER_SIZE - 1) {
        int recv_len = recv(sock, buffer + total, BUFFER_SIZE - 1 - total, 0);

        if (recv_len <= 0) {
            printf("[CLIENT] failed to receive CONNECT response. recv_len=%d error=%d\n", recv_len, WSAGetLastError());
            return -1;
        }

        total += recv_len;
        buffer[total] = '\0';

        if (strstr(buffer, "\r\n\r\n") != NULL) {
            break;
        }
    }

    printf("\n[CLIENT] CONNECT response from relay_proxy\n");
    printf("============================================================\n");
    printf("%s", buffer);
    printf("============================================================\n");

    if (strstr(buffer, "200") == NULL) {
        return -1;
    }

    return 0;
}

static const char* find_header_end(const char* data)
{
    if (data == NULL) {
        return NULL;
    }

    return strstr(data, "\r\n\r\n");
}

static int get_content_length_from_response(const char* response)
{
    const char* p;

    if (response == NULL) {
        return 0;
    }

    p = response;
    while (*p != '\0') {
        if (_strnicmp(p, "Content-Length:", 15) == 0) {
            int value = 0;
            p += 15;
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            value = atoi(p);
            return value;
        }

        p = strstr(p, "\r\n");
        if (p == NULL) {
            break;
        }
        p += 2;

        if (p[0] == '\r' && p[1] == '\n') {
            break;
        }
    }

    return 0;
}

static int read_one_http_response(SSL* ssl, char* response, int response_size)
{
    int total = 0;

    if (ssl == NULL || response == NULL || response_size <= 0) {
        return -1;
    }

    memset(response, 0, response_size);

    while (total < response_size - 1) {
        int read_len;
        const char* header_end;

        read_len = SSL_read(ssl, response + total, response_size - 1 - total);
        if (read_len <= 0) {
            int ssl_error = SSL_get_error(ssl, read_len);
            printf("[CLIENT] SSL_read() finished or failed. ssl_error=%d\n", ssl_error);
            break;
        }

        total += read_len;
        response[total] = '\0';

        header_end = find_header_end(response);
        if (header_end != NULL) {
            int header_length;
            int content_length;
            int expected_total;

            header_length = (int)(header_end - response) + 4;
            content_length = get_content_length_from_response(response);
            expected_total = header_length + content_length;

            if (total >= expected_total) {
                return total;
            }
        }
    }

    if (total > 0) {
        return total;
    }

    return -1;
}

static int build_get_request(
    char* request,
    int request_size,
    const char* path,
    const char* connection_value
)
{
    if (request == NULL || request_size <= 0 || path == NULL || connection_value == NULL) {
        return -1;
    }

    _snprintf_s(
        request,
        request_size,
        _TRUNCATE,
        "GET %s HTTP/1.1\r\n"
        "Host: " CONNECT_TARGET "\r\n"
        "Connection: %s\r\n"
        "\r\n",
        path,
        connection_value
    );

    return (int)strlen(request);
}

static int build_post_request(
    char* request,
    int request_size,
    const char* path,
    const char* body,
    const char* connection_value
)
{
    int body_length;

    if (request == NULL || request_size <= 0 || path == NULL || body == NULL || connection_value == NULL) {
        return -1;
    }

    body_length = (int)strlen(body);

    _snprintf_s(
        request,
        request_size,
        _TRUNCATE,
        "POST %s HTTP/1.1\r\n"
        "Host: " CONNECT_TARGET "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n"
        "\r\n"
        "%s",
        path,
        body_length,
        connection_value,
        body
    );

    return (int)strlen(request);
}

static int send_request_and_print_response(
    SSL* ssl,
    int index,
    const char* name,
    const char* request,
    int request_length
)
{
    char response[RESPONSE_BUFFER_SIZE];
    int response_length;

    printf("\n[CLIENT] ===== exchange %d: %s =====\n", index, name);
    printf("[CLIENT] request\n");
    printf("------------------------------------------------------------\n");
    printf("%s\n", request);
    printf("------------------------------------------------------------\n");

    if (ssl_write_all(ssl, request, request_length) < 0) {
        return -1;
    }

    response_length = read_one_http_response(ssl, response, sizeof(response));
    if (response_length < 0) {
        printf("[CLIENT] failed to read HTTP response for exchange %d\n", index);
        return -1;
    }

    printf("[CLIENT] response length=%d\n", response_length);
    printf("------------------------------------------------------------\n");
    printf("%s", response);
    printf("\n------------------------------------------------------------\n");

    return 0;
}

int main(void)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    int exit_code = 1;

    const char* connect_request =
        "CONNECT " CONNECT_TARGET " HTTP/1.1\r\n"
        "Host: " CONNECT_TARGET "\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "\r\n";

    char request1[REQUEST_BUFFER_SIZE];
    char request2[REQUEST_BUFFER_SIZE];
    char request3[REQUEST_BUFFER_SIZE];
    int request1_length;
    int request2_length;
    int request3_length;

    request1_length = build_get_request(
        request1,
        sizeof(request1),
        "/safe",
        "keep-alive"
    );

    request2_length = build_post_request(
        request2,
        sizeof(request2),
        "/upload",
        "{\"message\":\"hello from keep-alive post\"}",
        "keep-alive"
    );

    request3_length = build_get_request(
        request3,
        sizeof(request3),
        "/secret",
        "close"
    );

    if (request1_length <= 0 || request2_length <= 0 || request3_length <= 0) {
        printf("[CLIENT] failed to build requests\n");
        return 1;
    }

    printf("============================================================\n");
    printf(" CONNECT TLS Keep-Alive Test Client\n");
    printf("============================================================\n");
    printf("This client sends 3 HTTP requests inside one CONNECT TLS session.\n");
    printf("TLS SNI: %s\n", TLS_SNI_NAME);
    printf("1) GET /safe      -> allow, keep-alive\n");
    printf("2) POST /upload   -> allow, keep-alive\n");
    printf("3) GET /secret    -> response block, close\n");
    printf("============================================================\n");

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[CLIENT] WSAStartup failed\n");
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    sock = connect_tcp(PROXY_IP, PROXY_PORT);
    if (sock == INVALID_SOCKET) {
        goto cleanup;
    }

    printf("[CLIENT] connected to relay_proxy %s:%d\n", PROXY_IP, PROXY_PORT);
    printf("[CLIENT] sending CONNECT request for %s\n", CONNECT_TARGET);

    if (send_all(sock, connect_request, (int)strlen(connect_request)) == SOCKET_ERROR) {
        printf("[CLIENT] send CONNECT failed. error=%d\n", WSAGetLastError());
        goto cleanup;
    }

    if (recv_connect_response(sock) != 0) {
        printf("[CLIENT] CONNECT failed\n");
        goto cleanup;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        print_openssl_error("[CLIENT] SSL_CTX_new() failed");
        goto cleanup;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        print_openssl_error("[CLIENT] SSL_new() failed");
        goto cleanup;
    }

    if (SSL_set_tlsext_host_name(ssl, TLS_SNI_NAME) != 1) {
        print_openssl_error("[CLIENT] SSL_set_tlsext_host_name() failed");
        goto cleanup;
    }

    printf("[CLIENT] SNI set: %s\n", TLS_SNI_NAME);

    SSL_set_fd(ssl, (int)sock);

    printf("[CLIENT] starting TLS handshake through CONNECT tunnel\n");

    if (SSL_connect(ssl) != 1) {
        print_openssl_error("[CLIENT] SSL_connect() failed");
        goto cleanup;
    }

    printf("[CLIENT] TLS handshake complete with relay_proxy MITM\n");

    if (send_request_and_print_response(ssl, 1, "GET /safe allow", request1, request1_length) != 0) {
        goto cleanup;
    }

    if (send_request_and_print_response(ssl, 2, "POST /upload allow", request2, request2_length) != 0) {
        goto cleanup;
    }

    if (send_request_and_print_response(ssl, 3, "GET /secret response block", request3, request3_length) != 0) {
        goto cleanup;
    }

    printf("\n[CLIENT] keep-alive TLS MITM test finished.\n");
    exit_code = 0;

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }

    if (ctx != NULL) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    WSACleanup();

    return exit_code;
}
