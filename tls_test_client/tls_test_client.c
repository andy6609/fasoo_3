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

#define TARGET_HOST "127.0.0.1"
#define TARGET_PORT 8443
#define BUFFER_SIZE 8192

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

static SOCKET connect_tcp(const char* host, int port)
{
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    DWORD timeout_ms = 3000;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (InetPtonA(AF_INET, host, &addr.sin_addr) != 1) {
        printf("[ERROR] InetPtonA() failed for host=%s\n", host);
        close_socket_safe(&sock);
        return INVALID_SOCKET;
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[ERROR] connect() failed: %d\n", WSAGetLastError());
        close_socket_safe(&sock);
        return INVALID_SOCKET;
    }

    return sock;
}

static int ssl_write_all(SSL* ssl, const char* data, int length)
{
    int total_sent = 0;

    while (total_sent < length) {
        int sent = SSL_write(ssl, data + total_sent, length - total_sent);

        if (sent <= 0) {
            printf("[ERROR] SSL_write failed. ssl_error=%d\n", SSL_get_error(ssl, sent));
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

int main(void)
{
    WSADATA wsa_data;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    SOCKET sock = INVALID_SOCKET;

    const char* request =
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:9443\r\n"
        "Connection: close\r\n"
        "\r\n";

    char buffer[BUFFER_SIZE];
    int read_len;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        print_openssl_error("SSL_CTX_new failed");
        WSACleanup();
        return 1;
    }

    /* POC 전용: self-signed MITM cert 검증 비활성화 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    sock = connect_tcp(TARGET_HOST, TARGET_PORT);
    if (sock == INVALID_SOCKET) {
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        print_openssl_error("SSL_new failed");
        close_socket_safe(&sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    SSL_set_fd(ssl, (int)sock);
    SSL_set_tlsext_host_name(ssl, "127.0.0.1");

    if (SSL_connect(ssl) != 1) {
        print_openssl_error("SSL_connect failed");
        SSL_free(ssl);
        close_socket_safe(&sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    printf("[CLIENT] TLS handshake complete with MITM proxy\n");
    printf("[CLIENT] sending HTTP request over TLS\n");

    if (ssl_write_all(ssl, request, (int)strlen(request)) < 0) {
        SSL_free(ssl);
        close_socket_safe(&sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    printf("\n[CLIENT] response from MITM proxy\n");
    printf("------------------------------------------------------------\n");

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        read_len = SSL_read(ssl, buffer, sizeof(buffer) - 1);

        if (read_len > 0) {
            buffer[read_len] = '\0';
            printf("%s", buffer);
            continue;
        }
        else {
            int ssl_error = SSL_get_error(ssl, read_len);

            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                break;
            }

            break;
        }
    }

    printf("\n------------------------------------------------------------\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close_socket_safe(&sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    WSACleanup();

    return 0;
}
