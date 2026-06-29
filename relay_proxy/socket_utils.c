#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "socket_utils.h"

int send_all(SOCKET sock, const char* buffer, int length)
{
    int total_sent = 0;

    while (total_sent < length) {
        int sent = send(sock, buffer + total_sent, length - total_sent, 0);

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

void close_socket_safe(SOCKET* sock)
{
    if (*sock != INVALID_SOCKET) {
        closesocket(*sock);
        *sock = INVALID_SOCKET;
    }
}

SOCKET create_listener(unsigned short port)
{
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    int opt = 1;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("[WARN] setsockopt(SO_REUSEADDR) failed: %d\n", WSAGetLastError());
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

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

SOCKET connect_upstream(const char* ip, unsigned short port)
{
    SOCKET upstream_sock = INVALID_SOCKET;
    struct sockaddr_in upstream_addr;

    upstream_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (upstream_sock == INVALID_SOCKET) {
        printf("[ERROR] upstream socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &upstream_addr.sin_addr) <= 0) {
        printf("[ERROR] inet_pton() failed\n");
        close_socket_safe(&upstream_sock);
        return INVALID_SOCKET;
    }

    if (connect(upstream_sock, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr)) == SOCKET_ERROR) {
        printf("[ERROR] connect() to upstream failed: %d\n", WSAGetLastError());
        close_socket_safe(&upstream_sock);
        return INVALID_SOCKET;
    }

    return upstream_sock;
}