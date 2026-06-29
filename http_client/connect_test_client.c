#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")

#define PROXY_IP "127.0.0.1"
#define PROXY_PORT 8000
#define BUFFER_SIZE 4096

static int send_all_local(SOCKET sock, const char* data, int length)
{
    int total_sent = 0;

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

static SOCKET connect_to_proxy(void)
{
    SOCKET sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed. error=%d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);

    if (InetPtonA(AF_INET, PROXY_IP, &addr.sin_addr) != 1) {
        printf("InetPtonA() failed.\n");
        closesocket(sock);
        return INVALID_SOCKET;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("connect() failed. error=%d\n", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

int main(void)
{
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    char buffer[BUFFER_SIZE + 1];
    int recv_len;

    const char* connect_request =
        "CONNECT 127.0.0.1:9000 HTTP/1.1\r\n"
        "Host: 127.0.0.1:9000\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";

    const char* tunneled_http_request =
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:9000\r\n"
        "Connection: close\r\n"
        "\r\n";

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    sock = connect_to_proxy();
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    printf("[CLIENT] connected to proxy %s:%d\n", PROXY_IP, PROXY_PORT);

    if (send_all_local(sock, connect_request, (int)strlen(connect_request)) == SOCKET_ERROR) {
        printf("send CONNECT failed. error=%d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[CLIENT] CONNECT request sent.\n");

    memset(buffer, 0, sizeof(buffer));
    recv_len = recv(sock, buffer, BUFFER_SIZE, 0);
    if (recv_len <= 0) {
        printf("recv CONNECT response failed. error=%d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    buffer[recv_len] = '\0';
    printf("[CLIENT] CONNECT response:\n%s\n", buffer);

    if (strstr(buffer, "200 Connection Established") == NULL) {
        printf("[CLIENT] CONNECT tunnel was not established.\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (send_all_local(sock, tunneled_http_request, (int)strlen(tunneled_http_request)) == SOCKET_ERROR) {
        printf("send tunneled HTTP request failed. error=%d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[CLIENT] tunneled HTTP request sent.\n");

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        recv_len = recv(sock, buffer, BUFFER_SIZE, 0);

        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            printf("%s", buffer);
        }
        else if (recv_len == 0) {
            printf("\n[CLIENT] disconnected by server/proxy.\n");
            break;
        }
        else {
            printf("\nrecv tunneled response failed. error=%d\n", WSAGetLastError());
            break;
        }
    }

    closesocket(sock);
    WSACleanup();

    return 0;
}
