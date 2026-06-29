#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PROXY_IP "127.0.0.1"
#define PROXY_PORT 8000

#define BUFFER_SIZE 4096
#define REQUEST_SIZE 4096

static int send_all(SOCKET sock, const char* data, int length)
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

int main(void)
{
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;

    struct sockaddr_in server_addr;

    char request[REQUEST_SIZE];
    char response[BUFFER_SIZE + 1];

    int request_length;
    int recv_len;

    /*
        테스트용 Body.

        테스트 1: URL Encoded 이메일 탐지
        email=test%40example.com
        -> 디코딩 후 email=test@example.com
        -> EMAIL 정책에 걸려 BLOCK 되어야 함
    */
    const char* body = "message=hello";

    /*
        다른 테스트를 하고 싶으면 위 body만 바꾸면 됨.

        테스트 2:
        const char* body = "message=sec%72et";

        테스트 3:
        const char* body = "message=confidential";

        테스트 4:
        const char* body = "phone=010-1234-5678";
    */

    memset(request, 0, sizeof(request));
    memset(response, 0, sizeof(response));

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PROXY_PORT);

    if (InetPtonA(AF_INET, PROXY_IP, &server_addr.sin_addr) != 1) {
        printf("[ERROR] InetPtonA() failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[ERROR] connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[INFO] connected to proxy %s:%d\n", PROXY_IP, PROXY_PORT);

    request_length = snprintf(
        request,
        sizeof(request),
        "POST /upload HTTP/1.1\r\n"
        "Host: 127.0.0.1:9000\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        (int)strlen(body),
        body
    );

    if (request_length <= 0 || request_length >= (int)sizeof(request)) {
        printf("[ERROR] failed to build HTTP request\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("\n[HTTP REQUEST]\n%s\n", request);

    if (send_all(sock, request, request_length) == SOCKET_ERROR) {
        printf("[ERROR] send_all() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[INFO] request sent: %d bytes\n", request_length);

    while (1) {
        recv_len = recv(sock, response, BUFFER_SIZE, 0);

        if (recv_len > 0) {
            response[recv_len] = '\0';
            printf("%s", response);
        }
        else if (recv_len == 0) {
            printf("\n[INFO] server closed connection\n");
            break;
        }
        else {
            printf("[ERROR] recv() failed: %d\n", WSAGetLastError());
            break;
        }
    }

    closesocket(sock);
    WSACleanup();

    return 0;
}