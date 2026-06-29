#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PROXY_PORT 8000

#define UPSTREAM_IP "127.0.0.1"
#define UPSTREAM_PORT 9000

#define BUFFER_SIZE 1024

int send_all(SOCKET sock, const char* buffer, int length) {
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

int main(void) {
	WSADATA wsaData;

	SOCKET listen_sock = INVALID_SOCKET;
	SOCKET client_sock = INVALID_SOCKET;
	SOCKET upstream_sock = INVALID_SOCKET;

	struct sockaddr_in proxy_addr;
	struct sockaddr_in client_addr;
	struct sockaddr_in upstream_addr;

	int client_addr_len = sizeof(client_addr);

	char buffer[BUFFER_SIZE];

	// 1. Winsock 초기화
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("[ERROR] WSAStartup failed\n");
		return 1;
	}

	// 2. Proxy listen 소켓 생성
	listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_sock == INVALID_SOCKET) {
		printf("[ERROR] socket() listen failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// 3. Proxy 주소 설정
	memset(&proxy_addr, 0, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxy_addr.sin_port = htons(PROXY_PORT);

	// 4. bind()
	if (bind(listen_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
		printf("[ERROR] bind() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	// 5. listen()
	if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
		printf("[ERROR] listen() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Simple proxy listening on port %d...\n", PROXY_PORT);
	printf("[INFO] Upstream server: %s:%d\n", UPSTREAM_IP, UPSTREAM_PORT);

	// 6. Client 연결 수락
	client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
	if (client_sock == INVALID_SOCKET) {
		printf("[ERROR] accept() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Client connected to proxy\n");

	// 7. Upstream 서버로 연결
	upstream_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (upstream_sock == INVALID_SOCKET) {
		printf("[ERROR] socket() upstream failed: %d\n", WSAGetLastError());
		closesocket(client_sock);
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	upstream_addr.sin_port = htons(UPSTREAM_PORT);

	if (inet_pton(AF_INET, UPSTREAM_IP, &upstream_addr.sin_addr) <= 0) {
		printf("[ERROR] inet_pton() failed\n");
		closesocket(upstream_sock);
		closesocket(client_sock);
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	if (connect(upstream_sock, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr)) == SOCKET_ERROR) {
		printf("[ERROR] connect() to upstream failed: %d\n", WSAGetLastError());
		closesocket(upstream_sock);
		closesocket(client_sock);
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Connected to upstream server\n");

	// 8. Client -> Proxy -> Upstream -> Proxy -> Client
	while (1) {
		int recv_len;
		int upstream_recv_len;

		// Client에서 데이터 받기
		recv_len = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

		if (recv_len > 0) {
			buffer[recv_len] = '\0';
			printf("[CLIENT -> PROXY] %s", buffer);

			if (send_all(upstream_sock, buffer, recv_len) == SOCKET_ERROR) {
				printf("[ERROR] send_all() to upstream failed: %d\n", WSAGetLastError());
				break;
			}

			// Upstream 서버 응답 받기
			upstream_recv_len = recv(upstream_sock, buffer, BUFFER_SIZE - 1, 0);

			if (upstream_recv_len > 0) {
				buffer[upstream_recv_len] = '\0';
				printf("[UPSTREAM -> PROXY] %s", buffer);

				// Client에게 응답 전달
				if (send_all(client_sock, buffer, upstream_recv_len) == SOCKET_ERROR) {
					printf("[ERROR] send_all() to client failed: %d\n", WSAGetLastError());
					break;
				}
			}
			else if (upstream_recv_len == 0) {
				printf("[INFO] Upstream server closed connection\n");
				break;
			}
			else {
				printf("[ERROR] recv() from upstream failed: %d\n", WSAGetLastError());
				break;
			}
		}
		else if (recv_len == 0) {
			printf("[INFO] Client disconnected\n");
			break;
		}
		else {
			printf("[ERROR] recv() from client failed: %d\n", WSAGetLastError());
			break;
		}
	}

	// 9. 정리
	closesocket(upstream_sock);
	closesocket(client_sock);
	closesocket(listen_sock);
	WSACleanup();

	return 0;
}