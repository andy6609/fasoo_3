#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8000
#define BUFFER_SIZE 1024

int main(void) {
	WSADATA wsaData;
	SOCKET client_sock = INVALID_SOCKET;

	struct sockaddr_in server_addr;

	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];

	// 1. Winsock 초기화
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("[ERROR] WSAStrartup failed\n");
		return 1;
	}

	// 2. TCP 소켓 생성
	client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_sock == INVALID_SOCKET) {
		printf("[ERROR] socket() failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// 3. 서버 주소 설정
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);

	if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
		printf("[ERROR] inet_pton() failed\n");
		closesocket(client_sock);
		WSACleanup();
		return 1;
	}

	// 4. 서버에 연결
	if (connect(client_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
		printf("[ERROR] connect() failed: %d\n", WSAGetLastError());
		closesocket(client_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);
	printf("[INFO] Type message and press Enter. Type 'quit' to exit.\n");

	// 5. 사용자 입력 -> 서버 전송 -> 서버 응답 수신
	while (1) {
		int send_len;
		int recv_len;

		printf("\nInput> ");

		if (fgets(send_buffer, BUFFER_SIZE, stdin) == NULL) {
			printf("[INFO] fgets() failed or EOF\n");
			break;
		}

		// quit 입력 시 종료
		if (strncmp(send_buffer, "quit", 4) == 0) {
			printf("[INFO] Quit client\n");
			break;
		}

		// 서버로 데이터 전송
		send_len = send(client_sock, send_buffer, (int)strlen(send_buffer), 0);
		if (send_len == SOCKET_ERROR) {
			printf("[ERROR] send() failed: %d\n", WSAGetLastError());
			break;
		}

		// 서버 응답 수신
		recv_len = recv(client_sock, recv_buffer, BUFFER_SIZE - 1, 0);
		if (recv_len > 0) {
			recv_buffer[recv_len] = '\0';
			printf("[ECHO] %s", recv_buffer);
		}
		else if (recv_len == 0) {
			printf("[INFO] Server closed connection\n");
			break;
		}
		else {
			printf("[ERROR] recv() failed: %d\n", WSAGetLastError());
			break;
		}
	}

	// 6. 정리
	closesocket(client_sock);
	WSACleanup();

	return 0;
}