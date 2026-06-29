#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_PORT 9000							// 서버가 사용할 포트 번호
#define BUFFER_SIZE 1024							// 한 번에 받을 데이터 크기

int main(void) {
	WSADATA wsaData;								// Winsock 초기화 정보 저장
	SOCKET listen_sock = INVALID_SOCKET;			// 접속 대기용 소켓
	SOCKET client_sock = INVALID_SOCKET;			// 실제 데이터 송수신용 소켓

	struct sockaddr_in server_addr;					// 서버 자신의 주소 정보를 저장하는 구조체
	struct sockaddr_in client_addr;					// 클라이언트의 주소 정보를 받을 구조체 (Ex: IP, Port, etc ...)
	int client_addr_len = sizeof(client_addr);

	char buffer[BUFFER_SIZE];						// 클라이언트가 보낸 데이터를 임시로 저장할 버퍼

	// 1. Winsock 초기화
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {	// 소켓을 사용하기 위한 시작점 (Winsock 2.2 버전 사용)
		printf("[ERROR] WSAStartup failed\n");
		return 1;
	}

	// 2. TCP 소켓 생성
	listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);			// 소켓 하나 생성 (IPv4 기반 TCP 소켓)
	if (listen_sock == INVALID_SOCKET) {								// 소켓 생성이 실패했는지 확인
		printf("[ERROR] socket() failed: %d\n", WSAGetLastError());		// 소켓 관련 마지막 에러코드 프린트
		WSACleanup(); 
		return 1;
	}

	// 3. 서버 주소 설정
	memset(&server_addr, 0, sizeof(server_addr));		// server_addr 구조체를 전부 0으로 초기화 -> 쓰레기값으로 인한 문제 예방
	server_addr.sin_family = AF_INET;					// 주소 체계 = IPv4
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// 서버가 어떤 IP에서 접속을 받을지 설정 (INADDR_ANY = 모든 네트워크 인터페이스에서 접속 허용)
	server_addr.sin_port = htons(SERVER_PORT);			// 서버 포트 설정 (현재 셋팅값 9000)

	// 4. bind() <- 소켓에 IP와 포트를 연결하는 함수
	if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {	// 소켓에 IP와 포트를 연결하는 함수
		// listen_sock = 사용할 소켓, server_addr = 서버 IP/Port 정보, sizeof(server_addr) = 주소 구조체 크기
		// 9000번 포트를 이미 다른 프로그램이 사용중이라면 에러 출력
		printf("[ERROR] bind() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	// 5. listen() <- 소캣을 접속 대기 상태로 바꾸는 함수, listen()을 해야 진짜 서버처럼 클라이언트 접속을 기다림
	if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {				// SOMAXCONN = 접속 대기 큐의 최대 크기를 시스템 기본 최댓값으로 사용
		printf("[ERROR] listen() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Echo server listening on port %d...\n", SERVER_PORT);

	// 6. accept() <- 클라이언트 접속을 실제로 받아들이는 함수
	client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
	if (client_sock == INVALID_SOCKET) {								// 클라이언트 접속 수락에 실패했는지 확인
		printf("[ERROR] accept() failed: %d\n", WSAGetLastError());
		closesocket(listen_sock);
		WSACleanup();
		return 1;
	}

	printf("[INFO] Client connected\n");

	while (1) {
		int recv_len = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);			// 클라이언트가 보낸 데이터를 받는 부분
		// client_sock = 클라이언트와 연결된 소켓, buffer = 받은 데이터를 저장할 공간, BUFFER_SIZE - 1 = 최대 수신 크기, 0 = 기본 옵션

		if (recv_len > 0) {
			buffer[recv_len] = '\0';
			printf("[RECV] %s\n", buffer);

			int sent_len = send(client_sock, buffer, recv_len, 0);				// 받은 데이터를 그대로 클라이언트에게 다시 보내는 코드
			if (sent_len == SOCKET_ERROR) {
				printf("[ERROR] send() failed: %d\n", WSAGetLastError());
				break;
			}
		}
		else if (recv_len == 0) {
			printf("[INFO] Client disconnected\n");
			break;
		}
		else {
			printf("[ERROR] recv() failed: %d\n", WSAGetLastError());
			break;
		}
	}

	closesocket(client_sock);
	closesocket(listen_sock);
	WSACleanup();

	return 0;
}