#ifndef HTTP_BLOCK_RESPONSE_H
#define HTTP_BLOCK_RESPONSE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

int send_block_response(SOCKET client_sock, const char* reason);
int send_response_block_response(SOCKET client_sock, const char* reason);

#endif