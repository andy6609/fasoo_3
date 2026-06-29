#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

int send_all(SOCKET sock, const char* data, int length);
void close_socket_safe(SOCKET* sock);
SOCKET create_listener(int port);
SOCKET connect_upstream(const char* ip, int port);

#endif