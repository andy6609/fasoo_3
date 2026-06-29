#ifndef PROCESS_METADATA_H
#define PROCESS_METADATA_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#define PROCESS_NAME_SIZE 260
#define PROCESS_PATH_SIZE 1024

typedef struct process_metadata {
	int found;
	DWORD process_id;
	char process_name[PROCESS_NAME_SIZE];
	char process_path[PROCESS_PATH_SIZE];
} process_metadata_t;

void process_metadata_init(process_metadata_t* metadata);

int process_metadata_lookup_tcp_owner(
	const char* local_ip,
	int local_port,
	const char* remote_ip,
	int remote_port,
	process_metadata_t* metadata
);

void process_metadata_log(
	unsigned long session_id,
	const process_metadata_t* metadata
);

#endif