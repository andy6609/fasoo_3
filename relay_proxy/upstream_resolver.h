#ifndef UPSTREAM_RESOLVER_H
#define UPSTREAM_RESOLVER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#define UPSTREAM_HOST_SIZE 256
#define UPSTREAM_IP_SIZE 64

typedef struct upstream_target {
    char host[UPSTREAM_HOST_SIZE];
    char ip[UPSTREAM_IP_SIZE];
    int port;
} upstream_target_t;

void upstream_target_init(upstream_target_t* target);

int upstream_resolve_from_host_header(
    const char* host_header,
    upstream_target_t* target
);

int upstream_resolve_from_connect_target(
    const char* connect_target,
    upstream_target_t* target
);

void upstream_target_log(
    unsigned long session_id,
    const upstream_target_t* target
);

void upstream_target_log_connect(
    unsigned long session_id,
    const upstream_target_t* target
);

#endif
