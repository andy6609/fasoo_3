#ifndef SESSION_CONTEXT_H
#define SESSION_CONTEXT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "process_metadata.h"

#define SESSION_IP_SIZE 64

typedef struct proxy_session_context {
    unsigned long session_id;

    SOCKET client_sock;

    char client_ip[SESSION_IP_SIZE];
    int client_port;

    char proxy_ip[SESSION_IP_SIZE];
    int proxy_port;

    char upstream_ip[SESSION_IP_SIZE];
    int upstream_port;

    unsigned int thread_id;

    unsigned long long bytes_from_client;
    unsigned long long bytes_to_upstream;
    unsigned long long bytes_from_upstream;
    unsigned long long bytes_to_client;

    process_metadata_t process;
} proxy_session_context_t;

void session_context_init(
    proxy_session_context_t* session,
    SOCKET client_sock,
    const struct sockaddr_in* client_addr,
    const char* upstream_ip,
    int upstream_port
);

void session_context_set_thread_id(
    proxy_session_context_t* session,
    unsigned int thread_id
);

void session_context_set_upstream(
    proxy_session_context_t* session,
    const char* upstream_ip,
    int upstream_port
);

void session_context_set_process_metadata(
    proxy_session_context_t* session,
    const process_metadata_t* metadata
);

void session_context_add_bytes_from_client(
    proxy_session_context_t* session,
    int byte_count
);

void session_context_add_bytes_to_upstream(
    proxy_session_context_t* session,
    int byte_count
);

void session_context_add_bytes_from_upstream(
    proxy_session_context_t* session,
    int byte_count
);

void session_context_add_bytes_to_client(
    proxy_session_context_t* session,
    int byte_count
);

void session_context_log_created(const proxy_session_context_t* session);
void session_context_log_started(const proxy_session_context_t* session);
void session_context_log_finished(const proxy_session_context_t* session);

#endif
