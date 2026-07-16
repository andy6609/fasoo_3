#define _CRT_SECURE_NO_WARNINGS

#include "session_context.h"

#include <stdio.h>
#include <string.h>

#include "logger.h"

static volatile LONG g_next_session_id = 0;

static void copy_text(char* dest, int dest_size, const char* src)
{
    if (dest == NULL || dest_size <= 0) {
        return;
    }

    dest[0] = '\0';

    if (src == NULL || src[0] == '\0') {
        strncpy_s(dest, dest_size, "-", _TRUNCATE);
        return;
    }

    strncpy_s(dest, dest_size, src, _TRUNCATE);
}

static void set_client_address(
    proxy_session_context_t* session,
    const struct sockaddr_in* client_addr
)
{
    if (session == NULL) {
        return;
    }

    copy_text(session->client_ip, sizeof(session->client_ip), "-");
    session->client_port = 0;

    if (client_addr == NULL) {
        return;
    }

    if (InetNtopA(
        AF_INET,
        (void*)&client_addr->sin_addr,
        session->client_ip,
        sizeof(session->client_ip)
    ) == NULL) {
        copy_text(session->client_ip, sizeof(session->client_ip), "-");
    }

    session->client_port = ntohs(client_addr->sin_port);
}

static void set_proxy_address(
    proxy_session_context_t* session,
    SOCKET client_sock
)
{
    struct sockaddr_in local_addr;
    int local_addr_len;

    if (session == NULL) {
        return;
    }

    copy_text(session->proxy_ip, sizeof(session->proxy_ip), "-");
    session->proxy_port = 0;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr_len = sizeof(local_addr);

    if (getsockname(
        client_sock,
        (struct sockaddr*)&local_addr,
        &local_addr_len
    ) == SOCKET_ERROR) {
        log_warn("getsockname() failed while setting proxy address. error=%d", WSAGetLastError());
        return;
    }

    if (InetNtopA(
        AF_INET,
        (void*)&local_addr.sin_addr,
        session->proxy_ip,
        sizeof(session->proxy_ip)
    ) == NULL) {
        copy_text(session->proxy_ip, sizeof(session->proxy_ip), "-");
    }

    session->proxy_port = ntohs(local_addr.sin_port);
}

void session_context_init(
    proxy_session_context_t* session,
    SOCKET client_sock,
    const struct sockaddr_in* client_addr,
    const char* upstream_ip,
    int upstream_port
)
{
    if (session == NULL) {
        return;
    }

    memset(session, 0, sizeof(proxy_session_context_t));

    session->session_id = (unsigned long)InterlockedIncrement(&g_next_session_id);
    session->client_sock = client_sock;

    set_client_address(session, client_addr);
    set_proxy_address(session, client_sock);

    copy_text(session->upstream_ip, sizeof(session->upstream_ip), upstream_ip);
    session->upstream_port = upstream_port;

    process_metadata_init(&session->process);
}

void session_context_set_thread_id(
    proxy_session_context_t* session,
    unsigned int thread_id
)
{
    if (session == NULL) {
        return;
    }

    session->thread_id = thread_id;
}

void session_context_set_upstream(
    proxy_session_context_t* session,
    const char* upstream_ip,
    int upstream_port
)
{
    if (session == NULL) {
        return;
    }

    copy_text(session->upstream_ip, sizeof(session->upstream_ip), upstream_ip);
    session->upstream_port = upstream_port;
}

void session_context_set_process_metadata(
    proxy_session_context_t* session,
    const process_metadata_t* metadata
)
{
    if (session == NULL || metadata == NULL) {
        return;
    }

    memcpy(&session->process, metadata, sizeof(process_metadata_t));
}

void session_context_add_bytes_from_client(
    proxy_session_context_t* session,
    int byte_count
)
{
    if (session == NULL || byte_count <= 0) {
        return;
    }

    session->bytes_from_client += (unsigned long long)byte_count;
}

void session_context_add_bytes_to_upstream(
    proxy_session_context_t* session,
    int byte_count
)
{
    if (session == NULL || byte_count <= 0) {
        return;
    }

    session->bytes_to_upstream += (unsigned long long)byte_count;
}

void session_context_add_bytes_from_upstream(
    proxy_session_context_t* session,
    int byte_count
)
{
    if (session == NULL || byte_count <= 0) {
        return;
    }

    session->bytes_from_upstream += (unsigned long long)byte_count;
}

void session_context_add_bytes_to_client(
    proxy_session_context_t* session,
    int byte_count
)
{
    if (session == NULL || byte_count <= 0) {
        return;
    }

    session->bytes_to_client += (unsigned long long)byte_count;
}

void session_context_log_created(const proxy_session_context_t* session)
{
    if (session == NULL) {
        log_info("session created. session=NULL");
        return;
    }

    log_debug(
        "session created. session_id=%lu client=%s:%d proxy=%s:%d upstream=%s:%d",
        session->session_id,
        session->client_ip,
        session->client_port,
        session->proxy_ip,
        session->proxy_port,
        session->upstream_ip,
        session->upstream_port
    );
}

void session_context_log_started(const proxy_session_context_t* session)
{
    if (session == NULL) {
        log_info("session started. session=NULL");
        return;
    }

    log_info(
        "========== SESSION BEGIN id=%lu client=%s:%d process=%s(pid=%lu) thread=%u ==========",
        session->session_id,
        session->client_ip,
        session->client_port,
        session->process.process_name,
        (unsigned long)session->process.process_id,
        session->thread_id
    );
}

void session_context_log_finished(const proxy_session_context_t* session)
{
    if (session == NULL) {
        log_info("session finished. session=NULL");
        return;
    }

    log_info(
        "========== SESSION END id=%lu process=%s traffic=client:%llu/%llu upstream:%llu/%llu ==========",
        session->session_id,
        session->process.process_name,
        session->bytes_from_client,
        session->bytes_to_client,
        session->bytes_from_upstream,
        session->bytes_to_upstream
    );
}
