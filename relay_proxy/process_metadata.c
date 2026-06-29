#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Iphlpapi.h>

#include "process_metadata.h"
#include "logger.h"

#pragma comment(lib, "Iphlpapi.lib")

static void safe_copy(char* dest, int dest_size, const char* src)
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

static const char* extract_file_name(const char* path)
{
    const char* last_backslash;
    const char* last_slash;
    const char* result;

    if (path == NULL || path[0] == '\0') {
        return "-";
    }

    last_backslash = strrchr(path, '\\');
    last_slash = strrchr(path, '/');

    result = path;

    if (last_backslash != NULL && last_backslash + 1 > result) {
        result = last_backslash + 1;
    }

    if (last_slash != NULL && last_slash + 1 > result) {
        result = last_slash + 1;
    }

    if (result == NULL || result[0] == '\0') {
        return "-";
    }

    return result;
}

static int ipv4_to_addr(const char* ip, DWORD* out_addr)
{
    IN_ADDR addr;

    if (ip == NULL || out_addr == NULL) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));

    if (InetPtonA(AF_INET, ip, &addr) != 1) {
        return -1;
    }

    *out_addr = addr.S_un.S_addr;

    return 0;
}

static int tcp_row_port_to_host_order(DWORD port)
{
    return ntohs((unsigned short)port);
}

static int load_process_image_path(DWORD pid, char* path, int path_size)
{
    HANDLE process_handle;
    DWORD size;

    if (path == NULL || path_size <= 0) {
        return -1;
    }

    path[0] = '\0';

    process_handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    if (process_handle == NULL) {
        safe_copy(path, path_size, "-");
        return -1;
    }

    size = (DWORD)path_size;

    if (!QueryFullProcessImageNameA(
        process_handle,
        0,
        path,
        &size
    )) {
        CloseHandle(process_handle);
        safe_copy(path, path_size, "-");
        return -1;
    }

    CloseHandle(process_handle);

    return 0;
}

void process_metadata_init(process_metadata_t* metadata)
{
    if (metadata == NULL) {
        return;
    }

    memset(metadata, 0, sizeof(process_metadata_t));

    metadata->found = 0;
    metadata->process_id = 0;

    safe_copy(metadata->process_name, sizeof(metadata->process_name), "-");
    safe_copy(metadata->process_path, sizeof(metadata->process_path), "-");
}

static int fill_process_metadata(DWORD pid, process_metadata_t* metadata)
{
    if (metadata == NULL) {
        return -1;
    }

    process_metadata_init(metadata);

    metadata->found = 1;
    metadata->process_id = pid;

    if (load_process_image_path(
        pid,
        metadata->process_path,
        sizeof(metadata->process_path)
    ) == 0) {
        safe_copy(
            metadata->process_name,
            sizeof(metadata->process_name),
            extract_file_name(metadata->process_path)
        );
    }
    else {
        safe_copy(metadata->process_path, sizeof(metadata->process_path), "-");
        safe_copy(metadata->process_name, sizeof(metadata->process_name), "-");
    }

    return 0;
}

int process_metadata_lookup_tcp_owner(
    const char* local_ip,
    int local_port,
    const char* remote_ip,
    int remote_port,
    process_metadata_t* metadata
)
{
    DWORD local_addr;
    DWORD remote_addr;

    PMIB_TCPTABLE_OWNER_PID tcp_table;
    DWORD table_size;
    DWORD result;
    DWORD i;

    if (metadata == NULL) {
        return -1;
    }

    process_metadata_init(metadata);

    if (local_ip == NULL || remote_ip == NULL || local_port <= 0 || remote_port <= 0) {
        return -1;
    }

    if (ipv4_to_addr(local_ip, &local_addr) != 0) {
        log_warn("failed to parse local ip for process metadata: %s", local_ip);
        return -1;
    }

    if (ipv4_to_addr(remote_ip, &remote_addr) != 0) {
        log_warn("failed to parse remote ip for process metadata: %s", remote_ip);
        return -1;
    }

    table_size = 0;

    result = GetExtendedTcpTable(
        NULL,
        &table_size,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    if (result != ERROR_INSUFFICIENT_BUFFER) {
        log_warn("GetExtendedTcpTable() size query failed. error=%lu", result);
        return -1;
    }

    tcp_table = (PMIB_TCPTABLE_OWNER_PID)malloc(table_size);
    if (tcp_table == NULL) {
        log_error("malloc() failed for TCP table");
        return -1;
    }

    memset(tcp_table, 0, table_size);

    result = GetExtendedTcpTable(
        tcp_table,
        &table_size,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    if (result != NO_ERROR) {
        log_warn("GetExtendedTcpTable() failed. error=%lu", result);
        free(tcp_table);
        return -1;
    }

    /*
        우리가 찾는 연결:

        http_client.exe
            local  = client_ip:client_port
            remote = proxy_ip:proxy_port

        예:
            local  = 127.0.0.1:63480
            remote = 127.0.0.1:8000

        relay_proxy.exe 쪽 row는 반대 방향이다.

            local  = 127.0.0.1:8000
            remote = 127.0.0.1:63480

        그래서 local_port/client_port, remote_port/proxy_port 기준으로 찾는다.
    */
    for (i = 0; i < tcp_table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID* row = &tcp_table->table[i];

        int row_local_port = tcp_row_port_to_host_order(row->dwLocalPort);
        int row_remote_port = tcp_row_port_to_host_order(row->dwRemotePort);

        if (row_local_port != local_port) {
            continue;
        }

        if (row_remote_port != remote_port) {
            continue;
        }

        if (row->dwLocalAddr != local_addr) {
            continue;
        }

        if (row->dwRemoteAddr != remote_addr) {
            continue;
        }

        fill_process_metadata(row->dwOwningPid, metadata);

        free(tcp_table);

        return 0;
    }

    free(tcp_table);

    return -1;
}

void process_metadata_log(
    unsigned long session_id,
    const process_metadata_t* metadata
)
{
    if (metadata == NULL || !metadata->found) {
        log_warn(
            "process metadata not found. session_id=%lu",
            session_id
        );
        return;
    }

    log_info(
        "process metadata found. session_id=%lu pid=%lu process_name=%s process_path=\"%s\"",
        session_id,
        (unsigned long)metadata->process_id,
        metadata->process_name,
        metadata->process_path
    );
}