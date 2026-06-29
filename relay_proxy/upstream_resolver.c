#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "upstream_resolver.h"
#include "logger.h"

#pragma comment(lib, "Ws2_32.lib")

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

static char* trim_text(char* text)
{
    char* end;

    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;

    while (end > text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return text;
}

static int is_all_digits(const char* text)
{
    int i;

    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    for (i = 0; text[i] != '\0'; i++) {
        if (!isdigit((unsigned char)text[i])) {
            return 0;
        }
    }

    return 1;
}

static int count_char(const char* text, char ch)
{
    int count = 0;
    int i;

    if (text == NULL) {
        return 0;
    }

    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == ch) {
            count++;
        }
    }

    return count;
}

static int parse_host_and_port_with_default(
    const char* authority,
    int default_port,
    char* host_out,
    int host_out_size,
    int* port_out
)
{
    char temp[UPSTREAM_HOST_SIZE + 32];
    char* host_text;
    char* colon;
    int colon_count;
    int port;

    if (authority == NULL ||
        host_out == NULL ||
        host_out_size <= 0 ||
        port_out == NULL ||
        default_port <= 0 ||
        default_port > 65535) {
        return -1;
    }

    port = default_port;

    memset(temp, 0, sizeof(temp));
    strncpy_s(temp, sizeof(temp), authority, _TRUNCATE);

    host_text = trim_text(temp);
    if (host_text == NULL || host_text[0] == '\0') {
        return -1;
    }

    /*
        현재 단계에서는 IPv4/domain 중심으로 처리한다.

        지원:
            127.0.0.1
            127.0.0.1:9000
            localhost:9000
            example.com
            CONNECT example.com:443

        IPv6 Host 형식([::1]:9000)은 다음 단계에서 확장한다.
    */
    if (host_text[0] == '[') {
        log_warn("IPv6 authority is not supported yet: %s", host_text);
        return -1;
    }

    colon_count = count_char(host_text, ':');

    if (colon_count == 1) {
        colon = strrchr(host_text, ':');

        if (colon != NULL && colon[1] != '\0') {
            char* port_text = colon + 1;

            if (!is_all_digits(port_text)) {
                return -1;
            }

            port = atoi(port_text);
            if (port <= 0 || port > 65535) {
                return -1;
            }

            *colon = '\0';
        }
    }
    else if (colon_count > 1) {
        log_warn("IPv6-style authority is not supported yet: %s", host_text);
        return -1;
    }

    host_text = trim_text(host_text);
    if (host_text == NULL || host_text[0] == '\0') {
        return -1;
    }

    safe_copy(host_out, host_out_size, host_text);
    *port_out = port;

    return 0;
}

static int resolve_authority(
    const char* authority,
    int default_port,
    upstream_target_t* target
)
{
    char parsed_host[UPSTREAM_HOST_SIZE];
    int parsed_port;

    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* it = NULL;

    int gai_result;

    if (target == NULL) {
        return -1;
    }

    upstream_target_init(target);

    memset(parsed_host, 0, sizeof(parsed_host));
    parsed_port = default_port;

    if (parse_host_and_port_with_default(
        authority,
        default_port,
        parsed_host,
        sizeof(parsed_host),
        &parsed_port
    ) != 0) {
        log_warn("failed to parse authority: %s", authority != NULL ? authority : "-");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    gai_result = getaddrinfo(parsed_host, NULL, &hints, &result);
    if (gai_result != 0) {
        log_warn(
            "getaddrinfo() failed. host=%s error=%d",
            parsed_host,
            gai_result
        );
        return -1;
    }

    for (it = result; it != NULL; it = it->ai_next) {
        struct sockaddr_in* addr;

        if (it->ai_family != AF_INET) {
            continue;
        }

        addr = (struct sockaddr_in*)it->ai_addr;

        safe_copy(target->host, sizeof(target->host), parsed_host);
        target->port = parsed_port;

        if (InetNtopA(
            AF_INET,
            (void*)&addr->sin_addr,
            target->ip,
            sizeof(target->ip)
        ) == NULL) {
            safe_copy(target->ip, sizeof(target->ip), "-");
            freeaddrinfo(result);
            return -1;
        }

        freeaddrinfo(result);
        return 0;
    }

    freeaddrinfo(result);

    return -1;
}

void upstream_target_init(upstream_target_t* target)
{
    if (target == NULL) {
        return;
    }

    memset(target, 0, sizeof(upstream_target_t));

    safe_copy(target->host, sizeof(target->host), "-");
    safe_copy(target->ip, sizeof(target->ip), "-");
    target->port = 0;
}

int upstream_resolve_from_host_header(
    const char* host_header,
    upstream_target_t* target
)
{
    return resolve_authority(host_header, 80, target);
}

int upstream_resolve_from_connect_target(
    const char* connect_target,
    upstream_target_t* target
)
{
    return resolve_authority(connect_target, 443, target);
}

void upstream_target_log(
    unsigned long session_id,
    const upstream_target_t* target
)
{
    if (target == NULL) {
        log_warn("resolved upstream target is NULL. session_id=%lu", session_id);
        return;
    }

    log_info(
        "resolved upstream from Host. session_id=%lu host=%s ip=%s port=%d",
        session_id,
        target->host,
        target->ip,
        target->port
    );
}

void upstream_target_log_connect(
    unsigned long session_id,
    const upstream_target_t* target
)
{
    if (target == NULL) {
        log_warn("resolved CONNECT upstream target is NULL. session_id=%lu", session_id);
        return;
    }

    log_info(
        "resolved upstream for CONNECT. session_id=%lu host=%s ip=%s port=%d",
        session_id,
        target->host,
        target->ip,
        target->port
    );
}
