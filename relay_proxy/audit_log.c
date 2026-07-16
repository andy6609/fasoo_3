#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include "audit_log.h"
#include "logger.h"

static const char* safe_string(const char* value)
{
    if (value == NULL || value[0] == '\0') {
        return "-";
    }

    return value;
}

static const char* safe_request_path(const char* path)
{
    static __declspec(thread) char sanitized[512];
    const char* query;
    size_t length;

    if (path == NULL || path[0] == '\0') return "-";
    query = strchr(path, '?');
    length = query != NULL ? (size_t)(query - path) : strlen(path);
    if (length >= sizeof(sanitized)) length = sizeof(sanitized) - 1;
    memcpy(sanitized, path, length);
    sanitized[length] = '\0';
    return sanitized;
}

static unsigned long safe_session_id(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return 0;
    }

    return session->session_id;
}

static unsigned int safe_thread_id(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return 0;
    }

    return session->thread_id;
}

static const char* safe_client_ip(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return "-";
    }

    return safe_string(session->client_ip);
}

static int safe_client_port(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return 0;
    }

    return session->client_port;
}

static const char* safe_upstream_ip(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return "-";
    }

    return safe_string(session->upstream_ip);
}

static int safe_upstream_port(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return 0;
    }

    return session->upstream_port;
}

static unsigned long safe_process_id(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return 0;
    }

    return (unsigned long)session->process.process_id;
}

static const char* safe_process_name(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return "-";
    }

    return safe_string(session->process.process_name);
}

static const char* safe_process_path(const proxy_session_context_t* session)
{
    if (session == NULL) {
        return "-";
    }

    return safe_string(session->process.process_path);
}

void audit_log_block_event(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const dlp_result_t* result
)
{
    if (request == NULL || result == NULL) {
        log_security(
            "AUDIT session_id=%lu direction=REQUEST action=BLOCK error=\"invalid audit input\"",
            safe_session_id(session)
        );
        return;
    }

    log_security(
        "AUDIT session_id=%lu thread_id=%u direction=REQUEST action=BLOCK "
        "client=%s:%d upstream=%s:%d "
        "process_id=%lu process_name=%s process_path=\"%s\" "
        "method=%s path=%s host=%s "
        "rule_id=%d keyword=%s reason=\"%s\"",
        safe_session_id(session),
        safe_thread_id(session),
        safe_client_ip(session),
        safe_client_port(session),
        safe_upstream_ip(session),
        safe_upstream_port(session),
        safe_process_id(session),
        safe_process_name(session),
        safe_process_path(session),
        safe_string(request->method),
        safe_request_path(request->path),
        safe_string(request->host),
        result->matched_rule_id,
        safe_string(result->keyword),
        safe_string(result->reason)
    );
}

void audit_log_log_only_event(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const dlp_result_t* result
)
{
    if (request == NULL || result == NULL) {
        log_security(
            "AUDIT session_id=%lu direction=REQUEST action=LOG_ONLY error=\"invalid audit input\"",
            safe_session_id(session)
        );
        return;
    }

    log_security(
        "AUDIT session_id=%lu thread_id=%u direction=REQUEST action=LOG_ONLY "
        "client=%s:%d upstream=%s:%d "
        "process_id=%lu process_name=%s process_path=\"%s\" "
        "method=%s path=%s host=%s "
        "rule_id=%d keyword=%s reason=\"%s\"",
        safe_session_id(session),
        safe_thread_id(session),
        safe_client_ip(session),
        safe_client_port(session),
        safe_upstream_ip(session),
        safe_upstream_port(session),
        safe_process_id(session),
        safe_process_name(session),
        safe_process_path(session),
        safe_string(request->method),
        safe_request_path(request->path),
        safe_string(request->host),
        result->matched_rule_id,
        safe_string(result->keyword),
        safe_string(result->reason)
    );
}

void audit_log_response_block_event(
    const proxy_session_context_t* session,
    const http_response_t* response,
    const dlp_result_t* result
)
{
    if (response == NULL || result == NULL) {
        log_security(
            "AUDIT session_id=%lu direction=RESPONSE action=BLOCK error=\"invalid audit input\"",
            safe_session_id(session)
        );
        return;
    }

    log_security(
        "AUDIT session_id=%lu thread_id=%u direction=RESPONSE action=BLOCK "
        "client=%s:%d upstream=%s:%d "
        "process_id=%lu process_name=%s process_path=\"%s\" "
        "status=%d content_type=%s "
        "rule_id=%d keyword=%s reason=\"%s\"",
        safe_session_id(session),
        safe_thread_id(session),
        safe_client_ip(session),
        safe_client_port(session),
        safe_upstream_ip(session),
        safe_upstream_port(session),
        safe_process_id(session),
        safe_process_name(session),
        safe_process_path(session),
        response->status_code,
        safe_string(response->content_type),
        result->matched_rule_id,
        safe_string(result->keyword),
        safe_string(result->reason)
    );
}

void audit_log_response_log_only_event(
    const proxy_session_context_t* session,
    const http_response_t* response,
    const dlp_result_t* result
)
{
    if (response == NULL || result == NULL) {
        log_security(
            "AUDIT session_id=%lu direction=RESPONSE action=LOG_ONLY error=\"invalid audit input\"",
            safe_session_id(session)
        );
        return;
    }

    log_security(
        "AUDIT session_id=%lu thread_id=%u direction=RESPONSE action=LOG_ONLY "
        "client=%s:%d upstream=%s:%d "
        "process_id=%lu process_name=%s process_path=\"%s\" "
        "status=%d content_type=%s "
        "rule_id=%d keyword=%s reason=\"%s\"",
        safe_session_id(session),
        safe_thread_id(session),
        safe_client_ip(session),
        safe_client_port(session),
        safe_upstream_ip(session),
        safe_upstream_port(session),
        safe_process_id(session),
        safe_process_name(session),
        safe_process_path(session),
        response->status_code,
        safe_string(response->content_type),
        result->matched_rule_id,
        safe_string(result->keyword),
        safe_string(result->reason)
    );
}

void audit_log_connect_tunnel_event(
    const proxy_session_context_t* session,
    const http_request_t* request
)
{
    if (request == NULL) {
        log_debug(
            "AUDIT session_id=%lu direction=CONNECT action=TUNNEL error=\"invalid audit input\"",
            safe_session_id(session)
        );
        return;
    }

    log_debug(
        "AUDIT session_id=%lu thread_id=%u direction=CONNECT action=TUNNEL "
        "client=%s:%d upstream=%s:%d "
        "process_id=%lu process_name=%s process_path=\"%s\" "
        "method=%s target=%s host=%s",
        safe_session_id(session),
        safe_thread_id(session),
        safe_client_ip(session),
        safe_client_port(session),
        safe_upstream_ip(session),
        safe_upstream_port(session),
        safe_process_id(session),
        safe_process_name(session),
        safe_process_path(session),
        safe_string(request->method),
        safe_string(request->path),
        safe_string(request->host)
    );
}
