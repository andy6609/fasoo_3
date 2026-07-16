#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <direct.h>
#include <stdlib.h>
#include <process.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "socket_utils.h"
#include "http_parser.h"
#include "http_response_parser.h"
#include "dlp_engine.h"
#include "http_block_response.h"
#include "logger.h"
#include "audit_log.h"
#include "request_buffer.h"
#include "response_buffer.h"
#include "policy_engine.h"
#include "session_context.h"
#include "process_metadata.h"
#include "command_thread.h"
#include "upstream_resolver.h"
#include "tls_mitm_engine.h"
#include "tls_intercept_policy.h"
#include "multipart_parser.h"
#include "content_decoder.h"
#include "chunked_decoder.h"
#include "upload_capture.h"
#include "upload_tracker.h"
#include "file_analyzer.h"

#pragma comment(lib, "Ws2_32.lib")

#define PROXY_PORT 8000
#define POLICY_FILE_PATH "policy_rules.txt"
#define TLS_INTERCEPT_POLICY_FILE_PATH "tls_intercept_policy.txt"
#define UPLOAD_CAPTURE_HOSTS_FILE_PATH "upload_capture_hosts.txt"

#define BUFFER_SIZE 4096
#define SELECT_TIMEOUT_SEC 300
#define ENABLE_TLS_MITM 1
#define UPLOAD_HOST_DISCOVERY_ENV "LOCAL_DLP_DISCOVER_UPLOAD_HOSTS"
#define UPLOAD_HOST_DISCOVERY_MIN_BYTES_ENV "LOCAL_DLP_DISCOVERY_MIN_UPLOAD_BYTES"
#define UPLOAD_HOST_DISCOVERY_DEFAULT_MIN_BYTES 4096ULL
#define UPLOAD_HOST_DISCOVERY_WINDOW_MS 2000ULL

static int environment_flag_enabled(const char* name)
{
    const char* value;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    return _stricmp(value, "1") == 0 ||
           _stricmp(value, "true") == 0 ||
           _stricmp(value, "yes") == 0 ||
           _stricmp(value, "on") == 0;
}

static unsigned long long upload_host_discovery_min_bytes(void)
{
    const char* value = getenv(UPLOAD_HOST_DISCOVERY_MIN_BYTES_ENV);
    char* end = NULL;
    unsigned __int64 parsed;

    if (value == NULL || value[0] == '\0') {
        return UPLOAD_HOST_DISCOVERY_DEFAULT_MIN_BYTES;
    }

    parsed = _strtoui64(value, &end, 10);
    if (end == value || end == NULL || *end != '\0') {
        return UPLOAD_HOST_DISCOVERY_DEFAULT_MIN_BYTES;
    }

    return (unsigned long long)parsed;
}

static int upload_host_discovery_enabled(void)
{
    return environment_flag_enabled(UPLOAD_HOST_DISCOVERY_ENV);
}

static int is_same_endpoint(
    const char* ip1,
    int port1,
    const char* ip2,
    int port2
)
{
    if (ip1 == NULL || ip2 == NULL) {
        return 0;
    }

    return (_stricmp(ip1, ip2) == 0 && port1 == port2);
}

static int ensure_upstream_connected(
    proxy_session_context_t* session,
    SOCKET* upstream_sock,
    const http_request_t* request
)
{
    upstream_target_t target;

    if (session == NULL || upstream_sock == NULL || request == NULL) {
        return -1;
    }

    if (*upstream_sock != INVALID_SOCKET) {
        return 0;
    }

    upstream_target_init(&target);

    if (upstream_resolve_from_host_header(request->host, &target) != 0) {
        log_error(
            "failed to resolve upstream from Host header. session_id=%lu host=%s",
            session->session_id,
            request->host[0] != '\0' ? request->host : "-"
        );
        return -1;
    }

    upstream_target_log(session->session_id, &target);

    if (is_same_endpoint(target.ip, target.port, session->proxy_ip, session->proxy_port)) {
        log_error(
            "resolved upstream points to proxy itself. session_id=%lu upstream=%s:%d",
            session->session_id,
            target.ip,
            target.port
        );
        return -1;
    }

    *upstream_sock = connect_upstream(target.ip, target.port);
    if (*upstream_sock == INVALID_SOCKET) {
        log_error(
            "connect_upstream() failed. session_id=%lu host=%s ip=%s port=%d",
            session->session_id,
            target.host,
            target.ip,
            target.port
        );
        return -1;
    }

    session_context_set_upstream(session, target.ip, target.port);

    log_info(
        "connected to upstream server. session_id=%lu host=%s upstream=%s:%d",
        session->session_id,
        target.host,
        target.ip,
        target.port
    );

    return 0;
}


static int is_connect_request(const http_request_t* request)
{
    if (request == NULL) {
        return 0;
    }

    return _stricmp(request->method, "CONNECT") == 0;
}

static int is_web_browser_process(const process_metadata_t* metadata)
{
    static const char* browser_names[] = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "opera_gx.exe",
        "vivaldi.exe"
    };
    size_t i;

    if (metadata == NULL || !metadata->found || metadata->process_name[0] == '\0') {
        return 0;
    }

    for (i = 0; i < sizeof(browser_names) / sizeof(browser_names[0]); i++) {
        if (_stricmp(metadata->process_name, browser_names[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int apply_upload_capture_mitm_override(
    const proxy_session_context_t* session,
    const upstream_target_t* target,
    tls_intercept_decision_t* decision
)
{
    const char* process_name;

    if (session == NULL || target == NULL || decision == NULL ||
        decision->action == TLS_INTERCEPT_ACTION_BLOCK) {
        return 0;
    }

    process_name = session->process.process_name[0] != '\0'
        ? session->process.process_name : "-";
    if (!upload_capture_host_matches(process_name, target->host, target->port)) {
        return 0;
    }

    decision->action = TLS_INTERCEPT_ACTION_MITM;
    decision->matched = 1;
    decision->matched_default = 0;
    decision->rule_port = target->port;
    _snprintf_s(
        decision->rule_process,
        sizeof(decision->rule_process),
        _TRUNCATE,
        "%s",
        process_name
    );
    _snprintf_s(
        decision->rule_host,
        sizeof(decision->rule_host),
        _TRUNCATE,
        "%s",
        target->host
    );
    _snprintf_s(
        decision->reason,
        sizeof(decision->reason),
        _TRUNCATE,
        "confirmed_upload_capture_host"
    );
    return 1;
}

static int should_suppress_connect_policy_logs(
    proxy_session_context_t* session,
    const http_request_t* request
)
{
#if ENABLE_TLS_MITM
    upstream_target_t target;
    tls_intercept_decision_t decision;
    const char* connect_target;

    if (session == NULL || request == NULL || !is_connect_request(request)) {
        return 0;
    }

    connect_target = request->path[0] != '\0' ? request->path : request->host;
    if (connect_target == NULL || connect_target[0] == '\0') {
        return 0;
    }

    upstream_target_init(&target);
    if (upstream_resolve_from_connect_target(connect_target, &target) != 0) {
        return 0;
    }

    memset(&decision, 0, sizeof(decision));
    tls_intercept_policy_decide_with_process_silent(
        target.host,
        target.port,
        session->process.process_name,
        &decision
    );
    apply_upload_capture_mitm_override(session, &target, &decision);

    return decision.action == TLS_INTERCEPT_ACTION_IGNORE;
#else
    (void)session;
    (void)request;
    return 0;
#endif
}

static int send_connect_established_response(SOCKET client_sock)
{
    const char* response =
        "HTTP/1.1 200 Connection Established\r\n"
        "Proxy-Agent: local-dlp-proxy\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";

    int response_length = (int)strlen(response);

    if (send_all(client_sock, response, response_length) == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }

    return response_length;
}

#define RAW_TUNNEL_CHUNK_DEBUG 0
#define RAW_TUNNEL_IDLE_TIMEOUT_SEC 30

static const char* safe_log_string(const char* value)
{
    if (value == NULL || value[0] == '\0') {
        return "-";
    }

    return value;
}

static void log_upload_host_discovery_summary(
    const proxy_session_context_t* session,
    const char* target_host,
    int target_port,
    unsigned long long min_upload_bytes,
    unsigned long long bytes_client_to_upstream,
    unsigned long long bytes_upstream_to_client,
    unsigned long long duration_ms,
    const char* finish_reason,
    int result,
    int burst_candidate_detected
)
{
    int total_outbound_candidate;
    int candidate;
    const char* signal;

    if (session == NULL) {
        return;
    }

    total_outbound_candidate =
        bytes_client_to_upstream >= min_upload_bytes &&
        bytes_client_to_upstream > bytes_upstream_to_client;
    candidate = burst_candidate_detected || total_outbound_candidate;

    if (burst_candidate_detected) {
        signal = "outbound_burst";
    }
    else if (total_outbound_candidate) {
        signal = "outbound_total";
    }
    else if (bytes_client_to_upstream < min_upload_bytes) {
        signal = "below_threshold";
    }
    else {
        signal = "inbound_dominant_or_balanced";
    }

    log_info(
        "UPLOAD_HOST_DISCOVERY_SUMMARY session_id=%lu process=%s target=%s:%d candidate=%s signal=%s outbound_bytes=%llu inbound_bytes=%llu min_upload_bytes=%llu duration_ms=%llu result=%s finish_reason=%s mode=encrypted_metadata_only payload_decrypted=false",
        session->session_id,
        session->process.process_name[0] != '\0' ? session->process.process_name : "-",
        safe_log_string(target_host),
        target_port,
        candidate ? "YES" : "NO",
        signal,
        bytes_client_to_upstream,
        bytes_upstream_to_client,
        min_upload_bytes,
        duration_ms,
        result == 0 ? "OK" : "ERROR",
        safe_log_string(finish_reason)
    );
}

static void log_raw_tunnel_summary(
    const proxy_session_context_t* session,
    const char* target_host,
    int target_port,
    const char* policy_action,
    const char* policy_reason,
    unsigned long long bytes_client_to_upstream,
    unsigned long long bytes_upstream_to_client,
    unsigned long long chunk_count_client_to_upstream,
    unsigned long long chunk_count_upstream_to_client,
    unsigned long long duration_ms,
    const char* finish_reason,
    int result
)
{
    if (session == NULL) {
        return;
    }

    log_debug(
        "CONNECT raw tunnel summary. session_id=%lu process=%s target=%s:%d policy_action=%s result=%s finish_reason=%s duration_ms=%llu client_to_upstream_bytes=%llu upstream_to_client_bytes=%llu client_to_upstream_chunks=%llu upstream_to_client_chunks=%llu",
        session->session_id,
        session->process.process_name[0] != '\0' ? session->process.process_name : "-",
        safe_log_string(target_host),
        target_port,
        safe_log_string(policy_action),
        result == 0 ? "OK" : "ERROR",
        safe_log_string(finish_reason),
        duration_ms,
        bytes_client_to_upstream,
        bytes_upstream_to_client,
        chunk_count_client_to_upstream,
        chunk_count_upstream_to_client
    );

    log_debug(
        "AUDIT session_id=%lu direction=CONNECT action=RAW_TUNNEL_SUMMARY process_id=%lu process_name=%s process_path=\"%s\" target=%s:%d upstream=%s:%d policy_action=%s reason=\"%s\" result=%s finish_reason=%s duration_ms=%llu bytes_client_to_upstream=%llu bytes_upstream_to_client=%llu chunks_client_to_upstream=%llu chunks_upstream_to_client=%llu",
        session->session_id,
        (unsigned long)session->process.process_id,
        session->process.process_name[0] != '\0' ? session->process.process_name : "-",
        session->process.process_path[0] != '\0' ? session->process.process_path : "-",
        safe_log_string(target_host),
        target_port,
        session->upstream_ip[0] != '\0' ? session->upstream_ip : "-",
        session->upstream_port,
        safe_log_string(policy_action),
        safe_log_string(policy_reason),
        result == 0 ? "OK" : "ERROR",
        safe_log_string(finish_reason),
        duration_ms,
        bytes_client_to_upstream,
        bytes_upstream_to_client,
        chunk_count_client_to_upstream,
        chunk_count_upstream_to_client
    );
}

static int raw_tunnel_loop(
    proxy_session_context_t* session,
    SOCKET upstream_sock,
    const char* target_host,
    int target_port,
    const char* policy_action,
    const char* policy_reason,
    int suppress_tunnel_logs
)
{
    SOCKET client_sock;
    char tunnel_buffer[BUFFER_SIZE];
    unsigned long long bytes_client_to_upstream = 0;
    unsigned long long bytes_upstream_to_client = 0;
    unsigned long long chunk_count_client_to_upstream = 0;
    unsigned long long chunk_count_upstream_to_client = 0;
    unsigned long long discovery_window_client_bytes = 0;
    unsigned long long discovery_window_upstream_bytes = 0;
    unsigned long long discovery_min_upload_bytes = 0;
    ULONGLONG started_ms;
    ULONGLONG finished_ms;
    ULONGLONG discovery_window_started_ms;
    const char* finish_reason = "unknown";
    int upload_discovery_active = 0;
    int upload_candidate_logged = 0;
    int discovery_upstream_data_observed = 0;
    int result = 0;

    if (session == NULL || upstream_sock == INVALID_SOCKET) {
        return -1;
    }

    client_sock = session->client_sock;
    started_ms = GetTickCount64();
    discovery_window_started_ms = started_ms;

    upload_discovery_active =
        suppress_tunnel_logs &&
        policy_action != NULL &&
        _stricmp(policy_action, "IGNORE") == 0 &&
        upload_host_discovery_enabled();

    if (upload_discovery_active) {
        discovery_min_upload_bytes = upload_host_discovery_min_bytes();
        log_info(
            "UPLOAD_HOST_DISCOVERY_BEGIN session_id=%lu process=%s target=%s:%d min_upload_bytes=%llu window_ms=%llu mode=encrypted_metadata_only payload_decrypted=false",
            session->session_id,
            session->process.process_name[0] != '\0' ? session->process.process_name : "-",
            safe_log_string(target_host),
            target_port,
            discovery_min_upload_bytes,
            (unsigned long long)UPLOAD_HOST_DISCOVERY_WINDOW_MS
        );
    }

    if (!suppress_tunnel_logs) {
        log_debug(
            "CONNECT raw tunnel loop started. session_id=%lu process=%s target=%s:%d policy_action=%s client=%s:%d upstream=%s:%d",
            session->session_id,
            session->process.process_name[0] != '\0' ? session->process.process_name : "-",
            safe_log_string(target_host),
            target_port,
            safe_log_string(policy_action),
            session->client_ip,
            session->client_port,
            session->upstream_ip,
            session->upstream_port
        );
    }

    while (1) {
        fd_set read_fds;
        int select_result;
        struct timeval timeout;

        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(upstream_sock, &read_fds);

        timeout.tv_sec = RAW_TUNNEL_IDLE_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        select_result = select(0, &read_fds, NULL, NULL, &timeout);

        if (select_result == SOCKET_ERROR) {
            log_error(
                "CONNECT tunnel select() failed. session_id=%lu error=%d",
                session->session_id,
                WSAGetLastError()
            );
            finish_reason = "select_error";
            result = -1;
            break;
        }

        if (select_result == 0) {
            if (!suppress_tunnel_logs) {
                log_info(
                    "CONNECT tunnel idle timeout. session_id=%lu no data for %d seconds. raw tunnel will be summarized and closed",
                    session->session_id,
                    RAW_TUNNEL_IDLE_TIMEOUT_SEC
                );
            }
            finish_reason = "idle_timeout";
            result = 0;
            break;
        }

        if (FD_ISSET(client_sock, &read_fds)) {
            int recv_len = recv(client_sock, tunnel_buffer, BUFFER_SIZE, 0);

            if (recv_len > 0) {
                if (upload_discovery_active) {
                    ULONGLONG now_ms = GetTickCount64();

                    if (now_ms - discovery_window_started_ms > UPLOAD_HOST_DISCOVERY_WINDOW_MS) {
                        discovery_window_started_ms = now_ms;
                        discovery_window_client_bytes = 0;
                        discovery_window_upstream_bytes = 0;
                    }
                    discovery_window_client_bytes += (unsigned long long)recv_len;
                }

                session_context_add_bytes_from_client(session, recv_len);

                if (send_all(upstream_sock, tunnel_buffer, recv_len) == SOCKET_ERROR) {
                    log_error(
                        "CONNECT tunnel send_all() to upstream failed. session_id=%lu error=%d",
                        session->session_id,
                        WSAGetLastError()
                    );
                    finish_reason = "send_to_upstream_error";
                    result = -1;
                    break;
                }

                session_context_add_bytes_to_upstream(session, recv_len);
                bytes_client_to_upstream += (unsigned long long)recv_len;
                chunk_count_client_to_upstream++;

#if RAW_TUNNEL_CHUNK_DEBUG
                log_debug(
                    "CONNECT TUNNEL CLIENT -> UPSTREAM: session_id=%lu %d bytes relayed",
                    session->session_id,
                    recv_len
                );
#endif
            }
            else if (recv_len == 0) {
                if (!suppress_tunnel_logs) {
                    log_debug(
                        "CONNECT tunnel client disconnected. session_id=%lu",
                        session->session_id
                    );
                }
                finish_reason = "client_disconnected";
                result = 0;
                break;
            }
            else {
                log_error(
                    "CONNECT tunnel recv() from client failed. session_id=%lu error=%d",
                    session->session_id,
                    WSAGetLastError()
                );
                finish_reason = "recv_from_client_error";
                result = -1;
                break;
            }
        }

        if (FD_ISSET(upstream_sock, &read_fds)) {
            int recv_len = recv(upstream_sock, tunnel_buffer, BUFFER_SIZE, 0);

            if (recv_len > 0) {
                if (upload_discovery_active) {
                    ULONGLONG now_ms = GetTickCount64();

                    if (now_ms - discovery_window_started_ms > UPLOAD_HOST_DISCOVERY_WINDOW_MS) {
                        discovery_window_started_ms = now_ms;
                        discovery_window_client_bytes = 0;
                        discovery_window_upstream_bytes = 0;
                    }
                    discovery_window_upstream_bytes += (unsigned long long)recv_len;
                    discovery_upstream_data_observed = 1;
                }

                session_context_add_bytes_from_upstream(session, recv_len);

                if (send_all(client_sock, tunnel_buffer, recv_len) == SOCKET_ERROR) {
                    log_error(
                        "CONNECT tunnel send_all() to client failed. session_id=%lu error=%d",
                        session->session_id,
                        WSAGetLastError()
                    );
                    finish_reason = "send_to_client_error";
                    result = -1;
                    break;
                }

                session_context_add_bytes_to_client(session, recv_len);
                bytes_upstream_to_client += (unsigned long long)recv_len;
                chunk_count_upstream_to_client++;

#if RAW_TUNNEL_CHUNK_DEBUG
                log_debug(
                    "CONNECT TUNNEL UPSTREAM -> CLIENT: session_id=%lu %d bytes relayed",
                    session->session_id,
                    recv_len
                );
#endif
            }
            else if (recv_len == 0) {
                if (!suppress_tunnel_logs) {
                    log_info(
                        "CONNECT tunnel upstream disconnected. session_id=%lu",
                        session->session_id
                    );
                }
                finish_reason = "upstream_disconnected";
                result = 0;
                break;
            }
            else {
                log_error(
                    "CONNECT tunnel recv() from upstream failed. session_id=%lu error=%d",
                    session->session_id,
                    WSAGetLastError()
                );
                finish_reason = "recv_from_upstream_error";
                result = -1;
                break;
            }
        }

        if (upload_discovery_active &&
            !upload_candidate_logged &&
            discovery_upstream_data_observed &&
            discovery_window_client_bytes >= discovery_min_upload_bytes &&
            discovery_window_client_bytes >= discovery_window_upstream_bytes * 2ULL) {
            log_info(
                "UPLOAD_HOST_CANDIDATE session_id=%lu process=%s target=%s:%d signal=outbound_burst window_outbound_bytes=%llu window_inbound_bytes=%llu min_upload_bytes=%llu window_ms=%llu mode=encrypted_metadata_only payload_decrypted=false",
                session->session_id,
                session->process.process_name[0] != '\0' ? session->process.process_name : "-",
                safe_log_string(target_host),
                target_port,
                discovery_window_client_bytes,
                discovery_window_upstream_bytes,
                discovery_min_upload_bytes,
                (unsigned long long)UPLOAD_HOST_DISCOVERY_WINDOW_MS
            );
            upload_candidate_logged = 1;
        }
    }

    finished_ms = GetTickCount64();

    if (!suppress_tunnel_logs) {
        log_raw_tunnel_summary(
            session,
            target_host,
            target_port,
            policy_action,
            policy_reason,
            bytes_client_to_upstream,
            bytes_upstream_to_client,
            chunk_count_client_to_upstream,
            chunk_count_upstream_to_client,
            (unsigned long long)(finished_ms - started_ms),
            finish_reason,
            result
        );
    }
    else if (upload_discovery_active) {
        log_upload_host_discovery_summary(
            session,
            target_host,
            target_port,
            discovery_min_upload_bytes,
            session->bytes_to_upstream,
            session->bytes_from_upstream,
            (unsigned long long)(finished_ms - started_ms),
            finish_reason,
            result,
            upload_candidate_logged
        );
    }

    return result;
}


static int forward_buffered_connect_tunnel_data(
    proxy_session_context_t* session,
    SOCKET upstream_sock,
    request_buffer_t* request_buffer
)
{
    int remaining_length;
    const char* remaining_data;

    if (session == NULL || upstream_sock == INVALID_SOCKET || request_buffer == NULL) {
        return -1;
    }

    remaining_length = request_buffer_length(request_buffer);
    if (remaining_length <= 0) {
        return 0;
    }

    remaining_data = request_buffer_data(request_buffer);
    if (remaining_data == NULL) {
        return -1;
    }

    log_debug(
        "forwarding buffered CONNECT tunnel data. session_id=%lu length=%d bytes",
        session->session_id,
        remaining_length
    );

    if (send_all(upstream_sock, remaining_data, remaining_length) == SOCKET_ERROR) {
        log_error(
            "send_all() buffered CONNECT tunnel data failed. session_id=%lu error=%d",
            session->session_id,
            WSAGetLastError()
        );
        return -1;
    }

    session_context_add_bytes_to_upstream(session, remaining_length);
    request_buffer_consume(request_buffer, remaining_length);

    return 0;
}

static int handle_connect_request(
    proxy_session_context_t* session,
    SOCKET* upstream_sock,
    const http_request_t* request,
    request_buffer_t* request_buffer,
    int complete_request_length
)
{
    upstream_target_t target;
    const char* connect_target;
    int response_sent;
    int remaining_length;
#if ENABLE_TLS_MITM
    tls_intercept_decision_t tls_policy_decision;
    int suppress_policy_logs = 0;
#endif

    if (session == NULL ||
        upstream_sock == NULL ||
        request == NULL ||
        request_buffer == NULL) {
        return -1;
    }

    if (*upstream_sock != INVALID_SOCKET) {
        log_error(
            "CONNECT request received after upstream was already connected. session_id=%lu",
            session->session_id
        );
        return -1;
    }

    connect_target = request->path[0] != '\0' ? request->path : request->host;

    upstream_target_init(&target);

    if (upstream_resolve_from_connect_target(connect_target, &target) != 0) {
        int error_response_sent;

        log_error(
            "failed to resolve CONNECT target. session_id=%lu target=%s",
            session->session_id,
            connect_target != NULL ? connect_target : "-"
        );

        error_response_sent = send_block_response(
            session->client_sock,
            "Proxy failed to resolve CONNECT target."
        );

        if (error_response_sent != SOCKET_ERROR) {
            session_context_add_bytes_to_client(session, error_response_sent);
        }

        return -1;
    }

    if (is_same_endpoint(target.ip, target.port, session->proxy_ip, session->proxy_port)) {
        int error_response_sent;

        log_error(
            "CONNECT target points to proxy itself. session_id=%lu upstream=%s:%d",
            session->session_id,
            target.ip,
            target.port
        );

        error_response_sent = send_block_response(
            session->client_sock,
            "CONNECT target points to proxy itself."
        );

        if (error_response_sent != SOCKET_ERROR) {
            session_context_add_bytes_to_client(session, error_response_sent);
        }

        return -1;
    }

#if ENABLE_TLS_MITM
    memset(&tls_policy_decision, 0, sizeof(tls_policy_decision));
    tls_intercept_policy_decide_with_process(
        target.host,
        target.port,
        session->process.process_name,
        &tls_policy_decision
    );
    if (apply_upload_capture_mitm_override(session, &target, &tls_policy_decision)) {
        log_security(
            "UPLOAD_CAPTURE_MITM_SELECTED session_id=%lu process=%s target=%s:%d source=%s",
            session->session_id,
            session->process.process_name[0] != '\0' ? session->process.process_name : "-",
            target.host,
            target.port,
            UPLOAD_CAPTURE_HOSTS_FILE_PATH
        );
    }

    suppress_policy_logs = (tls_policy_decision.action == TLS_INTERCEPT_ACTION_IGNORE);

    if (!suppress_policy_logs) {
        log_info(
            "CONNECT request detected. session_id=%lu target=%s",
            session->session_id,
            connect_target != NULL && connect_target[0] != '\0' ? connect_target : "-"
        );

        log_info(
            "CONNECT TLS policy decision. session_id=%lu process=%s target=%s:%d action=%s matched=%s rule_process=%s reason=\"%s\"",
            session->session_id,
            session->process.process_name[0] != '\0' ? session->process.process_name : "-",
            target.host,
            target.port,
            tls_intercept_policy_action_to_string(tls_policy_decision.action),
            tls_policy_decision.matched ? "rule" : "default",
            tls_policy_decision.rule_process[0] != '\0' ? tls_policy_decision.rule_process : "-",
            tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "-"
        );
    }

    if (tls_policy_decision.action == TLS_INTERCEPT_ACTION_BLOCK) {
        int block_response_sent;

        log_security(
            "CONNECT blocked by TLS intercept policy. session_id=%lu process_id=%lu process_name=%s target=%s:%d reason=\"%s\"",
            session->session_id,
            (unsigned long)session->process.process_id,
            session->process.process_name[0] != '\0' ? session->process.process_name : "-",
            target.host,
            target.port,
            tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "TLS intercept policy BLOCK"
        );

        block_response_sent = send_block_response(
            session->client_sock,
            tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "CONNECT blocked by TLS intercept policy."
        );

        if (block_response_sent == SOCKET_ERROR) {
            log_error(
                "send_block_response() for CONNECT policy block failed. session_id=%lu error=%d",
                session->session_id,
                WSAGetLastError()
            );
            return -1;
        }

        session_context_add_bytes_to_client(session, block_response_sent);
        request_buffer_consume(request_buffer, complete_request_length);
        return 0;
    }
#endif

#if ENABLE_TLS_MITM
    if (!suppress_policy_logs) {
        upstream_target_log_connect(session->session_id, &target);
    }
#else
    upstream_target_log_connect(session->session_id, &target);
#endif

    *upstream_sock = connect_upstream(target.ip, target.port);
    if (*upstream_sock == INVALID_SOCKET) {
        int error_response_sent;

        log_error(
            "connect_upstream() failed for CONNECT. session_id=%lu host=%s ip=%s port=%d",
            session->session_id,
            target.host,
            target.ip,
            target.port
        );

        error_response_sent = send_block_response(
            session->client_sock,
            "Proxy failed to connect to CONNECT upstream server."
        );

        if (error_response_sent != SOCKET_ERROR) {
            session_context_add_bytes_to_client(session, error_response_sent);
        }

        return -1;
    }

    session_context_set_upstream(session, target.ip, target.port);

#if ENABLE_TLS_MITM
    if (!suppress_policy_logs) {
        log_debug(
            "connected to CONNECT upstream. session_id=%lu host=%s upstream=%s:%d",
            session->session_id,
            target.host,
            target.ip,
            target.port
        );
    }
#else
    log_debug(
        "connected to CONNECT upstream. session_id=%lu host=%s upstream=%s:%d",
        session->session_id,
        target.host,
        target.ip,
        target.port
    );
#endif

    response_sent = send_connect_established_response(session->client_sock);
    if (response_sent == SOCKET_ERROR) {
        log_error(
            "send CONNECT 200 response failed. session_id=%lu error=%d",
            session->session_id,
            WSAGetLastError()
        );
        return -1;
    }

    session_context_add_bytes_to_client(session, response_sent);

#if ENABLE_TLS_MITM
    if (!suppress_policy_logs) {
        log_debug(
            "CONNECT tunnel established. session_id=%lu target=%s upstream=%s:%d",
            session->session_id,
            target.host,
            target.ip,
            target.port
        );
        audit_log_connect_tunnel_event(session, request);
    }
#else
    log_debug(
        "CONNECT tunnel established. session_id=%lu target=%s upstream=%s:%d",
        session->session_id,
        target.host,
        target.ip,
        target.port
    );
    audit_log_connect_tunnel_event(session, request);
#endif

    request_buffer_consume(request_buffer, complete_request_length);

    remaining_length = request_buffer_length(request_buffer);

#if ENABLE_TLS_MITM
    if (tls_policy_decision.action == TLS_INTERCEPT_ACTION_BYPASS ||
        tls_policy_decision.action == TLS_INTERCEPT_ACTION_AUDIT ||
        tls_policy_decision.action == TLS_INTERCEPT_ACTION_IGNORE) {
        if (!suppress_policy_logs) {
            log_info(
                "CONNECT TLS MITM bypassed by policy. session_id=%lu target=%s:%d action=%s mode=raw_tunnel reason=\"%s\"",
                session->session_id,
                target.host,
                target.port,
                tls_intercept_policy_action_to_string(tls_policy_decision.action),
                tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "-"
            );
        }

        if (tls_policy_decision.action == TLS_INTERCEPT_ACTION_AUDIT) {
            log_security(
                "CONNECT audit-only policy decision. session_id=%lu process_id=%lu process_name=%s target=%s:%d encrypted_bytes_will_be_relayed=true reason=\"%s\"",
                session->session_id,
                (unsigned long)session->process.process_id,
                session->process.process_name[0] != '\0' ? session->process.process_name : "-",
                target.host,
                target.port,
                tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "AUDIT"
            );
        }

        if (forward_buffered_connect_tunnel_data(session, *upstream_sock, request_buffer) != 0) {
            return -1;
        }

        return raw_tunnel_loop(
            session,
            *upstream_sock,
            target.host,
            target.port,
            tls_intercept_policy_action_to_string(tls_policy_decision.action),
            tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "-",
            suppress_policy_logs
        );
    }

    if (remaining_length > 0) {
        log_warn(
            "CONNECT buffered data exists after CONNECT header. session_id=%lu length=%d. TLS MITM mode does not support pre-read TLS bytes yet.",
            session->session_id,
            remaining_length
        );
        return -1;
    }

    log_info(
        "CONNECT TLS MITM mode selected by policy. session_id=%lu target=%s:%d upstream=%s:%d reason=\"%s\"",
        session->session_id,
        target.host,
        target.port,
        session->upstream_ip,
        session->upstream_port,
        tls_policy_decision.reason[0] != '\0' ? tls_policy_decision.reason : "-"
    );

    return tls_mitm_handle_connect_session(session, *upstream_sock, request);
#else
    if (forward_buffered_connect_tunnel_data(session, *upstream_sock, request_buffer) != 0) {
        return -1;
    }

    return raw_tunnel_loop(
        session,
        *upstream_sock,
        target.host,
        target.port,
        "RAW",
        "TLS_MITM_DISABLED",
        0
    );
#endif
}

int relay_loop(proxy_session_context_t* session)
{
    SOCKET client_sock;
    SOCKET upstream_sock = INVALID_SOCKET;

    char recv_buffer[BUFFER_SIZE];
    request_buffer_t* request_buffer = NULL;
    response_buffer_t* response_buffer = NULL;

    int loop_result = 0;

    if (session == NULL) {
        log_error("relay_loop() received NULL session");
        return -1;
    }

    client_sock = session->client_sock;

    request_buffer = (request_buffer_t*)malloc(sizeof(request_buffer_t));
    response_buffer = (response_buffer_t*)malloc(sizeof(response_buffer_t));

    if (request_buffer == NULL || response_buffer == NULL) {
        log_error(
            "relay_loop() failed to allocate HTTP buffers. session_id=%lu",
            session->session_id
        );
        if (request_buffer != NULL) {
            free(request_buffer);
        }
        if (response_buffer != NULL) {
            free(response_buffer);
        }
        return -1;
    }

    request_buffer_init(request_buffer);
    response_buffer_init(response_buffer);

    while (1) {
        fd_set read_fds;
        int select_result;
        struct timeval timeout;

        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);

        if (upstream_sock != INVALID_SOCKET) {
            FD_SET(upstream_sock, &read_fds);
        }

        timeout.tv_sec = SELECT_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        select_result = select(0, &read_fds, NULL, NULL, &timeout);

        if (select_result == SOCKET_ERROR) {
            log_error(
                "select() failed. session_id=%lu error=%d",
                session->session_id,
                WSAGetLastError()
            );
            loop_result = -1;
            break;
        }

        if (select_result == 0) {
            log_info(
                "relay timeout. session_id=%lu no data for %d seconds",
                session->session_id,
                SELECT_TIMEOUT_SEC
            );
            loop_result = 0;
            break;
        }

        /*
            Client -> Proxy -> Dynamic Upstream
        */
        if (FD_ISSET(client_sock, &read_fds)) {
            int recv_len = recv(client_sock, recv_buffer, BUFFER_SIZE, 0);

            if (recv_len > 0) {
                int append_result;

                session_context_add_bytes_from_client(session, recv_len);

                log_debug(
                    "CLIENT -> PROXY: session_id=%lu %d bytes received",
                    session->session_id,
                    recv_len
                );

                append_result = request_buffer_append(
                    request_buffer,
                    recv_buffer,
                    recv_len
                );

                if (append_result != 0) {
                    log_error(
                        "request_buffer_append() failed. session_id=%lu buffer may be full.",
                        session->session_id
                    );
                    loop_result = -1;
                    break;
                }

                log_debug(
                    "request buffer size: session_id=%lu %d bytes",
                    session->session_id,
                    request_buffer_length(request_buffer)
                );

                while (1) {
                    int complete_request_length = 0;
                    int complete_result;

                    complete_result = request_buffer_get_complete_request_length(
                        request_buffer,
                        &complete_request_length
                    );

                    if (complete_result < 0) {
                        log_error(
                            "request_buffer_get_complete_request_length() failed. session_id=%lu",
                            session->session_id
                        );
                        loop_result = -1;
                        goto cleanup;
                    }

                    if (complete_result == 0) {
                        log_debug(
                            "HTTP request is incomplete. session_id=%lu waiting for more data.",
                            session->session_id
                        );
                        break;
                    }

                    if (complete_request_length <= 0) {
                        log_error(
                            "invalid complete_request_length. session_id=%lu length=%d",
                            session->session_id,
                            complete_request_length
                        );
                        loop_result = -1;
                        goto cleanup;
                    }

                    log_debug(
                        "complete HTTP request detected. session_id=%lu length=%d bytes",
                        session->session_id,
                        complete_request_length
                    );

                    {
                        const char* request_data;
                        http_request_t request;
                        dlp_result_t dlp_result;
                        int parsed_ok;

                        request_data = request_buffer_data(request_buffer);

                        memset(&request, 0, sizeof(request));
                        memset(&dlp_result, 0, sizeof(dlp_result));
                        dlp_result.action = DLP_ACTION_ALLOW;

                        parsed_ok = parse_http_request(
                            request_data,
                            complete_request_length,
                            &request
                        );

                        if (!parsed_ok) {
                            log_error(
                                "Received data could not be parsed as HTTP request. session_id=%lu",
                                session->session_id
                            );
                            loop_result = -1;
                            goto cleanup;
                        }

                        if (!should_suppress_connect_policy_logs(session, &request)) {
                            if (logger_is_debug_enabled()) {
                                print_http_request(&request);
                            }
                            log_http_request_analysis(&request, session->session_id, "HTTP");
                        }

                        if (is_connect_request(&request)) {
                            loop_result = handle_connect_request(
                                session,
                                &upstream_sock,
                                &request,
                                request_buffer,
                                complete_request_length
                            );

                            goto cleanup;
                        }

                        {
                            http_request_t decoded_request_for_dlp;
                            const http_request_t* request_for_dlp;
                            int chunked_decode_result;

                            memset(&decoded_request_for_dlp, 0, sizeof(decoded_request_for_dlp));
                            request_for_dlp = &request;

                            chunked_decode_result = chunked_decoder_prepare_request_for_dlp(
                                &request,
                                request_data,
                                complete_request_length,
                                &decoded_request_for_dlp,
                                "PLAIN HTTP REQUEST"
                            );

                            if (chunked_decode_result == 1) {
                                request_for_dlp = &decoded_request_for_dlp;
                                log_debug(
                                    "HTTP request DLP will inspect dechunked body. session_id=%lu",
                                    session->session_id
                                );
                            }
                            else if (chunked_decode_result < 0) {
                                log_warn(
                                    "HTTP request chunk decoding failed. session_id=%lu DLP will inspect original request body.",
                                    session->session_id
                                );
                            }

                        dlp_result = inspect_dlp_request(request_for_dlp);
                        if (dlp_request_should_inspect(request_for_dlp)) {
                            inspect_multipart_upload_request(request_for_dlp, &dlp_result);
                        }

                        if (dlp_result.action == DLP_ACTION_BLOCK) {
                            int block_response_sent;

                            log_security(
                                "Request blocked. session_id=%lu Not forwarding to upstream.",
                                session->session_id
                            );
                            log_security(
                                "Matched rule id: session_id=%lu rule_id=%d",
                                session->session_id,
                                dlp_result.matched_rule_id
                            );
                            log_security(
                                "Matched keyword: session_id=%lu keyword=%s",
                                session->session_id,
                                dlp_result.keyword
                            );
                            log_security(
                                "Block reason: session_id=%lu reason=%s",
                                session->session_id,
                                dlp_result.reason
                            );

                            audit_log_block_event(session, request_for_dlp, &dlp_result);

                            block_response_sent = send_block_response(
                                client_sock,
                                dlp_result.reason
                            );

                            if (block_response_sent == SOCKET_ERROR) {
                                log_error(
                                    "send_block_response() failed. session_id=%lu error=%d",
                                    session->session_id,
                                    WSAGetLastError()
                                );
                                loop_result = -1;
                                goto cleanup;
                            }

                            session_context_add_bytes_to_client(
                                session,
                                block_response_sent
                            );

                            loop_result = 0;
                            goto cleanup;
                        }
                        else if (dlp_result.action == DLP_ACTION_LOG_ONLY) {
                            log_security(
                                "DLP log-only rule matched. session_id=%lu",
                                session->session_id
                            );
                            log_security(
                                "Matched rule id: session_id=%lu rule_id=%d",
                                session->session_id,
                                dlp_result.matched_rule_id
                            );
                            log_security(
                                "Matched keyword: session_id=%lu keyword=%s",
                                session->session_id,
                                dlp_result.keyword
                            );
                            log_security(
                                "Reason: session_id=%lu reason=%s",
                                session->session_id,
                                dlp_result.reason
                            );

                            audit_log_log_only_event(session, request_for_dlp, &dlp_result);
                        }

                        if (ensure_upstream_connected(
                            session,
                            &upstream_sock,
                            &request
                        ) != 0) {
                            int error_response_sent;

                            error_response_sent = send_block_response(
                                client_sock,
                                "Proxy failed to resolve or connect to upstream server."
                            );

                            if (error_response_sent != SOCKET_ERROR) {
                                session_context_add_bytes_to_client(
                                    session,
                                    error_response_sent
                                );
                            }

                            loop_result = -1;
                            goto cleanup;
                        }

                        if (send_all(upstream_sock, request_data, complete_request_length) == SOCKET_ERROR) {
                            log_error(
                                "send_all() to upstream failed. session_id=%lu error=%d",
                                session->session_id,
                                WSAGetLastError()
                            );
                            loop_result = -1;
                            goto cleanup;
                        }

                        session_context_add_bytes_to_upstream(
                            session,
                            complete_request_length
                        );

                        log_debug(
                            "PROXY -> UPSTREAM: session_id=%lu %d bytes forwarded",
                            session->session_id,
                            complete_request_length
                        );

                        request_buffer_consume(
                            request_buffer,
                            complete_request_length
                        );
                    }
                }
            }
            }
            else if (recv_len == 0) {
                log_info(
                    "client disconnected. session_id=%lu",
                    session->session_id
                );
                loop_result = 0;
                break;
            }
            else {
                log_error(
                    "recv() from client failed. session_id=%lu error=%d",
                    session->session_id,
                    WSAGetLastError()
                );
                loop_result = -1;
                break;
            }
        }

        /*
            Dynamic Upstream -> Proxy -> Client
        */
        if (upstream_sock != INVALID_SOCKET && FD_ISSET(upstream_sock, &read_fds)) {
            int recv_len = recv(upstream_sock, recv_buffer, BUFFER_SIZE, 0);

            if (recv_len > 0) {
                int append_result;

                session_context_add_bytes_from_upstream(session, recv_len);

                log_debug(
                    "UPSTREAM -> PROXY: session_id=%lu %d bytes received",
                    session->session_id,
                    recv_len
                );

                append_result = response_buffer_append(
                    response_buffer,
                    recv_buffer,
                    recv_len
                );

                if (append_result != 0) {
                    log_error(
                        "response_buffer_append() failed. session_id=%lu buffer may be full.",
                        session->session_id
                    );
                    loop_result = -1;
                    break;
                }

                log_debug(
                    "response buffer size: session_id=%lu %d bytes",
                    session->session_id,
                    response_buffer_length(response_buffer)
                );

                while (1) {
                    int complete_response_length = 0;
                    int complete_result;

                    complete_result = response_buffer_get_complete_response_length(
                        response_buffer,
                        &complete_response_length
                    );

                    if (complete_result < 0) {
                        log_error(
                            "response_buffer_get_complete_response_length() failed. session_id=%lu",
                            session->session_id
                        );
                        loop_result = -1;
                        goto cleanup;
                    }

                    if (complete_result == 0) {
                        log_debug(
                            "HTTP response is incomplete. session_id=%lu waiting for more data.",
                            session->session_id
                        );
                        break;
                    }

                    if (complete_response_length <= 0) {
                        log_error(
                            "invalid complete_response_length. session_id=%lu length=%d",
                            session->session_id,
                            complete_response_length
                        );
                        loop_result = -1;
                        goto cleanup;
                    }

                    log_debug(
                        "complete HTTP response detected. session_id=%lu length=%d bytes",
                        session->session_id,
                        complete_response_length
                    );

                    {
                        const char* response_data;
                        http_response_t response;
                        dlp_result_t dlp_result;

                        response_data = response_buffer_data(response_buffer);

                        memset(&response, 0, sizeof(response));
                        memset(&dlp_result, 0, sizeof(dlp_result));
                        dlp_result.action = DLP_ACTION_ALLOW;

                        if (parse_http_response(response_data, complete_response_length, &response)) {
                            http_response_t decoded_response_for_dlp;
                            const http_response_t* response_for_dlp;
                            int decode_result;

                            if (logger_is_debug_enabled()) {
                                print_http_response(&response);
                            }
                            log_http_response_analysis(&response, session->session_id, "HTTP");

                            memset(&decoded_response_for_dlp, 0, sizeof(decoded_response_for_dlp));
                            response_for_dlp = &response;

                            decode_result = content_decoder_prepare_response_for_dlp(
                                &response,
                                response_data,
                                complete_response_length,
                                &decoded_response_for_dlp,
                                "PLAIN HTTP RESPONSE"
                            );

                            if (decode_result == 1) {
                                response_for_dlp = &decoded_response_for_dlp;
                                log_debug(
                                    "HTTP response DLP will inspect decompressed body. session_id=%lu",
                                    session->session_id
                                );
                            }
                            else if (decode_result < 0) {
                                log_warn(
                                    "HTTP response decompression failed. session_id=%lu DLP will inspect original response body.",
                                    session->session_id
                                );
                            }

                            dlp_result = inspect_dlp_response(response_for_dlp);

                            if (dlp_result.action == DLP_ACTION_BLOCK) {
                                int block_response_sent;

                                log_security(
                                    "Response blocked. session_id=%lu Not forwarding to client.",
                                    session->session_id
                                );
                                log_security(
                                    "Matched rule id: session_id=%lu rule_id=%d",
                                    session->session_id,
                                    dlp_result.matched_rule_id
                                );
                                log_security(
                                    "Matched keyword: session_id=%lu keyword=%s",
                                    session->session_id,
                                    dlp_result.keyword
                                );
                                log_security(
                                    "Block reason: session_id=%lu reason=%s",
                                    session->session_id,
                                    dlp_result.reason
                                );

                                audit_log_response_block_event(session, response_for_dlp, &dlp_result);

                                block_response_sent = send_response_block_response(
                                    client_sock,
                                    dlp_result.reason
                                );

                                if (block_response_sent == SOCKET_ERROR) {
                                    log_error(
                                        "send_response_block_response() failed. session_id=%lu error=%d",
                                        session->session_id,
                                        WSAGetLastError()
                                    );
                                    loop_result = -1;
                                    goto cleanup;
                                }

                                session_context_add_bytes_to_client(
                                    session,
                                    block_response_sent
                                );

                                loop_result = 0;
                                goto cleanup;
                            }
                            else if (dlp_result.action == DLP_ACTION_LOG_ONLY) {
                                log_security(
                                    "DLP response log-only rule matched. session_id=%lu",
                                    session->session_id
                                );
                                log_security(
                                    "Matched rule id: session_id=%lu rule_id=%d",
                                    session->session_id,
                                    dlp_result.matched_rule_id
                                );
                                log_security(
                                    "Matched keyword: session_id=%lu keyword=%s",
                                    session->session_id,
                                    dlp_result.keyword
                                );
                                log_security(
                                    "Reason: session_id=%lu reason=%s",
                                    session->session_id,
                                    dlp_result.reason
                                );

                                audit_log_response_log_only_event(session, response_for_dlp, &dlp_result);
                            }
                        }
                        else {
                            log_debug(
                                "Received data could not be parsed as HTTP response. session_id=%lu",
                                session->session_id
                            );
                        }

                        if (send_all(client_sock, response_data, complete_response_length) == SOCKET_ERROR) {
                            log_error(
                                "send_all() to client failed. session_id=%lu error=%d",
                                session->session_id,
                                WSAGetLastError()
                            );
                            loop_result = -1;
                            goto cleanup;
                        }

                        session_context_add_bytes_to_client(
                            session,
                            complete_response_length
                        );

                        log_debug(
                            "PROXY -> CLIENT: session_id=%lu %d bytes forwarded",
                            session->session_id,
                            complete_response_length
                        );

                        response_buffer_consume(
                            response_buffer,
                            complete_response_length
                        );
                    }
                }
            }
            else if (recv_len == 0) {
                int remaining_length = response_buffer_length(response_buffer);

                if (remaining_length > 0) {
                    const char* remaining_data = response_buffer_data(response_buffer);

                    log_warn(
                        "upstream disconnected with remaining response buffer. session_id=%lu forwarding raw %d bytes",
                        session->session_id,
                        remaining_length
                    );

                    if (send_all(client_sock, remaining_data, remaining_length) == SOCKET_ERROR) {
                        log_error(
                            "send_all() remaining response to client failed. session_id=%lu error=%d",
                            session->session_id,
                            WSAGetLastError()
                        );
                        loop_result = -1;
                        goto cleanup;
                    }

                    session_context_add_bytes_to_client(session, remaining_length);
                    response_buffer_consume(response_buffer, remaining_length);
                }

                log_info(
                    "upstream server disconnected. session_id=%lu",
                    session->session_id
                );
                loop_result = 0;
                break;
            }
            else {
                log_error(
                    "recv() from upstream failed. session_id=%lu error=%d",
                    session->session_id,
                    WSAGetLastError()
                );
                loop_result = -1;
                break;
            }
        }
    }

cleanup:
    close_socket_safe(&upstream_sock);

    if (request_buffer != NULL) {
        free(request_buffer);
        request_buffer = NULL;
    }
    if (response_buffer != NULL) {
        free(response_buffer);
        response_buffer = NULL;
    }

    return loop_result;
}

int handle_client_session(proxy_session_context_t* session)
{
    int relay_result;

    if (session == NULL) {
        log_error("handle_client_session() received NULL session");
        return -1;
    }

    session_context_log_started(session);

    relay_result = relay_loop(session);

    if (relay_result == 0) {
        log_debug(
            "relay_loop finished normally. session_id=%lu",
            session->session_id
        );
    }
    else {
        log_error(
            "relay_loop finished with error. session_id=%lu",
            session->session_id
        );
    }

    close_socket_safe(&session->client_sock);

    session_context_log_finished(session);

    return relay_result;
}

static unsigned __stdcall client_thread_proc(void* arg)
{
    proxy_session_context_t* session;
    int suppress_application_logs;

    session = (proxy_session_context_t*)arg;

    if (session == NULL) {
        log_error("client_thread_proc() received NULL session");
        return 1;
    }

    session_context_set_thread_id(
        session,
        (unsigned int)GetCurrentThreadId()
    );

    suppress_application_logs = !is_web_browser_process(&session->process);
    logger_set_thread_suppressed(suppress_application_logs);

    log_debug(
        "client thread started. session_id=%lu thread_id=%u",
        session->session_id,
        session->thread_id
    );

    handle_client_session(session);

    log_debug(
        "client thread finished. session_id=%lu thread_id=%u",
        session->session_id,
        session->thread_id
    );

    logger_set_thread_suppressed(0);

    free(session);

    return 0;
}


static SOCKET create_exclusive_listener(int port)
{
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    BOOL exclusive = TRUE;
    int bind_result;
    int listen_result;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        log_error("socket() failed while creating listener. wsa_error=%d", WSAGetLastError());
        return INVALID_SOCKET;
    }

    /*
     * Windows-specific safety option.
     *
     * Do NOT use SO_REUSEADDR for this proxy listener on Windows.
     * SO_REUSEADDR can allow another relay_proxy.exe instance to bind/listen
     * on the same port, which makes logs appear in a different console than
     * the one the developer is watching.
     *
     * SO_EXCLUSIVEADDRUSE makes the second process fail immediately if port
     * 8000 is already in use.
     */
    if (setsockopt(
            listen_sock,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (const char*)&exclusive,
            sizeof(exclusive)
        ) == SOCKET_ERROR) {
        log_error(
            "setsockopt(SO_EXCLUSIVEADDRUSE) failed. wsa_error=%d",
            WSAGetLastError()
        );
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((u_short)port);

    bind_result = bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (bind_result == SOCKET_ERROR) {
        int wsa_error = WSAGetLastError();

        if (wsa_error == WSAEADDRINUSE) {
            log_error(
                "bind() failed: port %d is already in use. "
                "Another relay_proxy.exe instance may still be running. "
                "Run: netstat -ano | findstr :%d",
                port,
                port
            );
        }
        else {
            log_error(
                "bind() failed for listener port %d. wsa_error=%d",
                port,
                wsa_error
            );
        }

        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    listen_result = listen(listen_sock, SOMAXCONN);
    if (listen_result == SOCKET_ERROR) {
        log_error(
            "listen() failed for listener port %d. wsa_error=%d",
            port,
            WSAGetLastError()
        );
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    log_info(
        "exclusive listener created. pid=%lu port=%d bind_address=0.0.0.0",
        (unsigned long)GetCurrentProcessId(),
        port
    );

    return listen_sock;
}

static int run_file_analyzer_cli(const char* file_path, const char* content_type)
{
    FILE* file = NULL;
    long file_size;
    unsigned char* data = NULL;
    size_t bytes_read;
    const char* filename;
    const char* slash;
    const char* backslash;
    file_analysis_result_t result;
    int exit_code = 1;

    if (file_path == NULL || file_path[0] == '\0') return 1;
    if (fopen_s(&file, file_path, "rb") != 0 || file == NULL) {
        fprintf(stderr, "file analyzer: cannot open %s\n", file_path);
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) <= 0 ||
        file_size > 32L * 1024L * 1024L || fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "file analyzer: unsupported file size\n");
        goto cleanup;
    }
    data = (unsigned char*)malloc((size_t)file_size);
    if (data == NULL) goto cleanup;
    bytes_read = fread(data, 1, (size_t)file_size, file);
    if (bytes_read != (size_t)file_size) goto cleanup;

    slash = strrchr(file_path, '/');
    backslash = strrchr(file_path, '\\');
    filename = file_path;
    if (slash != NULL && slash + 1 > filename) filename = slash + 1;
    if (backslash != NULL && backslash + 1 > filename) filename = backslash + 1;

    if (file_analyzer_inspect(filename, content_type, data, bytes_read, &result) != 0) {
        fprintf(stderr, "file analyzer: inspection failed\n");
        goto cleanup;
    }
    printf(
        "FILE ANALYSIS file=\"%s\" bytes=%llu type=%s format=%s entries=%u "
        "extracted_text_bytes=%llu sha256=%s action=%s reason=\"%s\"\n",
        filename,
        (unsigned long long)bytes_read,
        content_type != NULL && content_type[0] ? content_type : "unknown",
        result.format,
        result.archive_entries,
        result.extracted_text_bytes,
        result.sha256[0] ? result.sha256 : "unavailable",
        result.action == FILE_ANALYSIS_BLOCK ? "BLOCK" : "ALLOW",
        result.reason
    );
    exit_code = result.action == FILE_ANALYSIS_BLOCK ? 2 : 0;

cleanup:
    free(data);
    if (file != NULL) fclose(file);
    return exit_code;
}

int main(int argc, char** argv)
{
    WSADATA wsaData;

    SOCKET listen_sock = INVALID_SOCKET;

    char cwd[512];

    if (argc >= 3 && _stricmp(argv[1], "--analyze-file") == 0) {
        return run_file_analyzer_cli(argv[2], argc >= 4 ? argv[3] : "application/octet-stream");
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return 1;
    }

    if (_getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("[CWD] %s\n", cwd);
    }
    else {
        printf("[WARN] failed to get current working directory\n");
    }

    if (logger_init("relay_runtime.log") != 0) {
        printf("[WARN] logger_init failed. continue without file logging.\n");
    }

    if (upload_tracker_init() != 0) {
        log_warn("upload_tracker_init() failed. original file-name correlation is disabled.");
    }

    if (policy_engine_init(POLICY_FILE_PATH) != 0) {
        log_warn("policy_engine_init() failed. continue with available policy rules.");
    }

#if ENABLE_TLS_MITM
    if (tls_intercept_policy_load(TLS_INTERCEPT_POLICY_FILE_PATH) != 0) {
        log_warn("tls_intercept_policy_load() failed. continue with safe default TLS intercept policy.");
    }
    if (upload_capture_init(UPLOAD_CAPTURE_HOSTS_FILE_PATH) != 0) {
        log_warn("upload_capture_init() failed. continue without confirmed-host body capture.");
    }
#endif

    if (command_thread_start(POLICY_FILE_PATH) != 0) {
        log_warn("command_thread_start() failed. policy reload command is disabled.");
    }

    log_info("relay_proxy process started. pid=%lu", (unsigned long)GetCurrentProcessId());

    listen_sock = create_exclusive_listener(PROXY_PORT);
    if (listen_sock == INVALID_SOCKET) {
        log_error("create_exclusive_listener() failed. Check whether another relay_proxy.exe is already using port %d", PROXY_PORT);

        tls_intercept_policy_cleanup();
        upload_capture_cleanup();
        upload_tracker_cleanup();
        policy_engine_cleanup();
        logger_close();
        WSACleanup();

        return 1;
    }

    log_info("Relay proxy listening on port %d...", PROXY_PORT);
    log_info("Dynamic upstream mode enabled. Upstream is resolved from HTTP Host header.");
    #if ENABLE_TLS_MITM
    log_info("CONNECT TLS MITM mode enabled with TLS intercept policy. Policy actions: MITM, BYPASS, BLOCK, AUDIT, IGNORE.");
    log_info("CONNECT TLS intercept policy file: %s", TLS_INTERCEPT_POLICY_FILE_PATH);
    log_info("HTTPS DLP protocol mode: ALPN auto-select with HTTP/1.1 and HTTP/2 enforcement.");
    if (upload_host_discovery_enabled()) {
        log_info(
            "Upload host discovery enabled for browser IGNORE tunnels. min_upload_bytes=%llu window_ms=%llu mode=encrypted_metadata_only",
            upload_host_discovery_min_bytes(),
            (unsigned long long)UPLOAD_HOST_DISCOVERY_WINDOW_MS
        );
    }
#else
    log_info("CONNECT tunnel mode enabled. CONNECT traffic is relayed as raw encrypted TCP.");
#endif

    while (1) {
        SOCKET client_sock = INVALID_SOCKET;
        struct sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);

        proxy_session_context_t* session;
        uintptr_t thread_handle;
        unsigned int thread_id;

        memset(&client_addr, 0, sizeof(client_addr));

        log_debug("waiting for client connection...");

        client_sock = accept(
            listen_sock,
            (struct sockaddr*)&client_addr,
            &client_addr_len
        );

        if (client_sock == INVALID_SOCKET) {
            log_error("accept() failed: %d", WSAGetLastError());
            continue;
        }

        session = (proxy_session_context_t*)malloc(sizeof(proxy_session_context_t));
        if (session == NULL) {
            log_error("malloc() failed for proxy_session_context_t");
            close_socket_safe(&client_sock);
            continue;
        }

        session_context_init(
            session,
            client_sock,
            &client_addr,
            NULL,
            0
        );

        {
            process_metadata_t process_metadata;

            process_metadata_init(&process_metadata);

            if (process_metadata_lookup_tcp_owner(
                session->client_ip,
                session->client_port,
                session->proxy_ip,
                session->proxy_port,
                &process_metadata
            ) == 0) {
                session_context_set_process_metadata(session, &process_metadata);
                if (is_web_browser_process(&process_metadata)) {
                    session_context_log_created(session);
                    process_metadata_log(session->session_id, &process_metadata);
                }
            }
            else {
                log_debug(
                    "failed to lookup process metadata. session_id=%lu client=%s:%d proxy=%s:%d",
                    session->session_id,
                    session->client_ip,
                    session->client_port,
                    session->proxy_ip,
                    session->proxy_port
                );
            }
        }

        thread_id = 0;

        thread_handle = _beginthreadex(
            NULL,
            0,
            client_thread_proc,
            session,
            0,
            &thread_id
        );

        if (thread_handle == 0) {
            log_error(
                "_beginthreadex() failed. session_id=%lu",
                session->session_id
            );

            close_socket_safe(&client_sock);
            free(session);

            continue;
        }

        log_debug(
            "client thread created. session_id=%lu thread_id=%u",
            session->session_id,
            thread_id
        );

        CloseHandle((HANDLE)thread_handle);
    }

    close_socket_safe(&listen_sock);

    log_info("relay proxy terminated");

#if ENABLE_TLS_MITM
    tls_intercept_policy_cleanup();
    upload_capture_cleanup();
#endif
    upload_tracker_cleanup();
    policy_engine_cleanup();
    logger_close();
    WSACleanup();

    return 0;
}
