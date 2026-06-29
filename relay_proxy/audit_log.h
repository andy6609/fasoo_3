#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include "http_parser.h"
#include "http_response_parser.h"
#include "dlp_engine.h"
#include "session_context.h"

void audit_log_block_event(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const dlp_result_t* result
);

void audit_log_log_only_event(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const dlp_result_t* result
);

void audit_log_response_block_event(
    const proxy_session_context_t* session,
    const http_response_t* response,
    const dlp_result_t* result
);

void audit_log_response_log_only_event(
    const proxy_session_context_t* session,
    const http_response_t* response,
    const dlp_result_t* result
);

void audit_log_connect_tunnel_event(
    const proxy_session_context_t* session,
    const http_request_t* request
);

#endif
