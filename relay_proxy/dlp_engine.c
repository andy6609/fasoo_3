#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dlp_engine.h"
#include "policy_engine.h"
#include "body_decoder.h"
#include "logger.h"
#include "upload_capture.h"

#define DLP_MAX_INSPECTION_BODY_SIZE (1024 * 1024)

static dlp_result_t make_dlp_allow_result(void)
{
    dlp_result_t result;

    memset(&result, 0, sizeof(result));
    result.action = DLP_ACTION_ALLOW;
    result.matched_rule_id = 0;

    return result;
}

static int contains_text_ignore_case(const char* text, const char* needle)
{
    size_t text_length;
    size_t needle_length;
    size_t i;

    if (text == NULL || needle == NULL) {
        return 0;
    }

    text_length = strlen(text);
    needle_length = strlen(needle);
    if (needle_length == 0 || text_length < needle_length) {
        return 0;
    }

    for (i = 0; i + needle_length <= text_length; i++) {
        if (_strnicmp(text + i, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int request_header_contains(
    const http_request_t* request,
    const char* header_name,
    const char* token
)
{
    int i;

    if (request == NULL || header_name == NULL || token == NULL) {
        return 0;
    }

    for (i = 0; i < request->header_count; i++) {
        if (_stricmp(request->headers[i].name, header_name) == 0 &&
            contains_text_ignore_case(request->headers[i].value, token)) {
            return 1;
        }
    }
    return 0;
}

static int request_method_can_upload_file(const char* method)
{
    return method != NULL &&
        (_stricmp(method, "POST") == 0 ||
         _stricmp(method, "PUT") == 0 ||
         _stricmp(method, "PATCH") == 0);
}

static int content_type_is_file_payload(const char* content_type)
{
    static const char* file_types[] = {
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/msword",
        "application/vnd.ms-",
        "application/vnd.openxmlformats-officedocument",
        "application/rtf",
        "image/",
        "audio/",
        "video/"
    };
    size_t i;

    if (content_type == NULL || content_type[0] == '\0') {
        return 0;
    }

    for (i = 0; i < sizeof(file_types) / sizeof(file_types[0]); i++) {
        if (contains_text_ignore_case(content_type, file_types[i])) {
            return 1;
        }
    }
    return 0;
}

int dlp_request_is_file_upload(const http_request_t* request)
{
    int path_has_file_hint;

    if (request == NULL || !request_method_can_upload_file(request->method)) {
        return 0;
    }

    if (contains_text_ignore_case(request->content_type, "multipart/form-data")) {
        return 1;
    }

    if (request_header_contains(request, "Content-Disposition", "filename=") ||
        request_header_contains(request, "content-disposition", "filename=")) {
        return 1;
    }

    if (content_type_is_file_payload(request->content_type)) {
        return 1;
    }

    if (contains_text_ignore_case(request->content_type, "application/json") ||
        contains_text_ignore_case(request->content_type, "application/x-www-form-urlencoded")) {
        return 0;
    }

    path_has_file_hint =
        contains_text_ignore_case(request->path, "/upload") ||
        contains_text_ignore_case(request->path, "/files") ||
        contains_text_ignore_case(request->path, "/attachment");

    if (contains_text_ignore_case(request->path, "process_upload_stream") ||
        contains_text_ignore_case(request->path, "/telemetry") ||
        contains_text_ignore_case(request->path, "/ces/")) {
        return 0;
    }

    if (path_has_file_hint &&
        (request->content_length > 0 || request->body_data_length > 0 || request->body_length > 0)) {
        return 1;
    }

    return _stricmp(request->method, "PUT") == 0 &&
        request->content_type[0] != '\0';
}

static int host_equals_or_is_subdomain(const char* host, const char* domain)
{
    size_t host_length;
    size_t domain_length;

    if (host == NULL || domain == NULL) {
        return 0;
    }

    host_length = strlen(host);
    domain_length = strlen(domain);
    if (host_length == domain_length) {
        return _stricmp(host, domain) == 0;
    }
    return host_length > domain_length &&
        host[host_length - domain_length - 1] == '.' &&
        _stricmp(host + host_length - domain_length, domain) == 0;
}

static int dlp_host_is_supported_target(const char* authority)
{
    char host[HTTP_HOST_SIZE];
    char* colon;

    if (authority == NULL || authority[0] == '\0') {
        return 0;
    }

    _snprintf_s(host, sizeof(host), _TRUNCATE, "%s", authority);
    colon = strrchr(host, ':');
    if (colon != NULL && strchr(host, ':') == colon) {
        *colon = '\0';
    }

    return host_equals_or_is_subdomain(host, "chatgpt.com") ||
        host_equals_or_is_subdomain(host, "openai.com") ||
        host_equals_or_is_subdomain(host, "oaiusercontent.com") ||
        host_equals_or_is_subdomain(host, "gemini.google.com") ||
        host_equals_or_is_subdomain(host, "claude.ai") ||
        host_equals_or_is_subdomain(host, "anthropic.com") ||
        _stricmp(host, "demo.local") == 0 ||
        _stricmp(host, "localhost") == 0 ||
        _stricmp(host, "127.0.0.1") == 0;
}

int dlp_request_should_inspect(const http_request_t* request)
{
    if (!dlp_request_is_file_upload(request)) {
        return 0;
    }

    return dlp_host_is_supported_target(request->host) ||
        upload_capture_host_is_configured(request->host, 443);
}

static dlp_action_t convert_policy_action_to_dlp_action(policy_action_t action)
{
    switch (action) {
    case POLICY_ACTION_BLOCK:
        return DLP_ACTION_BLOCK;

    case POLICY_ACTION_LOG_ONLY:
        return DLP_ACTION_LOG_ONLY;

    case POLICY_ACTION_ALLOW:
    default:
        return DLP_ACTION_ALLOW;
    }
}

static dlp_result_t convert_policy_result_to_dlp_result(policy_result_t policy_result)
{
    dlp_result_t result;

    memset(&result, 0, sizeof(result));

    result.action = convert_policy_action_to_dlp_action(policy_result.action);
    result.matched_rule_id = policy_result.matched_rule_id;

    strncpy_s(result.keyword, sizeof(result.keyword), policy_result.keyword, _TRUNCATE);
    strncpy_s(result.reason, sizeof(result.reason), policy_result.reason, _TRUNCATE);

    return result;
}

static dlp_result_t inspect_body(
    const char* direction,
    const char* content_type,
    const char* body,
    int body_length
)
{
    char* inspection_body;
    int inspection_capacity;
    int inspection_body_length;
    int decode_result;

    policy_result_t policy_result;

    if (body == NULL || body_length <= 0) {
        return make_dlp_allow_result();
    }

    inspection_capacity = body_length < DLP_MAX_INSPECTION_BODY_SIZE
        ? body_length + 1
        : DLP_MAX_INSPECTION_BODY_SIZE + 1;
    inspection_body = (char*)malloc((size_t)inspection_capacity);
    if (inspection_body == NULL) {
        policy_result = inspect_policy_text(body, body_length);
        return convert_policy_result_to_dlp_result(policy_result);
    }

    memset(inspection_body, 0, (size_t)inspection_capacity);
    inspection_body_length = 0;

    decode_result = decode_body_for_inspection(
        content_type,
        body,
        body_length,
        inspection_body,
        inspection_capacity,
        &inspection_body_length
    );

    if (decode_result != 0) {
        log_warn("decode_body_for_inspection() failed. direction=%s using raw body.", direction);

        policy_result = inspect_policy_text(
            body,
            body_length
        );

        free(inspection_body);
        return convert_policy_result_to_dlp_result(policy_result);
    }

    if (content_type != NULL && content_type[0] != '\0') {
        log_debug("DLP inspection direction=%s content-type: %s", direction, content_type);
    }
    else {
        log_debug("DLP inspection direction=%s content-type: -", direction);
    }

    log_debug("DLP inspection direction=%s decoded_body_bytes=%d", direction, inspection_body_length);

    policy_result = inspect_policy_text(
        inspection_body,
        inspection_body_length
    );

    free(inspection_body);
    return convert_policy_result_to_dlp_result(policy_result);
}

dlp_result_t inspect_dlp_request(const http_request_t* request)
{
    const char* body;
    int body_length;

    if (request == NULL) {
        return make_dlp_allow_result();
    }

    if (!dlp_request_should_inspect(request)) {
        return make_dlp_allow_result();
    }

    body = request->body_data != NULL ? request->body_data : request->body;
    body_length = request->body_data != NULL && request->body_data_length >= 0
        ? request->body_data_length
        : request->body_length;

    if (body == NULL || body_length <= 0) {
        return make_dlp_allow_result();
    }

    return inspect_body(
        "REQUEST",
        request->content_type,
        body,
        body_length
    );
}

dlp_result_t inspect_dlp_response(const http_response_t* response)
{
    (void)response;
    return make_dlp_allow_result();
}
