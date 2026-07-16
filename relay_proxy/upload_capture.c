#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <Windows.h>

#include "upload_capture.h"
#include "logger.h"
#include "dlp_engine.h"

#define UPLOAD_CAPTURE_ENABLE_ENV "LOCAL_DLP_CAPTURE_UPLOAD_BODIES"
#define UPLOAD_CAPTURE_MAX_BYTES_ENV "LOCAL_DLP_CAPTURE_MAX_BYTES"
#define UPLOAD_CAPTURE_DEFAULT_MAX_BYTES (256ULL * 1024ULL * 1024ULL)
#define UPLOAD_CAPTURE_MAX_RULES 128
#define UPLOAD_CAPTURE_PROCESS_SIZE 128
#define UPLOAD_CAPTURE_HOST_SIZE 256
#define UPLOAD_CAPTURE_LINE_SIZE 768
#define UPLOAD_CAPTURE_DIRECTORY "upload_captures"

typedef struct upload_capture_rule {
    char process_name[UPLOAD_CAPTURE_PROCESS_SIZE];
    char host[UPLOAD_CAPTURE_HOST_SIZE];
    int port;
} upload_capture_rule_t;

static upload_capture_rule_t g_upload_capture_rules[UPLOAD_CAPTURE_MAX_RULES];
static int g_upload_capture_rule_count = 0;
static int g_upload_capture_enabled = 0;
static unsigned long long g_upload_capture_max_bytes = UPLOAD_CAPTURE_DEFAULT_MAX_BYTES;

static int upload_capture_env_flag_enabled(const char* name)
{
    const char* value = name != NULL ? getenv(name) : NULL;

    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    return _stricmp(value, "1") == 0 ||
           _stricmp(value, "true") == 0 ||
           _stricmp(value, "yes") == 0 ||
           _stricmp(value, "on") == 0;
}

static unsigned long long upload_capture_read_max_bytes(void)
{
    const char* value = getenv(UPLOAD_CAPTURE_MAX_BYTES_ENV);
    char* end = NULL;
    unsigned __int64 parsed;

    if (value == NULL || value[0] == '\0') {
        return UPLOAD_CAPTURE_DEFAULT_MAX_BYTES;
    }

    parsed = _strtoui64(value, &end, 10);
    if (end == value || end == NULL || *end != '\0' || parsed == 0) {
        return UPLOAD_CAPTURE_DEFAULT_MAX_BYTES;
    }

    return (unsigned long long)parsed;
}

static char* upload_capture_trim(char* text)
{
    char* end;

    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return text;
}

static int upload_capture_parse_target(
    const char* target,
    char* host,
    size_t host_size,
    int* port
)
{
    char copy[UPLOAD_CAPTURE_HOST_SIZE + 32];
    char* colon;
    char* end = NULL;
    long parsed_port;

    if (target == NULL || host == NULL || host_size == 0 || port == NULL) {
        return -1;
    }

    _snprintf_s(copy, sizeof(copy), _TRUNCATE, "%s", target);
    colon = strrchr(copy, ':');
    *port = 443;

    if (colon != NULL && strchr(copy, ':') == colon) {
        parsed_port = strtol(colon + 1, &end, 10);
        if (end == colon + 1 || end == NULL || *end != '\0' ||
            parsed_port <= 0 || parsed_port > 65535) {
            return -1;
        }
        *colon = '\0';
        *port = (int)parsed_port;
    }

    if (copy[0] == '\0') {
        return -1;
    }

    _snprintf_s(host, host_size, _TRUNCATE, "%s", copy);
    return 0;
}

static int upload_capture_extract_authority(
    const char* authority,
    int default_port,
    char* host,
    size_t host_size,
    int* port
)
{
    char copy[UPLOAD_CAPTURE_HOST_SIZE + 32];
    char* colon;
    char* end = NULL;
    long parsed_port;

    if (authority == NULL || authority[0] == '\0' ||
        host == NULL || host_size == 0 || port == NULL) {
        return -1;
    }

    _snprintf_s(copy, sizeof(copy), _TRUNCATE, "%s", authority);
    *port = default_port > 0 ? default_port : 443;

    colon = strrchr(copy, ':');
    if (colon != NULL && strchr(copy, ':') == colon) {
        parsed_port = strtol(colon + 1, &end, 10);
        if (end != colon + 1 && end != NULL && *end == '\0' &&
            parsed_port > 0 && parsed_port <= 65535) {
            *colon = '\0';
            *port = (int)parsed_port;
        }
    }

    if (copy[0] == '\0') {
        return -1;
    }

    _snprintf_s(host, host_size, _TRUNCATE, "%s", copy);
    return 0;
}

static int upload_capture_wildcard_match(const char* pattern, const char* value)
{
    size_t pattern_length;
    size_t value_length;

    if (pattern == NULL || value == NULL) {
        return 0;
    }

    if (strcmp(pattern, "*") == 0) {
        return 1;
    }

    if (pattern[0] == '*' && pattern[1] == '.') {
        pattern_length = strlen(pattern + 1);
        value_length = strlen(value);
        return value_length > pattern_length &&
            _stricmp(value + value_length - pattern_length, pattern + 1) == 0;
    }

    return _stricmp(pattern, value) == 0;
}

static int upload_capture_ensure_directory(void)
{
    DWORD attributes = GetFileAttributesA(UPLOAD_CAPTURE_DIRECTORY);

    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? 0 : -1;
    }

    if (CreateDirectoryA(UPLOAD_CAPTURE_DIRECTORY, NULL) != 0 ||
        GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    return -1;
}

int upload_capture_init(const char* hosts_file_path)
{
    FILE* file = NULL;
    char line[UPLOAD_CAPTURE_LINE_SIZE];
    int line_number = 0;

    memset(g_upload_capture_rules, 0, sizeof(g_upload_capture_rules));
    g_upload_capture_rule_count = 0;
    g_upload_capture_enabled = upload_capture_env_flag_enabled(UPLOAD_CAPTURE_ENABLE_ENV);
    g_upload_capture_max_bytes = upload_capture_read_max_bytes();

    if (!g_upload_capture_enabled) {
        return 0;
    }

    if (hosts_file_path == NULL || fopen_s(&file, hosts_file_path, "r") != 0 || file == NULL) {
        log_warn(
            "Upload body capture requested but host allowlist could not be opened. path=%s",
            hosts_file_path != NULL ? hosts_file_path : "-"
        );
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char* comment;
        char* context = NULL;
        char* process_name;
        char* target;
        upload_capture_rule_t* rule;

        line_number++;
        comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }

        process_name = strtok_s(upload_capture_trim(line), " \t", &context);
        target = strtok_s(NULL, " \t", &context);
        if (process_name == NULL) {
            continue;
        }
        if (target == NULL || strtok_s(NULL, " \t", &context) != NULL) {
            log_warn("Invalid upload capture host rule ignored. line=%d", line_number);
            continue;
        }
        if (g_upload_capture_rule_count >= UPLOAD_CAPTURE_MAX_RULES) {
            log_warn("Upload capture host rule limit reached. max_rules=%d", UPLOAD_CAPTURE_MAX_RULES);
            break;
        }

        rule = &g_upload_capture_rules[g_upload_capture_rule_count];
        _snprintf_s(rule->process_name, sizeof(rule->process_name), _TRUNCATE, "%s", process_name);
        if (upload_capture_parse_target(target, rule->host, sizeof(rule->host), &rule->port) != 0) {
            log_warn("Invalid upload capture target ignored. line=%d target=%s", line_number, target);
            memset(rule, 0, sizeof(*rule));
            continue;
        }
        g_upload_capture_rule_count++;
    }

    fclose(file);

    if (g_upload_capture_rule_count == 0) {
        log_warn(
            "Upload body capture enabled but no host rules are active. path=%s",
            hosts_file_path
        );
        return 0;
    }

    if (upload_capture_ensure_directory() != 0) {
        log_error("Upload capture directory could not be created. path=%s", UPLOAD_CAPTURE_DIRECTORY);
        g_upload_capture_enabled = 0;
        return -1;
    }

    log_info(
        "Upload body capture enabled. hosts_file=%s rule_count=%d output_directory=%s max_bytes_per_stream=%llu",
        hosts_file_path,
        g_upload_capture_rule_count,
        UPLOAD_CAPTURE_DIRECTORY,
        g_upload_capture_max_bytes
    );
    return 0;
}

void upload_capture_cleanup(void)
{
    memset(g_upload_capture_rules, 0, sizeof(g_upload_capture_rules));
    g_upload_capture_rule_count = 0;
    g_upload_capture_enabled = 0;
}

int upload_capture_is_enabled(void)
{
    return g_upload_capture_enabled && g_upload_capture_rule_count > 0;
}

int upload_capture_host_matches(
    const char* process_name,
    const char* authority,
    int default_port
)
{
    char host[UPLOAD_CAPTURE_HOST_SIZE];
    int port;
    int i;

    if (!upload_capture_is_enabled() ||
        upload_capture_extract_authority(authority, default_port, host, sizeof(host), &port) != 0) {
        return 0;
    }

    for (i = 0; i < g_upload_capture_rule_count; i++) {
        const upload_capture_rule_t* rule = &g_upload_capture_rules[i];
        if (rule->port != port) {
            continue;
        }
        if (!upload_capture_wildcard_match(rule->process_name, process_name != NULL ? process_name : "-")) {
            continue;
        }
        if (upload_capture_wildcard_match(rule->host, host)) {
            return 1;
        }
    }

    return 0;
}

int upload_capture_host_is_configured(
    const char* authority,
    int default_port
)
{
    char host[UPLOAD_CAPTURE_HOST_SIZE];
    int port;
    int i;

    if (!upload_capture_is_enabled() ||
        upload_capture_extract_authority(authority, default_port, host, sizeof(host), &port) != 0) {
        return 0;
    }

    for (i = 0; i < g_upload_capture_rule_count; i++) {
        const upload_capture_rule_t* rule = &g_upload_capture_rules[i];
        if (rule->port == port && upload_capture_wildcard_match(rule->host, host)) {
            return 1;
        }
    }
    return 0;
}

int upload_capture_begin(
    upload_capture_writer_t* writer,
    const proxy_session_context_t* session,
    const http_request_t* request,
    int default_port,
    const char* protocol,
    unsigned int stream_id
)
{
    SYSTEMTIME now;
    const char* process_name;

    if (writer == NULL || session == NULL || request == NULL) {
        return -1;
    }

    if (writer->attempted) {
        return writer->active ? 1 : 0;
    }
    writer->attempted = 1;

    process_name = session->process.process_name[0] != '\0'
        ? session->process.process_name : "-";
    if (!dlp_request_is_file_upload(request)) {
        return 0;
    }
    if (!upload_capture_host_matches(process_name, request->host, default_port)) {
        return 0;
    }

    if (upload_capture_ensure_directory() != 0) {
        writer->failed = 1;
        return -1;
    }

    GetLocalTime(&now);
    _snprintf_s(
        writer->file_path,
        sizeof(writer->file_path),
        _TRUNCATE,
        "%s\\%04u%02u%02u_%02u%02u%02u_%03u_pid%lu_session%lu_%s_stream%u_body.bin",
        UPLOAD_CAPTURE_DIRECTORY,
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        (unsigned long)GetCurrentProcessId(),
        session->session_id,
        protocol != NULL && protocol[0] != '\0' ? protocol : "http",
        stream_id
    );

    if (fopen_s(&writer->file, writer->file_path, "wb") != 0 || writer->file == NULL) {
        writer->failed = 1;
        log_error(
            "UPLOAD_BODY_CAPTURE_BEGIN failed. session_id=%lu stream_id=%u file=\"%s\"",
            session->session_id,
            stream_id,
            writer->file_path
        );
        return -1;
    }

    writer->active = 1;
    writer->stream_id = stream_id;
    writer->max_bytes = g_upload_capture_max_bytes;

    log_security(
        "UPLOAD_BODY_CAPTURE_BEGIN session_id=%lu process=%s protocol=%s stream_id=%u host=%s method=%s path=\"%s\" content_type=\"%s\" declared_bytes=%d file=\"%s\" max_bytes=%llu",
        session->session_id,
        process_name,
        protocol != NULL ? protocol : "-",
        stream_id,
        request->host[0] != '\0' ? request->host : "-",
        request->method[0] != '\0' ? request->method : "-",
        request->path[0] != '\0' ? request->path : "-",
        request->content_type[0] != '\0' ? request->content_type : "-",
        request->content_length,
        writer->file_path,
        writer->max_bytes
    );
    return 1;
}

int upload_capture_append(
    upload_capture_writer_t* writer,
    const void* data,
    size_t length
)
{
    unsigned long long remaining;
    size_t write_length;
    size_t written;

    if (writer == NULL || !writer->active || writer->file == NULL ||
        (data == NULL && length > 0)) {
        return writer != NULL && !writer->active ? 0 : -1;
    }
    if (length == 0 || writer->failed) {
        return writer->failed ? -1 : 0;
    }

    remaining = writer->max_bytes > writer->bytes_written
        ? writer->max_bytes - writer->bytes_written : 0;
    write_length = length;
    if ((unsigned long long)write_length > remaining) {
        write_length = (size_t)remaining;
        writer->truncated = 1;
    }

    if (write_length > 0) {
        written = fwrite(data, 1, write_length, writer->file);
        writer->bytes_written += (unsigned long long)written;
        if (written != write_length) {
            writer->failed = 1;
            return -1;
        }
    }

    if (write_length < length) {
        writer->truncated = 1;
    }
    return 0;
}

void upload_capture_finish(
    upload_capture_writer_t* writer,
    int request_complete
)
{
    if (writer == NULL || !writer->attempted) {
        return;
    }

    if (writer->file != NULL) {
        if (fflush(writer->file) != 0) {
            writer->failed = 1;
        }
        fclose(writer->file);
        writer->file = NULL;
    }

    if (writer->active) {
        log_security(
            "UPLOAD_BODY_CAPTURE_END stream_id=%u bytes_written=%llu complete=%s truncated=%s result=%s file=\"%s\"",
            writer->stream_id,
            writer->bytes_written,
            request_complete ? "true" : "false",
            writer->truncated ? "true" : "false",
            writer->failed ? "ERROR" : "OK",
            writer->file_path
        );
    }

    writer->active = 0;
}
