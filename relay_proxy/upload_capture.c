#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

#include <Windows.h>

#include "upload_capture.h"
#include "logger.h"
#include "dlp_engine.h"

#define UPLOAD_CAPTURE_ENABLE_ENV "LOCAL_DLP_CAPTURE_UPLOAD_BODIES"
#define UPLOAD_CAPTURE_MAX_BYTES_ENV "LOCAL_DLP_CAPTURE_MAX_BYTES"
#define UPLOAD_CAPTURE_DEFAULT_MAX_BYTES (128ULL * 1024ULL * 1024ULL)
#define UPLOAD_CAPTURE_MAX_RULES 128
#define UPLOAD_CAPTURE_PROCESS_SIZE 128
#define UPLOAD_CAPTURE_HOST_SIZE 256
#define UPLOAD_CAPTURE_LINE_SIZE 768
#define UPLOAD_CAPTURE_DIRECTORY "upload_captures"
#define UPLOAD_REASSEMBLY_DIRECTORY "upload_captures\\reassembled"
#define UPLOAD_RECORD_DIRECTORY "upload_records"
#define UPLOAD_RECORD_ENV "LOCAL_DLP_SAVE_UPLOAD_RECORDS"
#define UPLOAD_RECORD_DIRECTORY_ENV "LOCAL_DLP_UPLOAD_RECORD_DIRECTORY"
#define UPLOAD_RECORD_PREVIEW_BYTES 1024

typedef struct upload_capture_rule {
    char process_name[UPLOAD_CAPTURE_PROCESS_SIZE];
    char host[UPLOAD_CAPTURE_HOST_SIZE];
    int port;
} upload_capture_rule_t;

static upload_capture_rule_t g_upload_capture_rules[UPLOAD_CAPTURE_MAX_RULES];
static int g_upload_capture_rule_count = 0;
static int g_upload_capture_enabled = 0;
static unsigned long long g_upload_capture_max_bytes = UPLOAD_CAPTURE_DEFAULT_MAX_BYTES;
static volatile LONG g_upload_record_sequence = 0;
static SRWLOCK g_upload_reassembly_lock = SRWLOCK_INIT;

static void upload_capture_detect_fragment(
    upload_capture_writer_t* writer,
    const http_request_t* request
);
static void upload_capture_reassemble(upload_capture_writer_t* writer);
static unsigned long long upload_capture_hash_key(const char* value);
static void upload_record_sanitize_component(
    const char* value,
    char* output,
    size_t output_size
);

static int upload_capture_u64_add(
    unsigned long long left,
    unsigned long long right,
    unsigned long long* result
)
{
    if (result == NULL || right > ULLONG_MAX - left) return 0;
    *result = left + right;
    return 1;
}

/* Values copied from HTTP headers, file metadata, the OS, or CLI arguments
 * must stay on one line in both key=value evidence and quoted log fields. */
static void upload_capture_sanitize_external_text(
    const char* value,
    const char* fallback,
    char* output,
    size_t output_size
)
{
    size_t index;
    size_t out = 0;
    const char* source = value;

    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (source == NULL || source[0] == '\0') source = fallback != NULL ? fallback : "-";

    for (index = 0; source[index] != '\0' && out + 1 < output_size; ++index) {
        unsigned char ch = (unsigned char)source[index];
        if (ch < 0x20 || ch == 0x7f) output[out++] = '_';
        else if (ch == '"') output[out++] = '\'';
        else output[out++] = (char)ch;
    }
    output[out] = '\0';
}

static void upload_capture_redact_path(
    const char* path,
    char* output,
    size_t output_size
)
{
    size_t index;
    const char* query;
    size_t path_length;
    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (path == NULL || path[0] == '\0') {
        strcpy_s(output, output_size, "-");
        return;
    }
    query = strchr(path, '?');
    if (query == NULL) {
        _snprintf_s(output, output_size, _TRUNCATE, "%s", path);
    }
    else {
        path_length = (size_t)(query - path);
        if (path_length >= output_size) path_length = output_size - 1;
        memcpy(output, path, path_length);
        output[path_length] = '\0';
        if (path_length + sizeof("?<redacted>") <= output_size)
            strcat_s(output, output_size, "?<redacted>");
    }
    for (index = 0; output[index] != '\0'; ++index) {
        unsigned char ch = (unsigned char)output[index];
        if (ch < 0x20 || ch == 0x7f || ch == '"') output[index] = '_';
    }
}

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

    while (*value == ' ' || *value == '\t') value++;
    if (*value == '-' || *value == '+') return UPLOAD_CAPTURE_DEFAULT_MAX_BYTES;
    errno = 0;
    parsed = _strtoui64(value, &end, 10);
    while (end != NULL && (*end == ' ' || *end == '\t')) end++;
    if (errno == ERANGE || end == value || end == NULL || *end != '\0' ||
        parsed == 0 || parsed > (unsigned __int64)LLONG_MAX) {
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
        g_upload_capture_enabled = 0;
        return -1;
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
    char safe_process_name[UPLOAD_CAPTURE_PROCESS_SIZE];
    char safe_protocol_component[32];

    if (writer == NULL || session == NULL || request == NULL) {
        return -1;
    }

    if (writer->attempted) {
        return writer->active ? 1 : 0;
    }
    writer->attempted = 1;

    process_name = session->process.process_name[0] != '\0'
        ? session->process.process_name : "-";
    upload_capture_sanitize_external_text(
        process_name, "-", safe_process_name, sizeof(safe_process_name));
    upload_record_sanitize_component(
        protocol != NULL && protocol[0] != '\0' ? protocol : "http",
        safe_protocol_component, sizeof(safe_protocol_component));
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
        safe_protocol_component,
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
    writer->session_id = session->session_id;
    writer->max_bytes = g_upload_capture_max_bytes;
    if (request->content_length > 0) {
        writer->declared_bytes = (unsigned long long)request->content_length;
        writer->declared_bytes_known = 1;
    }
    _snprintf_s(writer->metadata_path, sizeof(writer->metadata_path), _TRUNCATE,
        "%s.meta.txt", writer->file_path);
    upload_capture_sanitize_external_text(
        request->host, "-", writer->host, sizeof(writer->host));
    upload_capture_sanitize_external_text(
        request->method, "-", writer->method, sizeof(writer->method));
    upload_capture_redact_path(request->path, writer->path, sizeof(writer->path));
    upload_capture_sanitize_external_text(
        request->content_type, "-", writer->content_type, sizeof(writer->content_type));
    upload_capture_sanitize_external_text(
        protocol, "-", writer->protocol, sizeof(writer->protocol));
    upload_capture_detect_fragment(writer, request);

    log_security(
        "UPLOAD_BODY_CAPTURE_BEGIN session_id=%lu process=%s protocol=%s stream_id=%u host=%s method=%s path=\"%s\" content_type=\"%s\" declared_bytes=%d file=\"%s\" max_bytes=%llu",
        session->session_id,
        safe_process_name,
        writer->protocol,
        stream_id,
        writer->host,
        writer->method,
        writer->path,
        writer->content_type,
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
    unsigned long long new_bytes_seen;
    unsigned long long fragment_end;
    size_t write_length;
    size_t written;

    if (writer == NULL || !writer->active || writer->file == NULL ||
        (data == NULL && length > 0)) {
        return writer != NULL && !writer->active ? 0 : -1;
    }
    if (length == 0 || writer->failed) {
        return writer->failed ? -1 : 0;
    }

    if (!upload_capture_u64_add(writer->bytes_seen, (unsigned long long)length,
        &new_bytes_seen)) {
        writer->failed = 1;
        writer->truncated = 1;
        return -1;
    }
    writer->bytes_seen = new_bytes_seen;

    if (writer->is_fragment &&
        (!upload_capture_u64_add(writer->fragment_offset, writer->bytes_seen,
            &fragment_end) ||
         writer->max_bytes == 0 || fragment_end > writer->max_bytes ||
         (writer->fragment_total_known && fragment_end > writer->fragment_total) ||
         (writer->fragment_expected_bytes_known &&
            writer->bytes_seen > writer->fragment_expected_bytes))) {
        writer->failed = 1;
        writer->truncated = 1;
        log_security(
            "UPLOAD_FRAGMENT_REJECTED session_id=%lu stream_id=%u reason=fragment_body_exceeds_declared_bounds offset=%llu bytes_seen=%llu total=%llu expected_bytes=%llu max_bytes=%llu",
            writer->session_id, writer->stream_id, writer->fragment_offset,
            writer->bytes_seen, writer->fragment_total,
            writer->fragment_expected_bytes, writer->max_bytes);
        return -1;
    }

    remaining = writer->max_bytes == 0
        ? (unsigned long long)length
        : (writer->max_bytes > writer->bytes_written
            ? writer->max_bytes - writer->bytes_written : 0);
    write_length = length;
    if (writer->max_bytes != 0 && (unsigned long long)write_length > remaining) {
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
    FILE* metadata = NULL;
    int metadata_write_result = -1;
    int metadata_close_result = 0;
    unsigned long long fragment_end = 0;

    if (writer == NULL || !writer->attempted || writer->finished) {
        return;
    }
    writer->finished = 1;
    writer->request_complete = request_complete != 0;

    if (writer->is_fragment &&
        ((writer->fragment_expected_bytes_known &&
            writer->bytes_seen != writer->fragment_expected_bytes) ||
         !upload_capture_u64_add(writer->fragment_offset, writer->bytes_seen,
            &fragment_end) ||
         writer->max_bytes == 0 || fragment_end > writer->max_bytes ||
         (writer->fragment_total_known && fragment_end > writer->fragment_total))) {
        writer->failed = 1;
        writer->truncated = 1;
    }

    if (writer->file != NULL) {
        if (fflush(writer->file) != 0) {
            writer->failed = 1;
        }
        if (fclose(writer->file) != 0) {
            writer->failed = 1;
        }
        writer->file = NULL;
    }

    writer->complete = writer->active && writer->request_complete &&
        !writer->truncated && !writer->failed &&
        writer->bytes_written == writer->bytes_seen &&
        (!writer->declared_bytes_known || writer->declared_bytes == writer->bytes_seen);

    if (writer->active) {
        upload_capture_reassemble(writer);
        if (writer->failed) {
            writer->complete = 0;
            writer->reassembly_complete = 0;
        }
        if (fopen_s(&metadata, writer->metadata_path, "wb") == 0 && metadata != NULL) {
            metadata_write_result = fprintf(metadata,
                "session_id=%lu\nstream_id=%u\nprotocol=%s\nhost=%s\nmethod=%s\npath=%s\n"
                "content_type=%s\ndeclared_bytes=%llu\ndeclared_bytes_known=%s\nbytes_seen=%llu\nbytes_written=%llu\nrequest_complete=%s\n"
                "capture_complete=%s\ntruncated=%s\nfailed=%s\nfragment=%s\nfragment_offset=%llu\n"
                "fragment_total=%llu\nfragment_total_known=%s\nfragment_expected_bytes=%llu\n"
                "fragment_expected_bytes_known=%s\nfragment_final=%s\n"
                "reassembly_complete=%s\nreassembled_bytes=%llu\nbody_file=%s\nreassembled_file=%s\n",
                writer->session_id, writer->stream_id, writer->protocol, writer->host,
                writer->method, writer->path, writer->content_type, writer->declared_bytes,
                writer->declared_bytes_known ? "true" : "false", writer->bytes_seen,
                writer->bytes_written, writer->request_complete ? "true" : "false",
                writer->complete ? "true" : "false", writer->truncated ? "true" : "false",
                writer->failed ? "true" : "false", writer->is_fragment ? "true" : "false",
                writer->fragment_offset, writer->fragment_total,
                writer->fragment_total_known ? "true" : "false",
                writer->fragment_expected_bytes,
                writer->fragment_expected_bytes_known ? "true" : "false",
                writer->fragment_final ? "true" : "false",
                writer->reassembly_complete ? "true" : "false", writer->reassembled_bytes,
                writer->file_path, writer->reassembled_path[0] ? writer->reassembled_path : "-");
            if (metadata_write_result < 0 || fflush(metadata) != 0) {
                writer->failed = 1;
            }
            metadata_close_result = fclose(metadata);
            metadata = NULL;
            if (metadata_close_result != 0) writer->failed = 1;
        }
        else writer->failed = 1;

        if (writer->failed) {
            writer->complete = 0;
            writer->reassembly_complete = 0;
        }
        log_security(
            "UPLOAD_BODY_CAPTURE_END stream_id=%u bytes_seen=%llu bytes_written=%llu request_complete=%s capture_complete=%s truncated=%s result=%s fragment=%s reassembly_complete=%s file=\"%s\" metadata=\"%s\"",
            writer->stream_id,
            writer->bytes_seen,
            writer->bytes_written,
            writer->request_complete ? "true" : "false",
            writer->complete ? "true" : "false",
            writer->truncated ? "true" : "false",
            writer->failed ? "ERROR" : "OK",
            writer->is_fragment ? "true" : "false",
            writer->reassembly_complete ? "true" : "false",
            writer->file_path,
            writer->metadata_path
        );
    }

    writer->active = 0;
}

int upload_capture_is_complete(const upload_capture_writer_t* writer)
{
    if (writer == NULL) return 0;
    return !writer->failed && (writer->reassembly_complete || writer->complete);
}

int upload_capture_open_complete_view(
    const upload_capture_writer_t* writer,
    upload_capture_view_t* view
)
{
    const char* path;
    HANDLE file_handle;
    HANDLE mapping_handle;
    LARGE_INTEGER file_size;
    const unsigned char* mapped;

    if (view == NULL) return -1;
    memset(view, 0, sizeof(*view));
    if (writer == NULL || !upload_capture_is_complete(writer)) return 0;
    path = writer->reassembly_complete ? writer->reassembled_path : writer->file_path;
    if (path == NULL || path[0] == '\0') return 0;

    file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file_handle, &file_size) || file_size.QuadPart <= 0 ||
        (unsigned __int64)file_size.QuadPart > (unsigned __int64)SIZE_MAX ||
        writer->max_bytes == 0 ||
        (unsigned __int64)file_size.QuadPart > writer->max_bytes) {
        CloseHandle(file_handle);
        return file_size.QuadPart == 0 ? 0 : -1;
    }
    mapping_handle = CreateFileMappingA(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (mapping_handle == NULL) {
        CloseHandle(file_handle);
        return -1;
    }
    mapped = (const unsigned char*)MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (mapped == NULL) {
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        return -1;
    }

    view->file_handle = file_handle;
    view->mapping_handle = mapping_handle;
    view->data = mapped;
    view->length = (size_t)file_size.QuadPart;
    view->reassembled = writer->reassembly_complete;
    return 1;
}

void upload_capture_close_view(upload_capture_view_t* view)
{
    if (view == NULL) return;
    if (view->data != NULL) UnmapViewOfFile(view->data);
    if (view->mapping_handle != NULL) CloseHandle((HANDLE)view->mapping_handle);
    if (view->file_handle != NULL && (HANDLE)view->file_handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)view->file_handle);
    memset(view, 0, sizeof(*view));
}

static const char* upload_capture_request_header(
    const http_request_t* request,
    const char* name
)
{
    int i;
    if (request == NULL || name == NULL) return NULL;
    for (i = 0; i < request->header_count; i++) {
        if (_stricmp(request->headers[i].name, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

static int upload_capture_header_has_token(const char* value, const char* token)
{
    size_t token_length;
    const char* cursor;
    if (value == NULL || token == NULL || token[0] == '\0') return 0;
    token_length = strlen(token);
    cursor = value;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') cursor++;
        if (_strnicmp(cursor, token, token_length) == 0 &&
            (cursor[token_length] == '\0' || cursor[token_length] == ',' ||
             cursor[token_length] == ' ' || cursor[token_length] == '\t')) return 1;
        cursor = strchr(cursor, ',');
        if (cursor == NULL) break;
        cursor++;
    }
    return 0;
}

static int upload_capture_parse_u64(const char* text, unsigned long long* value)
{
    char* end = NULL;
    unsigned __int64 parsed;
    if (text == NULL || value == NULL) return 0;
    while (*text == ' ' || *text == '\t') text++;
    if (!isdigit((unsigned char)*text)) return 0;
    errno = 0;
    parsed = _strtoui64(text, &end, 10);
    if (errno == ERANGE || end == text) return 0;
    while (*end == ' ' || *end == '\t') end++;
    if (*end != '\0') return 0;
    *value = (unsigned long long)parsed;
    return 1;
}

static int upload_capture_parse_content_range(
    const char* value,
    unsigned long long* start,
    unsigned long long* end,
    unsigned long long* total,
    int* total_known
)
{
    const char* cursor;
    char* number_end = NULL;
    unsigned __int64 parsed_start;
    unsigned __int64 parsed_end;
    unsigned __int64 parsed_total = 0;
    if (value == NULL || start == NULL || end == NULL || total == NULL || total_known == NULL)
        return 0;
    cursor = value;
    while (*cursor == ' ' || *cursor == '\t') cursor++;
    if (_strnicmp(cursor, "bytes", 5) != 0) return 0;
    cursor += 5;
    while (*cursor == ' ' || *cursor == '\t') cursor++;
    if (!isdigit((unsigned char)*cursor)) return 0;
    errno = 0;
    parsed_start = _strtoui64(cursor, &number_end, 10);
    if (errno == ERANGE || number_end == cursor || *number_end != '-') return 0;
    cursor = number_end + 1;
    if (!isdigit((unsigned char)*cursor)) return 0;
    errno = 0;
    parsed_end = _strtoui64(cursor, &number_end, 10);
    if (errno == ERANGE || number_end == cursor || *number_end != '/' ||
        parsed_end < parsed_start || parsed_end == ULLONG_MAX) return 0;
    cursor = number_end + 1;
    if (*cursor == '*') {
        cursor++;
        *total_known = 0;
    }
    else {
        if (!isdigit((unsigned char)*cursor)) return 0;
        errno = 0;
        parsed_total = _strtoui64(cursor, &number_end, 10);
        if (errno == ERANGE || number_end == cursor || parsed_total == 0 ||
            parsed_end >= parsed_total) return 0;
        cursor = number_end;
        *total_known = 1;
    }
    while (*cursor == ' ' || *cursor == '\t') cursor++;
    if (*cursor != '\0') return 0;
    *start = (unsigned long long)parsed_start;
    *end = (unsigned long long)parsed_end;
    *total = (unsigned long long)parsed_total;
    return 1;
}

static unsigned long long upload_capture_hash_key(const char* value)
{
    unsigned long long hash = 1469598103934665603ULL;
    const unsigned char* cursor = (const unsigned char*)value;
    while (cursor != NULL && *cursor != '\0') {
        hash ^= (unsigned long long)*cursor++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void upload_capture_detect_fragment(
    upload_capture_writer_t* writer,
    const http_request_t* request
)
{
    const char* content_range;
    const char* offset_header;
    const char* total_header;
    const char* command_header;
    unsigned long long content_range_start = 0;
    unsigned long long range_end = 0;
    unsigned long long content_range_total = 0;
    unsigned long long offset = 0;
    unsigned long long total = 0;
    unsigned long long end_offset = 0;
    int content_range_total_known = 0;
    int content_range_seen;
    int offset_seen;
    int total_seen;
    if (writer == NULL || request == NULL) return;
    if (!writer->declared_bytes_known && request->content_length > 0) {
        writer->declared_bytes = (unsigned long long)request->content_length;
        writer->declared_bytes_known = 1;
    }

    content_range = upload_capture_request_header(request, "Content-Range");
    content_range_seen = content_range != NULL;
    if (content_range_seen) {
        writer->is_fragment = 1;
        if (!upload_capture_parse_content_range(content_range, &content_range_start,
            &range_end, &content_range_total, &content_range_total_known)) {
            writer->failed = 1;
        }
        else {
            writer->fragment_offset = content_range_start;
            writer->fragment_expected_bytes = range_end - content_range_start + 1;
            writer->fragment_expected_bytes_known = 1;
            if (content_range_total_known) {
                writer->fragment_total = content_range_total;
                writer->fragment_total_known = 1;
                writer->fragment_final = range_end + 1 == content_range_total;
            }
        }
    }

    offset_header = upload_capture_request_header(request, "X-Goog-Upload-Offset");
    if (offset_header == NULL) offset_header = upload_capture_request_header(request, "Upload-Offset");
    offset_seen = offset_header != NULL;
    if (offset_seen) {
        writer->is_fragment = 1;
        if (!upload_capture_parse_u64(offset_header, &offset)) {
            writer->failed = 1;
        }
        else if (content_range_seen && !writer->failed && offset != content_range_start) {
            writer->failed = 1;
        }
        else {
            writer->fragment_offset = offset;
        }
    }

    total_header = upload_capture_request_header(request, "X-Goog-Upload-Header-Content-Length");
    if (total_header == NULL) total_header = upload_capture_request_header(request, "Upload-Length");
    total_seen = total_header != NULL;
    if (total_seen) {
        if (!upload_capture_parse_u64(total_header, &total) || total == 0) {
            writer->failed = 1;
        }
        else if (writer->fragment_total_known && total != writer->fragment_total) {
            writer->failed = 1;
        }
        else {
            writer->fragment_total = total;
            writer->fragment_total_known = 1;
        }
    }

    command_header = upload_capture_request_header(request, "X-Goog-Upload-Command");
    if (upload_capture_header_has_token(command_header, "upload")) writer->is_fragment = 1;
    if (upload_capture_header_has_token(command_header, "finalize")) writer->fragment_final = 1;
    if (upload_capture_header_has_token(upload_capture_request_header(request, "Upload-Complete"), "?1") ||
        upload_capture_header_has_token(upload_capture_request_header(request, "Upload-Complete"), "true")) {
        writer->fragment_final = 1;
    }

    if (writer->is_fragment) {
        if (writer->max_bytes == 0 || writer->max_bytes > (unsigned long long)LLONG_MAX ||
            writer->fragment_offset > writer->max_bytes ||
            (writer->fragment_total_known && writer->fragment_total > writer->max_bytes) ||
            (writer->fragment_total_known && writer->fragment_offset > writer->fragment_total) ||
            (writer->fragment_expected_bytes_known &&
                (!upload_capture_u64_add(writer->fragment_offset,
                    writer->fragment_expected_bytes, &end_offset) ||
                 end_offset > writer->max_bytes ||
                 (writer->fragment_total_known && end_offset > writer->fragment_total))) ||
            (writer->declared_bytes_known &&
                (!upload_capture_u64_add(writer->fragment_offset,
                    writer->declared_bytes, &end_offset) ||
                 end_offset > writer->max_bytes ||
                 (writer->fragment_total_known && end_offset > writer->fragment_total))) ||
            (writer->declared_bytes_known && writer->fragment_expected_bytes_known &&
                writer->declared_bytes != writer->fragment_expected_bytes)) {
            writer->failed = 1;
        }

        _snprintf_s(writer->reassembly_key, sizeof(writer->reassembly_key), _TRUNCATE,
            "%lu|%s|path_hash=%016llx", writer->session_id, writer->host,
            upload_capture_hash_key(request->path));

        if (writer->failed) {
            writer->truncated = 1;
            log_security(
                "UPLOAD_FRAGMENT_REJECTED session_id=%lu stream_id=%u reason=invalid_or_oversized_fragment_bounds offset=%llu declared_bytes=%llu expected_bytes=%llu total=%llu max_bytes=%llu",
                writer->session_id, writer->stream_id, writer->fragment_offset,
                writer->declared_bytes, writer->fragment_expected_bytes,
                writer->fragment_total, writer->max_bytes);
        }
    }
}

static int upload_capture_copy_fragment(
    FILE* source,
    FILE* destination,
    unsigned long long expected_bytes
)
{
    unsigned char buffer[64 * 1024];
    unsigned long long copied = 0;
    if (source == NULL || destination == NULL) return -1;
    while (copied < expected_bytes) {
        size_t wanted = sizeof(buffer);
        size_t read_length;
        if ((unsigned long long)wanted > expected_bytes - copied)
            wanted = (size_t)(expected_bytes - copied);
        read_length = fread(buffer, 1, wanted, source);
        if (read_length == 0) return -1;
        if (fwrite(buffer, 1, read_length, destination) != read_length) return -1;
        copied += read_length;
    }
    return 0;
}

static int upload_capture_flush_and_close(FILE** file)
{
    int flush_result;
    int close_result;
    if (file == NULL || *file == NULL) return -1;
    flush_result = fflush(*file);
    close_result = fclose(*file);
    *file = NULL;
    return flush_result == 0 && close_result == 0 ? 0 : -1;
}

typedef struct upload_capture_range {
    unsigned long long start;
    unsigned long long end;
} upload_capture_range_t;

static int upload_capture_compare_ranges(const void* left, const void* right)
{
    const upload_capture_range_t* a = (const upload_capture_range_t*)left;
    const upload_capture_range_t* b = (const upload_capture_range_t*)right;
    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}

static void upload_capture_reassemble(upload_capture_writer_t* writer)
{
    unsigned long long hash;
    char state_path[UPLOAD_CAPTURE_PATH_SIZE];
    char state_temp_path[UPLOAD_CAPTURE_PATH_SIZE];
    FILE* state = NULL;
    FILE* source = NULL;
    FILE* destination = NULL;
    unsigned long long contiguous = 0;
    unsigned long long total = 0;
    unsigned long long end_offset = 0;
    unsigned long long limit;
    __int64 existing_size;
    int total_known = 0;
    int final_seen = 0;
    upload_capture_range_t ranges[257];
    int range_count = 0;
    int merged_count = 0;
    int state_present = 0;
    int state_key_seen = 0;
    int state_valid = 1;
    int success = 0;
    int i;

    if (writer == NULL || !writer->is_fragment || !writer->complete ||
        writer->reassembly_key[0] == '\0') return;
    limit = writer->max_bytes;
    if (limit == 0 || limit > (unsigned long long)LLONG_MAX ||
        !upload_capture_u64_add(writer->fragment_offset, writer->bytes_written,
            &end_offset) ||
        writer->fragment_offset > limit || end_offset > limit ||
        (writer->fragment_total_known &&
            (writer->fragment_total == 0 || writer->fragment_total > limit ||
             end_offset > writer->fragment_total))) {
        writer->failed = 1;
        writer->reassembly_complete = 0;
        return;
    }
    if (upload_capture_ensure_directory() != 0) {
        writer->failed = 1;
        return;
    }
    if (CreateDirectoryA(UPLOAD_REASSEMBLY_DIRECTORY, NULL) == 0 &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        writer->failed = 1;
        return;
    }

    hash = upload_capture_hash_key(writer->reassembly_key);
    if (_snprintf_s(writer->reassembled_path, sizeof(writer->reassembled_path), _TRUNCATE,
            "%s\\%016llx.bin.part", UPLOAD_REASSEMBLY_DIRECTORY, hash) < 0 ||
        _snprintf_s(state_path, sizeof(state_path), _TRUNCATE,
            "%s\\%016llx.state", UPLOAD_REASSEMBLY_DIRECTORY, hash) < 0 ||
        _snprintf_s(state_temp_path, sizeof(state_temp_path), _TRUNCATE,
            "%s\\%016llx.state.tmp.%lu.%lu", UPLOAD_REASSEMBLY_DIRECTORY, hash,
            (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId()) < 0) {
        writer->failed = 1;
        return;
    }

    AcquireSRWLockExclusive(&g_upload_reassembly_lock);
    if (fopen_s(&state, state_path, "rb") == 0 && state != NULL) {
        char line[256];
        state_present = 1;
        while (fgets(line, sizeof(line), state) != NULL) {
            if (strncmp(line, "key=", 4) == 0) {
                char* value = line + 4;
                value[strcspn(value, "\r\n")] = '\0';
                state_key_seen = 1;
                if (strcmp(value, writer->reassembly_key) != 0) state_valid = 0;
                continue;
            }
            if (sscanf_s(line, "contiguous=%llu", &contiguous) == 1) continue;
            if (sscanf_s(line, "total=%llu", &total) == 1) continue;
            if (sscanf_s(line, "total_known=%d", &total_known) == 1) continue;
            if (sscanf_s(line, "final_seen=%d", &final_seen) == 1) continue;
            if (strncmp(line, "range=", 6) == 0) {
                if (range_count >= 256 ||
                    sscanf_s(line, "range=%llu-%llu", &ranges[range_count].start,
                        &ranges[range_count].end) != 2 ||
                    ranges[range_count].end <= ranges[range_count].start ||
                    ranges[range_count].end > limit) {
                    state_valid = 0;
                }
                else range_count++;
            }
        }
        if (ferror(state)) state_valid = 0;
        fclose(state);
        state = NULL;
    }

    if (state_present && !state_key_seen) state_valid = 0;
    if ((total_known != 0 && total_known != 1) ||
        (final_seen != 0 && final_seen != 1) ||
        contiguous > limit ||
        (total_known && (total == 0 || total > limit)) ||
        (writer->fragment_total_known && total_known && total != writer->fragment_total)) {
        state_valid = 0;
    }
    if (!state_valid) goto done;

    if (range_count == 0 && contiguous > 0) {
        ranges[range_count].start = 0;
        ranges[range_count].end = contiguous;
        range_count++;
    }
    ranges[range_count].start = writer->fragment_offset;
    ranges[range_count].end = end_offset;
    range_count++;
    qsort(ranges, (size_t)range_count, sizeof(ranges[0]), upload_capture_compare_ranges);
    for (i = 0; i < range_count; i++) {
        if (merged_count == 0 || ranges[i].start > ranges[merged_count - 1].end) {
            if (merged_count >= 256) goto done;
            ranges[merged_count++] = ranges[i];
        }
        else if (ranges[i].end > ranges[merged_count - 1].end) {
            ranges[merged_count - 1].end = ranges[i].end;
        }
    }
    range_count = merged_count;

    if (writer->fragment_total_known) {
        total = writer->fragment_total;
        total_known = 1;
    }
    if (writer->fragment_final) {
        final_seen = 1;
        if (!total_known) {
            total = end_offset;
            total_known = 1;
        }
    }
    if ((final_seen && !total_known) ||
        (total_known && (total == 0 || total > limit))) goto done;
    for (i = 0; i < range_count; ++i) {
        if (ranges[i].end > limit || (total_known && ranges[i].end > total)) goto done;
    }
    contiguous = range_count > 0 && ranges[0].start == 0 ? ranges[0].end : 0;

    if (fopen_s(&source, writer->file_path, "rb") != 0 || source == NULL) goto done;
    if (fopen_s(&destination, writer->reassembled_path, "r+b") != 0 || destination == NULL) {
        if (fopen_s(&destination, writer->reassembled_path, "w+b") != 0 || destination == NULL) goto done;
    }
    if (_fseeki64(destination, 0, SEEK_END) != 0) goto done;
    existing_size = _ftelli64(destination);
    if (existing_size < 0 || (unsigned long long)existing_size > limit) goto done;
    if (_fseeki64(destination, (__int64)writer->fragment_offset, SEEK_SET) != 0) goto done;
    if (upload_capture_copy_fragment(source, destination, writer->bytes_written) != 0) goto done;
    if (upload_capture_flush_and_close(&destination) != 0) goto done;
    fclose(source);
    source = NULL;

    if (fopen_s(&state, state_temp_path, "wb") != 0 || state == NULL) goto done;
    if (fprintf(state,
        "key=%s\ncontiguous=%llu\ntotal=%llu\ntotal_known=%d\nfinal_seen=%d\ncomplete=%d\n",
        writer->reassembly_key, contiguous, total, total_known, final_seen,
        final_seen && total_known && contiguous == total) < 0) goto done;
    for (i = 0; i < range_count; i++) {
        if (fprintf(state, "range=%llu-%llu\n", ranges[i].start, ranges[i].end) < 0)
            goto done;
    }
    if (upload_capture_flush_and_close(&state) != 0) goto done;
    if (!MoveFileExA(state_temp_path, state_path,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) goto done;

    writer->reassembled_bytes = contiguous;
    writer->reassembly_complete = final_seen && total_known && contiguous == total;
    success = 1;
    log_security(
        "UPLOAD_REASSEMBLY_UPDATE session_id=%lu stream_id=%u offset=%llu chunk_bytes=%llu contiguous_bytes=%llu total_bytes=%llu total_known=%s final_seen=%s complete=%s file=\"%s\"",
        writer->session_id, writer->stream_id, writer->fragment_offset,
        writer->bytes_written, contiguous, total, total_known ? "true" : "false",
        final_seen ? "true" : "false", writer->reassembly_complete ? "true" : "false",
        writer->reassembled_path);

done:
    if (source != NULL) fclose(source);
    if (destination != NULL) {
        if (upload_capture_flush_and_close(&destination) != 0) success = 0;
    }
    if (state != NULL) {
        if (upload_capture_flush_and_close(&state) != 0) success = 0;
    }
    DeleteFileA(state_temp_path);
    if (!success) {
        writer->failed = 1;
        writer->reassembly_complete = 0;
        log_security(
            "UPLOAD_REASSEMBLY_REJECTED session_id=%lu stream_id=%u offset=%llu chunk_bytes=%llu max_bytes=%llu reason=invalid_bounds_state_or_storage_failure",
            writer->session_id, writer->stream_id, writer->fragment_offset,
            writer->bytes_written, writer->max_bytes);
    }
    ReleaseSRWLockExclusive(&g_upload_reassembly_lock);
}

static const char* upload_record_service_for_host(const char* host)
{
    if (host == NULL) return "UnknownAI";
    if (strstr(host, "oaiusercontent.com") != NULL || strstr(host, "openai.com") != NULL ||
        strstr(host, "chatgpt.com") != NULL) return "ChatGPT";
    if (strstr(host, "claude.ai") != NULL || strstr(host, "anthropic.com") != NULL)
        return "Claude";
    if (strstr(host, "gemini.google.com") != NULL || strstr(host, "googleapis.com") != NULL ||
        strstr(host, "googleusercontent.com") != NULL) return "Gemini";
    return "UnknownAI";
}

static void upload_record_sanitize_component(
    const char* value,
    char* output,
    size_t output_size
)
{
    size_t i;
    size_t out = 0;
    const char* base;
    const char* slash;
    const char* backslash;
    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (value == NULL || value[0] == '\0') value = "unknown.bin";
    base = value;
    slash = strrchr(value, '/');
    backslash = strrchr(value, '\\');
    if (slash != NULL && slash + 1 > base) base = slash + 1;
    if (backslash != NULL && backslash + 1 > base) base = backslash + 1;
    for (i = 0; base[i] != '\0' && out + 1 < output_size; i++) {
        unsigned char ch = (unsigned char)base[i];
        if (isalnum(ch) || ch == '.' || ch == '-' || ch == '_') output[out++] = (char)ch;
        else output[out++] = '_';
    }
    while (out > 0 && (output[out - 1] == '.' || output[out - 1] == ' ')) out--;
    if (out == 0) strcpy_s(output, output_size, "unknown.bin");
    else output[out] = '\0';
}

static void upload_record_sanitize_display_filename(
    const char* value,
    char* output,
    size_t output_size
)
{
    size_t i;
    size_t out = 0;
    const char* base;
    const char* slash;
    const char* backslash;
    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (value == NULL || value[0] == '\0') value = "unknown.bin";
    base = value;
    slash = strrchr(value, '/');
    backslash = strrchr(value, '\\');
    if (slash != NULL && slash + 1 > base) base = slash + 1;
    if (backslash != NULL && backslash + 1 > base) base = backslash + 1;
    for (i = 0; base[i] != '\0' && out + 1 < output_size; ++i) {
        unsigned char ch = (unsigned char)base[i];
        /* Preserve valid UTF-8 bytes while preventing line/log injection. */
        if (ch < 0x20 || ch == 0x7f) output[out++] = '_';
        else if (ch == '"') output[out++] = '\'';
        else output[out++] = (char)ch;
    }
    if (out == 0) strcpy_s(output, output_size, "unknown.bin");
    else output[out] = '\0';
}

static int upload_record_ensure_directory(const char* path)
{
    DWORD attributes;
    if (path == NULL || path[0] == '\0') return -1;
    attributes = GetFileAttributesA(path);
    if (attributes != INVALID_FILE_ATTRIBUTES)
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? 0 : -1;
    if (CreateDirectoryA(path, NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    return -1;
}

static int upload_record_write_file_checked(
    const char* path,
    const void* data,
    size_t length
)
{
    FILE* file = NULL;
    int result = -1;
    if (path == NULL || path[0] == '\0' || (data == NULL && length > 0)) return -1;
    if (fopen_s(&file, path, "wb") != 0 || file == NULL) return -1;
    if ((length == 0 || fwrite(data, 1, length, file) == length) &&
        upload_capture_flush_and_close(&file) == 0) {
        result = 0;
    }
    if (file != NULL) fclose(file);
    if (result != 0) DeleteFileA(path);
    return result;
}

static int upload_record_write_content_checked(
    const char* path,
    const char* text,
    size_t text_length
)
{
    static const unsigned char utf8_bom[] = {0xef, 0xbb, 0xbf};
    FILE* file = NULL;
    int result = -1;
    if (path == NULL || path[0] == '\0' || (text == NULL && text_length > 0)) return -1;
    if (fopen_s(&file, path, "wb") != 0 || file == NULL) return -1;
    if (fwrite(utf8_bom, 1, sizeof(utf8_bom), file) == sizeof(utf8_bom) &&
        (text_length == 0 || fwrite(text, 1, text_length, file) == text_length) &&
        upload_capture_flush_and_close(&file) == 0) {
        result = 0;
    }
    if (file != NULL) fclose(file);
    if (result != 0) DeleteFileA(path);
    return result;
}

static void upload_record_remove_staging(
    const char* directory,
    const char* original_path,
    const char* content_path,
    const char* metadata_path
)
{
    if (metadata_path != NULL && metadata_path[0] != '\0') DeleteFileA(metadata_path);
    if (content_path != NULL && content_path[0] != '\0') DeleteFileA(content_path);
    if (original_path != NULL && original_path[0] != '\0') DeleteFileA(original_path);
    if (directory != NULL && directory[0] != '\0') RemoveDirectoryA(directory);
}

static void upload_record_make_preview(
    const char* text,
    size_t length,
    char output[UPLOAD_RECORD_PREVIEW_BYTES + 1]
)
{
    size_t i;
    size_t out = 0;
    if (output == NULL) return;
    output[0] = '\0';
    if (text == NULL) return;
    for (i = 0; i < length && out + 2 < UPLOAD_RECORD_PREVIEW_BYTES; i++) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '\r') continue;
        if (ch == '\n' || ch == '\t') output[out++] = ' ';
        else if (ch == '"') { output[out++] = '\''; }
        else if ((ch >= 0x20 && ch != 0x7f) || ch >= 0x80) output[out++] = (char)ch;
    }
    output[out] = '\0';
}

static const char* upload_record_extraction_status_name(file_extraction_status_t status)
{
    switch (status) {
    case FILE_EXTRACTION_COMPLETE: return "COMPLETE";
    case FILE_EXTRACTION_PARTIAL: return "PARTIAL";
    case FILE_EXTRACTION_OCR_REQUIRED: return "OCR_REQUIRED";
    case FILE_EXTRACTION_ENCRYPTED: return "ENCRYPTED";
    case FILE_EXTRACTION_UNSUPPORTED: return "UNSUPPORTED";
    case FILE_EXTRACTION_MALFORMED: return "MALFORMED";
    case FILE_EXTRACTION_NONE:
    default: return "NONE";
    }
}

int upload_record_store_file_ex(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const char* service,
    const char* protocol,
    unsigned int stream_id,
    const char* filename,
    const unsigned char* data,
    size_t length,
    unsigned long long observed_length,
    int original_complete,
    const file_analysis_result_t* analysis
)
{
    SYSTEMTIME local_time;
    SYSTEMTIME utc_time;
    char base_directory[MAX_PATH];
    char day_directory[MAX_PATH];
    char record_directory[MAX_PATH];
    char staging_directory[MAX_PATH];
    char safe_filename[192];
    char display_filename[512];
    char original_path[MAX_PATH];
    char content_path[MAX_PATH];
    char metadata_path[MAX_PATH];
    char staging_original_path[MAX_PATH];
    char staging_content_path[MAX_PATH];
    char staging_metadata_path[MAX_PATH];
    char redacted_request_path[512];
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    char user_name[256];
    char safe_computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    char safe_user_name[256];
    char safe_client_ip[SESSION_IP_SIZE];
    char safe_process_name[PROCESS_NAME_SIZE];
    char safe_process_path[PROCESS_PATH_SIZE];
    char safe_service[128];
    char safe_service_component[96];
    char safe_protocol[64];
    char safe_host[HTTP_HOST_SIZE];
    char safe_method[HTTP_METHOD_SIZE];
    char safe_content_type[HTTP_CONTENT_TYPE_SIZE];
    char safe_sha256[sizeof(((file_analysis_result_t*)0)->sha256)];
    char safe_format[sizeof(((file_analysis_result_t*)0)->format)];
    char safe_normalized_mime[sizeof(((file_analysis_result_t*)0)->normalized_mime)];
    char safe_reason[sizeof(((file_analysis_result_t*)0)->reason)];
    char safe_original_path[MAX_PATH];
    char safe_content_path[MAX_PATH];
    char safe_record_directory[MAX_PATH];
    DWORD computer_size = sizeof(computer_name);
    DWORD user_size = sizeof(user_name);
    FILE* file = NULL;
    char* extracted_text = NULL;
    size_t extracted_length = 0;
    int text_truncated = 0;
    char preview[UPLOAD_RECORD_PREVIEW_BYTES + 1];
    LONG sequence;
    const char* resolved_service;
    const char* directory_env;
    int metadata_write_result = -1;
    int metadata_close_result = -1;
    int staging_created = 0;
    int result = -1;

    if (!upload_capture_env_flag_enabled(UPLOAD_RECORD_ENV)) return 0;
    if (session == NULL || request == NULL || data == NULL || length == 0) return -1;

    directory_env = getenv(UPLOAD_RECORD_DIRECTORY_ENV);
    if (_snprintf_s(base_directory, sizeof(base_directory), _TRUNCATE, "%s",
        directory_env != NULL && directory_env[0] ? directory_env : UPLOAD_RECORD_DIRECTORY) < 0)
        return -1;
    if (upload_record_ensure_directory(base_directory) != 0) return -1;

    GetLocalTime(&local_time);
    GetSystemTime(&utc_time);
    if (_snprintf_s(day_directory, sizeof(day_directory), _TRUNCATE, "%s\\%04u%02u%02u",
        base_directory, local_time.wYear, local_time.wMonth, local_time.wDay) < 0)
        return -1;
    if (upload_record_ensure_directory(day_directory) != 0) return -1;

    sequence = InterlockedIncrement(&g_upload_record_sequence);
    resolved_service = service != NULL && service[0] ? service : upload_record_service_for_host(request->host);
    upload_capture_sanitize_external_text(
        resolved_service, "UnknownAI", safe_service, sizeof(safe_service));
    upload_record_sanitize_component(
        resolved_service, safe_service_component, sizeof(safe_service_component));
    upload_capture_redact_path(
        request->path, redacted_request_path, sizeof(redacted_request_path));
    upload_record_sanitize_component(filename, safe_filename, sizeof(safe_filename));
    upload_record_sanitize_display_filename(
        filename, display_filename, sizeof(display_filename));
    if (_snprintf_s(record_directory, sizeof(record_directory), _TRUNCATE,
        "%s\\%02u%02u%02u_%03u_%s_pid%lu_session%lu_stream%u_%ld",
        day_directory, local_time.wHour, local_time.wMinute, local_time.wSecond,
        local_time.wMilliseconds, safe_service_component,
        (unsigned long)GetCurrentProcessId(), session->session_id, stream_id, sequence) < 0 ||
        _snprintf_s(staging_directory, sizeof(staging_directory), _TRUNCATE,
        "%s.tmp.%lu", record_directory, (unsigned long)GetCurrentThreadId()) < 0 ||
        _snprintf_s(original_path, sizeof(original_path), _TRUNCATE,
        "%s\\original_%s", record_directory, safe_filename) < 0 ||
        _snprintf_s(content_path, sizeof(content_path), _TRUNCATE,
        "%s\\content.txt", record_directory) < 0 ||
        _snprintf_s(metadata_path, sizeof(metadata_path), _TRUNCATE,
        "%s\\metadata.txt", record_directory) < 0 ||
        _snprintf_s(staging_original_path, sizeof(staging_original_path), _TRUNCATE,
        "%s\\original_%s", staging_directory, safe_filename) < 0 ||
        _snprintf_s(staging_content_path, sizeof(staging_content_path), _TRUNCATE,
        "%s\\content.txt", staging_directory) < 0 ||
        _snprintf_s(staging_metadata_path, sizeof(staging_metadata_path), _TRUNCATE,
        "%s\\metadata.txt", staging_directory) < 0) {
        return -1;
    }
    if (GetFileAttributesA(record_directory) != INVALID_FILE_ATTRIBUTES ||
        CreateDirectoryA(staging_directory, NULL) == 0) return -1;
    staging_created = 1;

    if (upload_record_write_file_checked(staging_original_path, data, length) != 0)
        goto cleanup;

    if (file_analyzer_extract_text(filename, request->content_type, data, length,
        &extracted_text, &extracted_length, &text_truncated) != 0) {
        log_error(
            "UPLOAD_RECORD_REJECTED session_id=%lu stream_id=%u reason=text_extraction_failed",
            session->session_id, stream_id);
        goto cleanup;
    }
    if (upload_record_write_content_checked(
        staging_content_path, extracted_text, extracted_length) != 0) goto cleanup;

    computer_name[0] = '\0';
    user_name[0] = '\0';
    if (!GetComputerNameA(computer_name, &computer_size)) strcpy_s(computer_name, sizeof(computer_name), "unknown");
    if (!GetUserNameA(user_name, &user_size)) strcpy_s(user_name, sizeof(user_name), "unknown");

    upload_capture_sanitize_external_text(computer_name, "unknown",
        safe_computer_name, sizeof(safe_computer_name));
    upload_capture_sanitize_external_text(user_name, "unknown",
        safe_user_name, sizeof(safe_user_name));
    upload_capture_sanitize_external_text(session->client_ip, "unknown",
        safe_client_ip, sizeof(safe_client_ip));
    upload_capture_sanitize_external_text(session->process.process_name, "unknown",
        safe_process_name, sizeof(safe_process_name));
    upload_capture_sanitize_external_text(session->process.process_path, "unknown",
        safe_process_path, sizeof(safe_process_path));
    upload_capture_sanitize_external_text(protocol, "-",
        safe_protocol, sizeof(safe_protocol));
    upload_capture_sanitize_external_text(request->host, "-",
        safe_host, sizeof(safe_host));
    upload_capture_sanitize_external_text(request->method, "-",
        safe_method, sizeof(safe_method));
    upload_capture_sanitize_external_text(request->content_type, "unknown",
        safe_content_type, sizeof(safe_content_type));
    upload_capture_sanitize_external_text(
        analysis != NULL && analysis->sha256[0] ? analysis->sha256 : "unavailable",
        "unavailable", safe_sha256, sizeof(safe_sha256));
    upload_capture_sanitize_external_text(
        analysis != NULL && analysis->format[0] ? analysis->format : "UNKNOWN",
        "UNKNOWN", safe_format, sizeof(safe_format));
    upload_capture_sanitize_external_text(
        analysis != NULL && analysis->normalized_mime[0]
            ? analysis->normalized_mime : "unknown",
        "unknown", safe_normalized_mime, sizeof(safe_normalized_mime));
    upload_capture_sanitize_external_text(
        analysis != NULL && analysis->reason[0] ? analysis->reason : "-",
        "-", safe_reason, sizeof(safe_reason));
    upload_capture_sanitize_external_text(original_path, "-",
        safe_original_path, sizeof(safe_original_path));
    upload_capture_sanitize_external_text(content_path, "-",
        safe_content_path, sizeof(safe_content_path));
    upload_capture_sanitize_external_text(record_directory, "-",
        safe_record_directory, sizeof(safe_record_directory));

    if (fopen_s(&file, staging_metadata_path, "wb") == 0 && file != NULL) {
        metadata_write_result = fprintf(file,
            "captured_local=%04u-%02u-%02uT%02u:%02u:%02u.%03u\n"
            "captured_utc=%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\n"
            "computer=%s\nwindows_user=%s\nclient_ip=%s\nclient_port=%d\n"
            "process_id=%lu\nprocess_name=%s\nprocess_path=%s\n"
            "service=%s\nprotocol=%s\nsession_id=%lu\nstream_or_exchange=%u\n"
            "host=%s\nmethod=%s\npath=%s\nfilename=%s\ncontent_type=%s\n"
            "file_bytes=%llu\nobserved_upload_bytes=%llu\noriginal_complete=%s\n"
            "sha256=%s\nformat=%s\nnormalized_mime=%s\nsignature_match=%s\n"
            "encrypted=%s\nrequires_ocr=%s\nextraction_status=%s\n"
            "action=%s\nreason=%s\nextracted_text_bytes=%llu\nextracted_text_truncated=%s\n"
            "record_complete=true\noriginal_file=%s\ncontent_file=%s\n",
            local_time.wYear, local_time.wMonth, local_time.wDay, local_time.wHour,
            local_time.wMinute, local_time.wSecond, local_time.wMilliseconds,
            utc_time.wYear, utc_time.wMonth, utc_time.wDay, utc_time.wHour,
            utc_time.wMinute, utc_time.wSecond, utc_time.wMilliseconds,
            safe_computer_name, safe_user_name, safe_client_ip, session->client_port,
            (unsigned long)session->process.process_id,
            safe_process_name, safe_process_path,
            safe_service, safe_protocol, session->session_id, stream_id,
            safe_host, safe_method, redacted_request_path,
            display_filename,
            safe_content_type, (unsigned long long)length,
            observed_length != 0 ? observed_length : (unsigned long long)length,
            original_complete ? "true" : "false",
            safe_sha256,
            safe_format,
            safe_normalized_mime,
            analysis != NULL && analysis->signature_match ? "true" : "false",
            analysis != NULL && analysis->encrypted ? "true" : "false",
            analysis != NULL && analysis->requires_ocr ? "true" : "false",
            analysis != NULL ? upload_record_extraction_status_name(analysis->extraction_status) : "NONE",
            analysis != NULL && analysis->action == FILE_ANALYSIS_BLOCK ? "BLOCK" : "ALLOW",
            safe_reason,
            (unsigned long long)extracted_length, text_truncated ? "true" : "false",
            safe_original_path, safe_content_path);
        metadata_close_result = upload_capture_flush_and_close(&file);
        if (metadata_write_result < 0 || metadata_close_result != 0) goto cleanup;
    }
    else goto cleanup;

    if (!MoveFileExA(staging_directory, record_directory, MOVEFILE_WRITE_THROUGH))
        goto cleanup;
    staging_created = 0;

    if (upload_capture_env_flag_enabled("LOCAL_DLP_LOG_CONTENT_PREVIEW"))
        upload_record_make_preview(extracted_text, extracted_length, preview);
    else
        strcpy_s(preview, sizeof(preview), "disabled; see protected content.txt");
    log_event(
        "UPLOAD CONTENT SAVED service=%s computer=%s windows_user=%s client_ip=%s "
        "process=%s process_id=%lu session=%lu stream=%u file=\"%s\" bytes=%llu observed_bytes=%llu original_complete=%s "
        "text_bytes=%llu text_truncated=%s record=\"%s\" content_preview=\"%s\"",
        safe_service, safe_computer_name, safe_user_name, safe_client_ip,
        safe_process_name, (unsigned long)session->process.process_id,
        session->session_id, stream_id, display_filename,
        (unsigned long long)length,
        observed_length != 0 ? observed_length : (unsigned long long)length,
        original_complete ? "true" : "false", (unsigned long long)extracted_length,
        text_truncated ? "true" : "false", safe_record_directory, preview);

    result = 1;

cleanup:
    if (file != NULL) fclose(file);
    if (staging_created) {
        upload_record_remove_staging(staging_directory, staging_original_path,
            staging_content_path, staging_metadata_path);
    }
    free(extracted_text);
    return result;
}

int upload_record_store_file(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const char* service,
    const char* protocol,
    unsigned int stream_id,
    const char* filename,
    const unsigned char* data,
    size_t length,
    const file_analysis_result_t* analysis
)
{
    return upload_record_store_file_ex(session, request, service, protocol, stream_id,
        filename, data, length, (unsigned long long)length, 1, analysis);
}
