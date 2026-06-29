#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "multipart_parser.h"
#include "logger.h"

#define MULTIPART_BOUNDARY_SIZE 160
#define MULTIPART_FILENAME_SIZE 260
#define MULTIPART_EXT_SIZE 32
#define MULTIPART_MAX_SCAN_BYTES (1024 * 1024)
#define MULTIPART_MAX_FILE_SIZE_BYTES (10 * 1024 * 1024)
#define MULTIPART_SCAN_CHUNK_BYTES 4096
#define MULTIPART_RULE_MAX_FILE_SIZE 11
#define REQUEST_BODY_FALLBACK_SCAN_BYTES (20 * 1024 * 1024)

static int ascii_tolower_int(int ch)
{
    return tolower((unsigned char)ch);
}

static int text_starts_with_ci(const char* text, const char* prefix)
{
    size_t i;

    if (text == NULL || prefix == NULL) {
        return 0;
    }

    for (i = 0; prefix[i] != '\0'; ++i) {
        if (text[i] == '\0') {
            return 0;
        }
        if (ascii_tolower_int(text[i]) != ascii_tolower_int(prefix[i])) {
            return 0;
        }
    }

    return 1;
}

static const char* find_text_ci_n(
    const char* haystack,
    size_t haystack_len,
    const char* needle
)
{
    size_t needle_len;
    size_t i;
    size_t j;

    if (haystack == NULL || needle == NULL) {
        return NULL;
    }

    needle_len = strlen(needle);
    if (needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    for (i = 0; i + needle_len <= haystack_len; ++i) {
        for (j = 0; j < needle_len; ++j) {
            if (ascii_tolower_int(haystack[i + j]) != ascii_tolower_int(needle[j])) {
                break;
            }
        }

        if (j == needle_len) {
            return haystack + i;
        }
    }

    return NULL;
}

static const char* find_bytes_n(
    const char* haystack,
    size_t haystack_len,
    const char* needle,
    size_t needle_len
)
{
    size_t i;

    if (haystack == NULL || needle == NULL || needle_len == 0) {
        return NULL;
    }

    if (haystack_len < needle_len) {
        return NULL;
    }

    for (i = 0; i + needle_len <= haystack_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }

    return NULL;
}

static size_t bounded_strlen(const char* value, size_t limit)
{
    size_t len;

    if (value == NULL) {
        return 0;
    }

    for (len = 0; len < limit && value[len] != '\0'; ++len) {
        ;
    }

    return len;
}


static size_t read_size_limit_from_env(const char* name, size_t default_value)
{
    char buffer[64];
    size_t required_size;
    unsigned long long parsed;
    char* endptr;

    if (name == NULL || name[0] == '\0') {
        return default_value;
    }

    buffer[0] = '\0';
    required_size = 0;

    if (getenv_s(&required_size, buffer, sizeof(buffer), name) != 0 || required_size == 0) {
        return default_value;
    }

    parsed = strtoull(buffer, &endptr, 10);
    if (endptr == buffer || parsed == 0) {
        return default_value;
    }

    if (parsed > (unsigned long long)((size_t)-1)) {
        return default_value;
    }

    return (size_t)parsed;
}

static size_t multipart_max_file_size_bytes(void)
{
    return read_size_limit_from_env("LOCAL_DLP_MAX_UPLOAD_BYTES", MULTIPART_MAX_FILE_SIZE_BYTES);
}

static size_t multipart_max_scan_bytes(void)
{
    return read_size_limit_from_env("LOCAL_DLP_MAX_MULTIPART_SCAN_BYTES", MULTIPART_MAX_SCAN_BYTES);
}

static size_t min_size_t(size_t a, size_t b)
{
    return a < b ? a : b;
}

static size_t get_available_request_body_len(
    const http_request_t* request,
    const char* body,
    size_t scan_cap
)
{
    size_t declared_len;
    size_t limit;

    if (request == NULL || body == NULL) {
        return 0;
    }

    declared_len = request->content_length > 0 ? (size_t)request->content_length : scan_cap;
    limit = min_size_t(declared_len, scan_cap);

    /*
     * http_parser implementations in this PoC may expose request->body either as
     * a pointer into the complete request buffer or as a bounded body preview.
     * Never trust Content-Length as the readable length of request->body.
     * Using bounded_strlen() prevents scanning past a truncated body preview,
     * which previously caused 0xc0000005 on multi-MB multipart uploads.
     */
    return bounded_strlen(body, limit);
}

static int block_large_multipart_request_if_needed(
    const http_request_t* request,
    dlp_result_t* result
)
{
    size_t max_file_size;
    size_t declared_len;
    char reason[256];

    if (request == NULL || result == NULL || request->content_length <= 0) {
        return 0;
    }

    max_file_size = multipart_max_file_size_bytes();
    declared_len = (size_t)request->content_length;

    if (declared_len <= max_file_size) {
        return 0;
    }

    _snprintf_s(
        reason,
        sizeof(reason),
        _TRUNCATE,
        "Multipart upload blocked. request body too large: bytes=%lu limit=%lu",
        (unsigned long)declared_len,
        (unsigned long)max_file_size
    );

    log_security(
        "Multipart MAX_FILE_SIZE matched before full part parse. content_length=%lu limit=%lu",
        (unsigned long)declared_len,
        (unsigned long)max_file_size
    );

    return safe_set_result(result, DLP_ACTION_BLOCK, MULTIPART_RULE_MAX_FILE_SIZE, "MAX_FILE_SIZE", reason);
}

static int safe_set_result(
    dlp_result_t* result,
    int action,
    int rule_id,
    const char* keyword,
    const char* reason
)
{
    if (result == NULL) {
        return 0;
    }

    if (result->action == DLP_ACTION_BLOCK && action != DLP_ACTION_BLOCK) {
        return 0;
    }

    if (result->action == DLP_ACTION_LOG_ONLY && action == DLP_ACTION_LOG_ONLY) {
        return 0;
    }

    result->action = action;
    result->matched_rule_id = rule_id;

    if (keyword != NULL) {
        _snprintf_s(result->keyword, sizeof(result->keyword), _TRUNCATE, "%s", keyword);
    }
    else {
        result->keyword[0] = '\0';
    }

    if (reason != NULL) {
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE, "%s", reason);
    }
    else {
        result->reason[0] = '\0';
    }

    return 1;
}

static int extract_multipart_boundary(
    const char* content_type,
    char* boundary,
    size_t boundary_size
)
{
    const char* p;
    size_t i;

    if (content_type == NULL || boundary == NULL || boundary_size == 0) {
        return 0;
    }

    boundary[0] = '\0';

    if (find_text_ci_n(content_type, strlen(content_type), "multipart/form-data") == NULL) {
        return 0;
    }

    p = find_text_ci_n(content_type, strlen(content_type), "boundary=");
    if (p == NULL) {
        return 0;
    }

    p += strlen("boundary=");

    while (*p == ' ' || *p == '\t') {
        ++p;
    }

    if (*p == '"') {
        ++p;
        for (i = 0; i + 1 < boundary_size && p[i] != '\0' && p[i] != '"'; ++i) {
            boundary[i] = p[i];
        }
    }
    else {
        for (i = 0; i + 1 < boundary_size && p[i] != '\0' && p[i] != ';' && p[i] != '\r' && p[i] != '\n'; ++i) {
            boundary[i] = p[i];
        }
    }

    boundary[i] = '\0';

    return boundary[0] != '\0';
}

static void extract_quoted_parameter(
    const char* header,
    size_t header_len,
    const char* parameter_name,
    char* output,
    size_t output_size
)
{
    const char* p;
    const char* value_start;
    size_t i;

    if (output == NULL || output_size == 0) {
        return;
    }

    output[0] = '\0';

    if (header == NULL || parameter_name == NULL) {
        return;
    }

    p = find_text_ci_n(header, header_len, parameter_name);
    if (p == NULL) {
        return;
    }

    p += strlen(parameter_name);

    while (*p == ' ' || *p == '\t') {
        ++p;
    }

    if (*p != '=') {
        return;
    }

    ++p;

    while (*p == ' ' || *p == '\t') {
        ++p;
    }

    if (*p == '"') {
        ++p;
        value_start = p;
        for (i = 0; i + 1 < output_size && value_start[i] != '\0' && value_start[i] != '"'; ++i) {
            output[i] = value_start[i];
        }
        output[i] = '\0';
        return;
    }

    value_start = p;
    for (i = 0; i + 1 < output_size && value_start[i] != '\0' && value_start[i] != ';' && value_start[i] != '\r' && value_start[i] != '\n'; ++i) {
        output[i] = value_start[i];
    }
    output[i] = '\0';
}

static const char* filename_basename(const char* filename)
{
    const char* slash;
    const char* backslash;

    if (filename == NULL) {
        return "-";
    }

    slash = strrchr(filename, '/');
    backslash = strrchr(filename, '\\');

    if (slash == NULL && backslash == NULL) {
        return filename;
    }

    if (slash != NULL && backslash != NULL) {
        return slash > backslash ? slash + 1 : backslash + 1;
    }

    if (slash != NULL) {
        return slash + 1;
    }

    return backslash + 1;
}

static void extract_file_extension(
    const char* filename,
    char* ext,
    size_t ext_size
)
{
    const char* base;
    const char* dot;
    size_t i;

    if (ext == NULL || ext_size == 0) {
        return;
    }

    ext[0] = '\0';

    base = filename_basename(filename);
    dot = strrchr(base, '.');
    if (dot == NULL || dot[1] == '\0') {
        return;
    }

    for (i = 0; i + 1 < ext_size && dot[i] != '\0'; ++i) {
        ext[i] = (char)ascii_tolower_int(dot[i]);
    }
    ext[i] = '\0';
}

static int streaming_sample_contains_keyword(
    const char* part_body,
    size_t part_body_len,
    size_t sample_limit,
    const char* keyword,
    size_t* scanned_bytes
)
{
    size_t keyword_len;
    size_t scan_len;
    size_t offset;
    size_t overlap_len;
    char window[MULTIPART_SCAN_CHUNK_BYTES + 128];

    if (scanned_bytes != NULL) {
        *scanned_bytes = 0;
    }

    if (part_body == NULL || keyword == NULL || keyword[0] == '\0') {
        return 0;
    }

    keyword_len = strlen(keyword);
    if (keyword_len >= sizeof(window)) {
        return find_text_ci_n(part_body, part_body_len < sample_limit ? part_body_len : sample_limit, keyword) != NULL;
    }

    scan_len = part_body_len < sample_limit ? part_body_len : sample_limit;
    offset = 0;
    overlap_len = 0;

    while (offset < scan_len) {
        size_t remaining;
        size_t chunk_len;
        size_t window_len;
        size_t next_overlap_len;

        remaining = scan_len - offset;
        chunk_len = remaining < MULTIPART_SCAN_CHUNK_BYTES ? remaining : MULTIPART_SCAN_CHUNK_BYTES;

        if (overlap_len > 0) {
            memmove(window, window + MULTIPART_SCAN_CHUNK_BYTES, overlap_len);
        }

        memcpy(window + overlap_len, part_body + offset, chunk_len);
        window_len = overlap_len + chunk_len;

        if (find_text_ci_n(window, window_len, keyword) != NULL) {
            if (scanned_bytes != NULL) {
                *scanned_bytes = offset + chunk_len;
            }
            return 1;
        }

        next_overlap_len = keyword_len > 1 ? keyword_len - 1 : 0;
        if (next_overlap_len > window_len) {
            next_overlap_len = window_len;
        }

        if (next_overlap_len > 0) {
            memcpy(window + MULTIPART_SCAN_CHUNK_BYTES, window + window_len - next_overlap_len, next_overlap_len);
        }
        overlap_len = next_overlap_len;
        offset += chunk_len;
    }

    if (scanned_bytes != NULL) {
        *scanned_bytes = scan_len;
    }

    return 0;
}

static int part_body_looks_like_email(const char* part_body, size_t part_body_len)
{
    const char* at;
    const char* dot;

    at = find_bytes_n(part_body, part_body_len, "@", 1);
    if (at == NULL) {
        return 0;
    }

    dot = find_bytes_n(at, part_body_len - (size_t)(at - part_body), ".", 1);
    return dot != NULL;
}


static int part_body_sample_looks_like_email(
    const char* part_body,
    size_t part_body_len,
    size_t sample_limit
)
{
    size_t scan_len;

    if (part_body == NULL) {
        return 0;
    }

    scan_len = part_body_len < sample_limit ? part_body_len : sample_limit;
    return part_body_looks_like_email(part_body, scan_len);
}

static int inspect_one_file_part(
    const char* filename,
    const char* part_body,
    size_t part_body_len,
    dlp_result_t* result
)
{
    char ext[MULTIPART_EXT_SIZE];
    char reason[256];
    const char* base;
    int changed;
    size_t max_file_size;
    size_t max_scan_bytes;
    size_t scanned_bytes;

    if (filename == NULL || filename[0] == '\0' || part_body == NULL || result == NULL) {
        return 0;
    }

    changed = 0;
    scanned_bytes = 0;
    max_file_size = multipart_max_file_size_bytes();
    max_scan_bytes = multipart_max_scan_bytes();
    base = filename_basename(filename);
    extract_file_extension(filename, ext, sizeof(ext));

    log_security(
        "Multipart file upload detected. filename=%s extension=%s body_bytes=%lu max_file_bytes=%lu scan_limit_bytes=%lu",
        base,
        ext[0] != '\0' ? ext : "-",
        (unsigned long)part_body_len,
        (unsigned long)max_file_size,
        (unsigned long)max_scan_bytes
    );

    if (_stricmp(ext, ".zip") == 0) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload blocked. blocked file extension detected: %s",
            ext
        );
        return safe_set_result(result, DLP_ACTION_BLOCK, 9, ext, reason);
    }

    if (part_body_len > max_file_size) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload blocked. file too large: %s bytes=%lu limit=%lu",
            base,
            (unsigned long)part_body_len,
            (unsigned long)max_file_size
        );
        return safe_set_result(result, DLP_ACTION_BLOCK, MULTIPART_RULE_MAX_FILE_SIZE, "MAX_FILE_SIZE", reason);
    }

    if (part_body_len > max_scan_bytes) {
        log_security(
            "Multipart streaming sample scan enabled. filename=%s file_body_bytes=%lu scanned_body_bytes=%lu",
            base,
            (unsigned long)part_body_len,
            (unsigned long)max_scan_bytes
        );
    }
    else {
        log_debug(
            "Multipart file content scan. filename=%s scanned_body_bytes=%lu",
            base,
            (unsigned long)part_body_len
        );
    }

    if (streaming_sample_contains_keyword(part_body, part_body_len, max_scan_bytes, "secret", &scanned_bytes)) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload blocked. sensitive keyword detected in uploaded file sample: %s scanned=%lu",
            base,
            (unsigned long)scanned_bytes
        );
        return safe_set_result(result, DLP_ACTION_BLOCK, 1, "secret", reason);
    }

    if (streaming_sample_contains_keyword(part_body, part_body_len, max_scan_bytes, "password", &scanned_bytes)) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload blocked. password keyword detected in uploaded file sample: %s scanned=%lu",
            base,
            (unsigned long)scanned_bytes
        );
        return safe_set_result(result, DLP_ACTION_BLOCK, 2, "password", reason);
    }

    if (part_body_sample_looks_like_email(part_body, part_body_len, max_scan_bytes)) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload blocked. email-like pattern detected in uploaded file sample: %s",
            base
        );
        return safe_set_result(result, DLP_ACTION_BLOCK, 4, "EMAIL", reason);
    }

    if (_stricmp(ext, ".xlsx") == 0) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload log-only. Excel file upload detected: %s",
            base
        );
        changed = safe_set_result(result, DLP_ACTION_LOG_ONLY, 8, ext, reason);
    }
    else if (result->action == DLP_ACTION_ALLOW) {
        _snprintf_s(
            reason,
            sizeof(reason),
            _TRUNCATE,
            "Multipart upload log-only. file upload detected: %s",
            base
        );
        changed = safe_set_result(result, DLP_ACTION_LOG_ONLY, 10, "FILE_UPLOAD", reason);
    }

    return changed;
}

int inspect_multipart_upload_request(const http_request_t* request, dlp_result_t* result)
{
    char boundary[MULTIPART_BOUNDARY_SIZE];
    char boundary_marker[MULTIPART_BOUNDARY_SIZE + 4];
    size_t boundary_marker_len;
    const char* body;
    size_t body_len;
    const char* cursor;
    const char* body_end;
    int inspected;

    if (request == NULL || result == NULL) {
        return 0;
    }

    if (result->action == DLP_ACTION_BLOCK) {
        return 0;
    }

    if (!extract_multipart_boundary(request->content_type, boundary, sizeof(boundary))) {
        return 0;
    }

    body = request->body;
    if (body == NULL || body[0] == '\0') {
        return 0;
    }

    if (block_large_multipart_request_if_needed(request, result)) {
        return 1;
    }

    body_len = get_available_request_body_len(request, body, REQUEST_BODY_FALLBACK_SCAN_BYTES);

    if (body_len == 0) {
        return 0;
    }

    if (request->content_length > 0 && body_len < (size_t)request->content_length) {
        log_security(
            "Multipart body preview length is smaller than Content-Length. content_length=%lu available_body_bytes=%lu. Inspection will use available sample only.",
            (unsigned long)request->content_length,
            (unsigned long)body_len
        );
    }

    _snprintf_s(boundary_marker, sizeof(boundary_marker), _TRUNCATE, "--%s", boundary);
    boundary_marker_len = strlen(boundary_marker);

    cursor = body;
    body_end = body + body_len;
    inspected = 1;

    log_security(
        "Multipart/form-data request detected. boundary=%s content_length=%lu",
        boundary,
        (unsigned long)body_len
    );

    while (cursor < body_end) {
        const char* boundary_pos;
        const char* part_start;
        const char* header_end;
        const char* part_body;
        const char* next_boundary;
        const char* part_end;
        size_t remaining;
        size_t header_len;
        size_t part_body_len;
        char filename[MULTIPART_FILENAME_SIZE];

        remaining = (size_t)(body_end - cursor);
        boundary_pos = find_bytes_n(cursor, remaining, boundary_marker, boundary_marker_len);
        if (boundary_pos == NULL) {
            break;
        }

        part_start = boundary_pos + boundary_marker_len;
        if ((body_end - part_start) >= 2 && part_start[0] == '-' && part_start[1] == '-') {
            break;
        }

        if ((body_end - part_start) >= 2 && part_start[0] == '\r' && part_start[1] == '\n') {
            part_start += 2;
        }
        else if ((body_end - part_start) >= 1 && part_start[0] == '\n') {
            part_start += 1;
        }

        remaining = (size_t)(body_end - part_start);
        header_end = find_bytes_n(part_start, remaining, "\r\n\r\n", 4);
        if (header_end == NULL) {
            header_end = find_bytes_n(part_start, remaining, "\n\n", 2);
            if (header_end == NULL) {
                break;
            }
            part_body = header_end + 2;
        }
        else {
            part_body = header_end + 4;
        }

        header_len = (size_t)(header_end - part_start);
        remaining = (size_t)(body_end - part_body);
        next_boundary = find_bytes_n(part_body, remaining, boundary_marker, boundary_marker_len);
        if (next_boundary == NULL) {
            break;
        }

        part_end = next_boundary;
        while (part_end > part_body && (part_end[-1] == '\r' || part_end[-1] == '\n')) {
            --part_end;
        }

        part_body_len = (size_t)(part_end - part_body);
        extract_quoted_parameter(part_start, header_len, "filename", filename, sizeof(filename));

        if (filename[0] != '\0') {
            inspect_one_file_part(filename, part_body, part_body_len, result);
            if (result->action == DLP_ACTION_BLOCK) {
                return inspected;
            }
        }

        cursor = next_boundary;
    }

    return inspected;
}
