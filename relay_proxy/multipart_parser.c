#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/evp.h>

#include "multipart_parser.h"
#include "file_analyzer.h"
#include "logger.h"
#include "upload_capture.h"

#define MULTIPART_BOUNDARY_SIZE 160
#define MULTIPART_FILENAME_SIZE 260
#define MULTIPART_EXT_SIZE 32
#define REQUEST_BODY_FALLBACK_SCAN_BYTES (20 * 1024 * 1024)
#define MULTIPART_RECORD_FAILURE_RULE_ID 9301

static int safe_set_result(
    dlp_result_t* result,
    int action,
    int rule_id,
    const char* keyword,
    const char* reason
);

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

static int multipart_boundary_suffix_is_valid(
    const char* marker_end,
    const char* body_end
)
{
    if (marker_end == NULL || body_end == NULL || marker_end > body_end) {
        return 0;
    }

    if ((size_t)(body_end - marker_end) >= 2 &&
        marker_end[0] == '-' && marker_end[1] == '-') {
        const char* after_close = marker_end + 2;
        return after_close == body_end ||
            ((size_t)(body_end - after_close) >= 2 &&
             after_close[0] == '\r' && after_close[1] == '\n');
    }

    return (size_t)(body_end - marker_end) >= 2 &&
        marker_end[0] == '\r' && marker_end[1] == '\n';
}

/*
 * A MIME boundary delimiter is valid only at the beginning of the body or
 * after CRLF.  delimiter_start points at the framing CRLF for non-initial
 * delimiters so callers can remove exactly that CRLF from the part payload.
 */
static const char* find_multipart_boundary_marker(
    const char* body,
    const char* body_end,
    const char* search_start,
    const char* marker,
    size_t marker_length,
    const char** delimiter_start
)
{
    const char* cursor;

    if (delimiter_start != NULL) {
        *delimiter_start = NULL;
    }
    if (body == NULL || body_end == NULL || search_start == NULL ||
        marker == NULL || marker_length == 0 || body > body_end ||
        search_start < body || search_start > body_end) {
        return NULL;
    }

    if (search_start == body && (size_t)(body_end - body) >= marker_length &&
        memcmp(body, marker, marker_length) == 0 &&
        multipart_boundary_suffix_is_valid(body + marker_length, body_end)) {
        if (delimiter_start != NULL) {
            *delimiter_start = body;
        }
        return body;
    }

    cursor = search_start;
    while ((size_t)(body_end - cursor) >= marker_length + 2) {
        if (cursor[0] == '\r' && cursor[1] == '\n' &&
            memcmp(cursor + 2, marker, marker_length) == 0 &&
            multipart_boundary_suffix_is_valid(cursor + 2 + marker_length, body_end)) {
            if (delimiter_start != NULL) {
                *delimiter_start = cursor;
            }
            return cursor + 2;
        }
        cursor++;
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


static size_t min_size_t(size_t a, size_t b)
{
    return a < b ? a : b;
}

static int multipart_env_flag_enabled(const char* name)
{
    const char* value = name != NULL ? getenv(name) : NULL;
    return value != NULL && value[0] != '\0' &&
        _stricmp(value, "0") != 0 && _stricmp(value, "false") != 0 &&
        _stricmp(value, "no") != 0 && _stricmp(value, "off") != 0;
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

static void sha256_hex(const char* data, size_t length, char output[65])
{
    EVP_MD_CTX* ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    unsigned int i;

    output[0] = '\0';
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return;
    }
    digest_len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, length) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1) {
        for (i = 0; i < digest_len; ++i) {
            _snprintf_s(output + (i * 2), 65 - (i * 2), _TRUNCATE, "%02x", digest[i]);
        }
    }
    EVP_MD_CTX_free(ctx);
}

static const char* detect_file_signature(const unsigned char* data, size_t length)
{
    if (length >= 4 && data[0] == 0x50 && data[1] == 0x4b &&
        ((data[2] == 0x03 && data[3] == 0x04) ||
         (data[2] == 0x05 && data[3] == 0x06) ||
         (data[2] == 0x07 && data[3] == 0x08))) return "zip";
    if (length >= 5 && memcmp(data, "%PDF-", 5) == 0) return "pdf";
    if (length >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) return "png";
    if (length >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff) return "jpeg";
    if (length >= 6 && (memcmp(data, "GIF87a", 6) == 0 || memcmp(data, "GIF89a", 6) == 0)) return "gif";
    if (length >= 2 && data[0] == 'M' && data[1] == 'Z') return "exe";
    return "unknown";
}

static int signature_matches_extension(const char* signature, const char* ext)
{
    if (signature == NULL || ext == NULL || signature[0] == 'u') return 1;
    if (_stricmp(signature, "zip") == 0)
        return _stricmp(ext, ".zip") == 0 || _stricmp(ext, ".xlsx") == 0 ||
               _stricmp(ext, ".docx") == 0 || _stricmp(ext, ".pptx") == 0 ||
               _stricmp(ext, ".hwpx") == 0 || _stricmp(ext, ".odt") == 0 ||
               _stricmp(ext, ".ods") == 0 || _stricmp(ext, ".odp") == 0;
    if (_stricmp(signature, "jpeg") == 0) return _stricmp(ext, ".jpg") == 0 || _stricmp(ext, ".jpeg") == 0;
    { char expected[24]; _snprintf_s(expected, sizeof(expected), _TRUNCATE, ".%s", signature); return _stricmp(ext, expected) == 0; }
}

static void extract_part_content_type(const char* header, size_t header_len, char* output, size_t output_size)
{
    const char* p;
    const char* end;
    size_t len;

    output[0] = '\0';
    p = find_text_ci_n(header, header_len, "Content-Type:");
    if (p == NULL) return;
    p += strlen("Content-Type:");
    while (p < header + header_len && (*p == ' ' || *p == '\t')) ++p;
    end = p;
    while (end < header + header_len && *end != '\r' && *end != '\n') ++end;
    len = (size_t)(end - p);
    if (len >= output_size) len = output_size - 1;
    memcpy(output, p, len);
    output[len] = '\0';
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

    if (result->action == DLP_ACTION_BLOCK) {
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

static int find_parameter_value(
    const char* header,
    size_t header_len,
    const char* parameter_name,
    const char** value_start,
    size_t* value_length
)
{
    const char* cursor;
    const char* header_end;
    size_t name_length;

    if (value_start != NULL) *value_start = NULL;
    if (value_length != NULL) *value_length = 0;
    if (header == NULL || parameter_name == NULL || value_start == NULL ||
        value_length == NULL) return 0;

    header_end = header + header_len;
    name_length = strlen(parameter_name);
    for (cursor = header; (size_t)(header_end - cursor) >= name_length; cursor++) {
        const char* value;
        const char* end;
        int token_start = cursor == header || cursor[-1] == ';' ||
            cursor[-1] == ' ' || cursor[-1] == '\t';

        if (!token_start || _strnicmp(cursor, parameter_name, name_length) != 0) {
            continue;
        }

        value = cursor + name_length;
        while (value < header_end && (*value == ' ' || *value == '\t')) value++;
        if (value >= header_end || *value != '=') continue;
        value++;
        while (value < header_end && (*value == ' ' || *value == '\t')) value++;
        if (value >= header_end) return 0;

        if (*value == '"') {
            value++;
            end = value;
            while (end < header_end && *end != '"' && *end != '\r' && *end != '\n') end++;
            if (end >= header_end || *end != '"') return 0;
        }
        else {
            end = value;
            while (end < header_end && *end != ';' && *end != '\r' && *end != '\n') end++;
            while (end > value && (end[-1] == ' ' || end[-1] == '\t')) end--;
        }

        *value_start = value;
        *value_length = (size_t)(end - value);
        return 1;
    }

    return 0;
}

static int utf8_is_valid(const unsigned char* value, size_t length)
{
    size_t i = 0;
    while (i < length) {
        unsigned char first = value[i++];
        unsigned int codepoint;
        int continuation_count;
        int j;

        if (first <= 0x7f) continue;
        if (first >= 0xc2 && first <= 0xdf) {
            codepoint = first & 0x1f;
            continuation_count = 1;
        }
        else if (first >= 0xe0 && first <= 0xef) {
            codepoint = first & 0x0f;
            continuation_count = 2;
        }
        else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = first & 0x07;
            continuation_count = 3;
        }
        else return 0;

        if ((size_t)continuation_count > length - i) return 0;
        for (j = 0; j < continuation_count; j++) {
            unsigned char next = value[i++];
            if ((next & 0xc0) != 0x80) return 0;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((continuation_count == 2 && codepoint < 0x800) ||
            (continuation_count == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) return 0;
    }
    return 1;
}

static int hex_digit_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_rfc5987_utf8_filename(
    const char* value,
    size_t value_length,
    char* output,
    size_t output_size
)
{
    static const char prefix[] = "UTF-8''";
    size_t input_offset = sizeof(prefix) - 1;
    size_t output_offset = 0;

    if (value == NULL || output == NULL || output_size == 0 ||
        value_length < sizeof(prefix) - 1 ||
        _strnicmp(value, prefix, sizeof(prefix) - 1) != 0) return 0;

    while (input_offset < value_length) {
        unsigned char decoded;
        if (value[input_offset] == '%') {
            int high;
            int low;
            if (input_offset + 2 >= value_length) return 0;
            high = hex_digit_value(value[input_offset + 1]);
            low = hex_digit_value(value[input_offset + 2]);
            if (high < 0 || low < 0) return 0;
            decoded = (unsigned char)((high << 4) | low);
            input_offset += 3;
        }
        else {
            decoded = (unsigned char)value[input_offset++];
        }

        if (decoded == 0 || decoded == '\r' || decoded == '\n' || decoded == 0x7f) return 0;
        if (output_offset + 1 >= output_size) return 0;
        output[output_offset++] = (char)decoded;
    }

    if (!utf8_is_valid((const unsigned char*)output, output_offset)) return 0;
    output[output_offset] = '\0';
    return output_offset > 0;
}

static void extract_parameter(
    const char* header,
    size_t header_len,
    const char* parameter_name,
    char* output,
    size_t output_size
)
{
    const char* value;
    size_t value_length;
    size_t copy_length;

    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (!find_parameter_value(header, header_len, parameter_name, &value, &value_length)) return;
    copy_length = value_length < output_size - 1 ? value_length : output_size - 1;
    memcpy(output, value, copy_length);
    output[copy_length] = '\0';
}

static void extract_filename_parameter(
    const char* header,
    size_t header_len,
    char* output,
    size_t output_size
)
{
    const char* extended_value;
    size_t extended_length;

    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    if (find_parameter_value(header, header_len, "filename*", &extended_value, &extended_length) &&
        decode_rfc5987_utf8_filename(extended_value, extended_length, output, output_size)) {
        return;
    }
    extract_parameter(header, header_len, "filename", output, output_size);
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

static int inspect_one_file_part(
    const char* filename,
    const char* field_name,
    const char* part_content_type,
    const char* part_body,
    size_t part_body_len,
    dlp_result_t* result,
    const http_request_t* request,
    const proxy_session_context_t* session,
    const char* service,
    const char* protocol,
    unsigned int stream_id
)
{
    char ext[MULTIPART_EXT_SIZE];
    char reason[256];
    const char* base;
    int changed;
    int record_result = 0;
    char hash[65];
    const char* signature;
    int signature_mismatch;
    file_analysis_result_t analysis;
    int analysis_rule_id = 9001;
    char analysis_keyword[128] = "FILE_ANALYSIS";

    if (filename == NULL || filename[0] == '\0' || part_body == NULL || result == NULL) {
        return 0;
    }

    changed = 0;
    base = filename_basename(filename);
    extract_file_extension(filename, ext, sizeof(ext));

    sha256_hex(part_body, part_body_len, hash);
    signature = detect_file_signature((const unsigned char*)part_body, part_body_len);
    signature_mismatch = !signature_matches_extension(signature, ext);

    memset(&analysis, 0, sizeof(analysis));
    if (file_analyzer_inspect(
        base,
        part_content_type,
        (const unsigned char*)part_body,
        part_body_len,
        &analysis
    ) != 0) {
        analysis.action = FILE_ANALYSIS_BLOCK;
        strcpy_s(analysis.format, sizeof(analysis.format), "UNKNOWN");
        strcpy_s(analysis.reason, sizeof(analysis.reason), "file analyzer failed");
    }
    if (analysis.action != FILE_ANALYSIS_BLOCK) {
        dlp_result_t content_policy = inspect_dlp_file_content(
            base,
            part_content_type,
            (const unsigned char*)part_body,
            part_body_len,
            &analysis);
        if (content_policy.action == DLP_ACTION_BLOCK) {
            analysis.action = FILE_ANALYSIS_BLOCK;
            analysis_rule_id = content_policy.matched_rule_id;
            strncpy_s(analysis_keyword, sizeof(analysis_keyword),
                content_policy.keyword[0] ? content_policy.keyword : "DOCUMENT_CONTENT", _TRUNCATE);
            _snprintf_s(analysis.reason, sizeof(analysis.reason), _TRUNCATE,
                "content policy rule %d: %s",
                content_policy.matched_rule_id,
                content_policy.reason[0] ? content_policy.reason : "blocked");
        }
    }

    if (signature_mismatch) {
        analysis.action = FILE_ANALYSIS_BLOCK;
        analysis.signature_match = 0;
        analysis_rule_id = 12;
        strcpy_s(analysis_keyword, sizeof(analysis_keyword), "SIGNATURE_MISMATCH");
        _snprintf_s(analysis.reason, sizeof(analysis.reason), _TRUNCATE,
            "file signature mismatch: %s extension=%s signature=%s",
            base, ext[0] != '\0' ? ext : "-", signature);
    }

    if (session != NULL && request != NULL) {
        http_request_t part_request = *request;
        file_analysis_result_t stored_analysis = analysis;
        if (result->action == DLP_ACTION_BLOCK && stored_analysis.action != FILE_ANALYSIS_BLOCK) {
            stored_analysis.action = FILE_ANALYSIS_BLOCK;
            if (result->reason[0] != '\0')
                strncpy_s(stored_analysis.reason, sizeof(stored_analysis.reason), result->reason, _TRUNCATE);
        }
        strncpy_s(part_request.content_type, sizeof(part_request.content_type),
            part_content_type != NULL && part_content_type[0] != '\0'
                ? part_content_type : "application/octet-stream", _TRUNCATE);
        part_request.content_length = part_body_len <= INT_MAX ? (int)part_body_len : INT_MAX;
        record_result = upload_record_store_file(
            session,
            &part_request,
            service,
            protocol,
            stream_id,
            base,
            (const unsigned char*)part_body,
            part_body_len,
            &stored_analysis
        );
        if (multipart_env_flag_enabled("LOCAL_DLP_SAVE_UPLOAD_RECORDS") && record_result != 1) {
            log_error(
                "Multipart upload record save failed; request will fail closed. session_id=%lu stream_id=%u file=%s result=%d",
                session->session_id,
                stream_id,
                base,
                record_result
            );
            if (analysis.action != FILE_ANALYSIS_BLOCK) {
                analysis.action = FILE_ANALYSIS_BLOCK;
                analysis_rule_id = MULTIPART_RECORD_FAILURE_RULE_ID;
                strcpy_s(analysis_keyword, sizeof(analysis_keyword), "UPLOAD_RECORD_WRITE");
                strcpy_s(analysis.reason, sizeof(analysis.reason),
                    "upload record could not be saved; blocked fail-closed");
            }
        }
    }

    log_security(
        "FILE_UPLOAD field=%s filename=%s extension=%s mime=%s size=%llu sha256=%s signature=%s signature_mismatch=%s format=%s entries=%u extracted_text_bytes=%llu action=%s reason=\"%s\" inspection=full_file_part record_result=%d",
        field_name != NULL && field_name[0] != '\0' ? field_name : "-",
        base,
        ext[0] != '\0' ? ext : "-",
        part_content_type != NULL && part_content_type[0] != '\0' ? part_content_type : "-",
        (unsigned long long)part_body_len,
        hash[0] != '\0' ? hash : "-",
        signature,
        signature_mismatch ? "true" : "false",
        analysis.format[0] != '\0' ? analysis.format : "UNKNOWN",
        analysis.archive_entries,
        analysis.extracted_text_bytes,
        analysis.action == FILE_ANALYSIS_BLOCK ? "BLOCK" : "ALLOW",
        analysis.reason[0] != '\0' ? analysis.reason : "-",
        record_result
    );

    if (analysis.action == FILE_ANALYSIS_BLOCK) {
        _snprintf_s(reason, sizeof(reason), _TRUNCATE,
            "Multipart upload blocked. file=%s reason=%s", base,
            analysis.reason[0] != '\0' ? analysis.reason : "file analysis policy");
        changed = safe_set_result(result, DLP_ACTION_BLOCK, analysis_rule_id,
            analysis_keyword[0] != '\0' ? analysis_keyword :
                (analysis.format[0] != '\0' ? analysis.format : "FILE_ANALYSIS"), reason);
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

int inspect_multipart_upload_request_with_context(
    const http_request_t* request,
    dlp_result_t* result,
    const proxy_session_context_t* session,
    const char* service,
    const char* protocol,
    unsigned int stream_id
)
{
    char boundary[MULTIPART_BOUNDARY_SIZE];
    char boundary_marker[MULTIPART_BOUNDARY_SIZE + 4];
    size_t boundary_marker_len;
    const char* body;
    size_t body_len;
    const char* boundary_pos;
    const char* body_end;
    int inspected;

    if (request == NULL || result == NULL) {
        return 0;
    }

    if (!extract_multipart_boundary(request->content_type, boundary, sizeof(boundary))) {
        return 0;
    }

    body = request->body_data != NULL ? request->body_data : request->body;
    if (body == NULL) {
        return 0;
    }

    body_len = request->body_data != NULL && request->body_data_length >= 0
        ? (size_t)request->body_data_length
        : get_available_request_body_len(request, body, REQUEST_BODY_FALLBACK_SCAN_BYTES);

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

    body_end = body + body_len;
    inspected = 1;

    boundary_pos = find_multipart_boundary_marker(
        body,
        body_end,
        body,
        boundary_marker,
        boundary_marker_len,
        NULL
    );
    if (boundary_pos == NULL) {
        log_security("Multipart body did not contain a valid RFC boundary delimiter.");
        return inspected;
    }

    log_security(
        "Multipart/form-data request detected. boundary=%s content_length=%lu",
        boundary,
        (unsigned long)body_len
    );

    while (boundary_pos < body_end) {
        const char* part_start;
        const char* header_end;
        const char* part_body;
        const char* next_boundary;
        const char* next_boundary_delimiter;
        const char* part_end;
        size_t remaining;
        size_t header_len;
        size_t part_body_len;
        char filename[MULTIPART_FILENAME_SIZE];
        char field_name[128];
        char part_content_type[128];

        part_start = boundary_pos + boundary_marker_len;
        if ((body_end - part_start) >= 2 && part_start[0] == '-' && part_start[1] == '-') {
            break;
        }

        if ((body_end - part_start) >= 2 && part_start[0] == '\r' && part_start[1] == '\n') {
            part_start += 2;
        }
        else {
            log_security("Multipart boundary delimiter was not followed by CRLF.");
            break;
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
        next_boundary_delimiter = NULL;
        next_boundary = find_multipart_boundary_marker(
            body,
            body_end,
            part_body,
            boundary_marker,
            boundary_marker_len,
            &next_boundary_delimiter
        );
        if (next_boundary == NULL) {
            break;
        }

        /* Exclude only the CRLF that introduces the next delimiter.  Any CRLF
           bytes belonging to the uploaded file remain part of the original. */
        part_end = next_boundary_delimiter;

        part_body_len = (size_t)(part_end - part_body);
        extract_filename_parameter(part_start, header_len, filename, sizeof(filename));
        extract_parameter(part_start, header_len, "name", field_name, sizeof(field_name));
        extract_part_content_type(part_start, header_len, part_content_type, sizeof(part_content_type));

        if (filename[0] != '\0') {
            inspect_one_file_part(filename, field_name, part_content_type, part_body, part_body_len,
                result, request, session, service, protocol, stream_id);
        }

        boundary_pos = next_boundary;
    }

    return inspected;
}

int inspect_multipart_upload_request(const http_request_t* request, dlp_result_t* result)
{
    return inspect_multipart_upload_request_with_context(
        request, result, NULL, NULL, NULL, 0);
}
