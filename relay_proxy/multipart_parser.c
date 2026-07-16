#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <openssl/evp.h>

#include "multipart_parser.h"
#include "logger.h"

#define MULTIPART_BOUNDARY_SIZE 160
#define MULTIPART_FILENAME_SIZE 260
#define MULTIPART_EXT_SIZE 32
#define REQUEST_BODY_FALLBACK_SCAN_BYTES (20 * 1024 * 1024)

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
               _stricmp(ext, ".docx") == 0 || _stricmp(ext, ".pptx") == 0;
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

static int inspect_one_file_part(
    const char* filename,
    const char* field_name,
    const char* part_content_type,
    const char* part_body,
    size_t part_body_len,
    dlp_result_t* result
)
{
    char ext[MULTIPART_EXT_SIZE];
    char reason[256];
    const char* base;
    int changed;
    char hash[65];
    const char* signature;
    int signature_mismatch;

    if (filename == NULL || filename[0] == '\0' || part_body == NULL || result == NULL) {
        return 0;
    }

    changed = 0;
    base = filename_basename(filename);
    extract_file_extension(filename, ext, sizeof(ext));

    sha256_hex(part_body, part_body_len, hash);
    signature = detect_file_signature((const unsigned char*)part_body, part_body_len);
    signature_mismatch = !signature_matches_extension(signature, ext);

    log_security(
        "FILE_UPLOAD field=%s filename=%s extension=%s mime=%s size=%lu sha256=%s signature=%s signature_mismatch=%s inspection=file_metadata_only",
        field_name != NULL && field_name[0] != '\0' ? field_name : "-",
        base,
        ext[0] != '\0' ? ext : "-",
        part_content_type != NULL && part_content_type[0] != '\0' ? part_content_type : "-",
        (unsigned long)part_body_len,
        hash[0] != '\0' ? hash : "-",
        signature,
        signature_mismatch ? "true" : "false"
    );

    if (signature_mismatch) {
        _snprintf_s(reason, sizeof(reason), _TRUNCATE,
            "Multipart upload blocked. file signature mismatch: %s extension=%s signature=%s",
            base, ext[0] != '\0' ? ext : "-", signature);
        return safe_set_result(result, DLP_ACTION_BLOCK, 12, "SIGNATURE_MISMATCH", reason);
    }

    if (result->action == DLP_ACTION_ALLOW) {
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
        char field_name[128];
        char part_content_type[128];

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
        extract_quoted_parameter(part_start, header_len, "name", field_name, sizeof(field_name));
        extract_part_content_type(part_start, header_len, part_content_type, sizeof(part_content_type));

        if (filename[0] != '\0') {
            inspect_one_file_part(filename, field_name, part_content_type, part_body, part_body_len, result);
            if (result->action == DLP_ACTION_BLOCK) {
                return inspected;
            }
        }

        cursor = next_boundary;
    }

    return inspected;
}
