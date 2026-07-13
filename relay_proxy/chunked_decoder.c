#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "chunked_decoder.h"
#include "logger.h"

#define CHUNKED_DECODER_MAX_HEADER_VALUE 256
#define CHUNKED_DECODER_MAX_DECODED_SIZE (1024 * 1024)

static int ascii_tolower_local(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int ascii_strnicmp_local(const char* a, const char* b, int n)
{
    int i;
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL) {
        return (a == b) ? 0 : 1;
    }

    for (i = 0; i < n; i++) {
        ca = (unsigned char)a[i];
        cb = (unsigned char)b[i];

        if (ca == '\0' || cb == '\0') {
            return (int)ca - (int)cb;
        }

        ca = (unsigned char)ascii_tolower_local(ca);
        cb = (unsigned char)ascii_tolower_local(cb);

        if (ca != cb) {
            return (int)ca - (int)cb;
        }
    }

    return 0;
}

static int find_http_header_end_local(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return -1;
    }

    for (i = 0; i + 3 < length; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i + 4;
        }
    }

    return -1;
}

static int find_crlf_from(const char* data, int length, int start)
{
    int i;

    if (data == NULL || start < 0 || start >= length) {
        return -1;
    }

    for (i = start; i + 1 < length; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return i;
        }
    }

    return -1;
}

static void trim_header_value(char* value)
{
    char* start;
    char* end;
    size_t len;

    if (value == NULL) {
        return;
    }

    start = value;
    while (*start == ' ' || *start == '\t') {
        start++;
    }

    if (start != value) {
        memmove(value, start, strlen(start) + 1);
    }

    len = strlen(value);
    while (len > 0) {
        end = value + len - 1;
        if (*end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') {
            break;
        }
        *end = '\0';
        len--;
    }
}

static int extract_header_value_ci(
    const char* raw_message,
    int header_length,
    const char* header_name,
    char* value,
    int value_size
)
{
    const char* p;
    const char* line_start;
    const char* line_end;
    int header_name_len;
    int line_len;
    int copy_len;

    if (raw_message == NULL || header_length <= 0 || header_name == NULL ||
        value == NULL || value_size <= 0) {
        return 0;
    }

    value[0] = '\0';
    header_name_len = (int)strlen(header_name);

    line_end = strstr(raw_message, "\r\n");
    if (line_end == NULL) {
        return 0;
    }

    p = line_end + 2;

    while (p < raw_message + header_length) {
        line_start = p;
        line_end = strstr(line_start, "\r\n");
        if (line_end == NULL || line_end == line_start) {
            break;
        }

        line_len = (int)(line_end - line_start);

        if (line_len > header_name_len &&
            ascii_strnicmp_local(line_start, header_name, header_name_len) == 0 &&
            line_start[header_name_len] == ':') {
            copy_len = line_len - header_name_len - 1;
            if (copy_len >= value_size) {
                copy_len = value_size - 1;
            }

            memcpy(value, line_start + header_name_len + 1, copy_len);
            value[copy_len] = '\0';
            trim_header_value(value);
            return 1;
        }

        p = line_end + 2;
    }

    return 0;
}

static int header_value_contains_token_ci(const char* value, const char* token)
{
    const char* p;
    const char* start;
    const char* end;
    size_t token_len;
    size_t part_len;

    if (value == NULL || token == NULL) {
        return 0;
    }

    token_len = strlen(token);
    p = value;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }

        start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }

        end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        part_len = (size_t)(end - start);
        if (part_len == token_len && ascii_strnicmp_local(start, token, (int)token_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int parse_chunk_size_line(const char* line, int line_length, unsigned long* size_out)
{
    int i;
    unsigned long value;
    int saw_digit;

    if (line == NULL || line_length <= 0 || size_out == NULL) {
        return -1;
    }

    value = 0;
    saw_digit = 0;

    for (i = 0; i < line_length; i++) {
        unsigned char ch = (unsigned char)line[i];
        int digit;

        if (ch == ';') {
            break;
        }

        if (ch == ' ' || ch == '\t') {
            continue;
        }

        if (ch >= '0' && ch <= '9') {
            digit = ch - '0';
        }
        else if (ch >= 'a' && ch <= 'f') {
            digit = ch - 'a' + 10;
        }
        else if (ch >= 'A' && ch <= 'F') {
            digit = ch - 'A' + 10;
        }
        else {
            return -1;
        }

        saw_digit = 1;
        if (value > 0x7FFFFFFFUL / 16UL) {
            return -1;
        }
        value = value * 16UL + (unsigned long)digit;
    }

    if (!saw_digit) {
        return -1;
    }

    *size_out = value;
    return 0;
}

static int parse_chunked_body_complete_length(
    const char* body,
    int body_length,
    int* chunked_total_length
)
{
    int pos;

    if (body == NULL || body_length < 0 || chunked_total_length == NULL) {
        return -1;
    }

    *chunked_total_length = 0;
    pos = 0;

    for (;;) {
        int line_end;
        int line_len;
        unsigned long chunk_size;

        line_end = find_crlf_from(body, body_length, pos);
        if (line_end < 0) {
            return 0;
        }

        line_len = line_end - pos;
        if (parse_chunk_size_line(body + pos, line_len, &chunk_size) != 0) {
            return -1;
        }

        pos = line_end + 2;

        if (chunk_size == 0) {
            int trailer_end;

            if (pos + 1 >= body_length) {
                return 0;
            }

            if (body[pos] == '\r' && body[pos + 1] == '\n') {
                *chunked_total_length = pos + 2;
                return 1;
            }

            trailer_end = -1;
            while (pos + 3 < body_length) {
                if (body[pos] == '\r' && body[pos + 1] == '\n' &&
                    body[pos + 2] == '\r' && body[pos + 3] == '\n') {
                    trailer_end = pos + 4;
                    break;
                }
                pos++;
            }

            if (trailer_end < 0) {
                return 0;
            }

            *chunked_total_length = trailer_end;
            return 1;
        }

        if (chunk_size > (unsigned long)(body_length - pos)) {
            return 0;
        }

        pos += (int)chunk_size;

        if (pos + 1 >= body_length) {
            return 0;
        }

        if (body[pos] != '\r' || body[pos + 1] != '\n') {
            return -1;
        }

        pos += 2;
    }
}

int chunked_message_get_complete_length(
    const char* data,
    int length,
    int* complete_length,
    int* is_chunked
)
{
    int header_length;
    int chunked_body_total_length;
    char transfer_encoding[CHUNKED_DECODER_MAX_HEADER_VALUE];

    if (complete_length != NULL) {
        *complete_length = 0;
    }
    if (is_chunked != NULL) {
        *is_chunked = 0;
    }

    if (data == NULL || length <= 0 || complete_length == NULL || is_chunked == NULL) {
        return -1;
    }

    header_length = find_http_header_end_local(data, length);
    if (header_length < 0) {
        return 0;
    }

    if (!extract_header_value_ci(
        data,
        header_length,
        "Transfer-Encoding",
        transfer_encoding,
        sizeof(transfer_encoding)
    )) {
        return 0;
    }

    if (!header_value_contains_token_ci(transfer_encoding, "chunked")) {
        return 0;
    }

    *is_chunked = 1;

    if (parse_chunked_body_complete_length(
        data + header_length,
        length - header_length,
        &chunked_body_total_length
    ) < 0) {
        return -1;
    }

    if (chunked_body_total_length <= 0) {
        return 0;
    }

    *complete_length = header_length + chunked_body_total_length;
    return 1;
}

int chunked_decode_http_message_body(
    const char* raw_message,
    int raw_message_length,
    unsigned char** decoded_body,
    int* decoded_body_length
)
{
    int header_length;
    const char* body;
    int body_length;
    int pos;
    unsigned char* out;
    size_t capacity;
    size_t used;

    if (decoded_body != NULL) {
        *decoded_body = NULL;
    }
    if (decoded_body_length != NULL) {
        *decoded_body_length = 0;
    }

    if (raw_message == NULL || raw_message_length <= 0 || decoded_body == NULL || decoded_body_length == NULL) {
        return -1;
    }

    header_length = find_http_header_end_local(raw_message, raw_message_length);
    if (header_length < 0 || header_length > raw_message_length) {
        return -1;
    }

    body = raw_message + header_length;
    body_length = raw_message_length - header_length;

    capacity = (size_t)body_length + 1;
    if (capacity < 1) {
        capacity = 1;
    }
    if (capacity > CHUNKED_DECODER_MAX_DECODED_SIZE + 1) {
        capacity = CHUNKED_DECODER_MAX_DECODED_SIZE + 1;
    }

    out = (unsigned char*)malloc(capacity);
    if (out == NULL) {
        return -1;
    }

    pos = 0;
    used = 0;

    for (;;) {
        int line_end;
        int line_len;
        unsigned long chunk_size;

        line_end = find_crlf_from(body, body_length, pos);
        if (line_end < 0) {
            free(out);
            return -1;
        }

        line_len = line_end - pos;
        if (parse_chunk_size_line(body + pos, line_len, &chunk_size) != 0) {
            free(out);
            return -1;
        }

        pos = line_end + 2;

        if (chunk_size == 0) {
            break;
        }

        if (chunk_size > (unsigned long)(body_length - pos)) {
            free(out);
            return -1;
        }

        if (used + (size_t)chunk_size > CHUNKED_DECODER_MAX_DECODED_SIZE) {
            log_warn(
                "Chunked decoded body exceeds DLP decode limit. limit=%d",
                CHUNKED_DECODER_MAX_DECODED_SIZE
            );
            free(out);
            return -1;
        }

        if (used + (size_t)chunk_size + 1 > capacity) {
            size_t new_capacity;
            unsigned char* resized;

            new_capacity = capacity * 2;
            while (used + (size_t)chunk_size + 1 > new_capacity) {
                new_capacity *= 2;
            }
            if (new_capacity > CHUNKED_DECODER_MAX_DECODED_SIZE + 1) {
                new_capacity = CHUNKED_DECODER_MAX_DECODED_SIZE + 1;
            }

            resized = (unsigned char*)realloc(out, new_capacity);
            if (resized == NULL) {
                free(out);
                return -1;
            }

            out = resized;
            capacity = new_capacity;
        }

        memcpy(out + used, body + pos, (size_t)chunk_size);
        used += (size_t)chunk_size;
        pos += (int)chunk_size;

        if (pos + 1 >= body_length || body[pos] != '\r' || body[pos + 1] != '\n') {
            free(out);
            return -1;
        }

        pos += 2;
    }

    out[used] = '\0';
    *decoded_body = out;
    *decoded_body_length = (int)used;
    return 0;
}

int chunked_decoder_prepare_request_for_dlp(
    const http_request_t* original_request,
    const char* raw_request,
    int raw_request_length,
    http_request_t* decoded_request,
    const char* log_context
)
{
    int complete_length;
    int is_chunked;
    unsigned char* decoded_body;
    int decoded_body_length;
    int copy_length;
    size_t body_capacity;

    if (original_request == NULL || raw_request == NULL || raw_request_length <= 0 ||
        decoded_request == NULL) {
        return 0;
    }

    complete_length = 0;
    is_chunked = 0;
    if (chunked_message_get_complete_length(
        raw_request,
        raw_request_length,
        &complete_length,
        &is_chunked
    ) < 0) {
        log_warn(
            "Malformed chunked HTTP request detected. context=%s DLP will inspect original request body.",
            log_context != NULL ? log_context : "-"
        );
        return -1;
    }

    if (!is_chunked) {
        return 0;
    }

    log_info(
        "Chunked HTTP request body detected. context=%s raw_body_bytes=%d",
        log_context != NULL ? log_context : "-",
        raw_request_length
    );

    decoded_body = NULL;
    decoded_body_length = 0;
    if (chunked_decode_http_message_body(
        raw_request,
        raw_request_length,
        &decoded_body,
        &decoded_body_length
    ) != 0) {
        log_warn(
            "Failed to decode chunked HTTP request body. context=%s DLP will inspect original request body.",
            log_context != NULL ? log_context : "-"
        );
        return -1;
    }

    *decoded_request = *original_request;

    body_capacity = sizeof(decoded_request->body);
    copy_length = decoded_body_length;
    if ((size_t)copy_length >= body_capacity) {
        copy_length = (int)body_capacity - 1;
        log_warn(
            "Dechunked request body truncated for DLP. context=%s decoded_bytes=%d copied_bytes=%d",
            log_context != NULL ? log_context : "-",
            decoded_body_length,
            copy_length
        );
    }

    if (copy_length > 0) {
        memcpy(decoded_request->body, decoded_body, copy_length);
    }
    decoded_request->body[copy_length] = '\0';
    decoded_request->content_length = copy_length;
    decoded_request->body_data = decoded_request->body;
    decoded_request->body_data_length = copy_length;

    log_info(
        "Decoded chunked HTTP request body for DLP. context=%s decoded_body_bytes=%d copied_bytes=%d",
        log_context != NULL ? log_context : "-",
        decoded_body_length,
        copy_length
    );

    free(decoded_body);
    return 1;
}
