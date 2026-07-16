#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "http_response_parser.h"
#include "logger.h"

#define HTTP_RESPONSE_HEADER_BUFFER_SIZE 8192

static int find_header_end(const char* buffer, int length)
{
    int i;

    if (buffer == NULL || length <= 0) {
        return -1;
    }

    for (i = 0; i <= length - 4; i++) {
        if (buffer[i] == '\r' &&
            buffer[i + 1] == '\n' &&
            buffer[i + 2] == '\r' &&
            buffer[i + 3] == '\n') {
            return i + 4;
        }
    }

    return -1;
}

static int find_crlf(const char* data, int length, int start)
{
    int i;

    if (data == NULL || length <= 0 || start < 0) {
        return -1;
    }

    for (i = start; i <= length - 2; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return i;
        }
    }

    return -1;
}

static const char* skip_spaces(const char* text)
{
    if (text == NULL) {
        return NULL;
    }

    while (*text == ' ' || *text == '\t') {
        text++;
    }

    return text;
}

static int contains_ignore_case(const char* text, const char* token)
{
    int text_length;
    int token_length;
    int i;

    if (text == NULL || token == NULL) {
        return 0;
    }

    text_length = (int)strlen(text);
    token_length = (int)strlen(token);

    if (text_length <= 0 || token_length <= 0 || text_length < token_length) {
        return 0;
    }

    for (i = 0; i <= text_length - token_length; i++) {
        if (_strnicmp(text + i, token, token_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static void copy_header_value(
    char* dest,
    int dest_size,
    const char* value
)
{
    const char* start;
    int length;

    if (dest == NULL || dest_size <= 0) {
        return;
    }

    dest[0] = '\0';

    if (value == NULL) {
        return;
    }

    start = skip_spaces(value);
    if (start == NULL) {
        return;
    }

    length = (int)strlen(start);

    while (length > 0 &&
        (start[length - 1] == '\r' ||
            start[length - 1] == '\n' ||
            start[length - 1] == ' ' ||
            start[length - 1] == '\t')) {
        length--;
    }

    if (length <= 0) {
        return;
    }

    if (length >= dest_size) {
        length = dest_size - 1;
    }

    memcpy(dest, start, length);
    dest[length] = '\0';
}

static void store_header(http_response_t* response, const char* line)
{
    const char* colon;
    int name_length;
    http_header_t* header;

    if (response == NULL || line == NULL || line[0] == '\0') {
        return;
    }

    colon = strchr(line, ':');
    if (colon == NULL || colon == line) {
        return;
    }

    if (response->header_count >= HTTP_MAX_HEADER_COUNT) {
        response->headers_truncated = 1;
        return;
    }

    header = &response->headers[response->header_count];
    name_length = (int)(colon - line);

    while (name_length > 0 && isspace((unsigned char)line[name_length - 1])) {
        name_length--;
    }

    if (name_length <= 0) {
        return;
    }

    if (name_length >= HTTP_HEADER_NAME_SIZE) {
        name_length = HTTP_HEADER_NAME_SIZE - 1;
        header->value_truncated = 1;
    }

    memcpy(header->name, line, name_length);
    header->name[name_length] = '\0';
    copy_header_value(header->value, sizeof(header->value), colon + 1);

    if (strlen(skip_spaces(colon + 1)) >= sizeof(header->value)) {
        header->value_truncated = 1;
    }

    response->header_count++;
}

static int header_is_sensitive(const char* name)
{
    return name != NULL && (
        _stricmp(name, "Authorization") == 0 ||
        _stricmp(name, "Proxy-Authorization") == 0 ||
        _stricmp(name, "Cookie") == 0 ||
        _stricmp(name, "Set-Cookie") == 0 ||
        _stricmp(name, "X-Api-Key") == 0
    );
}

static int content_type_is_textual(const char* content_type)
{
    return content_type != NULL && (
        contains_ignore_case(content_type, "text/") ||
        contains_ignore_case(content_type, "json") ||
        contains_ignore_case(content_type, "xml") ||
        contains_ignore_case(content_type, "x-www-form-urlencoded") ||
        contains_ignore_case(content_type, "javascript")
    );
}

static int body_may_be_sensitive(const char* body)
{
    return body != NULL && (
        contains_ignore_case(body, "password") ||
        contains_ignore_case(body, "token") ||
        contains_ignore_case(body, "secret")
    );
}

static void make_log_preview(const char* source, int source_length, char* dest, int dest_size)
{
    int i;
    int out = 0;
    int limit;

    if (dest == NULL || dest_size <= 0) {
        return;
    }

    dest[0] = '\0';
    if (source == NULL || source_length <= 0) {
        return;
    }

    limit = source_length;
    if (limit > dest_size - 1) {
        limit = dest_size - 1;
    }

    for (i = 0; i < limit; i++) {
        unsigned char ch = (unsigned char)source[i];
        dest[out++] = (ch < 32 || ch == 127) ? ' ' : (char)ch;
    }

    dest[out] = '\0';
}

static void parse_status_line(const char* line, http_response_t* response)
{
    const char* p;

    if (line == NULL || response == NULL) {
        return;
    }

    sscanf_s(
        line,
        "%31s %d",
        response->version,
        (unsigned int)sizeof(response->version),
        &response->status_code
    );

    p = strchr(line, ' ');
    if (p == NULL) {
        return;
    }

    while (*p == ' ') {
        p++;
    }

    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    if (*p != '\0') {
        copy_header_value(
            response->reason_phrase,
            sizeof(response->reason_phrase),
            p
        );
    }
}

static int hex_char_to_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

static int parse_chunk_size_line(
    const char* data,
    int line_start,
    int line_end,
    unsigned long* chunk_size
)
{
    int i;
    unsigned long value = 0;
    int digit_count = 0;

    if (data == NULL || chunk_size == NULL || line_start < 0 || line_end < line_start) {
        return -1;
    }

    for (i = line_start; i < line_end; i++) {
        char ch = data[i];
        int hex_value;

        if (ch == ';') {
            break;
        }

        if (ch == ' ' || ch == '\t') {
            if (digit_count > 0) {
                break;
            }

            continue;
        }

        hex_value = hex_char_to_value(ch);
        if (hex_value < 0) {
            return -1;
        }

        if (value > 0x7FFFFFFFUL / 16) {
            return -1;
        }

        value = value * 16 + (unsigned long)hex_value;
        digit_count++;
    }

    if (digit_count <= 0) {
        return -1;
    }

    *chunk_size = value;

    return 0;
}

static int decode_chunked_body(
    const char* encoded_body,
    int encoded_length,
    char* decoded_body,
    int decoded_body_size,
    int* decoded_length
)
{
    int pos = 0;
    int out_pos = 0;

    if (encoded_body == NULL ||
        decoded_body == NULL ||
        decoded_body_size <= 0 ||
        decoded_length == NULL) {
        return -1;
    }

    decoded_body[0] = '\0';
    *decoded_length = 0;

    while (1) {
        int line_end;
        unsigned long chunk_size;

        line_end = find_crlf(encoded_body, encoded_length, pos);
        if (line_end < 0) {
            return -1;
        }

        chunk_size = 0;

        if (parse_chunk_size_line(encoded_body, pos, line_end, &chunk_size) != 0) {
            return -1;
        }

        pos = line_end + 2;

        if (chunk_size == 0) {
            break;
        }

        if (chunk_size > (unsigned long)(encoded_length - pos)) {
            return -1;
        }

        if (out_pos + (int)chunk_size >= decoded_body_size) {
            int copy_length = decoded_body_size - out_pos - 1;

            if (copy_length > 0) {
                memcpy(decoded_body + out_pos, encoded_body + pos, copy_length);
                out_pos += copy_length;
            }

            decoded_body[out_pos] = '\0';
            *decoded_length = out_pos;

            return 0;
        }

        memcpy(decoded_body + out_pos, encoded_body + pos, (int)chunk_size);
        out_pos += (int)chunk_size;

        pos += (int)chunk_size;

        if (pos + 2 > encoded_length) {
            return -1;
        }

        if (encoded_body[pos] != '\r' || encoded_body[pos + 1] != '\n') {
            return -1;
        }

        pos += 2;
    }

    decoded_body[out_pos] = '\0';
    *decoded_length = out_pos;

    return 0;
}

int parse_http_response(const char* buffer, int length, http_response_t* response)
{
    int header_end;
    int header_length;
    int raw_body_length;

    char header_copy[HTTP_RESPONSE_HEADER_BUFFER_SIZE];
    char* line;
    char* context = NULL;
    int is_first_line = 1;

    if (buffer == NULL || response == NULL || length <= 0) {
        return 0;
    }

    memset(response, 0, sizeof(http_response_t));

    header_end = find_header_end(buffer, length);
    if (header_end < 0) {
        return 0;
    }

    header_length = header_end;

    if (header_length >= HTTP_RESPONSE_HEADER_BUFFER_SIZE) {
        return 0;
    }

    memcpy(header_copy, buffer, header_length);
    header_copy[header_length] = '\0';

    line = strtok_s(header_copy, "\r\n", &context);

    while (line != NULL) {
        if (is_first_line) {
            parse_status_line(line, response);
            is_first_line = 0;
        }
        else {
            store_header(response, line);

            if (_strnicmp(line, "Content-Length:", 15) == 0) {
                const char* value = skip_spaces(line + 15);

                if (value != NULL) {
                    response->content_length = atoi(value);
                }
            }
            else if (_strnicmp(line, "Content-Type:", 13) == 0) {
                copy_header_value(
                    response->content_type,
                    sizeof(response->content_type),
                    line + 13
                );
            }
            else if (_strnicmp(line, "Transfer-Encoding:", 18) == 0) {
                copy_header_value(
                    response->transfer_encoding,
                    sizeof(response->transfer_encoding),
                    line + 18
                );

                if (contains_ignore_case(response->transfer_encoding, "chunked")) {
                    response->is_chunked = 1;
                }
            }
        }

        line = strtok_s(NULL, "\r\n", &context);
    }

    raw_body_length = length - header_end;

    if (raw_body_length < 0) {
        raw_body_length = 0;
    }

    if (response->is_chunked) {
        int decoded_length = 0;

        if (decode_chunked_body(
            buffer + header_end,
            raw_body_length,
            response->body,
            sizeof(response->body),
            &decoded_length
        ) == 0) {
            response->body_length = decoded_length;
        }
        else {
            int copy_length = raw_body_length;

            if (copy_length > HTTP_RESPONSE_BODY_SIZE - 1) {
                copy_length = HTTP_RESPONSE_BODY_SIZE - 1;
            }

            if (copy_length > 0) {
                memcpy(response->body, buffer + header_end, copy_length);
                response->body[copy_length] = '\0';
                response->body_length = copy_length;
            }
        }
    }
    else {
        int body_length = raw_body_length;

        if (body_length > HTTP_RESPONSE_BODY_SIZE - 1) {
            body_length = HTTP_RESPONSE_BODY_SIZE - 1;
        }

        if (body_length > 0) {
            memcpy(response->body, buffer + header_end, body_length);
            response->body[body_length] = '\0';
            response->body_length = body_length;
        }
    }

    return 1;
}

void print_http_response(const http_response_t* response)
{
    if (response == NULL) {
        return;
    }

    printf("\n[HTTP RESPONSE]\n");
    printf("Version          : %s\n", response->version);
    printf("Status Code      : %d\n", response->status_code);

    if (response->reason_phrase[0] != '\0') {
        printf("Reason           : %s\n", response->reason_phrase);
    }
    else {
        printf("Reason           : -\n");
    }

    if (response->content_type[0] != '\0') {
        printf("Content-Type     : %s\n", response->content_type);
    }
    else {
        printf("Content-Type     : -\n");
    }

    if (response->transfer_encoding[0] != '\0') {
        printf("Transfer-Encoding: %s\n", response->transfer_encoding);
    }
    else {
        printf("Transfer-Encoding: -\n");
    }

    printf("Content-Length   : %d\n", response->content_length);
    printf("Is-Chunked       : %d\n", response->is_chunked);
    printf("Headers (%d%s):\n", response->header_count, response->headers_truncated ? "+" : "");
    {
        int i;
        for (i = 0; i < response->header_count; i++) {
            printf("  %s: %s%s\n", response->headers[i].name, response->headers[i].value,
                response->headers[i].value_truncated ? " [truncated]" : "");
        }
    }

    if (response->body_length > 0) {
        printf("Body             : %s\n", response->body);
    }
    else {
        printf("Body             : -\n");
    }

    printf("\n");
}

void log_http_response_analysis(
    const http_response_t* response,
    unsigned long session_id,
    const char* transport
)
{
    int i;
    char body_preview[768];

    if (response == NULL) {
        return;
    }

    log_info(
        "HTTP_ANALYSIS direction=RESPONSE session_id=%lu transport=%s status=%d reason=%s content_type=%s content_length=%d headers=%d%s body_bytes=%d",
        session_id, transport != NULL ? transport : "-", response->status_code,
        response->reason_phrase[0] != '\0' ? response->reason_phrase : "-",
        response->content_type[0] != '\0' ? response->content_type : "-",
        response->content_length, response->header_count,
        response->headers_truncated ? "+" : "", response->body_length
    );

    for (i = 0; i < response->header_count; i++) {
        const http_header_t* header = &response->headers[i];
        log_debug(
            "HTTP_ANALYSIS direction=RESPONSE session_id=%lu header=%s value=%s%s",
            session_id, header->name,
            header_is_sensitive(header->name) ? "[REDACTED]" : header->value,
            header->value_truncated ? " [truncated]" : ""
        );
    }

    if (response->body_length <= 0) {
        log_debug("HTTP_ANALYSIS direction=RESPONSE session_id=%lu body=-", session_id);
    }
    else if (!content_type_is_textual(response->content_type)) {
        log_debug("HTTP_ANALYSIS direction=RESPONSE session_id=%lu body=[binary or unsupported content type omitted]", session_id);
    }
    else if (body_may_be_sensitive(response->body)) {
        log_debug("HTTP_ANALYSIS direction=RESPONSE session_id=%lu body=[REDACTED: sensitive field detected]", session_id);
    }
    else {
        make_log_preview(response->body, response->body_length, body_preview, sizeof(body_preview));
        log_debug("HTTP_ANALYSIS direction=RESPONSE session_id=%lu body_preview=%s%s", session_id,
            body_preview, response->body_length >= (int)sizeof(body_preview) ? " [truncated]" : "");
    }
}
