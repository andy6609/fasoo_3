#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "http_parser.h"
#include "logger.h"

#define HTTP_HEADER_BUFFER_SIZE 8192

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

static void store_header(http_request_t* request, const char* line)
{
    const char* colon;
    int name_length;
    http_header_t* header;

    if (request == NULL || line == NULL || line[0] == '\0') {
        return;
    }

    colon = strchr(line, ':');
    if (colon == NULL || colon == line) {
        return;
    }

    if (request->header_count >= HTTP_MAX_HEADER_COUNT) {
        request->headers_truncated = 1;
        return;
    }

    header = &request->headers[request->header_count];
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

    request->header_count++;
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

    if (token_length <= 0 || text_length < token_length) {
        return 0;
    }

    for (i = 0; i <= text_length - token_length; i++) {
        if (_strnicmp(text + i, token, token_length) == 0) {
            return 1;
        }
    }

    return 0;
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

int parse_http_request(const char* buffer, int length, http_request_t* request)
{
    int header_end;
    int header_length;
    int body_length;

    char header_copy[HTTP_HEADER_BUFFER_SIZE];
    char* line;
    char* context = NULL;
    int is_first_line = 1;

    if (buffer == NULL || request == NULL || length <= 0) {
        return 0;
    }

    memset(request, 0, sizeof(http_request_t));

    header_end = find_header_end(buffer, length);
    if (header_end < 0) {
        return 0;
    }

    header_length = header_end;

    if (header_length >= HTTP_HEADER_BUFFER_SIZE) {
        return 0;
    }

    memcpy(header_copy, buffer, header_length);
    header_copy[header_length] = '\0';

    line = strtok_s(header_copy, "\r\n", &context);

    while (line != NULL) {
        if (is_first_line) {
            sscanf_s(
                line,
                "%31s %511s %31s",
                request->method,
                (unsigned int)sizeof(request->method),
                request->path,
                (unsigned int)sizeof(request->path),
                request->version,
                (unsigned int)sizeof(request->version)
            );

            is_first_line = 0;
        }
        else {
            store_header(request, line);

            if (_strnicmp(line, "Host:", 5) == 0) {
                copy_header_value(
                    request->host,
                    sizeof(request->host),
                    line + 5
                );
            }
            else if (_strnicmp(line, "Content-Length:", 15) == 0) {
                const char* value = skip_spaces(line + 15);

                if (value != NULL) {
                    request->content_length = atoi(value);
                }
            }
            else if (_strnicmp(line, "Content-Type:", 13) == 0) {
                copy_header_value(
                    request->content_type,
                    sizeof(request->content_type),
                    line + 13
                );
            }
        }

        line = strtok_s(NULL, "\r\n", &context);
    }

    body_length = length - header_end;

    if (body_length < 0) {
        body_length = 0;
    }

    if (body_length > HTTP_BODY_SIZE - 1) {
        body_length = HTTP_BODY_SIZE - 1;
    }

    if (body_length > 0) {
        memcpy(request->body, buffer + header_end, body_length);
        request->body[body_length] = '\0';
        request->body_length = body_length;
    }

    return 1;
}

void print_http_request(const http_request_t* request)
{
    if (request == NULL) {
        return;
    }

    printf("\n[HTTP REQUEST]\n");
    printf("Method : %s\n", request->method);
    printf("Path   : %s\n", request->path);
    printf("Version: %s\n", request->version);
    printf("Host   : %s\n", request->host);

    if (request->content_type[0] != '\0') {
        printf("Content-Type  : %s\n", request->content_type);
    }
    else {
        printf("Content-Type  : -\n");
    }

    printf("Content-Length: %d\n", request->content_length);
    printf("Headers (%d%s):\n", request->header_count, request->headers_truncated ? "+" : "");
    {
        int i;
        for (i = 0; i < request->header_count; i++) {
            printf("  %s: %s%s\n", request->headers[i].name, request->headers[i].value,
                request->headers[i].value_truncated ? " [truncated]" : "");
        }
    }

    if (request->body_length > 0) {
        printf("Body   : %s\n", request->body);
    }
    else {
        printf("Body   : -\n");
    }

    printf("\n");
}

void log_http_request_analysis(
    const http_request_t* request,
    unsigned long session_id,
    const char* transport
)
{
    int i;
    char body_preview[768];

    if (request == NULL) {
        return;
    }

    log_info(
        "HTTP_ANALYSIS direction=REQUEST session_id=%lu transport=%s method=%s path=%s host=%s content_type=%s content_length=%d headers=%d%s body_bytes=%d",
        session_id, transport != NULL ? transport : "-", request->method, request->path,
        request->host[0] != '\0' ? request->host : "-",
        request->content_type[0] != '\0' ? request->content_type : "-",
        request->content_length, request->header_count,
        request->headers_truncated ? "+" : "", request->body_length
    );

    for (i = 0; i < request->header_count; i++) {
        const http_header_t* header = &request->headers[i];
        log_info(
            "HTTP_ANALYSIS direction=REQUEST session_id=%lu header=%s value=%s%s",
            session_id, header->name,
            header_is_sensitive(header->name) ? "[REDACTED]" : header->value,
            header->value_truncated ? " [truncated]" : ""
        );
    }

    if (request->body_length <= 0) {
        log_info("HTTP_ANALYSIS direction=REQUEST session_id=%lu body=-", session_id);
    }
    else if (!content_type_is_textual(request->content_type)) {
        log_info("HTTP_ANALYSIS direction=REQUEST session_id=%lu body=[binary or unsupported content type omitted]", session_id);
    }
    else if (body_may_be_sensitive(request->body)) {
        log_info("HTTP_ANALYSIS direction=REQUEST session_id=%lu body=[REDACTED: sensitive field detected]", session_id);
    }
    else {
        make_log_preview(request->body, request->body_length, body_preview, sizeof(body_preview));
        log_info("HTTP_ANALYSIS direction=REQUEST session_id=%lu body_preview=%s%s", session_id,
            body_preview, request->body_length >= (int)sizeof(body_preview) ? " [truncated]" : "");
    }
}
