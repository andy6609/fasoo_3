#define _CRT_SECURE_NO_WARNINGS

#include <string.h>
#include <stdlib.h>

#include "response_buffer.h"
#include "chunked_decoder.h"

static int find_http_header_end(const char* data, int length)
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

static int parse_content_length(const char* data, int header_length, int* content_length)
{
    const char* p;
    const char* line_end;
    const char* header_name = "Content-Length";
    int header_name_len;

    if (content_length == NULL) {
        return 0;
    }

    *content_length = 0;

    if (data == NULL || header_length <= 0) {
        return 0;
    }

    header_name_len = (int)strlen(header_name);
    line_end = strstr(data, "\r\n");
    if (line_end == NULL) {
        return 0;
    }

    p = line_end + 2;

    while (p < data + header_length) {
        const char* line_start = p;
        int line_len;

        line_end = strstr(line_start, "\r\n");
        if (line_end == NULL || line_end == line_start) {
            break;
        }

        line_len = (int)(line_end - line_start);
        if (line_len > header_name_len &&
            ascii_strnicmp_local(line_start, header_name, header_name_len) == 0 &&
            line_start[header_name_len] == ':') {
            const char* value = line_start + header_name_len + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            *content_length = atoi(value);
            if (*content_length < 0) {
                return -1;
            }
            return 1;
        }

        p = line_end + 2;
    }

    return 0;
}

void response_buffer_init(response_buffer_t* buffer)
{
    if (buffer == NULL) {
        return;
    }
    buffer->length = 0;
    buffer->data[0] = '\0';
}

int response_buffer_append(response_buffer_t* buffer, const char* data, int data_length)
{
    if (buffer == NULL || data == NULL || data_length < 0) {
        return -1;
    }

    if (buffer->length + data_length >= RESPONSE_BUFFER_CAPACITY) {
        return -1;
    }

    if (data_length > 0) {
        memcpy(buffer->data + buffer->length, data, data_length);
        buffer->length += data_length;
    }

    buffer->data[buffer->length] = '\0';
    return 0;
}

const char* response_buffer_data(const response_buffer_t* buffer)
{
    if (buffer == NULL) {
        return NULL;
    }
    return buffer->data;
}

int response_buffer_length(const response_buffer_t* buffer)
{
    if (buffer == NULL) {
        return 0;
    }
    return buffer->length;
}

void response_buffer_consume(response_buffer_t* buffer, int consume_length)
{
    if (buffer == NULL || consume_length <= 0) {
        return;
    }

    if (consume_length >= buffer->length) {
        buffer->length = 0;
        buffer->data[0] = '\0';
        return;
    }

    memmove(buffer->data, buffer->data + consume_length, buffer->length - consume_length);
    buffer->length -= consume_length;
    buffer->data[buffer->length] = '\0';
}

int response_buffer_get_complete_response_length(const response_buffer_t* buffer, int* complete_length)
{
    int header_length;
    int content_length;
    int chunked_result;
    int is_chunked;

    if (complete_length == NULL) {
        return -1;
    }
    *complete_length = 0;

    if (buffer == NULL || buffer->length <= 0) {
        return 0;
    }

    chunked_result = chunked_message_get_complete_length(
        buffer->data,
        buffer->length,
        complete_length,
        &is_chunked
    );
    if (chunked_result < 0) {
        return -1;
    }
    if (is_chunked) {
        return chunked_result;
    }

    header_length = find_http_header_end(buffer->data, buffer->length);
    if (header_length < 0) {
        return 0;
    }

    if (parse_content_length(buffer->data, header_length, &content_length) < 0) {
        return -1;
    }

    if (buffer->length >= header_length + content_length) {
        *complete_length = header_length + content_length;
        return 1;
    }

    return 0;
}
