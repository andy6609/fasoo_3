#define _CRT_SECURE_NO_WARNINGS

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>

#include "request_buffer.h"
#include "chunked_decoder.h"

#define REQUEST_BUFFER_MAX_BYTES_ENV "LOCAL_DLP_HTTP1_MAX_REQUEST_BYTES"
#define REQUEST_BUFFER_GLOBAL_MAX_BYTES_ENV "LOCAL_DLP_HTTP1_GLOBAL_BUFFER_BYTES"
#define REQUEST_BUFFER_DEFAULT_GLOBAL_MAX_CAPACITY (512LL * 1024LL * 1024LL)

static volatile LONG64 g_request_buffer_reserved_capacity = 0;

static int request_buffer_read_max_capacity(void)
{
    const char* value = getenv(REQUEST_BUFFER_MAX_BYTES_ENV);
    char* end = NULL;
    __int64 parsed;

    if (value == NULL || value[0] == '\0') return REQUEST_BUFFER_DEFAULT_MAX_CAPACITY;
    parsed = _strtoi64(value, &end, 10);
    if (end == value || end == NULL || *end != '\0' ||
        parsed < REQUEST_BUFFER_INITIAL_CAPACITY || parsed > INT_MAX - 1) {
        return REQUEST_BUFFER_DEFAULT_MAX_CAPACITY;
    }
    return (int)parsed;
}

static LONG64 request_buffer_read_global_max_capacity(void)
{
    const char* value = getenv(REQUEST_BUFFER_GLOBAL_MAX_BYTES_ENV);
    char* end = NULL;
    __int64 parsed;

    if (value == NULL || value[0] == '\0') {
        return REQUEST_BUFFER_DEFAULT_GLOBAL_MAX_CAPACITY;
    }
    parsed = _strtoi64(value, &end, 10);
    if (end == value || end == NULL || *end != '\0' ||
        parsed < REQUEST_BUFFER_INITIAL_CAPACITY || parsed > (16LL * 1024LL * 1024LL * 1024LL)) {
        return REQUEST_BUFFER_DEFAULT_GLOBAL_MAX_CAPACITY;
    }
    return (LONG64)parsed;
}

static int request_buffer_reserve_capacity(int additional_capacity)
{
    LONG64 current;
    LONG64 updated;
    LONG64 maximum;

    if (additional_capacity <= 0) return 0;
    maximum = request_buffer_read_global_max_capacity();
    for (;;) {
        current = InterlockedCompareExchange64(
            &g_request_buffer_reserved_capacity, 0, 0);
        if ((LONG64)additional_capacity > maximum - current) return -1;
        updated = current + (LONG64)additional_capacity;
        if (InterlockedCompareExchange64(
            &g_request_buffer_reserved_capacity, updated, current) == current) return 0;
    }
}

static void request_buffer_release_capacity(int capacity)
{
    if (capacity > 0) {
        InterlockedExchangeAdd64(
            &g_request_buffer_reserved_capacity, -(LONG64)capacity);
    }
}

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
            char* number_end = NULL;
            __int64 parsed_length;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            parsed_length = _strtoi64(value, &number_end, 10);
            if (number_end == value || parsed_length < 0 ||
                parsed_length > (INT_MAX - header_length)) {
                return -1;
            }
            *content_length = (int)parsed_length;
            return 1;
        }

        p = line_end + 2;
    }

    return 0;
}

void request_buffer_init(request_buffer_t* buffer)
{
    if (buffer == NULL) {
        return;
    }
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
    buffer->max_capacity = request_buffer_read_max_capacity();
}

void request_buffer_cleanup(request_buffer_t* buffer)
{
    if (buffer == NULL) {
        return;
    }
    free(buffer->data);
    request_buffer_release_capacity(buffer->capacity);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
    buffer->max_capacity = 0;
}

int request_buffer_append(request_buffer_t* buffer, const char* data, int data_length)
{
    int required;
    int new_capacity;
    char* resized;

    if (buffer == NULL || data == NULL || data_length < 0) {
        return -1;
    }

    if (data_length > INT_MAX - 1 - buffer->length) {
        return -1;
    }

    required = buffer->length + data_length + 1;
    if (buffer->max_capacity <= 0 || required > buffer->max_capacity) {
        return -2;
    }
    if (required > buffer->capacity) {
        int previous_capacity = buffer->capacity;
        int additional_capacity;
        new_capacity = buffer->capacity > 0
            ? buffer->capacity : REQUEST_BUFFER_INITIAL_CAPACITY;
        while (new_capacity < required) {
            if (new_capacity > INT_MAX / 2) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > buffer->max_capacity) {
            new_capacity = buffer->max_capacity;
        }
        additional_capacity = new_capacity - previous_capacity;
        if (request_buffer_reserve_capacity(additional_capacity) != 0) {
            return -3;
        }
        resized = (char*)realloc(buffer->data, (size_t)new_capacity);
        if (resized == NULL) {
            request_buffer_release_capacity(additional_capacity);
            return -1;
        }
        buffer->data = resized;
        buffer->capacity = new_capacity;
    }

    if (data_length > 0) {
        memcpy(buffer->data + buffer->length, data, data_length);
        buffer->length += data_length;
    }

    buffer->data[buffer->length] = '\0';
    return 0;
}

const char* request_buffer_data(const request_buffer_t* buffer)
{
    if (buffer == NULL) {
        return NULL;
    }
    return buffer->data;
}

int request_buffer_length(const request_buffer_t* buffer)
{
    if (buffer == NULL) {
        return 0;
    }
    return buffer->length;
}

int request_buffer_max_capacity(const request_buffer_t* buffer)
{
    if (buffer == NULL) return 0;
    return buffer->max_capacity;
}

void request_buffer_consume(request_buffer_t* buffer, int consume_length)
{
    if (buffer == NULL || consume_length <= 0) {
        return;
    }

    if (consume_length >= buffer->length) {
        free(buffer->data);
        request_buffer_release_capacity(buffer->capacity);
        buffer->data = NULL;
        buffer->length = 0;
        buffer->capacity = 0;
        return;
    }

    memmove(buffer->data, buffer->data + consume_length, buffer->length - consume_length);
    buffer->length -= consume_length;
    buffer->data[buffer->length] = '\0';
}

int request_buffer_get_complete_request_length(const request_buffer_t* buffer, int* complete_length)
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

    if (buffer->max_capacity <= 0 ||
        content_length > buffer->max_capacity - header_length - 1) {
        return -2;
    }

    if (buffer->length >= header_length + content_length) {
        *complete_length = header_length + content_length;
        return 1;
    }

    return 0;
}
