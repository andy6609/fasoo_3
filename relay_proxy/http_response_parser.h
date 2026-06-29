#ifndef HTTP_RESPONSE_PARSER_H
#define HTTP_RESPONSE_PARSER_H

#include "http_headers.h"

#define HTTP_RESPONSE_VERSION_SIZE 32
#define HTTP_RESPONSE_REASON_SIZE 256
#define HTTP_RESPONSE_CONTENT_TYPE_SIZE 256
#define HTTP_RESPONSE_TRANSFER_ENCODING_SIZE 128
#define HTTP_RESPONSE_BODY_SIZE 8192

typedef struct http_response {
    char version[HTTP_RESPONSE_VERSION_SIZE];
    int status_code;
    char reason_phrase[HTTP_RESPONSE_REASON_SIZE];

    char content_type[HTTP_RESPONSE_CONTENT_TYPE_SIZE];
    char transfer_encoding[HTTP_RESPONSE_TRANSFER_ENCODING_SIZE];

    int content_length;
    int is_chunked;

    http_header_t headers[HTTP_MAX_HEADER_COUNT];
    int header_count;
    int headers_truncated;

    char body[HTTP_RESPONSE_BODY_SIZE];
    int body_length;
} http_response_t;

int parse_http_response(const char* buffer, int length, http_response_t* response);
void print_http_response(const http_response_t* response);
void log_http_response_analysis(
    const http_response_t* response,
    unsigned long session_id,
    const char* transport
);

#endif
