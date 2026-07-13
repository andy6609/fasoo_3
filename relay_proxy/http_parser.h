#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "http_headers.h"

#define HTTP_METHOD_SIZE 32
#define HTTP_PATH_SIZE 512
#define HTTP_VERSION_SIZE 32
#define HTTP_HOST_SIZE 512
#define HTTP_CONTENT_TYPE_SIZE 256
#define HTTP_BODY_SIZE 4096

typedef struct http_request {
    char method[HTTP_METHOD_SIZE];
    char path[HTTP_PATH_SIZE];
    char version[HTTP_VERSION_SIZE];
    char host[HTTP_HOST_SIZE];
    char content_type[HTTP_CONTENT_TYPE_SIZE];

    int content_length;

    http_header_t headers[HTTP_MAX_HEADER_COUNT];
    int header_count;
    int headers_truncated;

    char body[HTTP_BODY_SIZE];
    int body_length;
    /* Full body view, valid while the source request buffer remains alive. */
    const char* body_data;
    int body_data_length;
} http_request_t;

int parse_http_request(const char* buffer, int length, http_request_t* request);
void print_http_request(const http_request_t* request);
void log_http_request_analysis(
    const http_request_t* request,
    unsigned long session_id,
    const char* transport
);

#endif
