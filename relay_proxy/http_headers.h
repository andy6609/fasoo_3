#ifndef HTTP_HEADERS_H
#define HTTP_HEADERS_H

/*
 * Keep the complete HTTP header set available to the analyzer.  The parser
 * deliberately caps this collection so a malformed request cannot consume
 * unbounded memory.  Individual values are also capped and marked truncated.
 */
#define HTTP_MAX_HEADER_COUNT 32
#define HTTP_HEADER_NAME_SIZE 64
#define HTTP_HEADER_VALUE_SIZE 512

typedef struct http_header {
    char name[HTTP_HEADER_NAME_SIZE];
    char value[HTTP_HEADER_VALUE_SIZE];
    int value_truncated;
} http_header_t;

#endif
