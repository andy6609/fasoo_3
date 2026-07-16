#ifndef UPLOAD_CAPTURE_H
#define UPLOAD_CAPTURE_H

#include <stdio.h>
#include <stddef.h>

#include "session_context.h"
#include "http_parser.h"

#define UPLOAD_CAPTURE_PATH_SIZE 512

typedef struct upload_capture_writer {
    FILE* file;
    char file_path[UPLOAD_CAPTURE_PATH_SIZE];
    unsigned long long bytes_written;
    unsigned long long max_bytes;
    unsigned int stream_id;
    int attempted;
    int active;
    int truncated;
    int failed;
} upload_capture_writer_t;

int upload_capture_init(const char* hosts_file_path);
void upload_capture_cleanup(void);
int upload_capture_is_enabled(void);

int upload_capture_host_matches(
    const char* process_name,
    const char* authority,
    int default_port
);

int upload_capture_host_is_configured(
    const char* authority,
    int default_port
);

int upload_capture_begin(
    upload_capture_writer_t* writer,
    const proxy_session_context_t* session,
    const http_request_t* request,
    int default_port,
    const char* protocol,
    unsigned int stream_id
);

int upload_capture_append(
    upload_capture_writer_t* writer,
    const void* data,
    size_t length
);

void upload_capture_finish(
    upload_capture_writer_t* writer,
    int request_complete
);

#endif /* UPLOAD_CAPTURE_H */
