#ifndef UPLOAD_CAPTURE_H
#define UPLOAD_CAPTURE_H

#include <stdio.h>
#include <stddef.h>

#include "session_context.h"
#include "http_parser.h"
#include "file_analyzer.h"

#define UPLOAD_CAPTURE_PATH_SIZE 512

typedef struct upload_capture_writer {
    FILE* file;
    char file_path[UPLOAD_CAPTURE_PATH_SIZE];
    char metadata_path[UPLOAD_CAPTURE_PATH_SIZE];
    char reassembled_path[UPLOAD_CAPTURE_PATH_SIZE];
    char reassembly_key[UPLOAD_CAPTURE_PATH_SIZE * 2];
    char host[HTTP_HOST_SIZE];
    char method[HTTP_METHOD_SIZE];
    char path[HTTP_PATH_SIZE];
    char content_type[HTTP_CONTENT_TYPE_SIZE];
    char protocol[32];
    unsigned long long bytes_written;
    unsigned long long bytes_seen;
    unsigned long long max_bytes;
    unsigned long long declared_bytes;
    unsigned long long reassembled_bytes;
    unsigned long long fragment_offset;
    unsigned long long fragment_total;
    unsigned long long fragment_expected_bytes;
    unsigned int stream_id;
    unsigned long session_id;
    int attempted;
    int active;
    int truncated;
    int failed;
    int finished;
    int request_complete;
    int complete;
    int declared_bytes_known;
    int is_fragment;
    int fragment_total_known;
    int fragment_expected_bytes_known;
    int fragment_final;
    int reassembly_complete;
} upload_capture_writer_t;

typedef struct upload_capture_view {
    void* file_handle;
    void* mapping_handle;
    const unsigned char* data;
    size_t length;
    int reassembled;
} upload_capture_view_t;

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

int upload_capture_open_complete_view(
    const upload_capture_writer_t* writer,
    upload_capture_view_t* view
);

void upload_capture_close_view(upload_capture_view_t* view);

int upload_capture_is_complete(const upload_capture_writer_t* writer);

/* Save one reconstructed upload as an incident directory containing the
   original file, extracted text, and endpoint metadata. */
int upload_record_store_file(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const char* service,
    const char* protocol,
    unsigned int stream_id,
    const char* filename,
    const unsigned char* data,
    size_t length,
    const file_analysis_result_t* analysis
);

int upload_record_store_file_ex(
    const proxy_session_context_t* session,
    const http_request_t* request,
    const char* service,
    const char* protocol,
    unsigned int stream_id,
    const char* filename,
    const unsigned char* data,
    size_t length,
    unsigned long long observed_length,
    int original_complete,
    const file_analysis_result_t* analysis
);

#endif /* UPLOAD_CAPTURE_H */
