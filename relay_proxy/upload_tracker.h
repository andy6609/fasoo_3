#ifndef UPLOAD_TRACKER_H
#define UPLOAD_TRACKER_H

#include <stddef.h>
#include "http_parser.h"

#define UPLOAD_TRACKER_FILENAME_SIZE 512
#define UPLOAD_TRACKER_CONTENT_TYPE_SIZE 256
#define UPLOAD_TRACKER_HOST_SIZE 512
#define UPLOAD_TRACKER_PATH_SIZE 512

typedef struct upload_tracking_info {
    unsigned long upload_id;
    char filename[UPLOAD_TRACKER_FILENAME_SIZE];
    char content_type[UPLOAD_TRACKER_CONTENT_TYPE_SIZE];
    unsigned long long declared_size;
    char upload_host[UPLOAD_TRACKER_HOST_SIZE];
    char upload_path[UPLOAD_TRACKER_PATH_SIZE];
} upload_tracking_info_t;

int upload_tracker_init(void);
void upload_tracker_cleanup(void);

int upload_tracker_is_metadata_request(
    const char* method,
    const char* host,
    const char* path
);

unsigned long upload_tracker_record_metadata_request(
    unsigned long session_id,
    unsigned int stream_id,
    const char* body,
    size_t body_length
);

unsigned long upload_tracker_record_resumable_start(
    unsigned long session_id,
    unsigned int stream_id,
    const http_request_t* request,
    const char* body,
    size_t body_length
);

int upload_tracker_match_resumable_finalize(
    unsigned long session_id,
    const http_request_t* request,
    unsigned long long content_length,
    upload_tracking_info_t* info
);

void upload_tracker_record_metadata_response(
    unsigned long upload_id,
    const char* body,
    size_t body_length
);

int upload_tracker_match_raw_put(
    const char* host,
    const char* path,
    const char* content_type,
    unsigned long long content_length,
    upload_tracking_info_t* info
);

void upload_tracker_sanitize_path(
    const char* path,
    char* sanitized,
    size_t sanitized_size
);

#endif
