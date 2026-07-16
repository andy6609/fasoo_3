#ifndef DLP_ENGINE_H
#define DLP_ENGINE_H

#include "http_parser.h"
#include "http_response_parser.h"

typedef enum {
    DLP_ACTION_ALLOW = 0,
    DLP_ACTION_BLOCK = 1,
    DLP_ACTION_LOG_ONLY = 2
} dlp_action_t;

typedef struct {
    dlp_action_t action;
    int matched_rule_id;
    char keyword[128];
    char reason[256];
} dlp_result_t;

dlp_result_t inspect_dlp_request(const http_request_t* request);
dlp_result_t inspect_dlp_response(const http_response_t* response);
int dlp_request_is_file_upload(const http_request_t* request);
int dlp_request_should_inspect(const http_request_t* request);

#endif
