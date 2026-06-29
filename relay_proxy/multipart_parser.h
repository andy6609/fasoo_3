#ifndef MULTIPART_PARSER_H
#define MULTIPART_PARSER_H

#include "http_parser.h"
#include "dlp_engine.h"

/*
 * Inspect multipart/form-data request bodies for browser file uploads.
 *
 * Large-upload behavior:
 *   - File size over LOCAL_DLP_MAX_UPLOAD_BYTES, default 10MB, is blocked.
 *   - File content keyword/email scan uses a bounded streaming-style sample,
 *     LOCAL_DLP_MAX_MULTIPART_SCAN_BYTES, default 1MB.
 *   - Existing extension rules are still applied before content scanning.
 *
 * The function treats result as an in/out value:
 *   - If result is already BLOCK, it is left unchanged.
 *   - Multipart BLOCK findings override ALLOW or LOG_ONLY.
 *   - Multipart LOG_ONLY findings are applied only when current result is ALLOW.
 *
 * Return value:
 *   1 = multipart/form-data was detected and inspected
 *   0 = request was not multipart/form-data or no body was available
 */
int inspect_multipart_upload_request(const http_request_t* request, dlp_result_t* result);

#endif
