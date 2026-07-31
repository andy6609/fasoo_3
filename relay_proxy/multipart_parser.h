#ifndef MULTIPART_PARSER_H
#define MULTIPART_PARSER_H

#include "http_parser.h"
#include "dlp_engine.h"
#include "session_context.h"

/*
 * Inspect multipart/form-data request bodies for browser file uploads.
 *
 * Parsing and record behavior:
 *   - MIME delimiters are accepted only at body start or after CRLF.
 *   - filename*=UTF-8''... parameters are RFC 5987 percent-decoded.
 *   - Every file part is analyzed and recorded even after an earlier part
 *     blocks the enclosing request.
 *   - When LOCAL_DLP_SAVE_UPLOAD_RECORDS is enabled, a reported record-write
 *     failure changes an otherwise allowed request to fail-closed BLOCK.
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

int inspect_multipart_upload_request_with_context(
    const http_request_t* request,
    dlp_result_t* result,
    const proxy_session_context_t* session,
    const char* service,
    const char* protocol,
    unsigned int stream_id
);

#endif
