#ifndef CONTENT_DECODER_H
#define CONTENT_DECODER_H

#include "http_response_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Build a decoded copy of an HTTP response for DLP inspection when the
 * response body is compressed with Content-Encoding: gzip or deflate.
 *
 * Return values:
 *   1  decoded_response contains decompressed body and should be inspected
 *   0  original_response should be inspected
 *  -1  decompression failed; original_response should be inspected as fallback
 *
 * Important: the original raw_response is still forwarded to the client when
 * the DLP result is ALLOW/LOG_ONLY. decoded_response is used only for scanning.
 */
int content_decoder_prepare_response_for_dlp(
    const http_response_t* original_response,
    const char* raw_response,
    int raw_response_length,
    http_response_t* decoded_response,
    const char* log_context
);

#ifdef __cplusplus
}
#endif

#endif /* CONTENT_DECODER_H */
