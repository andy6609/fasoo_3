#ifndef CHUNKED_DECODER_H
#define CHUNKED_DECODER_H

#include "http_parser.h"
#include "http_response_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Detect and parse HTTP messages using Transfer-Encoding: chunked.
 * Return values for chunked_message_get_complete_length():
 *   1  complete chunked message found; complete_length is set
 *   0  message is not chunked, or chunked message is not complete yet
 *  -1  malformed chunked framing
 * is_chunked is set to 1 when the HTTP headers contain Transfer-Encoding: chunked.
 */
int chunked_message_get_complete_length(
    const char* data,
    int length,
    int* complete_length,
    int* is_chunked
);

/*
 * Decode only the chunked transfer coding from a complete HTTP message body.
 * The returned buffer must be freed with free().
 */
int chunked_decode_http_message_body(
    const char* raw_message,
    int raw_message_length,
    unsigned char** decoded_body,
    int* decoded_body_length
);

/*
 * Build a decoded copy of a request for DLP inspection when the request uses
 * Transfer-Encoding: chunked. The original raw request should still be forwarded
 * to upstream when ALLOW/LOG_ONLY.
 * Return values:
 *   1 decoded_request contains dechunked body and should be inspected
 *   0 original_request should be inspected
 *  -1 chunk decoding failed; original_request should be inspected as fallback
 */
int chunked_decoder_prepare_request_for_dlp(
    const http_request_t* original_request,
    const char* raw_request,
    int raw_request_length,
    http_request_t* decoded_request,
    const char* log_context
);

#ifdef __cplusplus
}
#endif

#endif /* CHUNKED_DECODER_H */
