#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <WinSock2.h>
#include <Windows.h>

#include <openssl/err.h>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include "http2_engine.h"
#include "logger.h"
#include "dlp_engine.h"
#include "audit_log.h"
#include "multipart_parser.h"
#include "upload_capture.h"
#include "upload_tracker.h"
#include "file_analyzer.h"

#pragma comment(lib, "nghttp2.lib")

#define HTTP2_ENGINE_BUFFER_SIZE 16384
#define HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_PREFACE_LENGTH 24
#define HTTP2_PARSE_BUFFER_SIZE (256 * 1024)
#define HTTP2_HEADER_BLOCK_SIZE (128 * 1024)
#define HTTP2_MAX_STREAMS 128
#define HTTP2_BODY_INSPECTION_LIMIT (32 * 1024 * 1024)
#define HTTP2_METADATA_RESPONSE_LIMIT (256 * 1024)
#define HTTP2_FRAME_HEADER_SIZE 9

#define HTTP2_FRAME_DATA 0x0
#define HTTP2_FRAME_HEADERS 0x1
#define HTTP2_FRAME_RST_STREAM 0x3
#define HTTP2_FRAME_GOAWAY 0x7
#define HTTP2_FRAME_CONTINUATION 0x9

#define HTTP2_FLAG_END_STREAM 0x1
#define HTTP2_FLAG_END_HEADERS 0x4
#define HTTP2_FLAG_PADDED 0x8
#define HTTP2_FLAG_PRIORITY 0x20

#define HTTP2_ERROR_CANCEL 0x8

static int http2_ssl_read_is_expected_close(
    SSL* ssl,
    int read_result,
    int ssl_error,
    int* socket_error_out
)
{
    int socket_error;
    unsigned long openssl_error;

    (void)read_result;
    socket_error = WSAGetLastError();
    openssl_error = ERR_peek_error();

    if (socket_error_out != NULL) {
        *socket_error_out = socket_error;
    }

    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        ERR_clear_error();
        return 1;
    }

    if (ssl_error == SSL_ERROR_SYSCALL &&
        (openssl_error == 0 ||
            socket_error == WSAECONNRESET ||
            socket_error == WSAECONNABORTED ||
            socket_error == WSAENOTCONN)) {
        ERR_clear_error();
        return 1;
    }

#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    if (ssl_error == SSL_ERROR_SSL &&
        openssl_error != 0 &&
        ERR_GET_REASON(openssl_error) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        ERR_clear_error();
        return 1;
    }
#endif

    return 0;
}

typedef enum http2_direction {
    HTTP2_DIRECTION_REQUEST = 0,
    HTTP2_DIRECTION_RESPONSE = 1
} http2_direction_t;

typedef struct http2_stream_state {
    int in_use;
    unsigned int stream_id;
    http_request_t request;
    unsigned char* body;
    size_t body_length;
    size_t body_capacity;
    unsigned long long total_body_bytes;
    int headers_complete;
    int request_complete;
    int response_complete;
    int blocked;
    int log_only_audited;
    int multipart_initial_inspected;
    upload_capture_writer_t capture;
    int response_status;
    char response_content_type[HTTP_CONTENT_TYPE_SIZE];
    long long response_content_length;
    unsigned char* response_body;
    size_t response_body_length;
    size_t response_body_capacity;
    unsigned long metadata_upload_id;
    int upload_tracking_matched;
    upload_tracking_info_t upload_info;
    int file_analysis_complete;
    file_analysis_result_t file_analysis;
} http2_stream_state_t;

typedef struct http2_parser {
    unsigned char buffer[HTTP2_PARSE_BUFFER_SIZE];
    int length;
    int preface_consumed;
    http2_direction_t direction;
    nghttp2_hd_inflater* inflater;
    unsigned char header_block[HTTP2_HEADER_BLOCK_SIZE];
    size_t header_block_length;
    unsigned int continuation_stream_id;
    unsigned char initial_headers_flags;
} http2_parser_t;

typedef struct http2_engine {
    proxy_session_context_t* session;
    SSL* client_ssl;
    SSL* upstream_ssl;
    http2_parser_t request_parser;
    http2_parser_t response_parser;
    http2_stream_state_t streams[HTTP2_MAX_STREAMS];
} http2_engine_t;

static unsigned int http2_read_u24(const unsigned char* data)
{
    return ((unsigned int)data[0] << 16) |
        ((unsigned int)data[1] << 8) |
        (unsigned int)data[2];
}

static unsigned int http2_read_u31(const unsigned char* data)
{
    return (((unsigned int)data[0] & 0x7f) << 24) |
        ((unsigned int)data[1] << 16) |
        ((unsigned int)data[2] << 8) |
        (unsigned int)data[3];
}

static void http2_write_u24(unsigned char* data, unsigned int value)
{
    data[0] = (unsigned char)((value >> 16) & 0xff);
    data[1] = (unsigned char)((value >> 8) & 0xff);
    data[2] = (unsigned char)(value & 0xff);
}

static void http2_write_u31(unsigned char* data, unsigned int value)
{
    data[0] = (unsigned char)((value >> 24) & 0x7f);
    data[1] = (unsigned char)((value >> 16) & 0xff);
    data[2] = (unsigned char)((value >> 8) & 0xff);
    data[3] = (unsigned char)(value & 0xff);
}

static void http2_copy_bytes_as_text(
    char* destination,
    size_t destination_size,
    const unsigned char* source,
    size_t source_length
)
{
    size_t copy_length;

    if (destination == NULL || destination_size == 0) {
        return;
    }

    destination[0] = '\0';
    if (source == NULL || source_length == 0) {
        return;
    }

    copy_length = source_length;
    if (copy_length >= destination_size) {
        copy_length = destination_size - 1;
    }

    memcpy(destination, source, copy_length);
    destination[copy_length] = '\0';
}

static int http2_name_equals(
    const unsigned char* name,
    size_t name_length,
    const char* expected
)
{
    size_t expected_length;

    if (name == NULL || expected == NULL) {
        return 0;
    }

    expected_length = strlen(expected);
    return name_length == expected_length &&
        _strnicmp((const char*)name, expected, name_length) == 0;
}

static int http2_ssl_write_all(SSL* ssl, const unsigned char* data, int length)
{
    int total = 0;

    if (ssl == NULL || data == NULL || length <= 0) {
        return -1;
    }

    while (total < length) {
        int written = SSL_write(ssl, data + total, length - total);
        if (written <= 0) {
            log_error("HTTP/2 SSL_write() failed. ssl_error=%d", SSL_get_error(ssl, written));
            return -1;
        }
        total += written;
    }

    return total;
}

static int http2_send_frame(
    SSL* ssl,
    unsigned char type,
    unsigned char flags,
    unsigned int stream_id,
    const unsigned char* payload,
    unsigned int payload_length
)
{
    unsigned char header[HTTP2_FRAME_HEADER_SIZE];

    if (payload_length > 0x00ffffff) {
        return -1;
    }

    http2_write_u24(header, payload_length);
    header[3] = type;
    header[4] = flags;
    http2_write_u31(header + 5, stream_id);

    if (http2_ssl_write_all(ssl, header, sizeof(header)) < 0) {
        return -1;
    }
    if (payload_length > 0 && http2_ssl_write_all(ssl, payload, (int)payload_length) < 0) {
        return -1;
    }

    return 0;
}

static http2_stream_state_t* http2_find_stream(
    http2_engine_t* engine,
    unsigned int stream_id,
    int create
)
{
    int i;
    http2_stream_state_t* free_stream = NULL;

    if (engine == NULL || stream_id == 0) {
        return NULL;
    }

    for (i = 0; i < HTTP2_MAX_STREAMS; i++) {
        http2_stream_state_t* stream = &engine->streams[i];
        if (stream->in_use && stream->stream_id == stream_id) {
            return stream;
        }
        if (!stream->in_use && free_stream == NULL) {
            free_stream = stream;
        }
    }

    if (!create || free_stream == NULL) {
        return NULL;
    }

    memset(free_stream, 0, sizeof(*free_stream));
    free_stream->in_use = 1;
    free_stream->stream_id = stream_id;
    free_stream->response_content_length = -1;
    strcpy_s(free_stream->request.version, sizeof(free_stream->request.version), "HTTP/2");
    return free_stream;
}

static void http2_release_stream(http2_stream_state_t* stream)
{
    if (stream == NULL) {
        return;
    }

    upload_capture_finish(&stream->capture, stream->request_complete);
    free(stream->body);
    free(stream->response_body);
    memset(stream, 0, sizeof(*stream));
}

static int http2_append_body(
    http2_stream_state_t* stream,
    const unsigned char* data,
    size_t length
)
{
    size_t wanted;
    size_t new_capacity;
    unsigned char* resized;

    if (stream == NULL || (data == NULL && length > 0)) {
        return -1;
    }

    stream->total_body_bytes += length;
    if (length == 0 || stream->body_length >= HTTP2_BODY_INSPECTION_LIMIT) {
        return 0;
    }

    wanted = stream->body_length + length;
    if (wanted > HTTP2_BODY_INSPECTION_LIMIT) {
        wanted = HTTP2_BODY_INSPECTION_LIMIT;
    }

    if (wanted > stream->body_capacity) {
        new_capacity = stream->body_capacity == 0 ? 16384 : stream->body_capacity;
        while (new_capacity < wanted && new_capacity < HTTP2_BODY_INSPECTION_LIMIT) {
            new_capacity *= 2;
        }
        if (new_capacity > HTTP2_BODY_INSPECTION_LIMIT) {
            new_capacity = HTTP2_BODY_INSPECTION_LIMIT;
        }

        resized = (unsigned char*)realloc(stream->body, new_capacity + 1);
        if (resized == NULL) {
            return -1;
        }
        stream->body = resized;
        stream->body_capacity = new_capacity;
    }

    length = wanted - stream->body_length;
    memcpy(stream->body + stream->body_length, data, length);
    stream->body_length += length;
    stream->body[stream->body_length] = '\0';
    return 0;
}

static int http2_append_metadata_response_body(
    http2_stream_state_t* stream,
    const unsigned char* data,
    size_t length
)
{
    size_t wanted;
    size_t new_capacity;
    unsigned char* resized;

    if (stream == NULL || stream->metadata_upload_id == 0 || length == 0) return 0;
    if (stream->response_body_length >= HTTP2_METADATA_RESPONSE_LIMIT) return 0;
    wanted = stream->response_body_length + length;
    if (wanted > HTTP2_METADATA_RESPONSE_LIMIT) wanted = HTTP2_METADATA_RESPONSE_LIMIT;
    if (wanted > stream->response_body_capacity) {
        new_capacity = stream->response_body_capacity == 0 ? 4096 : stream->response_body_capacity;
        while (new_capacity < wanted) new_capacity *= 2;
        if (new_capacity > HTTP2_METADATA_RESPONSE_LIMIT) new_capacity = HTTP2_METADATA_RESPONSE_LIMIT;
        resized = (unsigned char*)realloc(stream->response_body, new_capacity + 1);
        if (resized == NULL) return -1;
        stream->response_body = resized;
        stream->response_body_capacity = new_capacity;
    }
    length = wanted - stream->response_body_length;
    memcpy(stream->response_body + stream->response_body_length, data, length);
    stream->response_body_length += length;
    stream->response_body[stream->response_body_length] = '\0';
    return 0;
}

static void http2_add_request_header(http2_stream_state_t* stream, const nghttp2_nv* nv)
{
    http_request_t* request;

    if (stream == NULL || nv == NULL) {
        return;
    }

    request = &stream->request;

    if (http2_name_equals(nv->name, nv->namelen, ":method")) {
        http2_copy_bytes_as_text(request->method, sizeof(request->method), nv->value, nv->valuelen);
        return;
    }
    if (http2_name_equals(nv->name, nv->namelen, ":path")) {
        http2_copy_bytes_as_text(request->path, sizeof(request->path), nv->value, nv->valuelen);
        return;
    }
    if (http2_name_equals(nv->name, nv->namelen, ":authority")) {
        http2_copy_bytes_as_text(request->host, sizeof(request->host), nv->value, nv->valuelen);
        return;
    }
    if (http2_name_equals(nv->name, nv->namelen, "content-type")) {
        http2_copy_bytes_as_text(request->content_type, sizeof(request->content_type), nv->value, nv->valuelen);
    }
    if (http2_name_equals(nv->name, nv->namelen, "content-length")) {
        char number[64];
        http2_copy_bytes_as_text(number, sizeof(number), nv->value, nv->valuelen);
        request->content_length = atoi(number);
    }

    if (request->header_count < HTTP_MAX_HEADER_COUNT) {
        http_header_t* header = &request->headers[request->header_count++];
        http2_copy_bytes_as_text(header->name, sizeof(header->name), nv->name, nv->namelen);
        http2_copy_bytes_as_text(header->value, sizeof(header->value), nv->value, nv->valuelen);
        header->value_truncated = nv->valuelen >= sizeof(header->value);
    }
    else {
        request->headers_truncated = 1;
    }
}

static void http2_add_response_header(http2_stream_state_t* stream, const nghttp2_nv* nv)
{
    if (stream == NULL || nv == NULL) {
        return;
    }

    if (http2_name_equals(nv->name, nv->namelen, ":status")) {
        char status[16];
        http2_copy_bytes_as_text(status, sizeof(status), nv->value, nv->valuelen);
        stream->response_status = atoi(status);
    }
    else if (http2_name_equals(nv->name, nv->namelen, "content-type")) {
        http2_copy_bytes_as_text(
            stream->response_content_type,
            sizeof(stream->response_content_type),
            nv->value,
            nv->valuelen
        );
    }
    else if (http2_name_equals(nv->name, nv->namelen, "content-length")) {
        char number[64];
        http2_copy_bytes_as_text(number, sizeof(number), nv->value, nv->valuelen);
        stream->response_content_length = _atoi64(number);
    }
}

static int http2_decode_header_block(
    http2_engine_t* engine,
    http2_parser_t* parser,
    unsigned int stream_id
)
{
    size_t offset = 0;
    int final_seen = 0;
    http2_stream_state_t* stream;

    if (engine == NULL || parser == NULL || parser->inflater == NULL) {
        return -1;
    }

    stream = http2_find_stream(engine, stream_id, 1);
    if (stream == NULL) {
        log_error("HTTP/2 stream table full. session_id=%lu stream_id=%u",
            engine->session->session_id, stream_id);
        return -1;
    }

    while (!final_seen) {
        nghttp2_nv nv;
        int inflate_flags = 0;
        nghttp2_ssize consumed;

        memset(&nv, 0, sizeof(nv));
        consumed = nghttp2_hd_inflate_hd3(
            parser->inflater,
            &nv,
            &inflate_flags,
            parser->header_block + offset,
            parser->header_block_length - offset,
            1
        );
        if (consumed < 0) {
            log_error(
                "HTTP/2 HPACK decode failed. session_id=%lu direction=%s stream_id=%u error=%s",
                engine->session->session_id,
                parser->direction == HTTP2_DIRECTION_REQUEST ? "REQUEST" : "RESPONSE",
                stream_id,
                nghttp2_strerror((int)consumed)
            );
            return -1;
        }

        offset += (size_t)consumed;
        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            if (parser->direction == HTTP2_DIRECTION_REQUEST) {
                http2_add_request_header(stream, &nv);
            }
            else {
                http2_add_response_header(stream, &nv);
            }
        }
        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            final_seen = 1;
        }
        if (consumed == 0 && !(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) && !final_seen) {
            log_error("HTTP/2 HPACK decoder made no progress. session_id=%lu stream_id=%u",
                engine->session->session_id, stream_id);
            return -1;
        }
    }

    nghttp2_hd_inflate_end_headers(parser->inflater);

    if (parser->direction == HTTP2_DIRECTION_REQUEST) {
        char sanitized_path[UPLOAD_TRACKER_PATH_SIZE];
        stream->headers_complete = 1;
        upload_tracker_sanitize_path(
            stream->request.path,
            sanitized_path,
            sizeof(sanitized_path)
        );
        log_info(
            "HTTP2_ANALYSIS direction=REQUEST session_id=%lu stream_id=%u method=%s path=%s host=%s content_type=%s content_length=%d headers=%d",
            engine->session->session_id,
            stream_id,
            stream->request.method[0] ? stream->request.method : "-",
            sanitized_path[0] ? sanitized_path : "-",
            stream->request.host[0] ? stream->request.host : "-",
            stream->request.content_type[0] ? stream->request.content_type : "-",
            stream->request.content_length,
            stream->request.header_count
        );
    }
    else {
        log_info(
            "HTTP2_ANALYSIS direction=RESPONSE session_id=%lu stream_id=%u status=%d content_type=%s content_length=%lld",
            engine->session->session_id,
            stream_id,
            stream->response_status,
            stream->response_content_type[0] ? stream->response_content_type : "-",
            stream->response_content_length
        );
    }

    parser->header_block_length = 0;
    parser->continuation_stream_id = 0;
    return 0;
}

static int http2_append_header_fragment(
    http2_engine_t* engine,
    http2_parser_t* parser,
    unsigned int stream_id,
    unsigned char type,
    unsigned char flags,
    const unsigned char* payload,
    unsigned int payload_length
)
{
    unsigned int offset = 0;
    unsigned int padding = 0;
    unsigned int fragment_length;

    if (type == HTTP2_FRAME_HEADERS) {
        if (parser->continuation_stream_id != 0) {
            return -1;
        }
        parser->header_block_length = 0;
        parser->continuation_stream_id = stream_id;
        parser->initial_headers_flags = flags;

        if ((flags & HTTP2_FLAG_PADDED) != 0) {
            if (payload_length < 1) return -1;
            padding = payload[0];
            offset++;
        }
        if ((flags & HTTP2_FLAG_PRIORITY) != 0) {
            if (payload_length < offset + 5) return -1;
            offset += 5;
        }
    }
    else {
        if (parser->continuation_stream_id != stream_id) {
            return -1;
        }
    }

    if (payload_length < offset + padding) {
        return -1;
    }
    fragment_length = payload_length - offset - padding;
    if (fragment_length > HTTP2_HEADER_BLOCK_SIZE - parser->header_block_length) {
        log_error("HTTP/2 header block too large. session_id=%lu stream_id=%u",
            engine->session->session_id, stream_id);
        return -1;
    }

    memcpy(parser->header_block + parser->header_block_length, payload + offset, fragment_length);
    parser->header_block_length += fragment_length;

    if ((flags & HTTP2_FLAG_END_HEADERS) != 0) {
        return http2_decode_header_block(engine, parser, stream_id);
    }

    return 0;
}

static int http2_get_data_payload(
    unsigned char flags,
    const unsigned char* payload,
    unsigned int payload_length,
    const unsigned char** body,
    unsigned int* body_length
)
{
    unsigned int padding = 0;
    unsigned int offset = 0;

    if (body == NULL || body_length == NULL) {
        return -1;
    }

    if ((flags & HTTP2_FLAG_PADDED) != 0) {
        if (payload_length < 1) return -1;
        padding = payload[0];
        offset = 1;
    }
    if (payload_length < offset + padding) {
        return -1;
    }

    *body = payload + offset;
    *body_length = payload_length - offset - padding;
    return 0;
}

static int http2_send_block_response(
    http2_engine_t* engine,
    http2_stream_state_t* stream,
    const dlp_result_t* result
)
{
    static const unsigned char status_403[] = { 0x18, 0x03, '4', '0', '3' };
    unsigned char rst_payload[4];
    char body[512];
    int body_length;

    if (engine == NULL || stream == NULL || result == NULL) {
        return -1;
    }

    http2_write_u31(rst_payload, HTTP2_ERROR_CANCEL);
    if (http2_send_frame(
        engine->upstream_ssl,
        HTTP2_FRAME_RST_STREAM,
        0,
        stream->stream_id,
        rst_payload,
        sizeof(rst_payload)
    ) != 0) {
        return -1;
    }

    body_length = _snprintf_s(
        body,
        sizeof(body),
        _TRUNCATE,
        "Blocked by Local DLP proxy. rule_id=%d reason=%s",
        result->matched_rule_id,
        result->reason
    );
    if (body_length < 0) {
        body_length = (int)strlen(body);
    }

    if (http2_send_frame(
        engine->client_ssl,
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        stream->stream_id,
        status_403,
        sizeof(status_403)
    ) != 0) {
        return -1;
    }
    if (http2_send_frame(
        engine->client_ssl,
        HTTP2_FRAME_DATA,
        HTTP2_FLAG_END_STREAM,
        stream->stream_id,
        (const unsigned char*)body,
        (unsigned int)body_length
    ) != 0) {
        return -1;
    }

    session_context_add_bytes_to_client(
        engine->session,
        HTTP2_FRAME_HEADER_SIZE * 2 + (int)sizeof(status_403) + body_length
    );
    return 0;
}

static dlp_result_t http2_inspect_request(http2_stream_state_t* stream, int end_stream)
{
    dlp_result_t result;

    if (stream == NULL) {
        dlp_result_t empty;
        memset(&empty, 0, sizeof(empty));
        return empty;
    }

    stream->request.body_data = (const char*)stream->body;
    stream->request.body_data_length = (int)stream->body_length;
    stream->request.body_length = (int)(stream->body_length < HTTP_BODY_SIZE - 1
        ? stream->body_length : HTTP_BODY_SIZE - 1);
    if (stream->request.body_length > 0) {
        memcpy(stream->request.body, stream->body, stream->request.body_length);
    }
    stream->request.body[stream->request.body_length] = '\0';

    if (!dlp_request_should_inspect(&stream->request)) {
        dlp_result_t allow;
        memset(&allow, 0, sizeof(allow));
        allow.action = DLP_ACTION_ALLOW;
        return allow;
    }

    result = inspect_dlp_request(&stream->request);

    /*
        Inspect multipart metadata once near the beginning (so declared-size
        rules can block early), then once more after the complete request body
        arrives so file names, extensions, signatures, and contents are final.
    */
    if (!stream->multipart_initial_inspected || end_stream) {
        stream->multipart_initial_inspected = 1;
        inspect_multipart_upload_request(&stream->request, &result);
    }

    return result;
}

static void http2_record_metadata_request(
    http2_engine_t* engine,
    http2_stream_state_t* stream,
    int end_stream
)
{
    if (engine == NULL || stream == NULL || !end_stream || stream->metadata_upload_id != 0) return;
    if (!upload_tracker_is_metadata_request(
        stream->request.method,
        stream->request.host,
        stream->request.path
    )) return;

    stream->metadata_upload_id = upload_tracker_record_metadata_request(
        engine->session->session_id,
        stream->stream_id,
        (const char*)stream->body,
        stream->body_length
    );
}

static void http2_match_upload_tracking(http2_stream_state_t* stream)
{
    if (stream == NULL || stream->upload_tracking_matched ||
        _stricmp(stream->request.method, "PUT") != 0 ||
        !dlp_request_is_file_upload(&stream->request)) return;

    stream->upload_tracking_matched = upload_tracker_match_raw_put(
        stream->request.host,
        stream->request.path,
        stream->request.content_type,
        stream->request.content_length > 0
            ? (unsigned long long)stream->request.content_length
            : stream->total_body_bytes,
        &stream->upload_info
    );
}

static void http2_apply_file_analysis(
    http2_engine_t* engine,
    http2_stream_state_t* stream,
    int end_stream,
    dlp_result_t* result
)
{
    const char* filename;
    const char* action;
    char sanitized_path[UPLOAD_TRACKER_PATH_SIZE];

    if (engine == NULL || stream == NULL || result == NULL || !end_stream ||
        stream->file_analysis_complete || !dlp_request_should_inspect(&stream->request)) return;

    http2_match_upload_tracking(stream);
    filename = stream->upload_info.filename[0] ? stream->upload_info.filename : "unknown";
    memset(&stream->file_analysis, 0, sizeof(stream->file_analysis));
    if (stream->total_body_bytes != stream->body_length) {
        stream->file_analysis.action = FILE_ANALYSIS_BLOCK;
        strcpy_s(stream->file_analysis.format, sizeof(stream->file_analysis.format), "TRUNCATED");
        strcpy_s(stream->file_analysis.reason, sizeof(stream->file_analysis.reason),
            "file exceeds complete inspection buffer");
    }
    else if (file_analyzer_inspect(
        filename,
        stream->request.content_type,
        stream->body,
        stream->body_length,
        &stream->file_analysis
    ) != 0) {
        stream->file_analysis.action = FILE_ANALYSIS_BLOCK;
        strcpy_s(stream->file_analysis.format, sizeof(stream->file_analysis.format), "UNKNOWN");
        strcpy_s(stream->file_analysis.reason, sizeof(stream->file_analysis.reason),
            "file analyzer failed");
    }
    stream->file_analysis_complete = 1;

    if (stream->file_analysis.action == FILE_ANALYSIS_BLOCK) {
        result->action = DLP_ACTION_BLOCK;
        result->matched_rule_id = 9001;
        strncpy_s(result->keyword, sizeof(result->keyword), stream->file_analysis.format, _TRUNCATE);
        strncpy_s(result->reason, sizeof(result->reason), stream->file_analysis.reason, _TRUNCATE);
    }

    action = stream->file_analysis.action == FILE_ANALYSIS_BLOCK ? "BLOCK" : "ALLOW";
    upload_tracker_sanitize_path(stream->request.path, sanitized_path, sizeof(sanitized_path));
    log_info(
        "UPLOAD INSPECTED id=%lu session=%lu stream=%u file=\"%s\" bytes=%llu type=%s format=%s entries=%u extracted_text_bytes=%llu sha256=%s action=%s reason=\"%s\" target=%s%s",
        stream->upload_info.upload_id,
        engine->session->session_id,
        stream->stream_id,
        filename,
        stream->total_body_bytes,
        stream->request.content_type[0] ? stream->request.content_type : "unknown",
        stream->file_analysis.format[0] ? stream->file_analysis.format : "UNKNOWN",
        stream->file_analysis.archive_entries,
        stream->file_analysis.extracted_text_bytes,
        stream->file_analysis.sha256[0] ? stream->file_analysis.sha256 : "unavailable",
        action,
        stream->file_analysis.reason[0] ? stream->file_analysis.reason : "-",
        stream->request.host[0] ? stream->request.host : "-",
        sanitized_path
    );
}

static void http2_finalize_response(http2_engine_t* engine, http2_stream_state_t* stream)
{
    if (engine == NULL || stream == NULL || stream->response_complete) return;

    if (stream->metadata_upload_id != 0 && stream->response_body_length > 0) {
        upload_tracker_record_metadata_response(
            stream->metadata_upload_id,
            (const char*)stream->response_body,
            stream->response_body_length
        );
    }

    if (stream->file_analysis_complete) {
        log_info(
            "UPLOAD FORWARDED id=%lu session=%lu stream=%u file=\"%s\" upstream_status=%d",
            stream->upload_info.upload_id,
            engine->session->session_id,
            stream->stream_id,
            stream->upload_info.filename[0] ? stream->upload_info.filename : "unknown",
            stream->response_status
        );
    }
}

static int http2_evaluate_request(
    http2_engine_t* engine,
    http2_stream_state_t* stream,
    int end_stream
)
{
    dlp_result_t result;

    if (engine == NULL || stream == NULL || stream->blocked) {
        return stream != NULL && stream->blocked ? 1 : -1;
    }

    result = http2_inspect_request(stream, end_stream);
    http2_record_metadata_request(engine, stream, end_stream);
    http2_apply_file_analysis(engine, stream, end_stream, &result);
    if (result.action == DLP_ACTION_BLOCK) {
        stream->blocked = 1;
        log_security(
            "HTTP2 request blocked. session_id=%lu stream_id=%u rule_id=%d keyword=%s reason=\"%s\" buffered_body_bytes=%lu total_body_bytes=%llu",
            engine->session->session_id,
            stream->stream_id,
            result.matched_rule_id,
            result.keyword,
            result.reason,
            (unsigned long)stream->body_length,
            stream->total_body_bytes
        );
        audit_log_block_event(engine->session, &stream->request, &result);
        return http2_send_block_response(engine, stream, &result) == 0 ? 1 : -1;
    }

    if (result.action == DLP_ACTION_LOG_ONLY && !stream->log_only_audited) {
        stream->log_only_audited = 1;
        log_security(
            "HTTP2 request log-only. session_id=%lu stream_id=%u rule_id=%d keyword=%s reason=\"%s\"",
            engine->session->session_id,
            stream->stream_id,
            result.matched_rule_id,
            result.keyword,
            result.reason
        );
        audit_log_log_only_event(engine->session, &stream->request, &result);
    }

    if (end_stream && dlp_request_should_inspect(&stream->request)) {
        log_debug(
            "HTTP2 request inspection completed. session_id=%lu stream_id=%u action=%s buffered_body_bytes=%lu total_body_bytes=%llu",
            engine->session->session_id,
            stream->stream_id,
            result.action == DLP_ACTION_LOG_ONLY ? "LOG_ONLY" : "ALLOW",
            (unsigned long)stream->body_length,
            stream->total_body_bytes
        );
    }

    return 0;
}

static int http2_forward_raw_frame(
    http2_engine_t* engine,
    http2_direction_t direction,
    const unsigned char* frame,
    int frame_length
)
{
    if (direction == HTTP2_DIRECTION_REQUEST) {
        if (http2_ssl_write_all(engine->upstream_ssl, frame, frame_length) < 0) return -1;
        session_context_add_bytes_to_upstream(engine->session, frame_length);
    }
    else {
        if (http2_ssl_write_all(engine->client_ssl, frame, frame_length) < 0) return -1;
        session_context_add_bytes_to_client(engine->session, frame_length);
    }
    return 0;
}

static int http2_process_frame(
    http2_engine_t* engine,
    http2_parser_t* parser,
    const unsigned char* frame,
    int frame_length
)
{
    unsigned int payload_length = http2_read_u24(frame);
    unsigned char type = frame[3];
    unsigned char flags = frame[4];
    unsigned int stream_id = http2_read_u31(frame + 5);
    const unsigned char* payload = frame + HTTP2_FRAME_HEADER_SIZE;
    http2_stream_state_t* stream = NULL;
    unsigned char header_start_flags = 0;
    int header_block_completed = 0;
    int request_end_stream = 0;

    log_debug(
        "HTTP2_FRAME session_id=%lu direction=%s type=0x%02x stream_id=%u flags=0x%02x payload_bytes=%u",
        engine->session->session_id,
        parser->direction == HTTP2_DIRECTION_REQUEST ? "REQUEST" : "RESPONSE",
        type,
        stream_id,
        flags,
        payload_length
    );

    if ((type == HTTP2_FRAME_HEADERS || type == HTTP2_FRAME_CONTINUATION) && stream_id != 0) {
        header_start_flags = type == HTTP2_FRAME_HEADERS
            ? flags
            : parser->initial_headers_flags;
        header_block_completed = (flags & HTTP2_FLAG_END_HEADERS) != 0;
        if (http2_append_header_fragment(
            engine,
            parser,
            stream_id,
            type,
            flags,
            payload,
            payload_length
        ) != 0) {
            return -1;
        }
        request_end_stream = header_block_completed &&
            ((header_start_flags & HTTP2_FLAG_END_STREAM) != 0);
    }

    stream = stream_id != 0 ? http2_find_stream(engine, stream_id, type == HTTP2_FRAME_HEADERS) : NULL;

    if (parser->direction == HTTP2_DIRECTION_REQUEST) {
        if (type == HTTP2_FRAME_DATA && stream != NULL) {
            const unsigned char* body;
            unsigned int body_length;
            int decision;

            if (http2_get_data_payload(flags, payload, payload_length, &body, &body_length) != 0) {
                return -1;
            }

            if (body_length > 0 && !stream->capture.attempted) {
                upload_capture_begin(
                    &stream->capture,
                    engine->session,
                    &stream->request,
                    443,
                    "h2",
                    stream->stream_id
                );
            }
            if (body_length > 0 && stream->capture.active) {
                upload_capture_append(&stream->capture, body, body_length);
            }
            if ((flags & HTTP2_FLAG_END_STREAM) != 0) {
                upload_capture_finish(&stream->capture, 1);
            }

            if (http2_append_body(stream, body, body_length) != 0) {
                return -1;
            }

            decision = http2_evaluate_request(engine, stream, (flags & HTTP2_FLAG_END_STREAM) != 0);
            if (decision < 0) return -1;
            if (decision > 0 || stream->blocked) {
                if ((flags & HTTP2_FLAG_END_STREAM) != 0) {
                    stream->request_complete = 1;
                }
                return 0;
            }
        }
        else if ((type == HTTP2_FRAME_HEADERS || type == HTTP2_FRAME_CONTINUATION) &&
                 request_end_stream && stream != NULL) {
            int decision = http2_evaluate_request(engine, stream, 1);
            if (decision < 0) return -1;
            if (decision > 0) {
                stream->request_complete = 1;
                return 0;
            }
        }

        if (stream != NULL && stream->blocked) {
            if ((flags & HTTP2_FLAG_END_STREAM) != 0 ||
                request_end_stream || type == HTTP2_FRAME_RST_STREAM) {
                stream->request_complete = 1;
            }
            if (stream->request_complete && stream->response_complete) {
                http2_release_stream(stream);
            }
            return 0;
        }
    }
    else if (type == HTTP2_FRAME_DATA && stream != NULL) {
        const unsigned char* body;
        unsigned int body_length;
        if (http2_get_data_payload(flags, payload, payload_length, &body, &body_length) != 0) {
            return -1;
        }
        if (http2_append_metadata_response_body(stream, body, body_length) != 0) {
            return -1;
        }
        log_debug(
            "HTTP2_ANALYSIS direction=RESPONSE session_id=%lu stream_id=%u body_bytes=%u end_stream=%s",
            engine->session->session_id,
            stream_id,
            body_length,
            (flags & HTTP2_FLAG_END_STREAM) ? "true" : "false"
        );
    }

    /*
        A local 403 has already completed a blocked stream for the browser.
        Consume upstream cleanup frames locally so a late RST_STREAM cannot
        overwrite that response. Header blocks were decoded above to preserve
        the response-direction HPACK dynamic table.
    */
    if (stream != NULL && stream->blocked &&
        parser->direction == HTTP2_DIRECTION_RESPONSE) {
        if ((flags & HTTP2_FLAG_END_STREAM) || request_end_stream ||
            type == HTTP2_FRAME_RST_STREAM) {
            stream->response_complete = 1;
            if (stream->request_complete) {
                http2_release_stream(stream);
            }
        }
        return 0;
    }

    if (http2_forward_raw_frame(engine, parser->direction, frame, frame_length) != 0) {
        return -1;
    }

    if (stream != NULL) {
        if (parser->direction == HTTP2_DIRECTION_REQUEST &&
            (((flags & HTTP2_FLAG_END_STREAM) != 0) || request_end_stream)) {
            stream->request_complete = 1;
        }
        if (parser->direction == HTTP2_DIRECTION_RESPONSE &&
            ((flags & HTTP2_FLAG_END_STREAM) || type == HTTP2_FRAME_RST_STREAM)) {
            http2_finalize_response(engine, stream);
            stream->response_complete = 1;
            http2_release_stream(stream);
        }
    }

    if (type == HTTP2_FRAME_GOAWAY) {
        log_info("HTTP2 GOAWAY observed. session_id=%lu direction=%s",
            engine->session->session_id,
            parser->direction == HTTP2_DIRECTION_REQUEST ? "REQUEST" : "RESPONSE");
    }

    return 0;
}

static int http2_parser_init(http2_parser_t* parser, http2_direction_t direction)
{
    if (parser == NULL) return -1;
    memset(parser, 0, sizeof(*parser));
    parser->direction = direction;
    parser->preface_consumed = direction == HTTP2_DIRECTION_RESPONSE;
    return nghttp2_hd_inflate_new(&parser->inflater);
}

static void http2_parser_cleanup(http2_parser_t* parser)
{
    if (parser != NULL && parser->inflater != NULL) {
        nghttp2_hd_inflate_del(parser->inflater);
        parser->inflater = NULL;
    }
}

static int http2_parser_feed(
    http2_engine_t* engine,
    http2_parser_t* parser,
    const unsigned char* data,
    int data_length
)
{
    int offset = 0;

    if (engine == NULL || parser == NULL || data == NULL || data_length < 0) return -1;
    if (data_length > HTTP2_PARSE_BUFFER_SIZE - parser->length) {
        log_error("HTTP/2 parser buffer exceeded. session_id=%lu direction=%s",
            engine->session->session_id,
            parser->direction == HTTP2_DIRECTION_REQUEST ? "REQUEST" : "RESPONSE");
        return -1;
    }

    memcpy(parser->buffer + parser->length, data, data_length);
    parser->length += data_length;

    if (!parser->preface_consumed) {
        if (parser->length < HTTP2_PREFACE_LENGTH) return 0;
        if (memcmp(parser->buffer, HTTP2_PREFACE, HTTP2_PREFACE_LENGTH) != 0) {
            log_error("HTTP/2 client preface mismatch. session_id=%lu", engine->session->session_id);
            return -1;
        }
        if (http2_ssl_write_all(engine->upstream_ssl, parser->buffer, HTTP2_PREFACE_LENGTH) < 0) {
            return -1;
        }
        session_context_add_bytes_to_upstream(engine->session, HTTP2_PREFACE_LENGTH);
        offset = HTTP2_PREFACE_LENGTH;
        parser->preface_consumed = 1;
        log_info("HTTP2_ANALYSIS direction=REQUEST session_id=%lu client_preface=ok",
            engine->session->session_id);
    }

    while (parser->length - offset >= HTTP2_FRAME_HEADER_SIZE) {
        unsigned int payload_length = http2_read_u24(parser->buffer + offset);
        int frame_length = HTTP2_FRAME_HEADER_SIZE + (int)payload_length;

        if (payload_length > HTTP2_PARSE_BUFFER_SIZE - HTTP2_FRAME_HEADER_SIZE) {
            return -1;
        }
        if (parser->length - offset < frame_length) break;

        if (http2_process_frame(engine, parser, parser->buffer + offset, frame_length) != 0) {
            return -1;
        }
        offset += frame_length;
    }

    if (offset > 0) {
        if (offset < parser->length) {
            memmove(parser->buffer, parser->buffer + offset, parser->length - offset);
            parser->length -= offset;
        }
        else {
            parser->length = 0;
        }
    }
    return 0;
}

int http2_engine_relay_loop(
    proxy_session_context_t* session,
    SSL* client_ssl,
    SSL* upstream_ssl,
    SOCKET upstream_sock
)
{
    http2_engine_t* engine;
    unsigned char buffer[HTTP2_ENGINE_BUFFER_SIZE];
    int result = 0;
    int i;

    if (session == NULL || client_ssl == NULL || upstream_ssl == NULL ||
        upstream_sock == INVALID_SOCKET) {
        return -1;
    }

    engine = (http2_engine_t*)calloc(1, sizeof(*engine));
    if (engine == NULL) return -1;
    engine->session = session;
    engine->client_ssl = client_ssl;
    engine->upstream_ssl = upstream_ssl;

    if (http2_parser_init(&engine->request_parser, HTTP2_DIRECTION_REQUEST) != 0 ||
        http2_parser_init(&engine->response_parser, HTTP2_DIRECTION_RESPONSE) != 0) {
        log_error("HTTP/2 HPACK inflater initialization failed. session_id=%lu", session->session_id);
        result = -1;
        goto cleanup;
    }

    log_info("TLS MITM HTTP/2 analysis and DLP enforcement started. session_id=%lu",
        session->session_id);

    while (1) {
        fd_set read_fds;
        struct timeval timeout;
        int select_result;
        int client_ready = SSL_pending(client_ssl) > 0;
        int upstream_ready = SSL_pending(upstream_ssl) > 0;

        if (!client_ready && !upstream_ready) {
            FD_ZERO(&read_fds);
            FD_SET(session->client_sock, &read_fds);
            FD_SET(upstream_sock, &read_fds);
            timeout.tv_sec = 300;
            timeout.tv_usec = 0;

            select_result = select(0, &read_fds, NULL, NULL, &timeout);
            if (select_result == SOCKET_ERROR) {
                result = -1;
                break;
            }
            if (select_result == 0) {
                log_info("TLS MITM HTTP/2 idle timeout. session_id=%lu", session->session_id);
                break;
            }

            client_ready = FD_ISSET(session->client_sock, &read_fds) != 0;
            upstream_ready = FD_ISSET(upstream_sock, &read_fds) != 0;
        }

        if (client_ready) {
            int read_length = SSL_read(client_ssl, buffer, sizeof(buffer));
            if (read_length <= 0) {
                int ssl_error = SSL_get_error(client_ssl, read_length);
                int socket_error = 0;

                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                if (http2_ssl_read_is_expected_close(
                    client_ssl,
                    read_length,
                    ssl_error,
                    &socket_error
                )) {
                    log_debug(
                        "HTTP/2 client connection closed; browser may reconnect. session_id=%lu ssl_error=%d socket_error=%d",
                        session->session_id,
                        ssl_error,
                        socket_error
                    );
                    break;
                }
                log_error("HTTP/2 client SSL_read failed. session_id=%lu ssl_error=%d socket_error=%d",
                    session->session_id, ssl_error, socket_error);
                result = -1;
                break;
            }
            session_context_add_bytes_from_client(session, read_length);
            if (http2_parser_feed(engine, &engine->request_parser, buffer, read_length) != 0) {
                result = -1;
                break;
            }
        }

        if (upstream_ready) {
            int read_length = SSL_read(upstream_ssl, buffer, sizeof(buffer));
            if (read_length <= 0) {
                int ssl_error = SSL_get_error(upstream_ssl, read_length);
                int socket_error = 0;

                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                if (http2_ssl_read_is_expected_close(
                    upstream_ssl,
                    read_length,
                    ssl_error,
                    &socket_error
                )) {
                    log_debug(
                        "HTTP/2 upstream connection closed normally. session_id=%lu ssl_error=%d socket_error=%d",
                        session->session_id,
                        ssl_error,
                        socket_error
                    );
                    break;
                }
                log_error("HTTP/2 upstream SSL_read failed. session_id=%lu ssl_error=%d socket_error=%d",
                    session->session_id, ssl_error, socket_error);
                result = -1;
                break;
            }
            session_context_add_bytes_from_upstream(session, read_length);
            if (http2_parser_feed(engine, &engine->response_parser, buffer, read_length) != 0) {
                result = -1;
                break;
            }
        }
    }

cleanup:
    http2_parser_cleanup(&engine->request_parser);
    http2_parser_cleanup(&engine->response_parser);
    for (i = 0; i < HTTP2_MAX_STREAMS; i++) {
        if (engine->streams[i].in_use) http2_release_stream(&engine->streams[i]);
    }
    free(engine);

    if (result == 0) {
        log_info("TLS MITM HTTP/2 analysis finished normally. session_id=%lu", session->session_id);
    }
    else {
        log_error("TLS MITM HTTP/2 analysis finished with error. session_id=%lu", session->session_id);
    }
    return result;
}
