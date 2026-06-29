#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "content_decoder.h"
#include "chunked_decoder.h"
#include "logger.h"

#if defined(__has_include)
#  if __has_include(<zlib.h>)
#    include <zlib.h>
#    define CONTENT_DECODER_HAS_ZLIB 1
#  else
#    define CONTENT_DECODER_HAS_ZLIB 0
#  endif
#else
#  include <zlib.h>
#  define CONTENT_DECODER_HAS_ZLIB 1
#endif

#if CONTENT_DECODER_HAS_ZLIB
#  if defined(_MSC_VER)
#    if defined(_DEBUG)
#      pragma comment(lib, "zd.lib")
#    else
#      pragma comment(lib, "z.lib")
#    endif
#  endif
#endif

#define CONTENT_DECODER_MAX_HEADER_VALUE 128
#define CONTENT_DECODER_MAX_DECOMPRESSED_SIZE (1024 * 1024)

static int ascii_tolower_int(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }

    return c;
}

static int ascii_stricmp_local(const char* a, const char* b)
{
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL) {
        return (a == b) ? 0 : 1;
    }

    while (*a != '\0' && *b != '\0') {
        ca = (unsigned char)ascii_tolower_int((unsigned char)*a);
        cb = (unsigned char)ascii_tolower_int((unsigned char)*b);

        if (ca != cb) {
            return (int)ca - (int)cb;
        }

        a++;
        b++;
    }

    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static int ascii_strnicmp_local(const char* a, const char* b, int n)
{
    int i;
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL) {
        return (a == b) ? 0 : 1;
    }

    for (i = 0; i < n; i++) {
        ca = (unsigned char)a[i];
        cb = (unsigned char)b[i];

        if (ca == '\0' || cb == '\0') {
            return (int)ca - (int)cb;
        }

        ca = (unsigned char)ascii_tolower_int(ca);
        cb = (unsigned char)ascii_tolower_int(cb);

        if (ca != cb) {
            return (int)ca - (int)cb;
        }
    }

    return 0;
}

static int find_http_header_end(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return -1;
    }

    for (i = 0; i + 3 < length; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i + 4;
        }
    }

    return -1;
}

static void trim_header_value(char* value)
{
    char* start;
    char* end;
    size_t len;

    if (value == NULL) {
        return;
    }

    start = value;

    while (*start == ' ' || *start == '\t') {
        start++;
    }

    if (start != value) {
        memmove(value, start, strlen(start) + 1);
    }

    len = strlen(value);

    while (len > 0) {
        end = value + len - 1;

        if (*end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') {
            break;
        }

        *end = '\0';
        len--;
    }
}

static int extract_header_value_ci(
    const char* raw_response,
    int header_length,
    const char* header_name,
    char* value,
    int value_size
)
{
    const char* p;
    const char* line_start;
    const char* line_end;
    int header_name_len;
    int line_len;
    int copy_len;

    if (raw_response == NULL || header_length <= 0 ||
        header_name == NULL || value == NULL || value_size <= 0) {
        return 0;
    }

    value[0] = '\0';
    header_name_len = (int)strlen(header_name);
    p = raw_response;

    /* Skip status line. */
    line_end = strstr(p, "\r\n");

    if (line_end == NULL) {
        return 0;
    }

    p = line_end + 2;

    while (p < raw_response + header_length) {
        line_start = p;
        line_end = strstr(line_start, "\r\n");

        if (line_end == NULL) {
            break;
        }

        if (line_end == line_start) {
            break;
        }

        line_len = (int)(line_end - line_start);

        if (line_len > header_name_len &&
            ascii_strnicmp_local(line_start, header_name, header_name_len) == 0 &&
            line_start[header_name_len] == ':') {
            copy_len = line_len - header_name_len - 1;

            if (copy_len >= value_size) {
                copy_len = value_size - 1;
            }

            memcpy(value, line_start + header_name_len + 1, copy_len);
            value[copy_len] = '\0';
            trim_header_value(value);
            return 1;
        }

        p = line_end + 2;
    }

    return 0;
}

static int copy_decoded_body_to_response(
    const http_response_t* original_response,
    const char* decoded_body,
    int decoded_body_length,
    http_response_t* decoded_response,
    const char* encoding,
    const char* log_context
)
{
    size_t body_capacity;
    int copy_length;

    if (original_response == NULL || decoded_body == NULL ||
        decoded_body_length < 0 || decoded_response == NULL) {
        return -1;
    }

    *decoded_response = *original_response;

    body_capacity = sizeof(decoded_response->body);

    if (body_capacity == 0) {
        log_warn(
            "Compressed response decoded but http_response_t.body capacity is zero. context=%s encoding=%s",
            log_context != NULL ? log_context : "-",
            encoding != NULL ? encoding : "-"
        );
        return -1;
    }

    copy_length = decoded_body_length;

    if ((size_t)copy_length >= body_capacity) {
        copy_length = (int)body_capacity - 1;
        log_warn(
            "Decoded response body truncated for DLP. context=%s encoding=%s decoded_bytes=%d copied_bytes=%d",
            log_context != NULL ? log_context : "-",
            encoding != NULL ? encoding : "-",
            decoded_body_length,
            copy_length
        );
    }

    if (copy_length > 0) {
        memcpy(decoded_response->body, decoded_body, copy_length);
    }

    decoded_response->body[copy_length] = '\0';
    decoded_response->content_length = copy_length;

    log_info(
        "Decompressed HTTP response body for DLP. context=%s content_encoding=%s decompressed_body_bytes=%d copied_bytes=%d",
        log_context != NULL ? log_context : "-",
        encoding != NULL ? encoding : "-",
        decoded_body_length,
        copy_length
    );

    return 0;
}

#if CONTENT_DECODER_HAS_ZLIB
static int inflate_buffer_with_window_bits(
    const unsigned char* input,
    int input_length,
    int window_bits,
    unsigned char** output,
    int* output_length
)
{
    z_stream stream;
    unsigned char* out;
    size_t capacity;
    int ret;

    if (input == NULL || input_length < 0 || output == NULL || output_length == NULL) {
        return -1;
    }

    *output = NULL;
    *output_length = 0;

    memset(&stream, 0, sizeof(stream));

    ret = inflateInit2(&stream, window_bits);

    if (ret != Z_OK) {
        return -1;
    }

    capacity = (size_t)input_length * 4 + 4096;

    if (capacity < 4096) {
        capacity = 4096;
    }

    if (capacity > CONTENT_DECODER_MAX_DECOMPRESSED_SIZE) {
        capacity = CONTENT_DECODER_MAX_DECOMPRESSED_SIZE;
    }

    out = (unsigned char*)malloc(capacity + 1);

    if (out == NULL) {
        inflateEnd(&stream);
        return -1;
    }

    stream.next_in = (Bytef*)input;
    stream.avail_in = (uInt)input_length;

    for (;;) {
        if (stream.total_out >= capacity) {
            size_t new_capacity;
            unsigned char* resized;

            if (capacity >= CONTENT_DECODER_MAX_DECOMPRESSED_SIZE) {
                log_warn(
                    "Compressed response exceeds decompression limit. limit=%d",
                    CONTENT_DECODER_MAX_DECOMPRESSED_SIZE
                );
                free(out);
                inflateEnd(&stream);
                return -1;
            }

            new_capacity = capacity * 2;

            if (new_capacity > CONTENT_DECODER_MAX_DECOMPRESSED_SIZE) {
                new_capacity = CONTENT_DECODER_MAX_DECOMPRESSED_SIZE;
            }

            resized = (unsigned char*)realloc(out, new_capacity + 1);

            if (resized == NULL) {
                free(out);
                inflateEnd(&stream);
                return -1;
            }

            out = resized;
            capacity = new_capacity;
        }

        stream.next_out = out + stream.total_out;
        stream.avail_out = (uInt)(capacity - stream.total_out);

        ret = inflate(&stream, Z_NO_FLUSH);

        if (ret == Z_STREAM_END) {
            break;
        }

        if (ret != Z_OK) {
            free(out);
            inflateEnd(&stream);
            return -1;
        }
    }

    *output_length = (int)stream.total_out;
    out[*output_length] = '\0';
    *output = out;

    inflateEnd(&stream);
    return 0;
}

static int decode_compressed_body(
    const char* encoding,
    const unsigned char* compressed_body,
    int transfer_body_length,
    unsigned char** decoded_body,
    int* decoded_body_length
)
{
    if (encoding == NULL || compressed_body == NULL || transfer_body_length < 0 ||
        decoded_body == NULL || decoded_body_length == NULL) {
        return -1;
    }

    if (ascii_stricmp_local(encoding, "gzip") == 0 ||
        ascii_stricmp_local(encoding, "x-gzip") == 0) {
        return inflate_buffer_with_window_bits(
            compressed_body,
            transfer_body_length,
            16 + MAX_WBITS,
            decoded_body,
            decoded_body_length
        );
    }

    if (ascii_stricmp_local(encoding, "deflate") == 0) {
        if (inflate_buffer_with_window_bits(
            compressed_body,
            transfer_body_length,
            MAX_WBITS,
            decoded_body,
            decoded_body_length
        ) == 0) {
            return 0;
        }

        /* Some servers send raw deflate instead of zlib-wrapped deflate. */
        return inflate_buffer_with_window_bits(
            compressed_body,
            transfer_body_length,
            -MAX_WBITS,
            decoded_body,
            decoded_body_length
        );
    }

    return -1;
}
#endif

int content_decoder_prepare_response_for_dlp(
    const http_response_t* original_response,
    const char* raw_response,
    int raw_response_length,
    http_response_t* decoded_response,
    const char* log_context
)
{
    int header_length;
    int transfer_body_length;
    const unsigned char* transfer_body;
    unsigned char* dechunked_body;
    int dechunked_body_length;
    int complete_length;
    int is_chunked;
    char encoding[CONTENT_DECODER_MAX_HEADER_VALUE];

#if CONTENT_DECODER_HAS_ZLIB
    unsigned char* decoded_body;
    int decoded_body_length;
#endif

    if (original_response == NULL || raw_response == NULL || raw_response_length <= 0 ||
        decoded_response == NULL) {
        return 0;
    }

    header_length = find_http_header_end(raw_response, raw_response_length);

    if (header_length <= 0 || header_length > raw_response_length) {
        return 0;
    }

    transfer_body = (const unsigned char*)(raw_response + header_length);
    transfer_body_length = raw_response_length - header_length;
    dechunked_body = NULL;
    dechunked_body_length = 0;
    complete_length = 0;
    is_chunked = 0;
    encoding[0] = '\0';

    if (chunked_message_get_complete_length(
        raw_response,
        raw_response_length,
        &complete_length,
        &is_chunked
    ) < 0) {
        log_warn(
            "Malformed chunked HTTP response detected. context=%s DLP will inspect original response body.",
            log_context != NULL ? log_context : "-"
        );
        return -1;
    }

    if (is_chunked) {
        if (chunked_decode_http_message_body(
            raw_response,
            raw_response_length,
            &dechunked_body,
            &dechunked_body_length
        ) != 0) {
            log_warn(
                "Failed to decode chunked HTTP response body. context=%s DLP will inspect original response body.",
                log_context != NULL ? log_context : "-"
            );
            return -1;
        }

        transfer_body = dechunked_body;
        transfer_body_length = dechunked_body_length;

        log_info(
            "Decoded chunked HTTP response body for DLP. context=%s decoded_body_bytes=%d",
            log_context != NULL ? log_context : "-",
            transfer_body_length
        );
    }

    if (!extract_header_value_ci(
        raw_response,
        header_length,
        "Content-Encoding",
        encoding,
        sizeof(encoding)
    )) {
        encoding[0] = '\0';
    }

    if (encoding[0] == '\0' || ascii_stricmp_local(encoding, "identity") == 0) {
        if (!is_chunked) {
            return 0;
        }

        if (copy_decoded_body_to_response(
            original_response,
            (const char*)transfer_body,
            transfer_body_length,
            decoded_response,
            "chunked",
            log_context
        ) != 0) {
            if (dechunked_body != NULL) {
                free(dechunked_body);
            }
            return -1;
        }

        if (dechunked_body != NULL) {
            free(dechunked_body);
        }
        return 1;
    }

    log_info(
        "Compressed HTTP response body detected. context=%s content_encoding=%s compressed_body_bytes=%d%s",
        log_context != NULL ? log_context : "-",
        encoding,
        transfer_body_length,
        is_chunked ? " after_dechunk" : ""
    );

    if (ascii_stricmp_local(encoding, "br") == 0) {
        log_warn(
            "Content-Encoding br detected but Brotli decoding is not implemented yet. context=%s DLP will inspect original compressed body only.",
            log_context != NULL ? log_context : "-"
        );
        if (dechunked_body != NULL) {
            free(dechunked_body);
        }
        return 0;
    }

    if (!(ascii_stricmp_local(encoding, "gzip") == 0 ||
        ascii_stricmp_local(encoding, "x-gzip") == 0 ||
        ascii_stricmp_local(encoding, "deflate") == 0)) {
        log_warn(
            "Unsupported Content-Encoding for response DLP. context=%s content_encoding=%s",
            log_context != NULL ? log_context : "-",
            encoding
        );
        if (dechunked_body != NULL) {
            free(dechunked_body);
        }
        return 0;
    }

#if CONTENT_DECODER_HAS_ZLIB
    decoded_body = NULL;
    decoded_body_length = 0;

    if (decode_compressed_body(
        encoding,
        transfer_body,
        transfer_body_length,
        &decoded_body,
        &decoded_body_length
    ) != 0) {
        log_warn(
            "Failed to decompress HTTP response body. context=%s content_encoding=%s compressed_body_bytes=%d",
            log_context != NULL ? log_context : "-",
            encoding,
            transfer_body_length
        );
        if (dechunked_body != NULL) {
            free(dechunked_body);
        }
        return -1;
    }

    if (copy_decoded_body_to_response(
        original_response,
        (const char*)decoded_body,
        decoded_body_length,
        decoded_response,
        encoding,
        log_context
    ) != 0) {
        free(decoded_body);
        if (dechunked_body != NULL) {
            free(dechunked_body);
        }
        return -1;
    }

    free(decoded_body);
    if (dechunked_body != NULL) {
        free(dechunked_body);
    }
    return 1;
#else
    log_warn(
        "zlib header was not found at build time. gzip/deflate response DLP is disabled. context=%s",
        log_context != NULL ? log_context : "-"
    );
    if (dechunked_body != NULL) {
        free(dechunked_body);
    }
    return 0;
#endif
}
