#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Include the implementation so this focused test can exercise private
 * boundary and staging helpers without widening the production API. */
#include "../../upload_capture.c"

#pragma comment(lib, "Advapi32.lib")

static int g_extract_should_fail = 0;
static int g_failures = 0;
static int g_tests = 0;

int dlp_request_is_file_upload(const http_request_t* request)
{
    (void)request;
    return 1;
}

int file_analyzer_extract_text(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    char** output,
    size_t* output_length,
    int* truncated
)
{
    const char text[] = "hello";
    (void)filename;
    (void)content_type;
    (void)data;
    (void)length;
    if (output == NULL || output_length == NULL) return -1;
    *output = NULL;
    *output_length = 0;
    if (truncated != NULL) *truncated = 0;
    if (g_extract_should_fail) return -1;
    *output = (char*)malloc(sizeof(text));
    if (*output == NULL) return -1;
    memcpy(*output, text, sizeof(text));
    *output_length = sizeof(text) - 1;
    return 0;
}

void log_debug(const char* format, ...) { (void)format; }
void log_info(const char* format, ...) { (void)format; }
void log_warn(const char* format, ...) { (void)format; }
void log_error(const char* format, ...) { (void)format; }
void log_security(const char* format, ...) { (void)format; }
void log_event(const char* format, ...) { (void)format; }

static void expect_true(int condition, const char* name)
{
    g_tests++;
    if (condition) {
        printf("[PASS] %s\n", name);
    }
    else {
        fprintf(stderr, "[FAIL] %s\n", name);
        g_failures++;
    }
}

static void add_header(http_request_t* request, const char* name, const char* value)
{
    http_header_t* header;
    if (request == NULL || request->header_count >= HTTP_MAX_HEADER_COUNT) return;
    header = &request->headers[request->header_count++];
    strcpy_s(header->name, sizeof(header->name), name);
    strcpy_s(header->value, sizeof(header->value), value);
}

static int find_named_file(
    const char* directory,
    const char* target_name,
    char* output,
    size_t output_size
)
{
    WIN32_FIND_DATAA entry;
    HANDLE search;
    char pattern[MAX_PATH];
    char child[MAX_PATH];

    if (_snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s\\*", directory) < 0)
        return 0;
    search = FindFirstFileA(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) return 0;
    do {
        if (strcmp(entry.cFileName, ".") == 0 || strcmp(entry.cFileName, "..") == 0)
            continue;
        if (_snprintf_s(child, sizeof(child), _TRUNCATE,
            "%s\\%s", directory, entry.cFileName) < 0) continue;
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if (find_named_file(child, target_name, output, output_size)) {
                FindClose(search);
                return 1;
            }
        }
        else if (_stricmp(entry.cFileName, target_name) == 0) {
            strcpy_s(output, output_size, child);
            FindClose(search);
            return 1;
        }
    } while (FindNextFileA(search, &entry));
    FindClose(search);
    return 0;
}

static int contains_staging_directory(const char* directory)
{
    WIN32_FIND_DATAA entry;
    HANDLE search;
    char pattern[MAX_PATH];
    char child[MAX_PATH];
    if (_snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s\\*", directory) < 0)
        return 1;
    search = FindFirstFileA(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) return 0;
    do {
        if (strcmp(entry.cFileName, ".") == 0 || strcmp(entry.cFileName, "..") == 0)
            continue;
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (strstr(entry.cFileName, ".tmp.") != NULL) {
            FindClose(search);
            return 1;
        }
        if (_snprintf_s(child, sizeof(child), _TRUNCATE,
            "%s\\%s", directory, entry.cFileName) >= 0 &&
            contains_staging_directory(child)) {
            FindClose(search);
            return 1;
        }
    } while (FindNextFileA(search, &entry));
    FindClose(search);
    return 0;
}

static char* read_file(const char* path)
{
    FILE* file = NULL;
    long length;
    char* data;
    if (fopen_s(&file, path, "rb") != 0 || file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    data = (char*)malloc((size_t)length + 1);
    if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    data[length] = '\0';
    fclose(file);
    return data;
}

static void test_fragment_bounds(void)
{
    upload_capture_writer_t writer;
    http_request_t request;
    unsigned long long parsed = 0;
    unsigned char bytes[16] = {0};

    expect_true(!upload_capture_parse_u64("-1", &parsed), "negative offset rejected");
    expect_true(!upload_capture_parse_u64("18446744073709551616", &parsed),
        "u64 overflow rejected");

    memset(&writer, 0, sizeof(writer));
    memset(&request, 0, sizeof(request));
    writer.max_bytes = 128;
    writer.session_id = 1;
    writer.stream_id = 2;
    request.content_length = 1;
    strcpy_s(request.host, sizeof(request.host), "content-push.googleapis.com");
    strcpy_s(request.path, sizeof(request.path), "/upload/huge-offset");
    add_header(&request, "X-Goog-Upload-Offset", "18446744073709551615");
    add_header(&request, "X-Goog-Upload-Command", "upload");
    upload_capture_detect_fragment(&writer, &request);
    expect_true(writer.failed, "huge X-Goog offset rejected before seek");

    memset(&writer, 0, sizeof(writer));
    memset(&request, 0, sizeof(request));
    writer.max_bytes = 128;
    writer.session_id = 1;
    writer.stream_id = 3;
    request.content_length = 16;
    strcpy_s(request.host, sizeof(request.host), "content-push.googleapis.com");
    strcpy_s(request.path, sizeof(request.path), "/upload/offset-plus-length");
    add_header(&request, "X-Goog-Upload-Offset", "120");
    add_header(&request, "X-Goog-Upload-Command", "upload");
    upload_capture_detect_fragment(&writer, &request);
    expect_true(writer.failed, "offset plus declared length over capture max rejected");

    memset(&writer, 0, sizeof(writer));
    memset(&request, 0, sizeof(request));
    writer.max_bytes = 128;
    writer.declared_bytes = 8;
    writer.declared_bytes_known = 1;
    strcpy_s(request.host, sizeof(request.host), "content-push.googleapis.com");
    strcpy_s(request.path, sizeof(request.path), "/upload/valid-range");
    add_header(&request, "Content-Range", "bytes 120-127/128");
    upload_capture_detect_fragment(&writer, &request);
    expect_true(!writer.failed && writer.fragment_final &&
        writer.fragment_expected_bytes == 8,
        "valid bounded Content-Range accepted");

    memset(&writer, 0, sizeof(writer));
    writer.active = 1;
    writer.is_fragment = 1;
    writer.max_bytes = 128;
    writer.fragment_offset = 120;
    writer.fragment_expected_bytes = 8;
    writer.fragment_expected_bytes_known = 1;
    writer.file = fopen("fragment_append.tmp", "w+b");
    expect_true(writer.file != NULL, "fragment append test file opened");
    if (writer.file != NULL) {
        expect_true(upload_capture_append(&writer, bytes, 9) < 0 &&
            writer.failed && writer.bytes_written == 0,
            "actual fragment body cannot exceed declared range");
        fclose(writer.file);
        writer.file = NULL;
        DeleteFileA("fragment_append.tmp");
    }

    _putenv_s(UPLOAD_CAPTURE_MAX_BYTES_ENV, "0");
    expect_true(upload_capture_read_max_bytes() == UPLOAD_CAPTURE_DEFAULT_MAX_BYTES,
        "zero capture limit cannot enable unbounded sparse files");
    _putenv_s(UPLOAD_CAPTURE_MAX_BYTES_ENV, "");
}

static void populate_record_context(
    proxy_session_context_t* session,
    http_request_t* request,
    file_analysis_result_t* analysis
)
{
    memset(session, 0, sizeof(*session));
    memset(request, 0, sizeof(*request));
    memset(analysis, 0, sizeof(*analysis));
    session->session_id = 77;
    strcpy_s(session->client_ip, sizeof(session->client_ip), "127.0.0.1");
    strcpy_s(session->process.process_name, sizeof(session->process.process_name),
        "browser\r\nforged_process=1\"");
    strcpy_s(session->process.process_path, sizeof(session->process.process_path),
        "C:\\Browser\\browser.exe\r\nforged_path=1\"");
    strcpy_s(request->host, sizeof(request->host), "chatgpt.com\r\nforged_host=1\"");
    strcpy_s(request->method, sizeof(request->method), "PUT\r\nforged_method=1");
    strcpy_s(request->path, sizeof(request->path), "/upload\r\nforged_path=1?secret=redact");
    strcpy_s(request->content_type, sizeof(request->content_type),
        "text/plain\r\nforged_type=1\"");
    request->content_length = 4;
    analysis->action = FILE_ANALYSIS_ALLOW;
    analysis->extraction_status = FILE_EXTRACTION_COMPLETE;
    strcpy_s(analysis->sha256, sizeof(analysis->sha256), "abc123");
    strcpy_s(analysis->format, sizeof(analysis->format), "TEXT");
    strcpy_s(analysis->normalized_mime, sizeof(analysis->normalized_mime), "text/plain");
    strcpy_s(analysis->reason, sizeof(analysis->reason), "bad\r\ninjected=\"x\"");
}

static void test_record_transaction_and_sanitization(void)
{
    proxy_session_context_t session;
    http_request_t request;
    file_analysis_result_t analysis;
    const unsigned char data[] = "safe";
    char metadata_path[MAX_PATH];
    char* metadata;
    int metadata_found;
    int store_result;

    _putenv_s(UPLOAD_RECORD_ENV, "1");
    _putenv_s(UPLOAD_RECORD_DIRECTORY_ENV, "records");
    metadata_path[0] = '\0';
    populate_record_context(&session, &request, &analysis);

    g_extract_should_fail = 1;
    store_result = upload_record_store_file_ex(&session, &request,
        "ChatGPT\r\nforged_service=1\"", "http1\r\nforged_protocol=1", 5,
        "safe.txt", data, sizeof(data) - 1, sizeof(data) - 1, 1, &analysis);
    expect_true(store_result < 0, "text extraction failure propagates fail-closed");
    expect_true(!find_named_file("records", "metadata.txt", metadata_path,
        sizeof(metadata_path)), "failed extraction publishes no record");
    expect_true(!contains_staging_directory("records"),
        "failed extraction removes staging directory");

    g_extract_should_fail = 0;
    store_result = upload_record_store_file_ex(&session, &request,
        "ChatGPT\r\nforged_service=1\"", "http1\r\nforged_protocol=1", 6,
        "safe\r\nforged_filename=1\".txt", data, sizeof(data) - 1,
        sizeof(data) - 1, 1, &analysis);
    expect_true(store_result == 1, "complete record staging commits successfully");
    metadata_found = find_named_file("records", "metadata.txt", metadata_path,
        sizeof(metadata_path));
    expect_true(metadata_found, "committed record contains metadata");
    expect_true(!contains_staging_directory("records"),
        "successful commit leaves no staging directory");

    metadata = metadata_found ? read_file(metadata_path) : NULL;
    expect_true(metadata != NULL, "metadata is readable after directory commit");
    if (metadata != NULL) {
        expect_true(strchr(metadata, '\r') == NULL, "metadata contains no CR injection");
        expect_true(strstr(metadata, "\nforged_") == NULL,
            "external values cannot inject metadata keys");
        expect_true(strstr(metadata, "reason=bad__injected='x'") != NULL,
            "analysis reason CR/LF and quote are sanitized");
        expect_true(strstr(metadata, "record_complete=true") != NULL,
            "metadata marks only committed records complete");
        free(metadata);
    }
}

int main(void)
{
    test_fragment_bounds();
    test_record_transaction_and_sanitization();
    printf("upload_capture safety tests: PASS=%d FAIL=%d\n",
        g_tests - g_failures, g_failures);
    return g_failures == 0 ? 0 : 1;
}
