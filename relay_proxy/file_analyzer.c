#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <bcrypt.h>
#include <zlib.h>

#include "file_analyzer.h"

#pragma comment(lib, "bcrypt.lib")

#define FILE_ANALYZER_MAX_ARCHIVE_ENTRIES 1024U
#define FILE_ANALYZER_MAX_TOTAL_UNCOMPRESSED (128ULL * 1024ULL * 1024ULL)
#define FILE_ANALYZER_MAX_ENTRY_OUTPUT (8U * 1024U * 1024U)
#define FILE_ANALYZER_MAX_PDF_STREAM_OUTPUT (8U * 1024U * 1024U)

static unsigned short read_u16_le(const unsigned char* value)
{
    return (unsigned short)(value[0] | ((unsigned short)value[1] << 8));
}

static unsigned int read_u32_le(const unsigned char* value)
{
    return (unsigned int)value[0] |
        ((unsigned int)value[1] << 8) |
        ((unsigned int)value[2] << 16) |
        ((unsigned int)value[3] << 24);
}

static int contains_ignore_case(const char* text, const char* needle)
{
    size_t needle_length;
    const char* cursor;
    if (text == NULL || needle == NULL || needle[0] == '\0') return 0;
    needle_length = strlen(needle);
    for (cursor = text; *cursor != '\0'; cursor++) {
        if (_strnicmp(cursor, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static int ends_with_ignore_case(const char* text, const char* suffix)
{
    size_t text_length;
    size_t suffix_length;
    if (text == NULL || suffix == NULL) return 0;
    text_length = strlen(text);
    suffix_length = strlen(suffix);
    return text_length >= suffix_length &&
        _stricmp(text + text_length - suffix_length, suffix) == 0;
}

static int filename_has_dangerous_extension(const char* filename)
{
    static const char* extensions[] = {
        ".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk"
    };
    size_t i;
    if (filename == NULL) return 0;
    for (i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (ends_with_ignore_case(filename, extensions[i])) return 1;
    }
    return 0;
}

static int archive_path_is_unsafe(const char* name)
{
    if (name == NULL || name[0] == '\0') return 0;
    if (name[0] == '/' || name[0] == '\\') return 1;
    if (strlen(name) > 2 && isalpha((unsigned char)name[0]) && name[1] == ':') return 1;
    return strstr(name, "../") != NULL || strstr(name, "..\\") != NULL;
}

static int calculate_sha256(const unsigned char* data, size_t length, char output[65])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD object_length = 0;
    DWORD bytes = 0;
    unsigned char* object = NULL;
    unsigned char digest[32];
    size_t i;
    NTSTATUS status;

    output[0] = '\0';
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) goto cleanup;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
        sizeof(object_length), &bytes, 0);
    if (status < 0 || object_length == 0) goto cleanup;
    object = (unsigned char*)malloc(object_length);
    if (object == NULL) goto cleanup;
    status = BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0, 0);
    if (status < 0) goto cleanup;
    status = BCryptHashData(hash, (PUCHAR)data, (ULONG)length, 0);
    if (status < 0) goto cleanup;
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (status < 0) goto cleanup;
    for (i = 0; i < sizeof(digest); i++) sprintf_s(output + i * 2, 65 - i * 2, "%02x", digest[i]);

cleanup:
    if (hash != NULL) BCryptDestroyHash(hash);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    free(object);
    return output[0] != '\0' ? 0 : -1;
}

static int inflate_buffer(
    const unsigned char* compressed,
    size_t compressed_length,
    size_t expected_length,
    unsigned char** output,
    size_t* output_length,
    size_t maximum_output
)
{
    z_stream stream;
    unsigned char* buffer;
    size_t capacity;
    int zresult;

    if (output == NULL || output_length == NULL || compressed == NULL) return -1;
    *output = NULL;
    *output_length = 0;
    capacity = expected_length > 0 ? expected_length : compressed_length * 8 + 4096;
    if (capacity < 4096) capacity = 4096;
    if (capacity > maximum_output) capacity = maximum_output;
    buffer = (unsigned char*)malloc(capacity + 1);
    if (buffer == NULL) return -1;

    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef*)compressed;
    stream.avail_in = (uInt)compressed_length;
    stream.next_out = buffer;
    stream.avail_out = (uInt)capacity;
    zresult = inflateInit2(&stream, -MAX_WBITS);
    if (zresult != Z_OK) {
        free(buffer);
        return -1;
    }
    zresult = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    if (zresult != Z_STREAM_END) {
        free(buffer);
        return -1;
    }
    buffer[stream.total_out] = '\0';
    *output = buffer;
    *output_length = stream.total_out;
    return 0;
}

static unsigned long long count_xml_text(const unsigned char* xml, size_t length)
{
    size_t i;
    int inside_tag = 0;
    unsigned long long count = 0;
    for (i = 0; i < length; i++) {
        unsigned char ch = xml[i];
        if (ch == '<') {
            inside_tag = 1;
            continue;
        }
        if (ch == '>') {
            inside_tag = 0;
            continue;
        }
        if (!inside_tag && ch != '\r' && ch != '\n' && ch != '\t') count++;
    }
    return count;
}

static unsigned long long count_plain_text(const unsigned char* data, size_t length)
{
    size_t i;
    unsigned long long count = 0;
    for (i = 0; i < length; i++) {
        unsigned char ch = data[i];
        if (ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 0x20 && ch != 0x7f) || ch >= 0x80) count++;
    }
    return count;
}

static int zip_entry_is_text(const char* name)
{
    static const char* extensions[] = {
        ".txt", ".csv", ".json", ".xml", ".md", ".log", ".yaml", ".yml", ".html", ".htm"
    };
    size_t i;
    for (i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (ends_with_ignore_case(name, extensions[i])) return 1;
    }
    return 0;
}

static int docx_entry_is_text(const char* name)
{
    return _stricmp(name, "word/document.xml") == 0 ||
        (_strnicmp(name, "word/header", 11) == 0 && ends_with_ignore_case(name, ".xml")) ||
        (_strnicmp(name, "word/footer", 11) == 0 && ends_with_ignore_case(name, ".xml")) ||
        _stricmp(name, "word/footnotes.xml") == 0 ||
        _stricmp(name, "word/endnotes.xml") == 0 ||
        _stricmp(name, "word/comments.xml") == 0;
}

static int analyze_zip(
    const unsigned char* data,
    size_t length,
    int is_docx,
    file_analysis_result_t* result
)
{
    size_t search_start;
    size_t eocd = (size_t)-1;
    unsigned int central_offset;
    unsigned short declared_entries;
    size_t cursor;
    unsigned int index;
    unsigned long long total_uncompressed = 0;
    int document_xml_found = 0;

    if (length < 22) return -1;
    search_start = length > 65557 ? length - 65557 : 0;
    for (cursor = length - 22;; cursor--) {
        if (read_u32_le(data + cursor) == 0x06054b50U) {
            eocd = cursor;
            break;
        }
        if (cursor == search_start) break;
    }
    if (eocd == (size_t)-1 || eocd + 22 > length) return -1;
    declared_entries = read_u16_le(data + eocd + 10);
    central_offset = read_u32_le(data + eocd + 16);
    if (declared_entries > FILE_ANALYZER_MAX_ARCHIVE_ENTRIES || central_offset >= length) {
        strcpy_s(result->reason, sizeof(result->reason), "archive entry limit exceeded");
        result->action = FILE_ANALYSIS_BLOCK;
        return 0;
    }

    cursor = central_offset;
    for (index = 0; index < declared_entries; index++) {
        unsigned short flags;
        unsigned short method;
        unsigned int compressed_size;
        unsigned int uncompressed_size;
        unsigned short name_length;
        unsigned short extra_length;
        unsigned short comment_length;
        unsigned int local_offset;
        char name[512];
        size_t copy_length;
        int should_extract;

        if (cursor + 46 > length || read_u32_le(data + cursor) != 0x02014b50U) return -1;
        flags = read_u16_le(data + cursor + 8);
        method = read_u16_le(data + cursor + 10);
        compressed_size = read_u32_le(data + cursor + 20);
        uncompressed_size = read_u32_le(data + cursor + 24);
        name_length = read_u16_le(data + cursor + 28);
        extra_length = read_u16_le(data + cursor + 30);
        comment_length = read_u16_le(data + cursor + 32);
        local_offset = read_u32_le(data + cursor + 42);
        if (cursor + 46ULL + name_length + extra_length + comment_length > length) return -1;

        copy_length = name_length < sizeof(name) - 1 ? name_length : sizeof(name) - 1;
        memcpy(name, data + cursor + 46, copy_length);
        name[copy_length] = '\0';
        result->archive_entries++;
        total_uncompressed += uncompressed_size;

        if ((flags & 1) != 0) {
            result->action = FILE_ANALYSIS_BLOCK;
            strcpy_s(result->reason, sizeof(result->reason), "encrypted archive entry cannot be inspected");
            return 0;
        }
        if (archive_path_is_unsafe(name)) {
            result->action = FILE_ANALYSIS_BLOCK;
            strcpy_s(result->reason, sizeof(result->reason), "unsafe archive path");
            return 0;
        }
        if (filename_has_dangerous_extension(name)) {
            result->action = FILE_ANALYSIS_BLOCK;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "dangerous file inside archive: %s", name);
            return 0;
        }
        if (total_uncompressed > FILE_ANALYZER_MAX_TOTAL_UNCOMPRESSED ||
            (compressed_size > 0 && uncompressed_size > 10U * 1024U * 1024U &&
             (unsigned long long)uncompressed_size > (unsigned long long)compressed_size * 1000ULL)) {
            result->action = FILE_ANALYSIS_BLOCK;
            strcpy_s(result->reason, sizeof(result->reason), "archive expansion limit exceeded");
            return 0;
        }

        should_extract = is_docx ? docx_entry_is_text(name) : zip_entry_is_text(name);
        if (is_docx && _stricmp(name, "word/document.xml") == 0) document_xml_found = 1;
        if (should_extract && uncompressed_size <= FILE_ANALYZER_MAX_ENTRY_OUTPUT) {
            unsigned short local_name_length;
            unsigned short local_extra_length;
            size_t payload_offset;
            unsigned char* extracted = NULL;
            size_t extracted_length = 0;

            if ((size_t)local_offset + 30 > length || read_u32_le(data + local_offset) != 0x04034b50U) return -1;
            local_name_length = read_u16_le(data + local_offset + 26);
            local_extra_length = read_u16_le(data + local_offset + 28);
            payload_offset = (size_t)local_offset + 30 + local_name_length + local_extra_length;
            if (payload_offset + compressed_size > length) return -1;

            if (method == 0) {
                extracted = (unsigned char*)malloc(compressed_size + 1);
                if (extracted == NULL) return -1;
                memcpy(extracted, data + payload_offset, compressed_size);
                extracted[compressed_size] = '\0';
                extracted_length = compressed_size;
            }
            else if (method == 8) {
                if (inflate_buffer(data + payload_offset, compressed_size, uncompressed_size,
                    &extracted, &extracted_length, FILE_ANALYZER_MAX_ENTRY_OUTPUT) != 0) return -1;
            }

            if (extracted != NULL) {
                result->extracted_text_bytes += ends_with_ignore_case(name, ".xml")
                    ? count_xml_text(extracted, extracted_length)
                    : count_plain_text(extracted, extracted_length);
                free(extracted);
            }
        }

        cursor += 46ULL + name_length + extra_length + comment_length;
    }

    if (is_docx && !document_xml_found) return -1;
    result->extraction_complete = 1;
    strcpy_s(result->reason, sizeof(result->reason), is_docx ? "DOCX content extracted" : "ZIP content inspected");
    return 0;
}

static int bytes_contain(const unsigned char* data, size_t length, const char* token)
{
    size_t token_length;
    size_t i;
    if (data == NULL || token == NULL) return 0;
    token_length = strlen(token);
    if (token_length == 0 || token_length > length) return 0;
    for (i = 0; i + token_length <= length; i++) {
        if (memcmp(data + i, token, token_length) == 0) return 1;
    }
    return 0;
}

static unsigned long long count_pdf_literal_text(const unsigned char* data, size_t length)
{
    size_t i;
    unsigned long long count = 0;
    int depth = 0;
    int escaped = 0;
    for (i = 0; i < length; i++) {
        unsigned char ch = data[i];
        if (depth == 0) {
            if (ch == '(') depth = 1;
            continue;
        }
        if (escaped) {
            escaped = 0;
            count++;
            continue;
        }
        if (ch == '\\') {
            escaped = 1;
            continue;
        }
        if (ch == '(') {
            depth++;
            continue;
        }
        if (ch == ')') {
            depth--;
            continue;
        }
        if (ch >= 0x20 || ch >= 0x80) count++;
    }
    return count;
}

static int inflate_pdf_stream(
    const unsigned char* compressed,
    size_t compressed_length,
    unsigned char** output,
    size_t* output_length
)
{
    z_stream stream;
    unsigned char* buffer;
    int zresult;
    size_t capacity = FILE_ANALYZER_MAX_PDF_STREAM_OUTPUT;

    buffer = (unsigned char*)malloc(capacity + 1);
    if (buffer == NULL) return -1;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef*)compressed;
    stream.avail_in = (uInt)compressed_length;
    stream.next_out = buffer;
    stream.avail_out = (uInt)capacity;
    zresult = inflateInit(&stream);
    if (zresult != Z_OK) {
        free(buffer);
        return -1;
    }
    zresult = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    if (zresult != Z_STREAM_END) {
        free(buffer);
        return -1;
    }
    buffer[stream.total_out] = '\0';
    *output = buffer;
    *output_length = stream.total_out;
    return 0;
}

static int analyze_pdf(const unsigned char* data, size_t length, file_analysis_result_t* result)
{
    size_t cursor = 0;
    if (bytes_contain(data, length, "/JavaScript") || bytes_contain(data, length, "/Launch") ||
        bytes_contain(data, length, "/EmbeddedFile")) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "active or embedded PDF content blocked");
        return 0;
    }

    result->extracted_text_bytes += count_pdf_literal_text(data, length);
    while (cursor + 6 < length) {
        size_t stream_pos;
        size_t data_start;
        size_t end_pos;
        size_t end_marker_pos;
        size_t dictionary_start;
        int flate = 0;
        for (stream_pos = cursor; stream_pos + 6 < length; stream_pos++) {
            if (memcmp(data + stream_pos, "stream", 6) == 0) break;
        }
        if (stream_pos + 6 >= length) break;
        dictionary_start = stream_pos > 2048 ? stream_pos - 2048 : 0;
        flate = bytes_contain(data + dictionary_start, stream_pos - dictionary_start, "/FlateDecode");
        data_start = stream_pos + 6;
        if (data_start < length && data[data_start] == '\r') data_start++;
        if (data_start < length && data[data_start] == '\n') data_start++;
        for (end_pos = data_start; end_pos + 9 <= length; end_pos++) {
            if (memcmp(data + end_pos, "endstream", 9) == 0) break;
        }
        if (end_pos + 9 > length) break;
        end_marker_pos = end_pos;
        while (end_pos > data_start && (data[end_pos - 1] == '\r' || data[end_pos - 1] == '\n')) end_pos--;
        if (flate && end_pos > data_start) {
            unsigned char* extracted = NULL;
            size_t extracted_length = 0;
            if (inflate_pdf_stream(data + data_start, end_pos - data_start, &extracted, &extracted_length) == 0) {
                result->extracted_text_bytes += count_pdf_literal_text(extracted, extracted_length);
                free(extracted);
            }
        }
        cursor = end_marker_pos + 9;
    }
    result->extraction_complete = 1;
    strcpy_s(result->reason, sizeof(result->reason), "PDF content streams inspected");
    return 0;
}

int file_analyzer_inspect(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
)
{
    int looks_zip;
    int looks_pdf;
    int declared_docx;
    int declared_zip;
    int declared_pdf;

    if (result == NULL || data == NULL || length == 0) return -1;
    memset(result, 0, sizeof(*result));
    result->action = FILE_ANALYSIS_ALLOW;
    strcpy_s(result->format, sizeof(result->format), "BINARY");
    strcpy_s(result->reason, sizeof(result->reason), "file type allowed");
    calculate_sha256(data, length, result->sha256);

    if (filename_has_dangerous_extension(filename) || (length >= 2 && data[0] == 'M' && data[1] == 'Z')) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "dangerous executable or script file");
        return 0;
    }

    looks_zip = length >= 4 && read_u32_le(data) == 0x04034b50U;
    looks_pdf = length >= 5 && memcmp(data, "%PDF-", 5) == 0;
    declared_docx = ends_with_ignore_case(filename, ".docx") ||
        contains_ignore_case(content_type, "wordprocessingml.document");
    declared_zip = ends_with_ignore_case(filename, ".zip") || contains_ignore_case(content_type, "application/zip");
    declared_pdf = ends_with_ignore_case(filename, ".pdf") || contains_ignore_case(content_type, "application/pdf");

    if ((declared_docx || declared_zip) && !looks_zip) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "ZIP/DOCX signature mismatch");
        return 0;
    }
    if (declared_pdf && !looks_pdf) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "PDF signature mismatch");
        return 0;
    }

    if (declared_docx) {
        strcpy_s(result->format, sizeof(result->format), "DOCX");
        if (analyze_zip(data, length, 1, result) != 0) {
            result->action = FILE_ANALYSIS_BLOCK;
            strcpy_s(result->reason, sizeof(result->reason), "malformed DOCX container");
        }
    }
    else if (declared_zip || looks_zip) {
        strcpy_s(result->format, sizeof(result->format), "ZIP");
        if (analyze_zip(data, length, 0, result) != 0) {
            result->action = FILE_ANALYSIS_BLOCK;
            strcpy_s(result->reason, sizeof(result->reason), "malformed ZIP container");
        }
    }
    else if (declared_pdf || looks_pdf) {
        strcpy_s(result->format, sizeof(result->format), "PDF");
        analyze_pdf(data, length, result);
    }
    else {
        result->extracted_text_bytes = count_plain_text(data, length);
        result->extraction_complete = 1;
    }
    return 0;
}
