#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <bcrypt.h>
#include <zlib.h>

#include "file_analyzer.h"
#include "windows_ocr.h"

#pragma comment(lib, "bcrypt.lib")

#define FILE_ANALYZER_MAX_ARCHIVE_ENTRIES 1024U
#define FILE_ANALYZER_MAX_TOTAL_UNCOMPRESSED (128ULL * 1024ULL * 1024ULL)
#define FILE_ANALYZER_MAX_ENTRY_OUTPUT (8U * 1024U * 1024U)
#define FILE_ANALYZER_MAX_PDF_STREAM_OUTPUT (8U * 1024U * 1024U)
#define FILE_ANALYZER_MIN_TEXT_RUN 4U
#define FILE_ANALYZER_MAX_CONTAINER_DEPTH 8U
#define FILE_ANALYZER_MAX_CUMULATIVE_ARCHIVE_ENTRIES 4096U

typedef enum analyzer_format_kind {
    ANALYZER_FORMAT_BINARY = 0,
    ANALYZER_FORMAT_DRM,
    ANALYZER_FORMAT_TEXT,
    ANALYZER_FORMAT_RTF,
    ANALYZER_FORMAT_EML,
    ANALYZER_FORMAT_PDF,
    ANALYZER_FORMAT_ZIP,
    ANALYZER_FORMAT_DOCX,
    ANALYZER_FORMAT_XLSX,
    ANALYZER_FORMAT_PPTX,
    ANALYZER_FORMAT_HWPX,
    ANALYZER_FORMAT_ODT,
    ANALYZER_FORMAT_ODS,
    ANALYZER_FORMAT_ODP,
    ANALYZER_FORMAT_HWP,
    ANALYZER_FORMAT_DOC,
    ANALYZER_FORMAT_XLS,
    ANALYZER_FORMAT_PPT,
    ANALYZER_FORMAT_MSG,
    ANALYZER_FORMAT_PNG,
    ANALYZER_FORMAT_JPEG,
    ANALYZER_FORMAT_GIF,
    ANALYZER_FORMAT_BMP,
    ANALYZER_FORMAT_TIFF,
    ANALYZER_FORMAT_RAR,
    ANALYZER_FORMAT_7Z,
    ANALYZER_FORMAT_GZIP,
    ANALYZER_FORMAT_TAR,
    ANALYZER_FORMAT_AUDIO,
    ANALYZER_FORMAT_VIDEO
} analyzer_format_kind_t;

typedef struct file_analyzer_context {
    unsigned int depth;
    unsigned int archive_entries;
    unsigned long long expanded_bytes;
} file_analyzer_context_t;

typedef struct zip_directory_info {
    size_t eocd_offset;
    size_t central_offset;
    size_t central_size;
    unsigned int entry_count;
} zip_directory_info_t;

static int file_analyzer_inspect_internal(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result,
    file_analyzer_context_t* context
);

static int file_analyzer_extract_text_internal(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    char** output,
    size_t* output_length,
    int* truncated,
    file_analyzer_context_t* context
);

static size_t read_extracted_text_limit(void);

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

static unsigned int read_u32_be(const unsigned char* value)
{
    return ((unsigned int)value[0] << 24) |
        ((unsigned int)value[1] << 16) |
        ((unsigned int)value[2] << 8) |
        (unsigned int)value[3];
}

static unsigned long long read_u64_le(const unsigned char* value)
{
    return (unsigned long long)read_u32_le(value) |
        ((unsigned long long)read_u32_le(value + 4) << 32);
}

static int file_analyzer_context_account_archive_entry(
    file_analyzer_context_t* context,
    unsigned long long expanded_bytes
)
{
    if (context == NULL ||
        context->archive_entries >= FILE_ANALYZER_MAX_CUMULATIVE_ARCHIVE_ENTRIES ||
        expanded_bytes > FILE_ANALYZER_MAX_TOTAL_UNCOMPRESSED - context->expanded_bytes) {
        return 0;
    }
    context->archive_entries++;
    context->expanded_bytes += expanded_bytes;
    return 1;
}

static int zip_directory_candidate_is_valid(
    const unsigned char* data,
    size_t length,
    size_t eocd_offset,
    zip_directory_info_t* info
)
{
    unsigned short disk_number;
    unsigned short central_disk;
    unsigned short disk_entries;
    unsigned short total_entries;
    unsigned short comment_length;
    unsigned int central_size_value;
    unsigned int central_offset_value;
    size_t central_end;
    size_t cursor;
    unsigned int index;
    size_t minimum_local_offset = (size_t)-1;

    if (data == NULL || info == NULL || eocd_offset > length ||
        length - eocd_offset < 22 || read_u32_le(data + eocd_offset) != 0x06054b50U) {
        return 0;
    }

    disk_number = read_u16_le(data + eocd_offset + 4);
    central_disk = read_u16_le(data + eocd_offset + 6);
    disk_entries = read_u16_le(data + eocd_offset + 8);
    total_entries = read_u16_le(data + eocd_offset + 10);
    central_size_value = read_u32_le(data + eocd_offset + 12);
    central_offset_value = read_u32_le(data + eocd_offset + 16);
    comment_length = read_u16_le(data + eocd_offset + 20);

    if (disk_number != 0 || central_disk != 0 || disk_entries != total_entries ||
        total_entries > FILE_ANALYZER_MAX_ARCHIVE_ENTRIES ||
        (size_t)comment_length != length - eocd_offset - 22) {
        return 0;
    }
    if ((unsigned long long)central_offset_value + central_size_value != eocd_offset) {
        return 0;
    }

    central_end = (size_t)central_offset_value + (size_t)central_size_value;
    cursor = central_offset_value;
    for (index = 0; index < total_entries; index++) {
        unsigned short flags;
        unsigned short method;
        unsigned int compressed_size;
        unsigned short name_length;
        unsigned short extra_length;
        unsigned short entry_comment_length;
        unsigned int local_offset;
        unsigned short local_flags;
        unsigned short local_method;
        unsigned short local_name_length;
        unsigned short local_extra_length;
        size_t central_record_length;
        size_t payload_offset;

        if (cursor > central_end || central_end - cursor < 46 ||
            read_u32_le(data + cursor) != 0x02014b50U) return 0;
        flags = read_u16_le(data + cursor + 8);
        method = read_u16_le(data + cursor + 10);
        compressed_size = read_u32_le(data + cursor + 20);
        name_length = read_u16_le(data + cursor + 28);
        extra_length = read_u16_le(data + cursor + 30);
        entry_comment_length = read_u16_le(data + cursor + 32);
        local_offset = read_u32_le(data + cursor + 42);
        central_record_length = 46ULL + name_length + extra_length + entry_comment_length;
        if (central_record_length > central_end - cursor || name_length == 0 ||
            name_length >= 512 || memchr(data + cursor + 46, '\0', name_length) != NULL) {
            return 0;
        }

        if ((size_t)local_offset > (size_t)central_offset_value ||
            (size_t)central_offset_value - (size_t)local_offset < 30 ||
            read_u32_le(data + local_offset) != 0x04034b50U) return 0;
        local_flags = read_u16_le(data + local_offset + 6);
        local_method = read_u16_le(data + local_offset + 8);
        local_name_length = read_u16_le(data + local_offset + 26);
        local_extra_length = read_u16_le(data + local_offset + 28);
        if (local_flags != flags || local_method != method || local_name_length != name_length ||
            (size_t)local_offset + 30ULL + local_name_length + local_extra_length > central_offset_value ||
            memcmp(data + local_offset + 30, data + cursor + 46, name_length) != 0) {
            return 0;
        }
        payload_offset = (size_t)local_offset + 30ULL + local_name_length + local_extra_length;
        if ((unsigned long long)payload_offset + compressed_size > central_offset_value) return 0;
        if ((size_t)local_offset < minimum_local_offset) minimum_local_offset = local_offset;
        cursor += central_record_length;
    }

    if (cursor != central_end ||
        (total_entries == 0 && central_offset_value != 0) ||
        (total_entries > 0 && minimum_local_offset != 0)) {
        return 0;
    }

    info->eocd_offset = eocd_offset;
    info->central_offset = central_offset_value;
    info->central_size = central_size_value;
    info->entry_count = total_entries;
    return 1;
}

static int zip_locate_directory(
    const unsigned char* data,
    size_t length,
    zip_directory_info_t* info
)
{
    size_t search_start;
    size_t cursor;
    unsigned int valid_candidates = 0;
    zip_directory_info_t candidate;

    if (data == NULL || info == NULL || length < 22) return -1;
    memset(info, 0, sizeof(*info));
    search_start = length > 65557 ? length - 65557 : 0;
    for (cursor = length - 22;; cursor--) {
        if (read_u32_le(data + cursor) == 0x06054b50U &&
            zip_directory_candidate_is_valid(data, length, cursor, &candidate)) {
            *info = candidate;
            valid_candidates++;
        }
        if (cursor == search_start) break;
    }
    return valid_candidates == 1 ? 0 : -1;
}

static int has_any_extension(const char* filename, const char* const* extensions, size_t count)
{
    size_t i;
    if (filename == NULL) return 0;
    for (i = 0; i < count; i++) {
        if (ends_with_ignore_case(filename, extensions[i])) return 1;
    }
    return 0;
}

static analyzer_format_kind_t format_from_filename(const char* filename)
{
    static const char* text_extensions[] = {
        ".txt", ".csv", ".tsv", ".json", ".xml", ".log", ".md", ".markdown",
        ".yaml", ".yml", ".ini", ".cfg", ".conf", ".properties", ".sql",
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".java", ".cs",
        ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".php", ".rb",
        ".swift", ".kt", ".kts", ".sh", ".bat", ".cmd", ".ps1", ".vbs"
    };
    if (has_any_extension(filename, text_extensions,
        sizeof(text_extensions) / sizeof(text_extensions[0]))) return ANALYZER_FORMAT_TEXT;
    if (ends_with_ignore_case(filename, ".rtf")) return ANALYZER_FORMAT_RTF;
    if (ends_with_ignore_case(filename, ".eml")) return ANALYZER_FORMAT_EML;
    if (ends_with_ignore_case(filename, ".pdf")) return ANALYZER_FORMAT_PDF;
    if (ends_with_ignore_case(filename, ".zip")) return ANALYZER_FORMAT_ZIP;
    if (ends_with_ignore_case(filename, ".docx") || ends_with_ignore_case(filename, ".docm")) return ANALYZER_FORMAT_DOCX;
    if (ends_with_ignore_case(filename, ".xlsx") || ends_with_ignore_case(filename, ".xlsm")) return ANALYZER_FORMAT_XLSX;
    if (ends_with_ignore_case(filename, ".pptx") || ends_with_ignore_case(filename, ".pptm")) return ANALYZER_FORMAT_PPTX;
    if (ends_with_ignore_case(filename, ".hwpx")) return ANALYZER_FORMAT_HWPX;
    if (ends_with_ignore_case(filename, ".odt")) return ANALYZER_FORMAT_ODT;
    if (ends_with_ignore_case(filename, ".ods")) return ANALYZER_FORMAT_ODS;
    if (ends_with_ignore_case(filename, ".odp")) return ANALYZER_FORMAT_ODP;
    if (ends_with_ignore_case(filename, ".hwp")) return ANALYZER_FORMAT_HWP;
    if (ends_with_ignore_case(filename, ".doc")) return ANALYZER_FORMAT_DOC;
    if (ends_with_ignore_case(filename, ".xls")) return ANALYZER_FORMAT_XLS;
    if (ends_with_ignore_case(filename, ".ppt")) return ANALYZER_FORMAT_PPT;
    if (ends_with_ignore_case(filename, ".msg")) return ANALYZER_FORMAT_MSG;
    if (ends_with_ignore_case(filename, ".png")) return ANALYZER_FORMAT_PNG;
    if (ends_with_ignore_case(filename, ".jpg") || ends_with_ignore_case(filename, ".jpeg") ||
        ends_with_ignore_case(filename, ".jpe")) return ANALYZER_FORMAT_JPEG;
    if (ends_with_ignore_case(filename, ".gif")) return ANALYZER_FORMAT_GIF;
    if (ends_with_ignore_case(filename, ".bmp") || ends_with_ignore_case(filename, ".dib")) return ANALYZER_FORMAT_BMP;
    if (ends_with_ignore_case(filename, ".tif") || ends_with_ignore_case(filename, ".tiff")) return ANALYZER_FORMAT_TIFF;
    if (ends_with_ignore_case(filename, ".rar")) return ANALYZER_FORMAT_RAR;
    if (ends_with_ignore_case(filename, ".7z")) return ANALYZER_FORMAT_7Z;
    if (ends_with_ignore_case(filename, ".gz") || ends_with_ignore_case(filename, ".gzip")) return ANALYZER_FORMAT_GZIP;
    if (ends_with_ignore_case(filename, ".tar")) return ANALYZER_FORMAT_TAR;
    if (ends_with_ignore_case(filename, ".mp3") || ends_with_ignore_case(filename, ".wav") ||
        ends_with_ignore_case(filename, ".flac") || ends_with_ignore_case(filename, ".m4a") ||
        ends_with_ignore_case(filename, ".aac") || ends_with_ignore_case(filename, ".ogg") ||
        ends_with_ignore_case(filename, ".opus") || ends_with_ignore_case(filename, ".wma")) return ANALYZER_FORMAT_AUDIO;
    if (ends_with_ignore_case(filename, ".mp4") || ends_with_ignore_case(filename, ".mov") ||
        ends_with_ignore_case(filename, ".avi") || ends_with_ignore_case(filename, ".mkv") ||
        ends_with_ignore_case(filename, ".webm") || ends_with_ignore_case(filename, ".wmv") ||
        ends_with_ignore_case(filename, ".mpeg") || ends_with_ignore_case(filename, ".mpg")) return ANALYZER_FORMAT_VIDEO;
    return ANALYZER_FORMAT_BINARY;
}

static analyzer_format_kind_t format_from_content_type(const char* content_type)
{
    if (content_type == NULL || content_type[0] == '\0') return ANALYZER_FORMAT_BINARY;
    if (contains_ignore_case(content_type, "wordprocessingml") ||
        contains_ignore_case(content_type, "ms-word.document.macroenabled")) return ANALYZER_FORMAT_DOCX;
    if (contains_ignore_case(content_type, "spreadsheetml") ||
        contains_ignore_case(content_type, "ms-excel.sheet.macroenabled")) return ANALYZER_FORMAT_XLSX;
    if (contains_ignore_case(content_type, "presentationml") ||
        contains_ignore_case(content_type, "ms-powerpoint.presentation.macroenabled")) return ANALYZER_FORMAT_PPTX;
    if (contains_ignore_case(content_type, "haansoft-hwpx") ||
        contains_ignore_case(content_type, "vnd.hancom.hwpx") ||
        contains_ignore_case(content_type, "hwp+zip")) return ANALYZER_FORMAT_HWPX;
    if (contains_ignore_case(content_type, "x-hwp") || contains_ignore_case(content_type, "haansoft-hwp") ||
        contains_ignore_case(content_type, "haansofthwp") ||
        contains_ignore_case(content_type, "vnd.hancom.hwp")) return ANALYZER_FORMAT_HWP;
    if (contains_ignore_case(content_type, "msword")) return ANALYZER_FORMAT_DOC;
    if (contains_ignore_case(content_type, "ms-excel")) return ANALYZER_FORMAT_XLS;
    if (contains_ignore_case(content_type, "ms-powerpoint")) return ANALYZER_FORMAT_PPT;
    if (contains_ignore_case(content_type, "vnd.ms-outlook")) return ANALYZER_FORMAT_MSG;
    if (contains_ignore_case(content_type, "vnd.oasis.opendocument.text")) return ANALYZER_FORMAT_ODT;
    if (contains_ignore_case(content_type, "vnd.oasis.opendocument.spreadsheet")) return ANALYZER_FORMAT_ODS;
    if (contains_ignore_case(content_type, "vnd.oasis.opendocument.presentation")) return ANALYZER_FORMAT_ODP;
    if (contains_ignore_case(content_type, "application/pdf")) return ANALYZER_FORMAT_PDF;
    if (contains_ignore_case(content_type, "application/rtf") || contains_ignore_case(content_type, "text/rtf")) return ANALYZER_FORMAT_RTF;
    if (contains_ignore_case(content_type, "message/rfc822")) return ANALYZER_FORMAT_EML;
    if (contains_ignore_case(content_type, "application/zip")) return ANALYZER_FORMAT_ZIP;
    if (contains_ignore_case(content_type, "application/x-rar") || contains_ignore_case(content_type, "application/vnd.rar")) return ANALYZER_FORMAT_RAR;
    if (contains_ignore_case(content_type, "application/x-7z")) return ANALYZER_FORMAT_7Z;
    if (contains_ignore_case(content_type, "application/gzip") || contains_ignore_case(content_type, "application/x-gzip")) return ANALYZER_FORMAT_GZIP;
    if (contains_ignore_case(content_type, "application/x-tar")) return ANALYZER_FORMAT_TAR;
    if (contains_ignore_case(content_type, "image/png")) return ANALYZER_FORMAT_PNG;
    if (contains_ignore_case(content_type, "image/jpeg")) return ANALYZER_FORMAT_JPEG;
    if (contains_ignore_case(content_type, "image/gif")) return ANALYZER_FORMAT_GIF;
    if (contains_ignore_case(content_type, "image/bmp")) return ANALYZER_FORMAT_BMP;
    if (contains_ignore_case(content_type, "image/tiff")) return ANALYZER_FORMAT_TIFF;
    if (contains_ignore_case(content_type, "audio/")) return ANALYZER_FORMAT_AUDIO;
    if (contains_ignore_case(content_type, "video/")) return ANALYZER_FORMAT_VIDEO;
    if (contains_ignore_case(content_type, "text/") || contains_ignore_case(content_type, "application/json") ||
        contains_ignore_case(content_type, "application/xml") || contains_ignore_case(content_type, "yaml")) return ANALYZER_FORMAT_TEXT;
    return ANALYZER_FORMAT_BINARY;
}

static int looks_like_ole(const unsigned char* data, size_t length)
{
    static const unsigned char signature[] = { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 };
    return length >= sizeof(signature) && memcmp(data, signature, sizeof(signature)) == 0;
}

static analyzer_format_kind_t format_from_magic(const unsigned char* data, size_t length)
{
    if (data == NULL) return ANALYZER_FORMAT_BINARY;
    if (length >= 9 && data[0] == 0x9b && memcmp(data + 1, " DRMONE", 7) == 0) return ANALYZER_FORMAT_DRM;
    if (length >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) return ANALYZER_FORMAT_PNG;
    if (length >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff) return ANALYZER_FORMAT_JPEG;
    if (length >= 6 && (memcmp(data, "GIF87a", 6) == 0 || memcmp(data, "GIF89a", 6) == 0)) return ANALYZER_FORMAT_GIF;
    if (length >= 2 && data[0] == 'B' && data[1] == 'M') return ANALYZER_FORMAT_BMP;
    if (length >= 4 && ((memcmp(data, "II\x2a\0", 4) == 0) || (memcmp(data, "MM\0\x2a", 4) == 0) ||
        (memcmp(data, "II\x2b\0", 4) == 0) || (memcmp(data, "MM\0\x2b", 4) == 0))) return ANALYZER_FORMAT_TIFF;
    if (length >= 5 && memcmp(data, "%PDF-", 5) == 0) return ANALYZER_FORMAT_PDF;
    if (length >= 4 && (read_u32_le(data) == 0x04034b50U || read_u32_le(data) == 0x06054b50U ||
        read_u32_le(data) == 0x08074b50U)) return ANALYZER_FORMAT_ZIP;
    if (looks_like_ole(data, length)) return ANALYZER_FORMAT_MSG; /* generic CFB/OLE; declaration resolves subtype */
    if (length >= 7 && memcmp(data, "Rar!\x1a\x07", 6) == 0) return ANALYZER_FORMAT_RAR;
    if (length >= 6 && memcmp(data, "7z\xbc\xaf\x27\x1c", 6) == 0) return ANALYZER_FORMAT_7Z;
    if (length >= 2 && data[0] == 0x1f && data[1] == 0x8b) return ANALYZER_FORMAT_GZIP;
    if (length >= 262 && memcmp(data + 257, "ustar", 5) == 0) return ANALYZER_FORMAT_TAR;
    if (length >= 5 && memcmp(data, "{\\rtf", 5) == 0) return ANALYZER_FORMAT_RTF;
    if (length >= 12 && memcmp(data, "RIFF", 4) == 0 && memcmp(data + 8, "WAVE", 4) == 0) return ANALYZER_FORMAT_AUDIO;
    if (length >= 4 && (memcmp(data, "fLaC", 4) == 0 || memcmp(data, "OggS", 4) == 0 ||
        memcmp(data, "ID3", 3) == 0)) return ANALYZER_FORMAT_AUDIO;
    if (length >= 12 && memcmp(data, "RIFF", 4) == 0 && memcmp(data + 8, "AVI ", 4) == 0) return ANALYZER_FORMAT_VIDEO;
    if (length >= 12 && memcmp(data + 4, "ftyp", 4) == 0) return ANALYZER_FORMAT_VIDEO;
    if (length >= 4 && data[0] == 0x1a && data[1] == 0x45 && data[2] == 0xdf && data[3] == 0xa3) return ANALYZER_FORMAT_VIDEO;
    return ANALYZER_FORMAT_BINARY;
}

static const char* format_name(analyzer_format_kind_t kind)
{
    switch (kind) {
    case ANALYZER_FORMAT_DRM: return "DRM-PROTECTED";
    case ANALYZER_FORMAT_TEXT: return "TEXT";
    case ANALYZER_FORMAT_RTF: return "RTF";
    case ANALYZER_FORMAT_EML: return "EML";
    case ANALYZER_FORMAT_PDF: return "PDF";
    case ANALYZER_FORMAT_ZIP: return "ZIP";
    case ANALYZER_FORMAT_DOCX: return "DOCX/DOCM";
    case ANALYZER_FORMAT_XLSX: return "XLSX/XLSM";
    case ANALYZER_FORMAT_PPTX: return "PPTX/PPTM";
    case ANALYZER_FORMAT_HWPX: return "HWPX";
    case ANALYZER_FORMAT_ODT: return "ODT";
    case ANALYZER_FORMAT_ODS: return "ODS";
    case ANALYZER_FORMAT_ODP: return "ODP";
    case ANALYZER_FORMAT_HWP: return "HWP";
    case ANALYZER_FORMAT_DOC: return "DOC";
    case ANALYZER_FORMAT_XLS: return "XLS";
    case ANALYZER_FORMAT_PPT: return "PPT";
    case ANALYZER_FORMAT_MSG: return "MSG/OLE";
    case ANALYZER_FORMAT_PNG: return "PNG";
    case ANALYZER_FORMAT_JPEG: return "JPEG";
    case ANALYZER_FORMAT_GIF: return "GIF";
    case ANALYZER_FORMAT_BMP: return "BMP";
    case ANALYZER_FORMAT_TIFF: return "TIFF";
    case ANALYZER_FORMAT_RAR: return "RAR";
    case ANALYZER_FORMAT_7Z: return "7Z";
    case ANALYZER_FORMAT_GZIP: return "GZIP";
    case ANALYZER_FORMAT_TAR: return "TAR";
    case ANALYZER_FORMAT_AUDIO: return "AUDIO";
    case ANALYZER_FORMAT_VIDEO: return "VIDEO";
    default: return "BINARY";
    }
}

static const char* normalized_mime_for_format(analyzer_format_kind_t kind)
{
    switch (kind) {
    case ANALYZER_FORMAT_DRM: return "application/x-fasoo-drm";
    case ANALYZER_FORMAT_TEXT: return "text/plain";
    case ANALYZER_FORMAT_RTF: return "application/rtf";
    case ANALYZER_FORMAT_EML: return "message/rfc822";
    case ANALYZER_FORMAT_PDF: return "application/pdf";
    case ANALYZER_FORMAT_ZIP: return "application/zip";
    case ANALYZER_FORMAT_DOCX: return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case ANALYZER_FORMAT_XLSX: return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case ANALYZER_FORMAT_PPTX: return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    case ANALYZER_FORMAT_HWPX: return "application/vnd.hancom.hwpx";
    case ANALYZER_FORMAT_ODT: return "application/vnd.oasis.opendocument.text";
    case ANALYZER_FORMAT_ODS: return "application/vnd.oasis.opendocument.spreadsheet";
    case ANALYZER_FORMAT_ODP: return "application/vnd.oasis.opendocument.presentation";
    case ANALYZER_FORMAT_HWP: return "application/x-hwp";
    case ANALYZER_FORMAT_DOC: return "application/msword";
    case ANALYZER_FORMAT_XLS: return "application/vnd.ms-excel";
    case ANALYZER_FORMAT_PPT: return "application/vnd.ms-powerpoint";
    case ANALYZER_FORMAT_MSG: return "application/vnd.ms-outlook";
    case ANALYZER_FORMAT_PNG: return "image/png";
    case ANALYZER_FORMAT_JPEG: return "image/jpeg";
    case ANALYZER_FORMAT_GIF: return "image/gif";
    case ANALYZER_FORMAT_BMP: return "image/bmp";
    case ANALYZER_FORMAT_TIFF: return "image/tiff";
    case ANALYZER_FORMAT_RAR: return "application/vnd.rar";
    case ANALYZER_FORMAT_7Z: return "application/x-7z-compressed";
    case ANALYZER_FORMAT_GZIP: return "application/gzip";
    case ANALYZER_FORMAT_TAR: return "application/x-tar";
    case ANALYZER_FORMAT_AUDIO: return "audio/*";
    case ANALYZER_FORMAT_VIDEO: return "video/*";
    default: return "application/octet-stream";
    }
}

static int format_is_zip_container(analyzer_format_kind_t kind)
{
    return kind == ANALYZER_FORMAT_ZIP || kind == ANALYZER_FORMAT_DOCX ||
        kind == ANALYZER_FORMAT_XLSX || kind == ANALYZER_FORMAT_PPTX ||
        kind == ANALYZER_FORMAT_HWPX || kind == ANALYZER_FORMAT_ODT ||
        kind == ANALYZER_FORMAT_ODS || kind == ANALYZER_FORMAT_ODP;
}

static int format_is_ole_document(analyzer_format_kind_t kind)
{
    return kind == ANALYZER_FORMAT_HWP || kind == ANALYZER_FORMAT_DOC ||
        kind == ANALYZER_FORMAT_XLS || kind == ANALYZER_FORMAT_PPT || kind == ANALYZER_FORMAT_MSG;
}

static int format_is_image(analyzer_format_kind_t kind)
{
    return kind == ANALYZER_FORMAT_PNG || kind == ANALYZER_FORMAT_JPEG ||
        kind == ANALYZER_FORMAT_GIF || kind == ANALYZER_FORMAT_BMP || kind == ANALYZER_FORMAT_TIFF;
}

static int content_type_is_dangerous(const char* content_type)
{
    static const char* types[] = {
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-bat",
        "application/x-cmd",
        "application/x-powershell",
        "text/x-shellscript",
        "text/x-bat"
    };
    size_t i;
    if (content_type == NULL) return 0;
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        if (contains_ignore_case(content_type, types[i])) return 1;
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
        ".txt", ".csv", ".tsv", ".json", ".xml", ".md", ".log", ".yaml", ".yml",
        ".html", ".htm", ".sql", ".c", ".cpp", ".h", ".java", ".cs", ".py", ".eml", ".rtf"
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

static int zip_entry_is_selected(analyzer_format_kind_t kind, const char* name)
{
    if (name == NULL) return 0;
    /* Inspect package metadata, custom XML, alternate text payloads, and the
     * format-specific primary parts.  Restricting OOXML to document.xml alone
     * misses content controls, comments/drawings, and custom XML data. */
    if (kind != ANALYZER_FORMAT_ZIP &&
        (ends_with_ignore_case(name, ".xml") || zip_entry_is_text(name))) return 1;
    switch (kind) {
    case ANALYZER_FORMAT_DOCX:
        return docx_entry_is_text(name);
    case ANALYZER_FORMAT_XLSX:
        return _stricmp(name, "xl/sharedStrings.xml") == 0 ||
            _stricmp(name, "xl/workbook.xml") == 0 ||
            (_strnicmp(name, "xl/worksheets/", 14) == 0 && ends_with_ignore_case(name, ".xml")) ||
            (_strnicmp(name, "xl/comments", 11) == 0 && ends_with_ignore_case(name, ".xml"));
    case ANALYZER_FORMAT_PPTX:
        return (_strnicmp(name, "ppt/slides/slide", 16) == 0 && ends_with_ignore_case(name, ".xml")) ||
            (_strnicmp(name, "ppt/notesSlides/notesSlide", 25) == 0 && ends_with_ignore_case(name, ".xml")) ||
            (_strnicmp(name, "ppt/comments/", 13) == 0 && ends_with_ignore_case(name, ".xml"));
    case ANALYZER_FORMAT_HWPX:
        return (_strnicmp(name, "Contents/section", 16) == 0 && ends_with_ignore_case(name, ".xml")) ||
            _stricmp(name, "Contents/header.xml") == 0 ||
            _stricmp(name, "Preview/PrvText.txt") == 0;
    case ANALYZER_FORMAT_ODT:
    case ANALYZER_FORMAT_ODS:
    case ANALYZER_FORMAT_ODP:
        return _stricmp(name, "content.xml") == 0 || _stricmp(name, "meta.xml") == 0;
    default:
        return zip_entry_is_text(name);
    }
}

static int archive_entry_is_embedded_payload(const char* name)
{
    if (name == NULL) return 0;
    return contains_ignore_case(name, "/embeddings/") ||
        contains_ignore_case(name, "/bindata/") ||
        contains_ignore_case(name, "/objects/") ||
        contains_ignore_case(name, "/objectreplacements/") ||
        contains_ignore_case(name, "/pictures/") ||
        _strnicmp(name, "BinData/", 8) == 0 ||
        _strnicmp(name, "Pictures/", 9) == 0 ||
        _strnicmp(name, "Objects/", 8) == 0;
}

static int archive_entry_is_directory(const char* name)
{
    size_t length;
    if (name == NULL) return 0;
    length = strlen(name);
    return length > 0 && (name[length - 1] == '/' || name[length - 1] == '\\');
}

static int archive_entry_recursive_format(
    const char* name,
    analyzer_format_kind_t* nested_kind
)
{
    analyzer_format_kind_t kind = format_from_filename(name);
    switch (kind) {
    case ANALYZER_FORMAT_DOCX:
    case ANALYZER_FORMAT_XLSX:
    case ANALYZER_FORMAT_PPTX:
    case ANALYZER_FORMAT_HWPX:
    case ANALYZER_FORMAT_ODT:
    case ANALYZER_FORMAT_ODS:
    case ANALYZER_FORMAT_ODP:
    case ANALYZER_FORMAT_HWP:
    case ANALYZER_FORMAT_DOC:
    case ANALYZER_FORMAT_XLS:
    case ANALYZER_FORMAT_PPT:
    case ANALYZER_FORMAT_MSG:
    case ANALYZER_FORMAT_PDF:
    case ANALYZER_FORMAT_RTF:
    case ANALYZER_FORMAT_EML:
    case ANALYZER_FORMAT_PNG:
    case ANALYZER_FORMAT_JPEG:
    case ANALYZER_FORMAT_GIF:
    case ANALYZER_FORMAT_BMP:
    case ANALYZER_FORMAT_TIFF:
        if (nested_kind != NULL) *nested_kind = kind;
        return 1;
    default:
        return 0;
    }
}

static void update_zip_profile(
    analyzer_format_kind_t kind,
    const char* name,
    int* required_primary,
    int* macro_found
)
{
    if (kind == ANALYZER_FORMAT_DOCX && _stricmp(name, "word/document.xml") == 0) *required_primary = 1;
    else if (kind == ANALYZER_FORMAT_XLSX && _stricmp(name, "xl/workbook.xml") == 0) *required_primary = 1;
    else if (kind == ANALYZER_FORMAT_PPTX && _stricmp(name, "ppt/presentation.xml") == 0) *required_primary = 1;
    else if (kind == ANALYZER_FORMAT_HWPX &&
        _strnicmp(name, "Contents/section", 16) == 0 && ends_with_ignore_case(name, ".xml")) *required_primary = 1;
    else if ((kind == ANALYZER_FORMAT_ODT || kind == ANALYZER_FORMAT_ODS || kind == ANALYZER_FORMAT_ODP) &&
        _stricmp(name, "content.xml") == 0) *required_primary = 1;
    if (ends_with_ignore_case(name, "vbaProject.bin")) *macro_found = 1;
}

static int analyze_zip(
    const unsigned char* data,
    size_t length,
    analyzer_format_kind_t kind,
    file_analysis_result_t* result,
    file_analyzer_context_t* context
)
{
    zip_directory_info_t directory;
    size_t cursor;
    unsigned int index;
    unsigned long long total_uncompressed = 0;
    int required_primary = kind == ANALYZER_FORMAT_ZIP ? 1 : 0;
    int macro_found = 0;

    if (zip_locate_directory(data, length, &directory) != 0) return -1;

    cursor = directory.central_offset;
    for (index = 0; index < directory.entry_count; index++) {
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
        int should_recurse;
        analyzer_format_kind_t nested_kind = ANALYZER_FORMAT_BINARY;

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
        update_zip_profile(kind, name, &required_primary, &macro_found);

        if (!file_analyzer_context_account_archive_entry(context, uncompressed_size)) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->extraction_status = FILE_EXTRACTION_PARTIAL;
            strcpy_s(result->reason, sizeof(result->reason),
                "cumulative archive inspection budget exceeded");
            return 0;
        }

        if ((flags & 1) != 0) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->encrypted = 1;
            result->extraction_status = FILE_EXTRACTION_ENCRYPTED;
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

        should_extract = zip_entry_is_selected(kind, name);
        should_recurse = archive_entry_recursive_format(name, &nested_kind);
        if (kind != ANALYZER_FORMAT_ZIP && archive_entry_is_embedded_payload(name) &&
            !archive_entry_is_directory(name) && !should_extract && !should_recurse) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "embedded package payload cannot be fully inspected: %s", name);
            return 0;
        }
        if (kind == ANALYZER_FORMAT_ZIP && !archive_entry_is_directory(name) &&
            !should_extract && !should_recurse) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "archive entry cannot be fully inspected: %s", name);
            return 0;
        }
        if ((should_extract || should_recurse) &&
            uncompressed_size > FILE_ANALYZER_MAX_ENTRY_OUTPUT) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->extraction_status = FILE_EXTRACTION_PARTIAL;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "archive entry exceeds inspection limit: %s", name);
            return 0;
        }
        if (should_extract || should_recurse) {
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
                if (compressed_size != uncompressed_size) return -1;
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
            else {
                result->action = FILE_ANALYSIS_BLOCK;
                result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
                _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                    "unsupported ZIP compression method %u for %s", method, name);
                return 0;
            }

            if (extracted != NULL) {
                if (should_extract) {
                    result->extracted_text_bytes += ends_with_ignore_case(name, ".xml")
                        ? count_xml_text(extracted, extracted_length)
                        : count_plain_text(extracted, extracted_length);
                }
                else {
                    file_analysis_result_t nested_result;
                    if (context == NULL || context->depth >= FILE_ANALYZER_MAX_CONTAINER_DEPTH) {
                        result->action = FILE_ANALYSIS_BLOCK;
                        result->extraction_status = FILE_EXTRACTION_PARTIAL;
                        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                            "nested entry %s blocked: container depth limit exceeded", name);
                        free(extracted);
                        return 0;
                    }
                    context->depth++;
                    if (file_analyzer_inspect_internal(
                        name, normalized_mime_for_format(nested_kind),
                        extracted, extracted_length, &nested_result, context) != 0) {
                        context->depth--;
                        free(extracted);
                        return -1;
                    }
                    context->depth--;
                    if (nested_result.action == FILE_ANALYSIS_BLOCK ||
                        !nested_result.extraction_complete) {
                        result->action = FILE_ANALYSIS_BLOCK;
                        result->extraction_status = nested_result.extraction_status;
                        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                            "nested entry %s blocked: %s", name,
                            nested_result.reason[0] ? nested_result.reason : "incomplete inspection");
                        free(extracted);
                        return 0;
                    }
                    result->extracted_text_bytes += nested_result.extracted_text_bytes;
                }
                free(extracted);
            }
        }

        cursor += 46ULL + name_length + extra_length + comment_length;
    }

    if (cursor != directory.eocd_offset) return -1;

    if (!required_primary) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_MALFORMED;
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
            "%s container is missing its required content part", format_name(kind));
        return 0;
    }
    result->extraction_complete = 1;
    result->extraction_status = FILE_EXTRACTION_COMPLETE;
    if (macro_found) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "macro-enabled Office content blocked after text extraction");
    }
    else {
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
            "%s content inspected", format_name(kind));
    }
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
    char* ocr_text = NULL;
    size_t ocr_length = 0;
    int page_truncated = 0;
    char status[160];
    int ocr_result;

    if (bytes_contain(data, length, "/Encrypt")) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->encrypted = 1;
        result->extraction_status = FILE_EXTRACTION_ENCRYPTED;
        strcpy_s(result->reason, sizeof(result->reason), "encrypted PDF cannot be inspected");
        return 0;
    }
    if (bytes_contain(data, length, "/JavaScript") || bytes_contain(data, length, "/Launch") ||
        bytes_contain(data, length, "/EmbeddedFile")) {
        result->action = FILE_ANALYSIS_BLOCK;
        strcpy_s(result->reason, sizeof(result->reason), "active or embedded PDF content blocked");
        return 0;
    }

    /*
     * Treat the rendered page as the authoritative PDF content.  Parsing every
     * Flate stream as a text stream also consumes fonts and image resources;
     * that creates binary garbage and can produce false policy matches.  Page
     * OCR gives one path for both born-digital and scanned PDFs and describes
     * what a user can actually see.
     */
    status[0] = '\0';
    result->requires_ocr = 1;
    result->extraction_status = FILE_EXTRACTION_OCR_REQUIRED;
    ocr_result = windows_pdf_ocr_extract_utf8(
        data, length, 100, &ocr_text, &ocr_length, &page_truncated,
        status, sizeof(status));
    if (ocr_result == 1 && !page_truncated) {
        result->extracted_text_bytes = ocr_length;
        result->extraction_complete = 1;
        result->extraction_status = FILE_EXTRACTION_COMPLETE;
        result->requires_ocr = 0;
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
            "PDF rendered-page OCR completed (%llu UTF-8 bytes)",
            (unsigned long long)ocr_length);
    }
    else if (ocr_result == 1) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extracted_text_bytes = ocr_length;
        result->extraction_status = FILE_EXTRACTION_PARTIAL;
        strcpy_s(result->reason, sizeof(result->reason),
            "PDF OCR page or image dimension limit reached; blocked fail-closed");
    }
    else {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_PARTIAL;
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
            "PDF page OCR unavailable or failed; blocked fail-closed: %s",
            status[0] ? status : "unknown OCR error");
    }
    free(ocr_text);
    return 0;
}

static int bytes_contain_utf16le_ascii(
    const unsigned char* data,
    size_t length,
    const char* token
)
{
    size_t token_length;
    size_t start;
    if (data == NULL || token == NULL) return 0;
    token_length = strlen(token);
    if (token_length == 0 || token_length > length / 2) return 0;
    for (start = 0; start + token_length * 2 <= length; ++start) {
        size_t index;
        for (index = 0; index < token_length; ++index) {
            if (data[start + index * 2] != (unsigned char)token[index] ||
                data[start + index * 2 + 1] != 0) break;
        }
        if (index == token_length) return 1;
    }
    return 0;
}

static int analyze_ole_document(
    analyzer_format_kind_t kind,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
);

static int data_looks_probably_text(const unsigned char* data, size_t length)
{
    size_t i;
    size_t controls = 0;
    size_t examined = length > 65536 ? 65536 : length;
    size_t pairs;
    size_t even_zero = 0;
    size_t odd_zero = 0;
    if (length >= 4 && ((data[0] == 0xff && data[1] == 0xfe &&
        data[2] == 0 && data[3] == 0) ||
        (data[0] == 0 && data[1] == 0 &&
        data[2] == 0xfe && data[3] == 0xff))) return 1;
    if (length >= 2 && ((data[0] == 0xff && data[1] == 0xfe) ||
        (data[0] == 0xfe && data[1] == 0xff))) return 1;
    if (length >= 3 && memcmp(data, "\xef\xbb\xbf", 3) == 0) return 1;
    pairs = examined / 2;
    for (i = 0; i < pairs; ++i) {
        if (data[i * 2] == 0) even_zero++;
        if (data[i * 2 + 1] == 0) odd_zero++;
    }
    if (pairs >= 4 && ((odd_zero * 3 >= pairs && even_zero * 8 < pairs) ||
        (even_zero * 3 >= pairs && odd_zero * 8 < pairs))) return 1;
    for (i = 0; i < examined; i++) {
        unsigned char ch = data[i];
        if (ch == 0) return 0;
        if (ch < 0x20 && ch != '\r' && ch != '\n' && ch != '\t' && ch != '\f') controls++;
    }
    return examined == 0 || controls * 100 <= examined * 2;
}

static int signature_matches_declared(
    analyzer_format_kind_t declared,
    analyzer_format_kind_t magic
)
{
    if (declared == ANALYZER_FORMAT_BINARY || declared == ANALYZER_FORMAT_TEXT ||
        declared == ANALYZER_FORMAT_EML) return magic == ANALYZER_FORMAT_BINARY;
    if (format_is_zip_container(declared)) return magic == ANALYZER_FORMAT_ZIP;
    if (format_is_ole_document(declared)) return magic == ANALYZER_FORMAT_MSG;
    if ((declared == ANALYZER_FORMAT_AUDIO || declared == ANALYZER_FORMAT_VIDEO) &&
        (magic == ANALYZER_FORMAT_AUDIO || magic == ANALYZER_FORMAT_VIDEO)) return 1;
    return declared == magic;
}

static void set_format_result(file_analysis_result_t* result, analyzer_format_kind_t kind)
{
    strcpy_s(result->format, sizeof(result->format), format_name(kind));
    strcpy_s(result->normalized_mime, sizeof(result->normalized_mime), normalized_mime_for_format(kind));
}

static int analyze_image_with_ocr(
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
)
{
    char* text = NULL;
    size_t text_length = 0;
    char status[160];
    int ocr_result;
    status[0] = '\0';
    result->requires_ocr = 1;
    result->extraction_status = FILE_EXTRACTION_OCR_REQUIRED;
    ocr_result = windows_ocr_extract_utf8(data, length, &text, &text_length, status, sizeof(status));
    if (ocr_result == 1) {
        result->extracted_text_bytes = text_length;
        result->extraction_complete = 1;
        result->extraction_status = FILE_EXTRACTION_COMPLETE;
        result->requires_ocr = 0;
        _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
            "image decoded and OCR completed (%llu UTF-8 bytes)", (unsigned long long)text_length);
        free(text);
        return 0;
    }
    free(text);
    result->action = FILE_ANALYSIS_BLOCK; /* fail closed: unreadable image may contain a document */
    _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
        "image OCR unavailable or failed: %s", status[0] ? status : "unknown OCR error");
    return 0;
}

static int file_analyzer_inspect_internal(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result,
    file_analyzer_context_t* context
)
{
    analyzer_format_kind_t filename_kind;
    analyzer_format_kind_t mime_kind;
    analyzer_format_kind_t declared;
    analyzer_format_kind_t magic;
    analyzer_format_kind_t resolved;

    if (result == NULL || data == NULL || length == 0) return -1;
    memset(result, 0, sizeof(*result));
    result->action = FILE_ANALYSIS_ALLOW;
    result->signature_match = 1;
    result->extraction_status = FILE_EXTRACTION_NONE;
    calculate_sha256(data, length, result->sha256);

    filename_kind = format_from_filename(filename);
    mime_kind = format_from_content_type(content_type);
    declared = filename_kind != ANALYZER_FORMAT_BINARY ? filename_kind : mime_kind;
    magic = format_from_magic(data, length);
    resolved = declared != ANALYZER_FORMAT_BINARY ? declared : magic;
    set_format_result(result, resolved);

    if (filename_has_dangerous_extension(filename) || content_type_is_dangerous(content_type) ||
        (length >= 2 && data[0] == 'M' && data[1] == 'Z')) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
        strcpy_s(result->reason, sizeof(result->reason), "dangerous executable or script file");
        return 0;
    }

    if (magic == ANALYZER_FORMAT_DRM) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->encrypted = 1;
        result->signature_match = 1;
        result->extraction_status = FILE_EXTRACTION_ENCRYPTED;
        _snprintf_s(result->format, sizeof(result->format), _TRUNCATE,
            "DRM-%s", format_name(declared));
        strcpy_s(result->normalized_mime, sizeof(result->normalized_mime),
            normalized_mime_for_format(declared));
        strcpy_s(result->reason, sizeof(result->reason),
            "Fasoo DRM-protected file cannot be inspected outside the authorized decryptor");
        return 0;
    }

    /* Password-protected OOXML is a valid OLE compound wrapper containing
     * EncryptionInfo and EncryptedPackage streams, not a ZIP signature. */
    if ((declared == ANALYZER_FORMAT_DOCX || declared == ANALYZER_FORMAT_XLSX ||
         declared == ANALYZER_FORMAT_PPTX) && magic == ANALYZER_FORMAT_MSG &&
        bytes_contain_utf16le_ascii(data, length, "EncryptionInfo") &&
        bytes_contain_utf16le_ascii(data, length, "EncryptedPackage")) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->encrypted = 1;
        result->signature_match = 1;
        result->extraction_status = FILE_EXTRACTION_ENCRYPTED;
        strcpy_s(result->reason, sizeof(result->reason),
            "password-protected OOXML cannot be inspected without an authorized decryptor");
        return 0;
    }

    if (declared != ANALYZER_FORMAT_BINARY && !signature_matches_declared(declared, magic)) {
        /* Plain text and EML intentionally have no universal signature. */
        if (!((declared == ANALYZER_FORMAT_TEXT || declared == ANALYZER_FORMAT_EML) &&
            magic == ANALYZER_FORMAT_BINARY && data_looks_probably_text(data, length))) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->signature_match = 0;
            result->extraction_status = FILE_EXTRACTION_MALFORMED;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "%s signature mismatch (detected %s)", format_name(declared), format_name(magic));
            return 0;
        }
    }

    if (format_is_zip_container(resolved)) {
        if (analyze_zip(data, length, resolved, result, context) != 0) {
            result->action = FILE_ANALYSIS_BLOCK;
            result->extraction_status = FILE_EXTRACTION_MALFORMED;
            _snprintf_s(result->reason, sizeof(result->reason), _TRUNCATE,
                "malformed %s container", format_name(resolved));
        }
    }
    else if (resolved == ANALYZER_FORMAT_PDF) {
        analyze_pdf(data, length, result);
    }
    else if (format_is_ole_document(resolved)) {
        analyze_ole_document(resolved, data, length, result);
    }
    else if (format_is_image(resolved)) {
        analyze_image_with_ocr(data, length, result);
    }
    else if (resolved == ANALYZER_FORMAT_EML) {
        /* Raw RFC 822 text alone is not a complete inspection: MIME parts can
         * contain base64/quoted-printable attachments and nested messages. */
        result->action = FILE_ANALYSIS_BLOCK;
        result->extracted_text_bytes = count_plain_text(data, length);
        result->extraction_complete = 0;
        result->extraction_status = FILE_EXTRACTION_PARTIAL;
        strcpy_s(result->reason, sizeof(result->reason),
            "EML MIME attachments require a dedicated decoder; blocked fail-closed");
    }
    else if (resolved == ANALYZER_FORMAT_TEXT || resolved == ANALYZER_FORMAT_RTF) {
        result->extracted_text_bytes = count_plain_text(data, length);
        result->extraction_complete = 1;
        result->extraction_status = FILE_EXTRACTION_COMPLETE;
        strcpy_s(result->reason, sizeof(result->reason),
            resolved == ANALYZER_FORMAT_RTF ? "RTF text extraction available" :
            resolved == ANALYZER_FORMAT_EML ? "EML text body extraction available" : "plain text inspected");
    }
    else if (resolved == ANALYZER_FORMAT_RAR || resolved == ANALYZER_FORMAT_7Z ||
        resolved == ANALYZER_FORMAT_GZIP || resolved == ANALYZER_FORMAT_TAR) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
        strcpy_s(result->reason, sizeof(result->reason), "archive format requires a dedicated safe unpacker; blocked fail-closed");
    }
    else if (resolved == ANALYZER_FORMAT_AUDIO || resolved == ANALYZER_FORMAT_VIDEO) {
        result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
        strcpy_s(result->reason, sizeof(result->reason), "media original identified; speech transcription is not enabled");
    }
    else {
        result->extraction_status = FILE_EXTRACTION_UNSUPPORTED;
        strcpy_s(result->reason, sizeof(result->reason), "binary original identified; no safe content extractor available");
    }
    if (result->action != FILE_ANALYSIS_BLOCK && result->extraction_complete &&
        result->extracted_text_bytes >= read_extracted_text_limit()) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_complete = 0;
        result->extraction_status = FILE_EXTRACTION_PARTIAL;
        strcpy_s(result->reason, sizeof(result->reason),
            "extracted text reached the inspection limit; blocked fail-closed");
    }
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
    file_analyzer_context_t context;
    memset(&context, 0, sizeof(context));
    return file_analyzer_inspect_internal(
        filename, content_type, data, length, result, &context);
}

typedef struct extracted_text_builder {
    char* data;
    size_t length;
    size_t capacity;
    size_t maximum;
    int truncated;
} extracted_text_builder_t;

static size_t read_extracted_text_limit(void)
{
    const char* value = getenv("LOCAL_DLP_MAX_EXTRACTED_TEXT_BYTES");
    unsigned long long parsed;
    if (value == NULL || value[0] == '\0') return 16U * 1024U * 1024U;
    parsed = _strtoui64(value, NULL, 10);
    if (parsed < 4096ULL) parsed = 4096ULL;
    if (parsed > 64ULL * 1024ULL * 1024ULL) parsed = 64ULL * 1024ULL * 1024ULL;
    return (size_t)parsed;
}

static int extracted_text_reserve(extracted_text_builder_t* builder, size_t additional)
{
    size_t wanted;
    size_t capacity;
    char* resized;
    if (builder == NULL) return -1;
    if (additional > builder->maximum - builder->length) {
        builder->truncated = 1;
        additional = builder->maximum - builder->length;
    }
    wanted = builder->length + additional + 1;
    if (wanted <= builder->capacity) return 0;
    capacity = builder->capacity ? builder->capacity : 4096;
    while (capacity < wanted && capacity < builder->maximum + 1) {
        size_t next = capacity * 2;
        capacity = next > builder->maximum + 1 ? builder->maximum + 1 : next;
    }
    resized = (char*)realloc(builder->data, capacity);
    if (resized == NULL) return -1;
    builder->data = resized;
    builder->capacity = capacity;
    return 0;
}

static int extracted_text_append(extracted_text_builder_t* builder, const void* data, size_t length)
{
    size_t writable = length;
    if (builder == NULL || (data == NULL && length > 0)) return -1;
    if (writable > builder->maximum - builder->length) {
        writable = builder->maximum - builder->length;
        builder->truncated = 1;
    }
    if (extracted_text_reserve(builder, writable) != 0) return -1;
    if (writable > 0) memcpy(builder->data + builder->length, data, writable);
    builder->length += writable;
    builder->data[builder->length] = '\0';
    return 0;
}

static int extracted_text_append_cstr(extracted_text_builder_t* builder, const char* text)
{
    return extracted_text_append(builder, text, text != NULL ? strlen(text) : 0);
}

static int extracted_text_append_codepoint(extracted_text_builder_t* builder, unsigned int codepoint)
{
    unsigned char encoded[4];
    size_t encoded_length;
    if (codepoint <= 0x7f) {
        encoded[0] = (unsigned char)codepoint;
        encoded_length = 1;
    }
    else if (codepoint <= 0x7ff) {
        encoded[0] = (unsigned char)(0xc0 | (codepoint >> 6));
        encoded[1] = (unsigned char)(0x80 | (codepoint & 0x3f));
        encoded_length = 2;
    }
    else if (codepoint <= 0xffff) {
        encoded[0] = (unsigned char)(0xe0 | (codepoint >> 12));
        encoded[1] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3f));
        encoded[2] = (unsigned char)(0x80 | (codepoint & 0x3f));
        encoded_length = 3;
    }
    else if (codepoint <= 0x10ffff) {
        encoded[0] = (unsigned char)(0xf0 | (codepoint >> 18));
        encoded[1] = (unsigned char)(0x80 | ((codepoint >> 12) & 0x3f));
        encoded[2] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3f));
        encoded[3] = (unsigned char)(0x80 | (codepoint & 0x3f));
        encoded_length = 4;
    }
    else return 0;
    return extracted_text_append(builder, encoded, encoded_length);
}

static int extracted_text_append_utf16(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length,
    int big_endian
)
{
    size_t i;
    for (i = 0; i + 1 < length && builder->length < builder->maximum; i += 2) {
        unsigned int value = big_endian ? ((unsigned int)data[i] << 8) | data[i + 1] : read_u16_le(data + i);
        unsigned int codepoint = value;
        if (value >= 0xd800 && value <= 0xdbff && i + 3 < length) {
            unsigned int low = big_endian ? ((unsigned int)data[i + 2] << 8) | data[i + 3] : read_u16_le(data + i + 2);
            if (low >= 0xdc00 && low <= 0xdfff) {
                codepoint = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
                i += 2;
            }
        }
        if (codepoint == '\r') continue;
        if (codepoint == '\n' || codepoint == '\t' || codepoint >= 0x20)
            if (extracted_text_append_codepoint(builder, codepoint) != 0) return -1;
    }
    return 0;
}

static int extracted_text_append_utf32(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length,
    int big_endian
)
{
    size_t i;
    for (i = 0; i + 3 < length && builder->length < builder->maximum; i += 4) {
        unsigned int codepoint = big_endian
            ? read_u32_be(data + i)
            : read_u32_le(data + i);
        if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU))
            return -1;
        /* Ignore a duplicated BOM or an embedded NUL instead of allowing it
         * to terminate the C-string view used by keyword policy matching. */
        if (codepoint == 0U || codepoint == 0xfeffU) continue;
        if (codepoint == '\r') continue;
        if (codepoint == '\n' || codepoint == '\t' || codepoint >= 0x20)
            if (extracted_text_append_codepoint(builder, codepoint) != 0) return -1;
    }
    return 0;
}

static int extracted_text_append_filtered_utf8(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length
)
{
    size_t i;
    for (i = 0; i < length && builder->length < builder->maximum; ++i) {
        unsigned char ch = data[i];
        if (ch == '\r') continue;
        if (ch == '\n' || ch == '\t' || (ch >= 0x20 && ch != 0x7f) || ch >= 0x80) {
            if (extracted_text_append(builder, &ch, 1) != 0) return -1;
        }
    }
    return 0;
}

/* Return 1 when conversion succeeded, 0 for an invalid code page sequence,
 * and -1 for an allocation/output failure. */
static int extracted_text_append_code_page(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length,
    UINT code_page
)
{
    int wide_length;
    int utf8_length;
    wchar_t* wide = NULL;
    unsigned char* utf8 = NULL;
    int result = -1;
    if (length == 0) return 1;
    if (length > INT_MAX) return -1;
    wide_length = MultiByteToWideChar(
        code_page, MB_ERR_INVALID_CHARS, (const char*)data, (int)length, NULL, 0);
    if (wide_length <= 0) return 0;
    wide = (wchar_t*)malloc(((size_t)wide_length + 1) * sizeof(wchar_t));
    if (wide == NULL) return -1;
    if (MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, (const char*)data,
        (int)length, wide, wide_length) != wide_length) goto cleanup;
    utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
        wide_length, NULL, 0, NULL, NULL);
    if (utf8_length <= 0) goto cleanup;
    utf8 = (unsigned char*)malloc((size_t)utf8_length + 1);
    if (utf8 == NULL) goto cleanup;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, wide_length,
        (char*)utf8, utf8_length, NULL, NULL) != utf8_length) goto cleanup;
    utf8[utf8_length] = '\0';
    result = extracted_text_append_filtered_utf8(builder, utf8, (size_t)utf8_length) == 0 ? 1 : -1;

cleanup:
    free(utf8);
    free(wide);
    return result;
}

static int extracted_text_append_plain(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length
)
{
    int conversion;
    UINT active_code_page;
    size_t pairs;
    size_t index;
    size_t even_zero = 0;
    size_t odd_zero = 0;
    if (length >= 4 && data[0] == 0xff && data[1] == 0xfe &&
        data[2] == 0 && data[3] == 0)
        return extracted_text_append_utf32(builder, data + 4, length - 4, 0);
    if (length >= 4 && data[0] == 0 && data[1] == 0 &&
        data[2] == 0xfe && data[3] == 0xff)
        return extracted_text_append_utf32(builder, data + 4, length - 4, 1);
    if (length >= 2 && data[0] == 0xff && data[1] == 0xfe)
        return extracted_text_append_utf16(builder, data + 2, length - 2, 0);
    if (length >= 2 && data[0] == 0xfe && data[1] == 0xff)
        return extracted_text_append_utf16(builder, data + 2, length - 2, 1);
    if (length >= 3 && memcmp(data, "\xef\xbb\xbf", 3) == 0) {
        data += 3;
        length -= 3;
    }

    pairs = length / 2;
    for (index = 0; index < pairs && index < 32768; ++index) {
        if (data[index * 2] == 0) even_zero++;
        if (data[index * 2 + 1] == 0) odd_zero++;
    }
    if (index >= 4 && odd_zero * 3 >= index && even_zero * 8 < index)
        return extracted_text_append_utf16(builder, data, length, 0);
    if (index >= 4 && even_zero * 3 >= index && odd_zero * 8 < index)
        return extracted_text_append_utf16(builder, data, length, 1);

    conversion = extracted_text_append_code_page(builder, data, length, CP_UTF8);
    if (conversion != 0) return conversion > 0 ? 0 : -1;

    /* Korean Windows business documents commonly use CP949 without a BOM. */
    conversion = extracted_text_append_code_page(builder, data, length, 949);
    if (conversion != 0) return conversion > 0 ? 0 : -1;
    active_code_page = GetACP();
    if (active_code_page != 949 && active_code_page != CP_UTF8) {
        conversion = extracted_text_append_code_page(builder, data, length, active_code_page);
        if (conversion != 0) return conversion > 0 ? 0 : -1;
    }
    return extracted_text_append_filtered_utf8(builder, data, length);
}

static int xml_tag_is_paragraph_break(const char* tag)
{
    const char* name = tag;
    if (name == NULL) return 0;
    while (*name == ' ' || *name == '\t') name++;
    if (*name == '/') name++;
    return _strnicmp(name, "w:p", 3) == 0 || _strnicmp(name, "a:p", 3) == 0 ||
        _strnicmp(name, "text:p", 6) == 0 || _strnicmp(name, "text:h", 6) == 0 ||
        _strnicmp(name, "hp:p", 4) == 0 || _strnicmp(name, "hp:sec", 6) == 0 ||
        _strnicmp(name, "row", 3) == 0;
}

static size_t decode_xml_entity(const unsigned char* data, size_t length, unsigned int* codepoint)
{
    size_t i;
    unsigned int value = 0;
    int base = 10;
    if (length >= 5 && memcmp(data, "&amp;", 5) == 0) { *codepoint = '&'; return 5; }
    if (length >= 4 && memcmp(data, "&lt;", 4) == 0) { *codepoint = '<'; return 4; }
    if (length >= 4 && memcmp(data, "&gt;", 4) == 0) { *codepoint = '>'; return 4; }
    if (length >= 6 && memcmp(data, "&quot;", 6) == 0) { *codepoint = '"'; return 6; }
    if (length >= 6 && memcmp(data, "&apos;", 6) == 0) { *codepoint = '\''; return 6; }
    if (length < 4 || data[0] != '&' || data[1] != '#') return 0;
    i = 2;
    if (i < length && (data[i] == 'x' || data[i] == 'X')) { base = 16; i++; }
    for (; i < length && data[i] != ';' && i < 12; i++) {
        unsigned int digit;
        if (data[i] >= '0' && data[i] <= '9') digit = data[i] - '0';
        else if (base == 16 && data[i] >= 'a' && data[i] <= 'f') digit = data[i] - 'a' + 10;
        else if (base == 16 && data[i] >= 'A' && data[i] <= 'F') digit = data[i] - 'A' + 10;
        else return 0;
        value = value * (unsigned int)base + digit;
    }
    if (i >= length || data[i] != ';') return 0;
    *codepoint = value;
    return i + 1;
}

static int extracted_text_append_xml(
    extracted_text_builder_t* builder,
    const unsigned char* xml,
    size_t length
)
{
    size_t i = 0;
    int inside_tag = 0;
    char tag[32];
    size_t tag_length = 0;
    while (i < length && builder->length < builder->maximum) {
        unsigned char ch = xml[i++];
        if (ch == '<') {
            inside_tag = 1;
            tag_length = 0;
            continue;
        }
        if (inside_tag) {
            if (ch == '>') {
                tag[tag_length] = '\0';
                if (xml_tag_is_paragraph_break(tag) || _strnicmp(tag, "w:br", 4) == 0 ||
                    _strnicmp(tag, "a:br", 4) == 0 || _strnicmp(tag, "hp:lineBreak", 12) == 0)
                    extracted_text_append_cstr(builder, "\n");
                else if (_strnicmp(tag, "w:tab", 5) == 0 || _strnicmp(tag, "a:tab", 5) == 0 ||
                    _strnicmp(tag, "hp:tab", 6) == 0)
                    extracted_text_append_cstr(builder, "\t");
                inside_tag = 0;
            }
            else if (tag_length + 1 < sizeof(tag)) tag[tag_length++] = (char)ch;
            continue;
        }
        if (ch == '&') {
            unsigned int codepoint;
            size_t consumed = decode_xml_entity(xml + i - 1, length - (i - 1), &codepoint);
            if (consumed > 0) {
                if (extracted_text_append_codepoint(builder, codepoint) != 0) return -1;
                i += consumed - 1;
                continue;
            }
        }
        if (ch != '\r' && ch != '\n') {
            if (extracted_text_append(builder, &ch, 1) != 0) return -1;
        }
    }
    return 0;
}

#define CFB_FREE_SECTOR 0xffffffffU
#define CFB_END_OF_CHAIN 0xfffffffeU
#define CFB_FAT_SECTOR 0xfffffffdU
#define CFB_DIFAT_SECTOR 0xfffffffcU

typedef struct cfb_context {
    const unsigned char* data;
    size_t length;
    unsigned int sector_size;
    unsigned int mini_sector_size;
    unsigned int mini_cutoff;
    unsigned int* fat;
    size_t fat_count;
    unsigned int* mini_fat;
    size_t mini_fat_count;
    unsigned char* directory;
    size_t directory_length;
    unsigned char* root_mini_stream;
    size_t root_mini_length;
} cfb_context_t;

typedef struct cfb_stream_info {
    char name[96];
    unsigned char type;
    unsigned int start_sector;
    unsigned long long size;
} cfb_stream_info_t;

static const unsigned char* cfb_sector_pointer(const cfb_context_t* context, unsigned int sector)
{
    unsigned long long offset;
    if (context == NULL || sector >= 0xfffffffaU) return NULL;
    offset = ((unsigned long long)sector + 1ULL) * context->sector_size;
    if (offset + context->sector_size > context->length) return NULL;
    return context->data + (size_t)offset;
}

static void cfb_cleanup(cfb_context_t* context)
{
    if (context == NULL) return;
    free(context->fat);
    free(context->mini_fat);
    free(context->directory);
    free(context->root_mini_stream);
    memset(context, 0, sizeof(*context));
}

static int cfb_read_regular_chain(
    const cfb_context_t* context,
    unsigned int first_sector,
    unsigned long long declared_size,
    unsigned char** output,
    size_t* output_length,
    size_t maximum
)
{
    unsigned int sector = first_sector;
    size_t wanted;
    size_t written = 0;
    size_t hops = 0;
    unsigned char* buffer;
    if (output == NULL || output_length == NULL || context == NULL) return -1;
    *output = NULL;
    *output_length = 0;
    if (first_sector == CFB_END_OF_CHAIN || first_sector == CFB_FREE_SECTOR) {
        buffer = (unsigned char*)calloc(1, 1);
        if (buffer == NULL) return -1;
        *output = buffer;
        return 0;
    }
    if (declared_size > maximum || declared_size > SIZE_MAX) return -1;
    if (declared_size > 0) wanted = (size_t)declared_size;
    else {
        unsigned long long available = context->length > context->sector_size ? context->length - context->sector_size : 0;
        wanted = available > maximum ? maximum : (size_t)available;
    }
    buffer = (unsigned char*)malloc(wanted + 1);
    if (buffer == NULL) return -1;
    while (sector != CFB_END_OF_CHAIN && sector != CFB_FREE_SECTOR && written < wanted) {
        const unsigned char* source;
        size_t copy_length;
        if (sector >= context->fat_count || hops++ > context->fat_count) { free(buffer); return -1; }
        source = cfb_sector_pointer(context, sector);
        if (source == NULL) { free(buffer); return -1; }
        copy_length = wanted - written;
        if (copy_length > context->sector_size) copy_length = context->sector_size;
        memcpy(buffer + written, source, copy_length);
        written += copy_length;
        sector = context->fat[sector];
    }
    if (declared_size > 0 && written < declared_size && declared_size <= maximum) { free(buffer); return -1; }
    if (declared_size == 0 && written == wanted &&
        sector != CFB_END_OF_CHAIN && sector != CFB_FREE_SECTOR) {
        free(buffer);
        return -1;
    }
    buffer[written] = '\0';
    *output = buffer;
    *output_length = written;
    return 0;
}

static void cfb_directory_name(const unsigned char* entry, char* output, size_t output_size)
{
    unsigned short byte_length;
    size_t units;
    size_t i;
    size_t out = 0;
    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    byte_length = read_u16_le(entry + 64);
    if (byte_length < 2 || byte_length > 64) return;
    units = byte_length / 2 - 1;
    for (i = 0; i < units && out + 1 < output_size; i++) {
        unsigned short ch = read_u16_le(entry + i * 2);
        output[out++] = ch >= 0x20 && ch <= 0x7e ? (char)ch : '?';
    }
    output[out] = '\0';
}

static int cfb_get_stream_info(const cfb_context_t* context, size_t index, cfb_stream_info_t* info)
{
    const unsigned char* entry;
    if (context == NULL || info == NULL || (index + 1) * 128 > context->directory_length) return 0;
    entry = context->directory + index * 128;
    memset(info, 0, sizeof(*info));
    cfb_directory_name(entry, info->name, sizeof(info->name));
    info->type = entry[66];
    info->start_sector = read_u32_le(entry + 116);
    info->size = read_u64_le(entry + 120);
    return info->type == 1 || info->type == 2 || info->type == 5;
}

static int cfb_find_stream(const cfb_context_t* context, const char* name, cfb_stream_info_t* info)
{
    size_t index;
    size_t count = context->directory_length / 128;
    for (index = 0; index < count; index++) {
        cfb_stream_info_t current;
        if (cfb_get_stream_info(context, index, &current) && current.type == 2 &&
            _stricmp(current.name, name) == 0) {
            if (info != NULL) *info = current;
            return 1;
        }
    }
    return 0;
}

static int cfb_read_stream(
    const cfb_context_t* context,
    const cfb_stream_info_t* info,
    unsigned char** output,
    size_t* output_length,
    size_t maximum
)
{
    unsigned char* buffer;
    size_t wanted;
    size_t written = 0;
    size_t hops = 0;
    unsigned int mini_sector;
    if (context == NULL || info == NULL || output == NULL || output_length == NULL) return -1;
    if (info->size >= context->mini_cutoff || context->root_mini_stream == NULL) {
        return cfb_read_regular_chain(context, info->start_sector, info->size, output, output_length, maximum);
    }
    if (info->size > maximum || info->size > SIZE_MAX) return -1;
    wanted = (size_t)info->size;
    buffer = (unsigned char*)malloc(wanted + 1);
    if (buffer == NULL) return -1;
    mini_sector = info->start_sector;
    while (mini_sector != CFB_END_OF_CHAIN && mini_sector != CFB_FREE_SECTOR && written < wanted) {
        unsigned long long offset = (unsigned long long)mini_sector * context->mini_sector_size;
        size_t copy_length = wanted - written;
        if (mini_sector >= context->mini_fat_count || offset + context->mini_sector_size > context->root_mini_length ||
            hops++ > context->mini_fat_count) { free(buffer); return -1; }
        if (copy_length > context->mini_sector_size) copy_length = context->mini_sector_size;
        memcpy(buffer + written, context->root_mini_stream + (size_t)offset, copy_length);
        written += copy_length;
        mini_sector = context->mini_fat[mini_sector];
    }
    if (written < info->size && info->size <= maximum) { free(buffer); return -1; }
    buffer[written] = '\0';
    *output = buffer;
    *output_length = written;
    return 0;
}

static int cfb_initialize(const unsigned char* data, size_t length, cfb_context_t* context)
{
    unsigned short sector_shift;
    unsigned short mini_shift;
    unsigned int declared_fat_sectors;
    unsigned int fat_sector_ids[4096];
    size_t fat_sector_count = 0;
    unsigned int index;
    unsigned int difat_sector;
    unsigned int difat_count;
    size_t entries_per_sector;
    cfb_stream_info_t root;
    unsigned char* mini_fat_bytes = NULL;
    size_t mini_fat_bytes_length = 0;
    if (context == NULL || !looks_like_ole(data, length) || length < 512) return -1;
    memset(context, 0, sizeof(*context));
    context->data = data;
    context->length = length;
    sector_shift = read_u16_le(data + 30);
    mini_shift = read_u16_le(data + 32);
    if ((sector_shift != 9 && sector_shift != 12) || mini_shift < 3 || mini_shift > sector_shift) return -1;
    context->sector_size = 1U << sector_shift;
    context->mini_sector_size = 1U << mini_shift;
    context->mini_cutoff = read_u32_le(data + 56);
    if (context->mini_cutoff == 0 || context->mini_cutoff > 1024U * 1024U) context->mini_cutoff = 4096;
    if (context->sector_size > length) return -1;

    declared_fat_sectors = read_u32_le(data + 44);
    if (declared_fat_sectors == 0 || declared_fat_sectors > 4096) return -1;
    for (index = 0; index < 109 && fat_sector_count < declared_fat_sectors; index++) {
        unsigned int sector = read_u32_le(data + 76 + index * 4);
        if (sector != CFB_FREE_SECTOR) fat_sector_ids[fat_sector_count++] = sector;
    }
    difat_sector = read_u32_le(data + 68);
    difat_count = read_u32_le(data + 72);
    for (index = 0; index < difat_count && difat_sector != CFB_END_OF_CHAIN &&
        fat_sector_count < declared_fat_sectors; index++) {
        const unsigned char* sector_data = cfb_sector_pointer(context, difat_sector);
        size_t entry;
        size_t count;
        if (sector_data == NULL) return -1;
        count = context->sector_size / 4 - 1;
        for (entry = 0; entry < count && fat_sector_count < declared_fat_sectors; entry++) {
            unsigned int sector = read_u32_le(sector_data + entry * 4);
            if (sector != CFB_FREE_SECTOR) fat_sector_ids[fat_sector_count++] = sector;
        }
        difat_sector = read_u32_le(sector_data + count * 4);
    }
    if (fat_sector_count < declared_fat_sectors) return -1;
    entries_per_sector = context->sector_size / 4;
    context->fat_count = fat_sector_count * entries_per_sector;
    context->fat = (unsigned int*)malloc(context->fat_count * sizeof(unsigned int));
    if (context->fat == NULL) goto failure;
    for (index = 0; index < fat_sector_count; index++) {
        const unsigned char* sector_data = cfb_sector_pointer(context, fat_sector_ids[index]);
        size_t entry;
        if (sector_data == NULL) goto failure;
        for (entry = 0; entry < entries_per_sector; entry++)
            context->fat[index * entries_per_sector + entry] = read_u32_le(sector_data + entry * 4);
    }
    if (cfb_read_regular_chain(context, read_u32_le(data + 48), 0,
        &context->directory, &context->directory_length, 32U * 1024U * 1024U) != 0) goto failure;

    memset(&root, 0, sizeof(root));
    for (index = 0; (size_t)(index + 1) * 128 <= context->directory_length; index++) {
        if (cfb_get_stream_info(context, index, &root) && root.type == 5) break;
    }
    if (root.type == 5 && root.size > 0 && cfb_read_regular_chain(context, root.start_sector, root.size,
        &context->root_mini_stream, &context->root_mini_length, FILE_ANALYZER_MAX_TOTAL_UNCOMPRESSED) != 0) goto failure;

    if (read_u32_le(data + 64) > 0 && context->root_mini_stream != NULL) {
        unsigned long long declared_mini_bytes = (unsigned long long)read_u32_le(data + 64) * context->sector_size;
        if (cfb_read_regular_chain(context, read_u32_le(data + 60), declared_mini_bytes,
            &mini_fat_bytes, &mini_fat_bytes_length, 16U * 1024U * 1024U) != 0) goto failure;
        context->mini_fat_count = mini_fat_bytes_length / 4;
        context->mini_fat = (unsigned int*)malloc(context->mini_fat_count * sizeof(unsigned int));
        if (context->mini_fat == NULL) goto failure;
        for (index = 0; index < context->mini_fat_count; index++)
            context->mini_fat[index] = read_u32_le(mini_fat_bytes + index * 4);
    }
    free(mini_fat_bytes);
    return 0;

failure:
    free(mini_fat_bytes);
    cfb_cleanup(context);
    return -1;
}

static int inflate_raw_growing(
    const unsigned char* compressed,
    size_t compressed_length,
    unsigned char** output,
    size_t* output_length,
    size_t maximum
)
{
    z_stream stream;
    unsigned char* buffer;
    size_t capacity = compressed_length * 4 + 4096;
    int zresult;
    if (capacity > maximum) capacity = maximum;
    buffer = (unsigned char*)malloc(capacity + 1);
    if (buffer == NULL) return -1;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef*)compressed;
    stream.avail_in = (uInt)compressed_length;
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) { free(buffer); return -1; }
    for (;;) {
        stream.next_out = buffer + stream.total_out;
        stream.avail_out = (uInt)(capacity - stream.total_out);
        zresult = inflate(&stream, Z_NO_FLUSH);
        if (zresult == Z_STREAM_END) break;
        if (zresult != Z_OK || capacity >= maximum) { inflateEnd(&stream); free(buffer); return -1; }
        {
            size_t next_capacity = capacity * 2;
            unsigned char* resized;
            if (next_capacity > maximum) next_capacity = maximum;
            resized = (unsigned char*)realloc(buffer, next_capacity + 1);
            if (resized == NULL) { inflateEnd(&stream); free(buffer); return -1; }
            buffer = resized;
            capacity = next_capacity;
        }
    }
    inflateEnd(&stream);
    buffer[stream.total_out] = '\0';
    *output = buffer;
    *output_length = stream.total_out;
    return 0;
}

static int append_hwp_section_text(
    extracted_text_builder_t* builder,
    const unsigned char* section,
    size_t length
)
{
    size_t cursor = 0;
    while (cursor + 4 <= length && builder->length < builder->maximum) {
        unsigned int header = read_u32_le(section + cursor);
        unsigned int tag = header & 0x3ffU;
        unsigned int record_size = header >> 20;
        cursor += 4;
        if (record_size == 0xfffU) {
            if (cursor + 4 > length) return -1;
            record_size = read_u32_le(section + cursor);
            cursor += 4;
        }
        if ((unsigned long long)cursor + record_size > length) return -1;
        if (tag == 0x43U) {
            size_t i;
            for (i = 0; i + 1 < record_size; i += 2) {
                unsigned int value = read_u16_le(section + cursor + i);
                if (value == 9) extracted_text_append_cstr(builder, "\t");
                else if (value == 10 || value == 13) extracted_text_append_cstr(builder, "\n");
                else if (value >= 0x20 && !(value >= 0xd800 && value <= 0xdfff))
                    extracted_text_append_codepoint(builder, value);
            }
            extracted_text_append_cstr(builder, "\n");
        }
        cursor += record_size;
    }
    return 0;
}

static int append_binary_string_runs(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length
)
{
    size_t i = 0;
    while (i < length && builder->length < builder->maximum) {
        size_t start = i;
        while (i < length && (data[i] == '\t' || (data[i] >= 0x20 && data[i] <= 0x7e))) i++;
        if (i - start >= FILE_ANALYZER_MIN_TEXT_RUN) {
            extracted_text_append(builder, data + start, i - start);
            extracted_text_append_cstr(builder, "\n");
        }
        i = i == start ? i + 1 : i;
    }
    i = 0;
    while (i + 1 < length && builder->length < builder->maximum) {
        size_t start = i;
        size_t units = 0;
        while (i + 1 < length) {
            unsigned int value = read_u16_le(data + i);
            if (value < 0x20 || (value >= 0x7f && value < 0xa0)) break;
            units++;
            i += 2;
        }
        if (units >= FILE_ANALYZER_MIN_TEXT_RUN) {
            extracted_text_append_utf16(builder, data + start, units * 2, 0);
            extracted_text_append_cstr(builder, "\n");
        }
        i = i == start ? i + 2 : i;
    }
    return 0;
}

static int hwp_stream_requires_dedicated_inspection(const char* name)
{
    if (name == NULL || name[0] == '\0') return 0;
    return _strnicmp(name, "BIN", 3) == 0 ||
        contains_ignore_case(name, "JScript") ||
        contains_ignore_case(name, "Object") ||
        contains_ignore_case(name, "Package");
}

static int extract_ole_text(
    analyzer_format_kind_t kind,
    const unsigned char* data,
    size_t length,
    extracted_text_builder_t* builder,
    int* encrypted,
    int* complete,
    int* uninspected_payload
)
{
    cfb_context_t context;
    size_t index;
    size_t stream_count;
    int section_count = 0;
    int section_failures = 0;
    int payloads_not_inspected = 0;
    int hwp_compressed = 0;
    cfb_stream_info_t file_header;
    if (encrypted != NULL) *encrypted = 0;
    if (complete != NULL) *complete = 0;
    if (uninspected_payload != NULL) *uninspected_payload = 0;
    if (cfb_initialize(data, length, &context) != 0) return -1;
    if (cfb_find_stream(&context, "EncryptedPackage", NULL) ||
        cfb_find_stream(&context, "EncryptionInfo", NULL)) {
        if (encrypted != NULL) *encrypted = 1;
        cfb_cleanup(&context);
        return 0;
    }
    if (kind == ANALYZER_FORMAT_HWP) {
        unsigned char* header_data = NULL;
        size_t header_length = 0;
        if (!cfb_find_stream(&context, "FileHeader", &file_header) ||
            cfb_read_stream(&context, &file_header, &header_data, &header_length, 4096) != 0 ||
            header_length < 40 || !bytes_contain(header_data, header_length, "HWP Document File")) {
            free(header_data);
            cfb_cleanup(&context);
            return -1;
        }
        {
            unsigned int flags = read_u32_le(header_data + 36);
            hwp_compressed = (flags & 1U) != 0;
            if ((flags & 2U) != 0 || (flags & 4U) != 0) {
                if (encrypted != NULL) *encrypted = 1;
                free(header_data);
                cfb_cleanup(&context);
                return 0;
            }
        }
        free(header_data);
    }
    stream_count = context.directory_length / 128;
    for (index = 0; index < stream_count; index++) {
        cfb_stream_info_t info;
        unsigned char* stream_data = NULL;
        size_t stream_length = 0;
        if (!cfb_get_stream_info(&context, index, &info) || info.type != 2 || info.size == 0) continue;
        if (kind == ANALYZER_FORMAT_HWP) {
            if (_strnicmp(info.name, "Section", 7) != 0) {
                if (hwp_stream_requires_dedicated_inspection(info.name))
                    payloads_not_inspected++;
                continue;
            }
            section_count++;
            if (builder->truncated || builder->length >= builder->maximum ||
                info.size >= FILE_ANALYZER_MAX_ENTRY_OUTPUT) {
                builder->truncated = 1;
                section_failures++;
                continue;
            }
            if (cfb_read_stream(&context, &info, &stream_data, &stream_length,
                FILE_ANALYZER_MAX_ENTRY_OUTPUT) != 0) { section_failures++; continue; }
            if (hwp_compressed) {
                unsigned char* inflated = NULL;
                size_t inflated_length = 0;
                if (inflate_raw_growing(stream_data, stream_length, &inflated, &inflated_length,
                    FILE_ANALYZER_MAX_ENTRY_OUTPUT) != 0) {
                    free(stream_data);
                    section_failures++;
                    continue;
                }
                free(stream_data);
                stream_data = inflated;
                stream_length = inflated_length;
                if (stream_length >= FILE_ANALYZER_MAX_ENTRY_OUTPUT) {
                    builder->truncated = 1;
                    section_failures++;
                    free(stream_data);
                    continue;
                }
            }
            if (append_hwp_section_text(builder, stream_data, stream_length) != 0) section_failures++;
            if (builder->length >= builder->maximum) builder->truncated = 1;
            free(stream_data);
        }
    }
    if (kind == ANALYZER_FORMAT_HWP) {
        if (uninspected_payload != NULL) *uninspected_payload = payloads_not_inspected > 0;
        if (complete != NULL) *complete = section_count > 0 && section_failures == 0 &&
            payloads_not_inspected == 0 && !builder->truncated &&
            builder->length < builder->maximum;
    }
    else {
        /* Legacy Office/MSG binary structures need format-specific parsers.
         * Preserve useful Unicode/ASCII evidence, but mark the result partial. */
        append_binary_string_runs(builder, data, length);
    }
    cfb_cleanup(&context);
    return 0;
}

static int analyze_ole_document(
    analyzer_format_kind_t kind,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
)
{
    extracted_text_builder_t builder;
    int encrypted = 0;
    int complete = 0;
    int uninspected_payload = 0;
    int extract_result;
    memset(&builder, 0, sizeof(builder));
    builder.maximum = read_extracted_text_limit();
    if (extracted_text_reserve(&builder, 0) != 0) return -1;
    builder.data[0] = '\0';
    extract_result = extract_ole_text(kind, data, length, &builder, &encrypted,
        &complete, &uninspected_payload);
    result->extracted_text_bytes = builder.length;
    free(builder.data);
    if (extract_result != 0) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_MALFORMED;
        strcpy_s(result->reason, sizeof(result->reason), "malformed OLE compound document");
    }
    else if (encrypted) {
        result->action = FILE_ANALYSIS_BLOCK;
        result->encrypted = 1;
        result->extraction_status = FILE_EXTRACTION_ENCRYPTED;
        strcpy_s(result->reason, sizeof(result->reason), "encrypted or distribution-protected OLE document cannot be inspected");
    }
    else if (kind == ANALYZER_FORMAT_HWP && complete) {
        result->extraction_complete = 1;
        result->extraction_status = FILE_EXTRACTION_COMPLETE;
        strcpy_s(result->reason, sizeof(result->reason), "HWP 5.x BodyText sections extracted");
    }
    else {
        result->action = FILE_ANALYSIS_BLOCK;
        result->extraction_status = FILE_EXTRACTION_PARTIAL;
        if (kind == ANALYZER_FORMAT_HWP && uninspected_payload) {
            strcpy_s(result->reason, sizeof(result->reason),
                "HWP contains embedded BinData, script, or object content that was not inspected");
        }
        else if (kind == ANALYZER_FORMAT_HWP &&
            (builder.truncated || builder.length >= builder.maximum)) {
            strcpy_s(result->reason, sizeof(result->reason),
                "HWP extraction limit reached; blocked fail-closed");
        }
        else {
            strcpy_s(result->reason, sizeof(result->reason),
                kind == ANALYZER_FORMAT_HWP ? "HWP body extraction incomplete; blocked fail-closed" :
                "legacy OLE text evidence extracted partially; dedicated parser required, blocked fail-closed");
        }
    }
    return 0;
}

static int extracted_text_append_rtf(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length
)
{
    size_t i = 0;
    int depth = 0;
    int skip_group[256];
    int unicode_fallback = 1;
    int fallback_remaining = 0;
    memset(skip_group, 0, sizeof(skip_group));
    while (i < length && builder->length < builder->maximum) {
        unsigned char ch = data[i++];
        if (ch == '{') {
            if (depth + 1 < (int)(sizeof(skip_group) / sizeof(skip_group[0]))) {
                skip_group[depth + 1] = skip_group[depth];
                depth++;
            }
            continue;
        }
        if (ch == '}') {
            if (depth > 0) depth--;
            continue;
        }
        if (ch != '\\') {
            if (!skip_group[depth] && fallback_remaining == 0 && ch != '\r' && ch != '\n')
                extracted_text_append(builder, &ch, 1);
            else if (fallback_remaining > 0 && ch != '\r' && ch != '\n') fallback_remaining--;
            continue;
        }
        if (i >= length) break;
        ch = data[i++];
        if (ch == '\\' || ch == '{' || ch == '}') {
            if (!skip_group[depth] && fallback_remaining == 0) extracted_text_append(builder, &ch, 1);
            else if (fallback_remaining > 0) fallback_remaining--;
            continue;
        }
        if (ch == '\'' && i + 1 < length) {
            unsigned int value = 0;
            int digit;
            int valid = 1;
            size_t n;
            for (n = 0; n < 2; n++) {
                unsigned char hex = data[i++];
                if (hex >= '0' && hex <= '9') digit = hex - '0';
                else if (hex >= 'a' && hex <= 'f') digit = hex - 'a' + 10;
                else if (hex >= 'A' && hex <= 'F') digit = hex - 'A' + 10;
                else { valid = 0; digit = 0; }
                value = value * 16 + (unsigned int)digit;
            }
            if (valid && !skip_group[depth] && fallback_remaining == 0)
                extracted_text_append_codepoint(builder, value);
            else if (fallback_remaining > 0) fallback_remaining--;
            continue;
        }
        if (ch == '*') {
            skip_group[depth] = 1;
            continue;
        }
        if (isalpha(ch)) {
            char word[48];
            size_t word_length = 0;
            int negative = 0;
            long parameter = 0;
            int has_parameter = 0;
            word[word_length++] = (char)ch;
            while (i < length && isalpha(data[i]) && word_length + 1 < sizeof(word))
                word[word_length++] = (char)data[i++];
            word[word_length] = '\0';
            if (i < length && data[i] == '-') { negative = 1; i++; }
            while (i < length && isdigit(data[i])) {
                has_parameter = 1;
                parameter = parameter * 10 + (data[i++] - '0');
            }
            if (negative) parameter = -parameter;
            if (i < length && data[i] == ' ') i++;
            if (_stricmp(word, "fonttbl") == 0 || _stricmp(word, "colortbl") == 0 ||
                _stricmp(word, "stylesheet") == 0 || _stricmp(word, "pict") == 0 ||
                _stricmp(word, "object") == 0 || _stricmp(word, "info") == 0 ||
                _stricmp(word, "datastore") == 0) skip_group[depth] = 1;
            if (!skip_group[depth]) {
                if (_stricmp(word, "par") == 0 || _stricmp(word, "line") == 0)
                    extracted_text_append_cstr(builder, "\n");
                else if (_stricmp(word, "tab") == 0) extracted_text_append_cstr(builder, "\t");
                else if (_stricmp(word, "uc") == 0 && has_parameter && parameter >= 0 && parameter <= 16)
                    unicode_fallback = (int)parameter;
                else if (_stricmp(word, "u") == 0 && has_parameter) {
                    unsigned int codepoint = parameter < 0 ? (unsigned int)(parameter + 65536L) : (unsigned int)parameter;
                    extracted_text_append_codepoint(builder, codepoint);
                    fallback_remaining = unicode_fallback;
                }
            }
            continue;
        }
        if (ch == '~' && !skip_group[depth]) extracted_text_append_cstr(builder, " ");
        else if (ch == '_' && !skip_group[depth]) extracted_text_append_cstr(builder, "-");
    }
    return 0;
}

static int extracted_text_append_pdf_literals(
    extracted_text_builder_t* builder,
    const unsigned char* data,
    size_t length
)
{
    size_t i;
    int depth = 0;
    int escaped = 0;
    for (i = 0; i < length && builder->length < builder->maximum; i++) {
        unsigned char ch = data[i];
        if (depth == 0) { if (ch == '(') depth = 1; continue; }
        if (escaped) {
            if (ch == 'n') ch = '\n'; else if (ch == 'r') ch = '\r'; else if (ch == 't') ch = '\t';
            if (extracted_text_append(builder, &ch, 1) != 0) return -1;
            escaped = 0;
            continue;
        }
        if (ch == '\\') { escaped = 1; continue; }
        if (ch == '(') { depth++; continue; }
        if (ch == ')') {
            depth--;
            if (depth == 0) extracted_text_append_cstr(builder, "\n");
            continue;
        }
        if ((ch >= 0x20 && ch != 0x7f) || ch >= 0x80)
            if (extracted_text_append(builder, &ch, 1) != 0) return -1;
    }
    return 0;
}

static int extract_zip_text(
    const unsigned char* data,
    size_t length,
    analyzer_format_kind_t kind,
    extracted_text_builder_t* builder,
    file_analyzer_context_t* context
)
{
    zip_directory_info_t directory;
    size_t cursor;
    unsigned int index;

    if (zip_locate_directory(data, length, &directory) != 0) return -1;
    cursor = directory.central_offset;
    for (index = 0; index < directory.entry_count; index++) {
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
        int selected;
        int recursive;
        analyzer_format_kind_t nested_kind = ANALYZER_FORMAT_BINARY;

        if (cursor > directory.eocd_offset || directory.eocd_offset - cursor < 46 ||
            read_u32_le(data + cursor) != 0x02014b50U) return -1;
        flags = read_u16_le(data + cursor + 8);
        method = read_u16_le(data + cursor + 10);
        compressed_size = read_u32_le(data + cursor + 20);
        uncompressed_size = read_u32_le(data + cursor + 24);
        name_length = read_u16_le(data + cursor + 28);
        extra_length = read_u16_le(data + cursor + 30);
        comment_length = read_u16_le(data + cursor + 32);
        local_offset = read_u32_le(data + cursor + 42);
        if (46ULL + name_length + extra_length + comment_length >
            directory.eocd_offset - cursor) return -1;

        copy_length = name_length < sizeof(name) - 1 ? name_length : sizeof(name) - 1;
        memcpy(name, data + cursor + 46, copy_length);
        name[copy_length] = '\0';
        if (!file_analyzer_context_account_archive_entry(context, uncompressed_size)) {
            builder->truncated = 1;
            return -1;
        }
        if ((flags & 1) != 0) return -1;
        selected = zip_entry_is_selected(kind, name);
        recursive = archive_entry_recursive_format(name, &nested_kind);
        if (kind == ANALYZER_FORMAT_ZIP && !archive_entry_is_directory(name) &&
            !selected && !recursive) return -1;
        if ((selected || recursive) && uncompressed_size > FILE_ANALYZER_MAX_ENTRY_OUTPUT)
            return -1;

        if (selected || recursive) {
            unsigned short local_name_length;
            unsigned short local_extra_length;
            size_t payload_offset;
            unsigned char* extracted = NULL;
            size_t extracted_length = 0;

            if ((size_t)local_offset > directory.central_offset ||
                directory.central_offset - (size_t)local_offset < 30 ||
                read_u32_le(data + local_offset) != 0x04034b50U) return -1;
            local_name_length = read_u16_le(data + local_offset + 26);
            local_extra_length = read_u16_le(data + local_offset + 28);
            payload_offset = (size_t)local_offset + 30ULL + local_name_length + local_extra_length;
            if ((unsigned long long)payload_offset + compressed_size > directory.central_offset)
                return -1;

            if (builder->truncated || builder->length >= builder->maximum) {
                builder->truncated = 1;
                cursor += 46ULL + name_length + extra_length + comment_length;
                continue;
            }

            if (method == 0 && compressed_size == uncompressed_size) {
                extracted = (unsigned char*)malloc((size_t)compressed_size + 1);
                if (extracted == NULL) return -1;
                memcpy(extracted, data + payload_offset, compressed_size);
                extracted[compressed_size] = '\0';
                extracted_length = compressed_size;
            }
            else if (method == 8) {
                if (inflate_buffer(data + payload_offset, compressed_size, uncompressed_size,
                    &extracted, &extracted_length, FILE_ANALYZER_MAX_ENTRY_OUTPUT) != 0)
                    return -1;
            }
            else return -1;

            if (kind == ANALYZER_FORMAT_ZIP &&
                (extracted_text_append_cstr(builder, "\n--- ") != 0 ||
                 extracted_text_append_cstr(builder, name) != 0 ||
                 extracted_text_append_cstr(builder, " ---\n") != 0)) {
                free(extracted);
                return -1;
            }
            if (selected) {
                int append_result = ends_with_ignore_case(name, ".xml")
                    ? extracted_text_append_xml(builder, extracted, extracted_length)
                    : extracted_text_append_plain(builder, extracted, extracted_length);
                if (append_result != 0) {
                    free(extracted);
                    return -1;
                }
            }
            else {
                char* nested_text = NULL;
                size_t nested_length = 0;
                int nested_truncated = 0;
                int nested_result;
                if (context == NULL || context->depth >= FILE_ANALYZER_MAX_CONTAINER_DEPTH) {
                    builder->truncated = 1;
                    free(extracted);
                    return -1;
                }
                context->depth++;
                nested_result = file_analyzer_extract_text_internal(
                    name, normalized_mime_for_format(nested_kind),
                    extracted, extracted_length, &nested_text,
                    &nested_length, &nested_truncated, context);
                context->depth--;
                if (nested_result != 0) {
                    free(extracted);
                    free(nested_text);
                    return -1;
                }
                if (nested_text != NULL && nested_length > 0 &&
                    extracted_text_append(builder, nested_text, nested_length) != 0) {
                    free(extracted);
                    free(nested_text);
                    return -1;
                }
                if (nested_truncated) builder->truncated = 1;
                free(nested_text);
            }
            free(extracted);
            if (builder->length >= builder->maximum) builder->truncated = 1;
        }
        cursor += 46ULL + name_length + extra_length + comment_length;
    }
    return cursor == directory.eocd_offset ? 0 : -1;
}

static int extract_pdf_text(
    const unsigned char* data,
    size_t length,
    extracted_text_builder_t* builder
)
{
    char* ocr_text = NULL;
    size_t ocr_length = 0;
    int page_truncated = 0;
    char status[160];
    int ocr_result;

    if (bytes_contain(data, length, "/Encrypt")) return 0;
    status[0] = '\0';
    ocr_result = windows_pdf_ocr_extract_utf8(data, length, 100, &ocr_text, &ocr_length,
        &page_truncated, status, sizeof(status));
    if (ocr_result != 1) {
        free(ocr_text);
        return -1;
    }
    if (ocr_text != NULL && ocr_length > 0)
        extracted_text_append(builder, ocr_text, ocr_length);
    if (page_truncated) builder->truncated = 1;
    free(ocr_text);
    return 0;
}

static int file_analyzer_extract_text_internal(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    char** output,
    size_t* output_length,
    int* truncated,
    file_analyzer_context_t* context
)
{
    extracted_text_builder_t builder;
    analyzer_format_kind_t filename_kind;
    analyzer_format_kind_t mime_kind;
    analyzer_format_kind_t declared;
    analyzer_format_kind_t magic;
    analyzer_format_kind_t resolved;
    int result = 0;

    if (output == NULL || output_length == NULL || data == NULL) return -1;
    *output = NULL;
    *output_length = 0;
    if (truncated != NULL) *truncated = 0;
    memset(&builder, 0, sizeof(builder));
    builder.maximum = read_extracted_text_limit();
    if (extracted_text_reserve(&builder, 0) != 0) return -1;
    builder.data[0] = '\0';

    filename_kind = format_from_filename(filename);
    mime_kind = format_from_content_type(content_type);
    declared = filename_kind != ANALYZER_FORMAT_BINARY ? filename_kind : mime_kind;
    magic = format_from_magic(data, length);
    resolved = declared != ANALYZER_FORMAT_BINARY ? declared : magic;

    if (declared != ANALYZER_FORMAT_BINARY && !signature_matches_declared(declared, magic) &&
        !((declared == ANALYZER_FORMAT_TEXT || declared == ANALYZER_FORMAT_EML) &&
          magic == ANALYZER_FORMAT_BINARY && data_looks_probably_text(data, length))) {
        /* Preserve the original file, but do not emit attacker-controlled binary
         * bytes as if they were readable text when extension/MIME is spoofed. */
        result = 0;
    }
    else if (format_is_zip_container(resolved) && magic == ANALYZER_FORMAT_ZIP) {
        result = extract_zip_text(data, length, resolved, &builder, context);
    }
    else if (resolved == ANALYZER_FORMAT_PDF && magic == ANALYZER_FORMAT_PDF) {
        result = extract_pdf_text(data, length, &builder);
    }
    else if (format_is_ole_document(resolved) && magic == ANALYZER_FORMAT_MSG) {
        int encrypted = 0;
        int complete = 0;
        int uninspected_payload = 0;
        result = extract_ole_text(resolved, data, length, &builder, &encrypted, &complete,
            &uninspected_payload);
    }
    else if (format_is_image(resolved) && resolved == magic) {
        char* ocr_text = NULL;
        size_t ocr_length = 0;
        char status[160];
        int ocr_result;
        status[0] = '\0';
        ocr_result = windows_ocr_extract_utf8(data, length, &ocr_text, &ocr_length,
            status, sizeof(status));
        if (ocr_result == 1 && ocr_text != NULL)
            result = extracted_text_append(&builder, ocr_text, ocr_length);
        free(ocr_text);
    }
    else if (resolved == ANALYZER_FORMAT_RTF && magic == ANALYZER_FORMAT_RTF) {
        result = extracted_text_append_rtf(&builder, data, length);
    }
    else if ((resolved == ANALYZER_FORMAT_TEXT || resolved == ANALYZER_FORMAT_EML) &&
        data_looks_probably_text(data, length)) {
        result = extracted_text_append_plain(&builder, data, length);
    }
    else {
        /* Known unsupported binary/media/archive: return a valid empty UTF-8
         * buffer.  The inspection result carries UNSUPPORTED/ENCRYPTED status. */
        result = 0;
    }

    if (result != 0) {
        free(builder.data);
        return -1;
    }
    if (builder.length >= builder.maximum) builder.truncated = 1;
    *output = builder.data;
    *output_length = builder.length;
    if (truncated != NULL) *truncated = builder.truncated;
    return 0;
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
    file_analyzer_context_t context;
    memset(&context, 0, sizeof(context));
    return file_analyzer_extract_text_internal(filename, content_type, data, length,
        output, output_length, truncated, &context);
}
