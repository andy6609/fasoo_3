#ifndef FILE_ANALYZER_H
#define FILE_ANALYZER_H

#include <stddef.h>

typedef enum file_analysis_action {
    FILE_ANALYSIS_ALLOW = 0,
    FILE_ANALYSIS_BLOCK = 1
} file_analysis_action_t;

/*
 * Why readable content is (or is not) available.  Values are appended to the
 * public result structure so existing callers that only use the original
 * fields keep their behaviour.
 */
typedef enum file_extraction_status {
    FILE_EXTRACTION_NONE = 0,
    FILE_EXTRACTION_COMPLETE = 1,
    FILE_EXTRACTION_PARTIAL = 2,
    FILE_EXTRACTION_OCR_REQUIRED = 3,
    FILE_EXTRACTION_ENCRYPTED = 4,
    FILE_EXTRACTION_UNSUPPORTED = 5,
    FILE_EXTRACTION_MALFORMED = 6
} file_extraction_status_t;

typedef struct file_analysis_result {
    file_analysis_action_t action;
    char format[32];
    char sha256[65];
    char reason[256];
    unsigned int archive_entries;
    unsigned long long extracted_text_bytes;
    int extraction_complete;
    file_extraction_status_t extraction_status;
    int encrypted;
    int signature_match;
    int requires_ocr;
    char normalized_mime[96];
} file_analysis_result_t;

int file_analyzer_inspect(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
);

/*
 * Extract human-readable upload content into a caller-owned UTF-8 buffer.
 * The buffer is allocated with malloc() and must be released with free().
 * Binary formats without extractable text return an empty buffer.
 */
int file_analyzer_extract_text(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    char** output,
    size_t* output_length,
    int* truncated
);

#endif
