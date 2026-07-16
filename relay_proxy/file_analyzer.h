#ifndef FILE_ANALYZER_H
#define FILE_ANALYZER_H

#include <stddef.h>

typedef enum file_analysis_action {
    FILE_ANALYSIS_ALLOW = 0,
    FILE_ANALYSIS_BLOCK = 1
} file_analysis_action_t;

typedef struct file_analysis_result {
    file_analysis_action_t action;
    char format[32];
    char sha256[65];
    char reason[256];
    unsigned int archive_entries;
    unsigned long long extracted_text_bytes;
    int extraction_complete;
} file_analysis_result_t;

int file_analyzer_inspect(
    const char* filename,
    const char* content_type,
    const unsigned char* data,
    size_t length,
    file_analysis_result_t* result
);

#endif
