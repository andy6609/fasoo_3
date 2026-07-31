#ifndef WINDOWS_OCR_H
#define WINDOWS_OCR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode an image with Windows Imaging Component and run the local
 * Windows.Media.Ocr engine. The returned UTF-8 buffer is allocated with
 * malloc() and must be released by the caller with free(). No network or
 * cloud service is used.
 *
 * Return values:
 *   1  OCR completed (the text may be empty)
 *   0  OCR is unavailable for the current image/language configuration
 *  -1  invalid input or an unexpected decoding/OCR failure
 */
int windows_ocr_extract_utf8(
    const unsigned char* image_data,
    size_t image_length,
    char** output,
    size_t* output_length,
    char* status,
    size_t status_size
);

/* Render PDF pages locally with Windows.Data.Pdf and OCR each rendered page.
 * max_pages bounds CPU usage; *truncated is set when the document has more
 * pages than were inspected. */
int windows_pdf_ocr_extract_utf8(
    const unsigned char* pdf_data,
    size_t pdf_length,
    unsigned int max_pages,
    char** output,
    size_t* output_length,
    int* truncated,
    char* status,
    size_t status_size
);

#ifdef __cplusplus
}
#endif

#endif /* WINDOWS_OCR_H */
