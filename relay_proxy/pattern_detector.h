#ifndef PATTERN_DETECTOR_H
#define PATTERN_DETECTOR_H

int detect_email_pattern(const char* data, int length);
int detect_phone_pattern(const char* data, int length);
int detect_resident_id_pattern(const char* data, int length);
int detect_credit_card_pattern(const char* data, int length);

int detect_file_upload_pattern(const char* data, int length);
int detect_file_extension_pattern(const char* data, int length, const char* extension);

#endif