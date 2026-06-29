#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "pattern_detector.h"

#define DETECTED_FILENAME_SIZE 512

static int is_digit_char(char ch)
{
    return ch >= '0' && ch <= '9';
}

static int is_email_local_char(char ch)
{
    if (isalnum((unsigned char)ch)) {
        return 1;
    }

    return ch == '.' || ch == '_' || ch == '%' || ch == '+' || ch == '-';
}

static int is_email_domain_char(char ch)
{
    if (isalnum((unsigned char)ch)) {
        return 1;
    }

    return ch == '.' || ch == '-';
}

static int match_token_ignore_case(
    const char* data,
    int length,
    int pos,
    const char* token
)
{
    int token_length;

    if (data == NULL || token == NULL || pos < 0) {
        return 0;
    }

    token_length = (int)strlen(token);

    if (token_length <= 0) {
        return 0;
    }

    if (pos + token_length > length) {
        return 0;
    }

    return _strnicmp(data + pos, token, token_length) == 0;
}

static int ends_with_ignore_case(const char* text, const char* suffix)
{
    int text_length;
    int suffix_length;

    if (text == NULL || suffix == NULL) {
        return 0;
    }

    text_length = (int)strlen(text);
    suffix_length = (int)strlen(suffix);

    if (text_length <= 0 || suffix_length <= 0) {
        return 0;
    }

    if (text_length < suffix_length) {
        return 0;
    }

    return _stricmp(text + text_length - suffix_length, suffix) == 0;
}

int detect_email_pattern(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        int left;
        int right;
        int local_length;
        int domain_length;
        int has_dot = 0;
        int last_dot_index = -1;

        if (data[i] != '@') {
            continue;
        }

        left = i - 1;
        while (left >= 0 && is_email_local_char(data[left])) {
            left--;
        }

        local_length = i - left - 1;

        right = i + 1;
        while (right < length && is_email_domain_char(data[right])) {
            if (data[right] == '.') {
                has_dot = 1;
                last_dot_index = right;
            }

            right++;
        }

        domain_length = right - i - 1;

        if (local_length <= 0) {
            continue;
        }

        if (domain_length < 3) {
            continue;
        }

        if (!has_dot) {
            continue;
        }

        if (last_dot_index <= i + 1) {
            continue;
        }

        if (last_dot_index >= right - 1) {
            continue;
        }

        if (right - last_dot_index - 1 < 2) {
            continue;
        }

        return 1;
    }

    return 0;
}

static int match_digits(
    const char* data,
    int length,
    int* pos,
    int digit_count
)
{
    int i;

    if (data == NULL || pos == NULL || digit_count <= 0) {
        return 0;
    }

    if (*pos + digit_count > length) {
        return 0;
    }

    for (i = 0; i < digit_count; i++) {
        if (!is_digit_char(data[*pos + i])) {
            return 0;
        }
    }

    *pos += digit_count;

    return 1;
}

static void skip_optional_separator(
    const char* data,
    int length,
    int* pos
)
{
    if (data == NULL || pos == NULL) {
        return;
    }

    if (*pos >= length) {
        return;
    }

    if (data[*pos] == '-' || data[*pos] == ' ') {
        (*pos)++;
    }
}

int detect_phone_pattern(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        int pos = i;

        if (pos + 3 > length) {
            continue;
        }

        if (data[pos] != '0' || data[pos + 1] != '1' || data[pos + 2] != '0') {
            continue;
        }

        pos += 3;

        skip_optional_separator(data, length, &pos);

        if (!match_digits(data, length, &pos, 4)) {
            continue;
        }

        skip_optional_separator(data, length, &pos);

        if (!match_digits(data, length, &pos, 4)) {
            continue;
        }

        return 1;
    }

    return 0;
}

int detect_resident_id_pattern(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        int pos = i;

        if (!match_digits(data, length, &pos, 6)) {
            continue;
        }

        skip_optional_separator(data, length, &pos);

        if (pos >= length) {
            continue;
        }

        if (data[pos] < '1' || data[pos] > '4') {
            continue;
        }

        pos++;

        if (!match_digits(data, length, &pos, 6)) {
            continue;
        }

        return 1;
    }

    return 0;
}

static int luhn_check(const char* digits, int length)
{
    int sum = 0;
    int double_digit = 0;
    int i;

    if (digits == NULL || length <= 0) {
        return 0;
    }

    for (i = length - 1; i >= 0; i--) {
        int value = digits[i] - '0';

        if (double_digit) {
            value *= 2;

            if (value > 9) {
                value -= 9;
            }
        }

        sum += value;
        double_digit = !double_digit;
    }

    return (sum % 10) == 0;
}

int detect_credit_card_pattern(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        char digits[32];
        int digit_count = 0;
        int j;

        if (!is_digit_char(data[i])) {
            continue;
        }

        memset(digits, 0, sizeof(digits));

        j = i;

        while (j < length) {
            if (is_digit_char(data[j])) {
                if (digit_count >= (int)sizeof(digits) - 1) {
                    break;
                }

                digits[digit_count] = data[j];
                digit_count++;
                j++;
                continue;
            }

            if (data[j] == '-' || data[j] == ' ') {
                j++;
                continue;
            }

            break;
        }

        if (digit_count >= 13 && digit_count <= 19) {
            if (luhn_check(digits, digit_count)) {
                return 1;
            }
        }
    }

    return 0;
}

int detect_file_upload_pattern(const char* data, int length)
{
    int i;

    if (data == NULL || length <= 0) {
        return 0;
    }

    /*
        multipart/form-data 파일 업로드 파트에는 보통 이런 헤더가 들어간다.

        Content-Disposition: form-data; name="file"; filename="test.txt"

        그래서 filename= 존재 여부를 파일 업로드로 판단한다.
    */
    for (i = 0; i < length; i++) {
        if (match_token_ignore_case(data, length, i, "filename=")) {
            return 1;
        }
    }

    return 0;
}

static int extract_filename_at(
    const char* data,
    int length,
    int filename_token_pos,
    char* filename,
    int filename_size
)
{
    int pos;
    int out_pos = 0;
    int quoted = 0;
    int token_length = 9; /* strlen("filename=") */

    if (data == NULL || filename == NULL || filename_size <= 0) {
        return 0;
    }

    filename[0] = '\0';

    pos = filename_token_pos + token_length;

    while (pos < length && (data[pos] == ' ' || data[pos] == '\t')) {
        pos++;
    }

    if (pos < length && data[pos] == '"') {
        quoted = 1;
        pos++;
    }

    while (pos < length && out_pos < filename_size - 1) {
        char ch = data[pos];

        if (quoted) {
            if (ch == '"') {
                break;
            }
        }
        else {
            if (ch == ';' || ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') {
                break;
            }
        }

        filename[out_pos] = ch;
        out_pos++;
        pos++;
    }

    filename[out_pos] = '\0';

    return out_pos > 0;
}

int detect_file_extension_pattern(const char* data, int length, const char* extension)
{
    int i;

    if (data == NULL || length <= 0 || extension == NULL || extension[0] == '\0') {
        return 0;
    }

    if (strcmp(extension, "-") == 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        char filename[DETECTED_FILENAME_SIZE];

        if (!match_token_ignore_case(data, length, i, "filename=")) {
            continue;
        }

        memset(filename, 0, sizeof(filename));

        if (!extract_filename_at(data, length, i, filename, sizeof(filename))) {
            continue;
        }

        if (ends_with_ignore_case(filename, extension)) {
            return 1;
        }
    }

    return 0;
}