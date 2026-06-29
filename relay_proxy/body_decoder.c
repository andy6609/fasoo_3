#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "body_decoder.h"

static int hex_to_int(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

static int contains_ignore_case(const char* text, const char* keyword)
{
    int text_length;
    int keyword_length;
    int i;

    if (text == NULL || keyword == NULL) {
        return 0;
    }

    text_length = (int)strlen(text);
    keyword_length = (int)strlen(keyword);

    if (text_length <= 0 || keyword_length <= 0) {
        return 0;
    }

    if (text_length < keyword_length) {
        return 0;
    }

    for (i = 0; i <= text_length - keyword_length; i++) {
        if (_strnicmp(text + i, keyword, keyword_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_form_urlencoded(const char* content_type)
{
    if (content_type == NULL) {
        return 0;
    }

    return contains_ignore_case(
        content_type,
        "application/x-www-form-urlencoded"
    );
}

static int is_json_content_type(const char* content_type)
{
    if (content_type == NULL) {
        return 0;
    }

    /*
        application/json
        application/problem+json
        application/vnd.api+json
        이런 형태까지 어느 정도 처리하기 위해 json 포함 여부로 판단한다.
    */
    return contains_ignore_case(content_type, "json");
}

static int copy_raw_body(
    const char* input_body,
    int input_length,
    char* output_body,
    int output_size,
    int* output_length
)
{
    int copy_length;

    if (input_body == NULL ||
        output_body == NULL ||
        output_size <= 0 ||
        output_length == NULL) {
        return -1;
    }

    copy_length = input_length;

    if (copy_length >= output_size) {
        copy_length = output_size - 1;
    }

    if (copy_length < 0) {
        copy_length = 0;
    }

    memcpy(output_body, input_body, copy_length);
    output_body[copy_length] = '\0';

    *output_length = copy_length;

    return 0;
}

static int append_char(
    char* output_body,
    int output_size,
    int* out_pos,
    char ch
)
{
    if (output_body == NULL || out_pos == NULL || output_size <= 0) {
        return -1;
    }

    if (*out_pos >= output_size - 1) {
        return -1;
    }

    output_body[*out_pos] = ch;
    (*out_pos)++;

    return 0;
}

static int append_utf8(
    char* output_body,
    int output_size,
    int* out_pos,
    unsigned int codepoint
)
{
    if (output_body == NULL || out_pos == NULL || output_size <= 0) {
        return -1;
    }

    /*
        ASCII
    */
    if (codepoint <= 0x7F) {
        return append_char(output_body, output_size, out_pos, (char)codepoint);
    }

    /*
        2-byte UTF-8
    */
    if (codepoint <= 0x7FF) {
        if (*out_pos + 2 >= output_size) {
            return -1;
        }

        output_body[*out_pos] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | (codepoint & 0x3F));
        (*out_pos)++;

        return 0;
    }

    /*
        3-byte UTF-8
    */
    if (codepoint <= 0xFFFF) {
        if (*out_pos + 3 >= output_size) {
            return -1;
        }

        output_body[*out_pos] = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | (codepoint & 0x3F));
        (*out_pos)++;

        return 0;
    }

    /*
        4-byte UTF-8
    */
    if (codepoint <= 0x10FFFF) {
        if (*out_pos + 4 >= output_size) {
            return -1;
        }

        output_body[*out_pos] = (char)(0xF0 | ((codepoint >> 18) & 0x07));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        (*out_pos)++;

        output_body[*out_pos] = (char)(0x80 | (codepoint & 0x3F));
        (*out_pos)++;

        return 0;
    }

    return -1;
}

static int parse_json_unicode_escape(
    const char* input_body,
    int input_length,
    int pos,
    unsigned int* codepoint
)
{
    int h1;
    int h2;
    int h3;
    int h4;

    if (input_body == NULL || codepoint == NULL) {
        return -1;
    }

    /*
        pos는 '\' 위치라고 가정한다.
        필요한 형태:
        \uXXXX
    */
    if (pos + 5 >= input_length) {
        return -1;
    }

    if (input_body[pos] != '\\' || input_body[pos + 1] != 'u') {
        return -1;
    }

    h1 = hex_to_int(input_body[pos + 2]);
    h2 = hex_to_int(input_body[pos + 3]);
    h3 = hex_to_int(input_body[pos + 4]);
    h4 = hex_to_int(input_body[pos + 5]);

    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) {
        return -1;
    }

    *codepoint =
        ((unsigned int)h1 << 12) |
        ((unsigned int)h2 << 8) |
        ((unsigned int)h3 << 4) |
        ((unsigned int)h4);

    return 0;
}

static int decode_urlencoded_body(
    const char* input_body,
    int input_length,
    char* output_body,
    int output_size,
    int* output_length
)
{
    int i;
    int out_pos;

    if (input_body == NULL ||
        output_body == NULL ||
        output_size <= 0 ||
        output_length == NULL) {
        return -1;
    }

    i = 0;
    out_pos = 0;

    while (i < input_length) {
        char ch = input_body[i];

        if (out_pos >= output_size - 1) {
            break;
        }

        if (ch == '+') {
            output_body[out_pos] = ' ';
            out_pos++;
            i++;
            continue;
        }

        if (ch == '%' && i + 2 < input_length) {
            int high = hex_to_int(input_body[i + 1]);
            int low = hex_to_int(input_body[i + 2]);

            if (high >= 0 && low >= 0) {
                output_body[out_pos] = (char)((high << 4) | low);
                out_pos++;
                i += 3;
                continue;
            }
        }

        output_body[out_pos] = ch;
        out_pos++;
        i++;
    }

    output_body[out_pos] = '\0';
    *output_length = out_pos;

    return 0;
}

static int decode_json_escaped_body(
    const char* input_body,
    int input_length,
    char* output_body,
    int output_size,
    int* output_length
)
{
    int i;
    int out_pos;

    if (input_body == NULL ||
        output_body == NULL ||
        output_size <= 0 ||
        output_length == NULL) {
        return -1;
    }

    i = 0;
    out_pos = 0;

    while (i < input_length) {
        char ch;

        if (out_pos >= output_size - 1) {
            break;
        }

        ch = input_body[i];

        if (ch != '\\') {
            output_body[out_pos] = ch;
            out_pos++;
            i++;
            continue;
        }

        /*
            여기부터 JSON escape 처리.
            예:
            \" \\ \/ \n \r \t \u0040
        */
        if (i + 1 >= input_length) {
            output_body[out_pos] = ch;
            out_pos++;
            i++;
            continue;
        }

        switch (input_body[i + 1]) {
        case '"':
            append_char(output_body, output_size, &out_pos, '"');
            i += 2;
            break;

        case '\\':
            append_char(output_body, output_size, &out_pos, '\\');
            i += 2;
            break;

        case '/':
            append_char(output_body, output_size, &out_pos, '/');
            i += 2;
            break;

        case 'b':
            append_char(output_body, output_size, &out_pos, '\b');
            i += 2;
            break;

        case 'f':
            append_char(output_body, output_size, &out_pos, '\f');
            i += 2;
            break;

        case 'n':
            append_char(output_body, output_size, &out_pos, '\n');
            i += 2;
            break;

        case 'r':
            append_char(output_body, output_size, &out_pos, '\r');
            i += 2;
            break;

        case 't':
            append_char(output_body, output_size, &out_pos, '\t');
            i += 2;
            break;

        case 'u':
        {
            unsigned int codepoint;

            if (parse_json_unicode_escape(input_body, input_length, i, &codepoint) == 0) {
                /*
                    \u0040 → @
                    \u002E → .
                    같은 ASCII escape를 복원할 수 있다.
                */
                if (append_utf8(output_body, output_size, &out_pos, codepoint) != 0) {
                    output_body[out_pos] = '\0';
                    *output_length = out_pos;
                    return 0;
                }

                i += 6;
            }
            else {
                /*
                    잘못된 \u escape면 원본 그대로 보존한다.
                */
                append_char(output_body, output_size, &out_pos, input_body[i]);
                i++;
            }

            break;
        }

        default:
            /*
                알 수 없는 escape면 '\'는 제거하지 않고 그대로 보존한다.
            */
            append_char(output_body, output_size, &out_pos, input_body[i]);
            i++;
            break;
        }
    }

    output_body[out_pos] = '\0';
    *output_length = out_pos;

    return 0;
}

int decode_body_for_inspection(
    const char* content_type,
    const char* input_body,
    int input_length,
    char* output_body,
    int output_size,
    int* output_length
)
{
    if (input_body == NULL ||
        output_body == NULL ||
        output_size <= 0 ||
        output_length == NULL) {
        return -1;
    }

    if (input_length <= 0) {
        output_body[0] = '\0';
        *output_length = 0;
        return 0;
    }

    if (is_form_urlencoded(content_type)) {
        return decode_urlencoded_body(
            input_body,
            input_length,
            output_body,
            output_size,
            output_length
        );
    }

    if (is_json_content_type(content_type)) {
        return decode_json_escaped_body(
            input_body,
            input_length,
            output_body,
            output_size,
            output_length
        );
    }

    return copy_raw_body(
        input_body,
        input_length,
        output_body,
        output_size,
        output_length
    );
}