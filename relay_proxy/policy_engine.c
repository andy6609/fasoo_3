#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <Windows.h>

#include "policy_engine.h"
#include "pattern_detector.h"
#include "logger.h"

#define POLICY_MAX_RULES 128
#define POLICY_PATTERN_SIZE 128
#define POLICY_REASON_SIZE 256
#define POLICY_LINE_SIZE 1024

typedef enum {
    POLICY_RULE_TYPE_FILE_UPLOAD = 0,
    POLICY_RULE_TYPE_FILE_EXT = 1,
    POLICY_RULE_TYPE_KEYWORD = 2,
    POLICY_RULE_TYPE_EMAIL = 3,
    POLICY_RULE_TYPE_PHONE = 4,
    POLICY_RULE_TYPE_RESIDENT_ID = 5,
    POLICY_RULE_TYPE_CREDIT_CARD = 6
} policy_rule_type_t;

typedef struct {
    int rule_id;
    policy_action_t action;
    policy_rule_type_t type;
    char pattern[POLICY_PATTERN_SIZE];
    char reason[POLICY_REASON_SIZE];
} policy_rule_t;

static policy_rule_t g_policy_rules[POLICY_MAX_RULES];
static int g_policy_rule_count = 0;

static CRITICAL_SECTION g_policy_lock;
static int g_policy_lock_ready = 0;

static void policy_engine_ensure_lock(void)
{
    if (!g_policy_lock_ready) {
        InitializeCriticalSection(&g_policy_lock);
        g_policy_lock_ready = 1;
    }
}

static void policy_engine_lock(void)
{
    policy_engine_ensure_lock();
    EnterCriticalSection(&g_policy_lock);
}

static void policy_engine_unlock(void)
{
    LeaveCriticalSection(&g_policy_lock);
}

static void clear_policy_rules_no_lock(void)
{
    memset(g_policy_rules, 0, sizeof(g_policy_rules));
    g_policy_rule_count = 0;
}

static char* trim_text(char* text)
{
    char* end;

    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;

    while (end > text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return text;
}

static void remove_newline(char* text)
{
    int length;

    if (text == NULL) {
        return;
    }

    length = (int)strlen(text);

    while (length > 0 &&
        (text[length - 1] == '\n' || text[length - 1] == '\r')) {
        text[length - 1] = '\0';
        length--;
    }
}

static const char* policy_action_to_string(policy_action_t action)
{
    switch (action) {
    case POLICY_ACTION_BLOCK:
        return "BLOCK";

    case POLICY_ACTION_LOG_ONLY:
        return "LOG_ONLY";

    case POLICY_ACTION_ALLOW:
    default:
        return "ALLOW";
    }
}

static const char* policy_rule_type_to_string(policy_rule_type_t type)
{
    switch (type) {
    case POLICY_RULE_TYPE_FILE_UPLOAD:
        return "FILE_UPLOAD";

    case POLICY_RULE_TYPE_FILE_EXT:
        return "FILE_EXT";

    case POLICY_RULE_TYPE_KEYWORD:
        return "KEYWORD";

    case POLICY_RULE_TYPE_EMAIL:
        return "EMAIL";

    case POLICY_RULE_TYPE_PHONE:
        return "PHONE";

    case POLICY_RULE_TYPE_RESIDENT_ID:
        return "RESIDENT_ID";

    case POLICY_RULE_TYPE_CREDIT_CARD:
        return "CREDIT_CARD";

    default:
        return "UNKNOWN";
    }
}

static int parse_policy_action(const char* action_text, policy_action_t* action)
{
    if (action_text == NULL || action == NULL) {
        return -1;
    }

    if (_stricmp(action_text, "BLOCK") == 0) {
        *action = POLICY_ACTION_BLOCK;
        return 0;
    }

    if (_stricmp(action_text, "LOG_ONLY") == 0) {
        *action = POLICY_ACTION_LOG_ONLY;
        return 0;
    }

    if (_stricmp(action_text, "ALLOW") == 0) {
        *action = POLICY_ACTION_ALLOW;
        return 0;
    }

    return -1;
}

static int parse_policy_rule_type(
    const char* type_text,
    policy_rule_type_t* type
)
{
    if (type_text == NULL || type == NULL) {
        return -1;
    }

    if (_stricmp(type_text, "FILE_UPLOAD") == 0) {
        *type = POLICY_RULE_TYPE_FILE_UPLOAD;
        return 0;
    }

    if (_stricmp(type_text, "FILE_EXT") == 0) {
        *type = POLICY_RULE_TYPE_FILE_EXT;
        return 0;
    }

    if (_stricmp(type_text, "KEYWORD") == 0) {
        *type = POLICY_RULE_TYPE_KEYWORD;
        return 0;
    }
    if (_stricmp(type_text, "EMAIL") == 0) {
        *type = POLICY_RULE_TYPE_EMAIL;
        return 0;
    }
    if (_stricmp(type_text, "PHONE") == 0) {
        *type = POLICY_RULE_TYPE_PHONE;
        return 0;
    }
    if (_stricmp(type_text, "RESIDENT_ID") == 0) {
        *type = POLICY_RULE_TYPE_RESIDENT_ID;
        return 0;
    }
    if (_stricmp(type_text, "CREDIT_CARD") == 0) {
        *type = POLICY_RULE_TYPE_CREDIT_CARD;
        return 0;
    }

    return -1;
}

static int add_policy_rule_no_lock(
    int rule_id,
    policy_action_t action,
    policy_rule_type_t type,
    const char* pattern,
    const char* reason
)
{
    policy_rule_t* rule;

    if (rule_id <= 0) {
        return -1;
    }

    if (g_policy_rule_count >= POLICY_MAX_RULES) {
        return -1;
    }

    if (type == POLICY_RULE_TYPE_FILE_EXT || type == POLICY_RULE_TYPE_KEYWORD) {
        if (pattern == NULL || pattern[0] == '\0' || strcmp(pattern, "-") == 0) {
            return -1;
        }
    }

    rule = &g_policy_rules[g_policy_rule_count];

    memset(rule, 0, sizeof(policy_rule_t));

    rule->rule_id = rule_id;
    rule->action = action;
    rule->type = type;

    if (pattern != NULL && pattern[0] != '\0') {
        strncpy_s(rule->pattern, sizeof(rule->pattern), pattern, _TRUNCATE);
    }
    else {
        strncpy_s(rule->pattern, sizeof(rule->pattern), "-", _TRUNCATE);
    }

    if (reason != NULL && reason[0] != '\0') {
        strncpy_s(rule->reason, sizeof(rule->reason), reason, _TRUNCATE);
    }
    else {
        strncpy_s(rule->reason, sizeof(rule->reason), "No reason", _TRUNCATE);
    }

    g_policy_rule_count++;

    return 0;
}

static void load_default_policy_rules_no_lock(void)
{
    clear_policy_rules_no_lock();

    add_policy_rule_no_lock(1, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".exe", "Executable file upload blocked");
    add_policy_rule_no_lock(2, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".dll", "DLL file upload blocked");
    add_policy_rule_no_lock(3, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".msi", "Installer file upload blocked");
    add_policy_rule_no_lock(4, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".bat", "Batch script upload blocked");
    add_policy_rule_no_lock(5, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".cmd", "Command script upload blocked");
    add_policy_rule_no_lock(6, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".ps1", "PowerShell script upload blocked");
    add_policy_rule_no_lock(7, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".vbs", "VBScript upload blocked");
    add_policy_rule_no_lock(8, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".scr", "Screen saver executable upload blocked");
    add_policy_rule_no_lock(9, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_FILE_EXT,
        ".com", "Executable command upload blocked");
    add_policy_rule_no_lock(10, POLICY_ACTION_LOG_ONLY, POLICY_RULE_TYPE_FILE_UPLOAD,
        "-", "File upload detected. log only");
    add_policy_rule_no_lock(100, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_KEYWORD,
        "대외비", "Confidential Korean document marker detected");
    add_policy_rule_no_lock(101, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_KEYWORD,
        "기밀", "Confidential document marker detected");
    add_policy_rule_no_lock(102, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_KEYWORD,
        "CONFIDENTIAL", "Confidential document marker detected");
    add_policy_rule_no_lock(110, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_RESIDENT_ID,
        "-", "Korean resident registration number detected");
    add_policy_rule_no_lock(111, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_CREDIT_CARD,
        "-", "Credit card number detected");
    add_policy_rule_no_lock(120, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_KEYWORD,
        "BEGIN PRIVATE KEY", "Private key material detected");
    add_policy_rule_no_lock(121, POLICY_ACTION_BLOCK, POLICY_RULE_TYPE_KEYWORD,
        "api_key=", "API key assignment detected");

    log_warn("using built-in default policy rules. rule_count=%d", g_policy_rule_count);
}

static int parse_policy_line_no_lock(char* line, int line_number)
{
    char* rule_id_text;
    char* action_text;
    char* type_text;
    char* pattern_text;
    char* reason_text;
    char* extra_text;

    char* context = NULL;
    char* trimmed_line;

    int rule_id;
    policy_action_t action;
    policy_rule_type_t type;

    trimmed_line = trim_text(line);

    if (trimmed_line == NULL || trimmed_line[0] == '\0') {
        return 0;
    }

    if (trimmed_line[0] == '#') {
        return 0;
    }

    rule_id_text = strtok_s(trimmed_line, "|", &context);
    action_text = strtok_s(NULL, "|", &context);
    type_text = strtok_s(NULL, "|", &context);
    pattern_text = strtok_s(NULL, "|", &context);
    reason_text = strtok_s(NULL, "|", &context);
    extra_text = strtok_s(NULL, "|", &context);

    if (rule_id_text == NULL ||
        action_text == NULL ||
        type_text == NULL ||
        pattern_text == NULL ||
        reason_text == NULL ||
        extra_text != NULL) {
        log_warn("invalid policy line %d. expected: rule_id|action|type|pattern|reason", line_number);
        return -1;
    }

    rule_id_text = trim_text(rule_id_text);
    action_text = trim_text(action_text);
    type_text = trim_text(type_text);
    pattern_text = trim_text(pattern_text);
    reason_text = trim_text(reason_text);

    rule_id = atoi(rule_id_text);
    if (rule_id <= 0) {
        log_warn("invalid rule_id at policy line %d", line_number);
        return -1;
    }

    {
        int index;
        for (index = 0; index < g_policy_rule_count; ++index) {
            if (g_policy_rules[index].rule_id == rule_id) {
                log_warn("duplicate rule_id at policy line %d: %d", line_number, rule_id);
                return -1;
            }
        }
    }

    if (parse_policy_action(action_text, &action) != 0) {
        log_warn("invalid action at policy line %d: %s", line_number, action_text);
        return -1;
    }

    if (parse_policy_rule_type(type_text, &type) != 0) {
        log_warn("invalid rule type at policy line %d: %s", line_number, type_text);
        return -1;
    }

    if (add_policy_rule_no_lock(rule_id, action, type, pattern_text, reason_text) != 0) {
        log_warn("failed to add policy rule at line %d", line_number);
        return -1;
    }

    log_debug(
        "policy rule loaded. rule_id=%d action=%s type=%s pattern=%s",
        rule_id,
        policy_action_to_string(action),
        policy_rule_type_to_string(type),
        pattern_text
    );

    return 1;
}

int policy_engine_init(const char* policy_file_path)
{
    FILE* fp;
    char line[POLICY_LINE_SIZE];
    policy_rule_t previous_rules[POLICY_MAX_RULES];

    int line_number = 0;
    int loaded_count = 0;
    int previous_count;
    int parse_failed = 0;
    int load_result = 0;

    policy_engine_lock();

    previous_count = g_policy_rule_count;
    memcpy(previous_rules, g_policy_rules, sizeof(previous_rules));
    clear_policy_rules_no_lock();

    if (policy_file_path == NULL || policy_file_path[0] == '\0') {
        log_warn("policy file path is empty. policy update rejected.");
        if (previous_count > 0) {
            memcpy(g_policy_rules, previous_rules, sizeof(g_policy_rules));
            g_policy_rule_count = previous_count;
        }
        else {
            load_default_policy_rules_no_lock();
        }
        policy_engine_unlock();
        return -1;
    }

    fp = fopen(policy_file_path, "r");
    if (fp == NULL) {
        log_warn("policy file not found; policy update rejected: %s", policy_file_path);
        if (previous_count > 0) {
            memcpy(g_policy_rules, previous_rules, sizeof(g_policy_rules));
            g_policy_rule_count = previous_count;
        }
        else {
            load_default_policy_rules_no_lock();
        }
        policy_engine_unlock();
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int parse_result;
        size_t line_length;

        line_number++;

        line_length = strlen(line);
        if (line_length == sizeof(line) - 1 && line[line_length - 1] != '\n' && !feof(fp)) {
            int ch;
            log_warn("policy line %d exceeds %d bytes; entire policy update rejected",
                line_number, POLICY_LINE_SIZE - 1);
            parse_failed = 1;
            do { ch = fgetc(fp); } while (ch != '\n' && ch != EOF);
            continue;
        }

        remove_newline(line);

        parse_result = parse_policy_line_no_lock(line, line_number);
        if (parse_result > 0) {
            loaded_count++;
        }
        else if (parse_result < 0) {
            parse_failed = 1;
        }
    }

    if (ferror(fp)) {
        log_warn("policy file read failed; entire policy update rejected: %s", policy_file_path);
        parse_failed = 1;
    }
    if (fclose(fp) != 0) {
        log_warn("policy file close failed; entire policy update rejected: %s", policy_file_path);
        parse_failed = 1;
    }

    if (parse_failed || loaded_count <= 0) {
        log_warn("policy file is incomplete or invalid; keeping the last complete policy");
        if (previous_count > 0) {
            memcpy(g_policy_rules, previous_rules, sizeof(g_policy_rules));
            g_policy_rule_count = previous_count;
        }
        else {
            load_default_policy_rules_no_lock();
        }
        load_result = -1;
    }
    else {
        log_info(
            "policy engine initialized atomically from file: %s, rule_count=%d",
            policy_file_path,
            g_policy_rule_count
        );
    }

    policy_engine_unlock();

    return load_result;
}

int policy_engine_reload(const char* policy_file_path)
{
    log_info("policy reload requested. file=%s",
        policy_file_path != NULL ? policy_file_path : "-");

    return policy_engine_init(policy_file_path);
}

void policy_engine_cleanup(void)
{
    if (!g_policy_lock_ready) {
        return;
    }

    policy_engine_lock();
    clear_policy_rules_no_lock();
    log_info("policy engine cleaned up");
    policy_engine_unlock();

    DeleteCriticalSection(&g_policy_lock);
    g_policy_lock_ready = 0;
}

static policy_result_t make_policy_allow_result(void)
{
    policy_result_t result;

    memset(&result, 0, sizeof(result));
    result.action = POLICY_ACTION_ALLOW;
    result.matched_rule_id = 0;

    return result;
}

static policy_result_t make_policy_match_result(const policy_rule_t* rule)
{
    policy_result_t result;

    memset(&result, 0, sizeof(result));

    if (rule == NULL) {
        result.action = POLICY_ACTION_ALLOW;
        return result;
    }

    result.action = rule->action;
    result.matched_rule_id = rule->rule_id;

    if (rule->type == POLICY_RULE_TYPE_FILE_EXT || rule->type == POLICY_RULE_TYPE_KEYWORD) {
        strncpy_s(result.keyword, sizeof(result.keyword), rule->pattern, _TRUNCATE);
    }
    else {
        strncpy_s(
            result.keyword,
            sizeof(result.keyword),
            policy_rule_type_to_string(rule->type),
            _TRUNCATE
        );
    }

    strncpy_s(result.reason, sizeof(result.reason), rule->reason, _TRUNCATE);

    return result;
}

static int contains_keyword_ignore_case(
    const char* data,
    int data_length,
    const char* keyword
)
{
    int i;
    int keyword_length;

    if (data == NULL || keyword == NULL) {
        return 0;
    }

    if (data_length <= 0 || keyword[0] == '\0') {
        return 0;
    }

    keyword_length = (int)strlen(keyword);

    if (keyword_length <= 0 || data_length < keyword_length) {
        return 0;
    }

    for (i = 0; i <= data_length - keyword_length; i++) {
        if (_strnicmp(data + i, keyword, keyword_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_long_ascii_word(const char* keyword, int keyword_length)
{
    int i;
    if (keyword == NULL || keyword_length < 8) return 0;
    for (i = 0; i < keyword_length; ++i) {
        unsigned char ch = (unsigned char)keyword[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))) return 0;
    }
    return 1;
}

static int ocr_character_matches(unsigned char observed, unsigned char expected)
{
    observed = (unsigned char)tolower(observed);
    expected = (unsigned char)tolower(expected);
    if (observed == expected) return 1;

    /* Frequent OCR substitutions in rendered business-document headings. */
    if (expected == 'i' && (observed == 'l' || observed == '1' || observed == '|')) return 1;
    if (expected == 'o' && observed == '0') return 1;
    if (expected == 's' && observed == '5') return 1;
    if (expected == 'b' && observed == '8') return 1;
    if (expected == 'g' && observed == '6') return 1;
    return 0;
}

static int contains_ocr_tolerant_ascii_keyword(
    const char* data,
    int data_length,
    const char* keyword
)
{
    int keyword_length;
    int start;

    if (data == NULL || keyword == NULL) return 0;
    keyword_length = (int)strlen(keyword);
    if (data_length < keyword_length || !is_long_ascii_word(keyword, keyword_length)) return 0;

    for (start = 0; start <= data_length - keyword_length; ++start) {
        int offset;
        int substitutions = 0;
        for (offset = 0; offset < keyword_length; ++offset) {
            unsigned char observed = (unsigned char)data[start + offset];
            unsigned char expected = (unsigned char)keyword[offset];
            if (tolower(observed) == tolower(expected)) continue;
            if (!ocr_character_matches(observed, expected) || ++substitutions > 2) break;
        }
        if (offset == keyword_length && substitutions > 0) return 1;
    }
    return 0;
}

static int is_ascii_digit(char value)
{
    return value >= '0' && value <= '9';
}

static int korean_resident_id_checksum_valid(const int digits[13])
{
    static const int weights[12] = { 2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5 };
    int sum = 0;
    int index;
    for (index = 0; index < 12; ++index) sum += digits[index] * weights[index];
    return ((11 - (sum % 11)) % 10) == digits[12];
}

static int korean_resident_id_date_valid(const int digits[13])
{
    static const int days_in_month[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int year;
    int month = digits[2] * 10 + digits[3];
    int day = digits[4] * 10 + digits[5];
    int maximum_day;

    if (digits[6] < 1 || digits[6] > 4 || month < 1 || month > 12) return 0;
    year = (digits[6] <= 2 ? 1900 : 2000) + digits[0] * 10 + digits[1];
    maximum_day = days_in_month[month - 1];
    if (month == 2 && (year % 400 == 0 || (year % 4 == 0 && year % 100 != 0))) {
        maximum_day = 29;
    }
    return day >= 1 && day <= maximum_day;
}

static int detect_valid_korean_resident_id(const char* data, int length)
{
    int start;
    if (data == NULL || length <= 0) return 0;

    for (start = 0; start < length; ++start) {
        int digits[13];
        int cursor = start;
        int index;

        if ((start > 0 && is_ascii_digit(data[start - 1])) ||
            !is_ascii_digit(data[cursor])) continue;
        for (index = 0; index < 6; ++index) {
            if (cursor >= length || !is_ascii_digit(data[cursor])) break;
            digits[index] = data[cursor++] - '0';
        }
        if (index != 6) continue;
        if (cursor < length && data[cursor] == '-') ++cursor;
        for (index = 6; index < 13; ++index) {
            if (cursor >= length || !is_ascii_digit(data[cursor])) break;
            digits[index] = data[cursor++] - '0';
        }
        if (index != 13 || (cursor < length && is_ascii_digit(data[cursor]))) continue;
        if (korean_resident_id_date_valid(digits) &&
            korean_resident_id_checksum_valid(digits)) return 1;
    }
    return 0;
}

static int policy_rule_matches(
    const policy_rule_t* rule,
    const char* data,
    int length
)
{
    if (rule == NULL || data == NULL || length <= 0) {
        return 0;
    }

    switch (rule->type) {
    case POLICY_RULE_TYPE_FILE_UPLOAD:
        return detect_file_upload_pattern(data, length);

    case POLICY_RULE_TYPE_FILE_EXT:
        return detect_file_extension_pattern(data, length, rule->pattern);

    case POLICY_RULE_TYPE_KEYWORD:
        return contains_keyword_ignore_case(data, length, rule->pattern) ||
            contains_ocr_tolerant_ascii_keyword(data, length, rule->pattern);

    case POLICY_RULE_TYPE_EMAIL:
        return detect_email_pattern(data, length);

    case POLICY_RULE_TYPE_PHONE:
        return detect_phone_pattern(data, length);

    case POLICY_RULE_TYPE_RESIDENT_ID:
        return detect_valid_korean_resident_id(data, length);

    case POLICY_RULE_TYPE_CREDIT_CARD:
        return detect_credit_card_pattern(data, length);

    default:
        return 0;
    }
}

static int policy_action_priority(policy_action_t action)
{
    if (action == POLICY_ACTION_BLOCK) return 3;
    if (action == POLICY_ACTION_LOG_ONLY) return 2;
    return 1;
}

static policy_result_t inspect_policy_text_internal(
    const char* data,
    int length,
    int document_text_only)
{
    int i;
    policy_result_t result;

    if (data == NULL || length <= 0) {
        return make_policy_allow_result();
    }

    result = make_policy_allow_result();

    policy_engine_lock();

    if (g_policy_rule_count <= 0) {
        log_warn("policy rule count is zero. allowing request.");
        policy_engine_unlock();
        return result;
    }

    for (i = 0; i < g_policy_rule_count; i++) {
        policy_rule_t* rule = &g_policy_rules[i];
        policy_result_t candidate;

        if (document_text_only &&
            (rule->type == POLICY_RULE_TYPE_FILE_UPLOAD ||
             rule->type == POLICY_RULE_TYPE_FILE_EXT)) {
            continue;
        }

        if (policy_rule_matches(rule, data, length)) {
            candidate = make_policy_match_result(rule);

            log_security(
                "POLICY matched rule_id=%d type=%s pattern=%s action=%s reason=\"%s\"",
                candidate.matched_rule_id,
                policy_rule_type_to_string(rule->type),
                rule->pattern,
                policy_action_to_string(candidate.action),
                candidate.reason
            );
            if (result.matched_rule_id == 0 ||
                policy_action_priority(candidate.action) > policy_action_priority(result.action)) {
                result = candidate;
            }
        }
    }

    policy_engine_unlock();

    return result;
}

policy_result_t inspect_policy_text(const char* data, int length)
{
    return inspect_policy_text_internal(data, length, 0);
}

policy_result_t inspect_policy_document_text(const char* data, int length)
{
    return inspect_policy_text_internal(data, length, 1);
}
