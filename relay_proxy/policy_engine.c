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
    POLICY_RULE_TYPE_FILE_EXT = 1
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

    if (type == POLICY_RULE_TYPE_FILE_EXT) {
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

    log_warn("using built-in default policy rules. rule_count=%d", g_policy_rule_count);
}

static int parse_policy_line_no_lock(char* line, int line_number)
{
    char* rule_id_text;
    char* action_text;
    char* type_text;
    char* pattern_text;
    char* reason_text;

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

    if (rule_id_text == NULL ||
        action_text == NULL ||
        type_text == NULL ||
        pattern_text == NULL ||
        reason_text == NULL) {
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

    int line_number = 0;
    int loaded_count = 0;

    policy_engine_lock();

    clear_policy_rules_no_lock();

    if (policy_file_path == NULL || policy_file_path[0] == '\0') {
        log_warn("policy file path is empty. using default policy rules.");
        load_default_policy_rules_no_lock();
        policy_engine_unlock();
        return 0;
    }

    fp = fopen(policy_file_path, "r");
    if (fp == NULL) {
        log_warn("policy file not found: %s", policy_file_path);
        load_default_policy_rules_no_lock();
        policy_engine_unlock();
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int parse_result;

        line_number++;

        remove_newline(line);

        parse_result = parse_policy_line_no_lock(line, line_number);
        if (parse_result > 0) {
            loaded_count++;
        }
    }

    fclose(fp);

    if (loaded_count <= 0) {
        log_warn("policy file has no valid rule. using default policy rules.");
        load_default_policy_rules_no_lock();
        policy_engine_unlock();
        return 0;
    }

    log_info(
        "policy engine initialized from file: %s, rule_count=%d",
        policy_file_path,
        g_policy_rule_count
    );

    policy_engine_unlock();

    return 0;
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

    if (rule->type == POLICY_RULE_TYPE_FILE_EXT) {
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

    default:
        return 0;
    }
}

policy_result_t inspect_policy_text(const char* data, int length)
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

        if (policy_rule_matches(rule, data, length)) {
            result = make_policy_match_result(rule);

            log_security(
                "POLICY matched rule_id=%d type=%s pattern=%s action=%s reason=\"%s\"",
                result.matched_rule_id,
                policy_rule_type_to_string(rule->type),
                rule->pattern,
                policy_action_to_string(result.action),
                result.reason
            );

            policy_engine_unlock();
            return result;
        }
    }

    policy_engine_unlock();

    return result;
}
