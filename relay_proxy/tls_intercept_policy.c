#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <Windows.h>

#include "tls_intercept_policy.h"
#include "logger.h"

typedef struct tls_intercept_rule {
    char process[TLS_INTERCEPT_POLICY_PROCESS_SIZE];
    int process_match_all;
    char host[TLS_INTERCEPT_POLICY_HOST_SIZE];
    int port;
    int wildcard_suffix;
    int match_all;
    int is_default;
    tls_intercept_action_t action;
    char reason[TLS_INTERCEPT_POLICY_REASON_SIZE];
} tls_intercept_rule_t;

static tls_intercept_rule_t g_rules[TLS_INTERCEPT_POLICY_MAX_RULES];
static int g_rule_count = 0;
static int g_loaded = 0;
static tls_intercept_action_t g_default_action = TLS_INTERCEPT_ACTION_BYPASS;
static char g_default_reason[TLS_INTERCEPT_POLICY_REASON_SIZE] = "default bypass";

static void tls_intercept_policy_lowercase(char* text)
{
    int i;

    if (text == NULL) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        text[i] = (char)tolower((unsigned char)text[i]);
    }
}

static void tls_intercept_policy_trim(char* text)
{
    char* start;
    char* end;
    size_t len;

    if (text == NULL) {
        return;
    }

    start = text;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    if (start != text) {
        memmove(text, start, strlen(start) + 1);
    }

    len = strlen(text);
    if (len == 0) {
        return;
    }

    end = text + len - 1;
    while (end >= text && isspace((unsigned char)*end)) {
        *end = '\0';
        if (end == text) {
            break;
        }
        end--;
    }
}

static void tls_intercept_policy_remove_inline_comment(char* text)
{
    char* comment;

    if (text == NULL) {
        return;
    }

    comment = strchr(text, '#');
    if (comment != NULL) {
        *comment = '\0';
    }

    comment = strchr(text, ';');
    if (comment != NULL) {
        *comment = '\0';
    }
}

static int tls_intercept_policy_parse_port(const char* text)
{
    long value;
    char* end_ptr;

    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    end_ptr = NULL;
    value = strtol(text, &end_ptr, 10);

    if (end_ptr == text || *end_ptr != '\0') {
        return -1;
    }

    if (value < 1 || value > 65535) {
        return -1;
    }

    return (int)value;
}

const char* tls_intercept_policy_action_to_string(tls_intercept_action_t action)
{
    switch (action) {
    case TLS_INTERCEPT_ACTION_MITM:
        return "MITM";
    case TLS_INTERCEPT_ACTION_BLOCK:
        return "BLOCK";
    case TLS_INTERCEPT_ACTION_AUDIT:
        return "AUDIT";
    case TLS_INTERCEPT_ACTION_IGNORE:
        return "IGNORE";
    case TLS_INTERCEPT_ACTION_BYPASS:
    default:
        return "BYPASS";
    }
}

static int tls_intercept_policy_parse_action(
    const char* text,
    tls_intercept_action_t* action
)
{
    if (text == NULL || action == NULL) {
        return -1;
    }

    if (_stricmp(text, "MITM") == 0 || _stricmp(text, "INTERCEPT") == 0 || _stricmp(text, "DECRYPT") == 0) {
        *action = TLS_INTERCEPT_ACTION_MITM;
        return 0;
    }

    if (_stricmp(text, "BYPASS") == 0 || _stricmp(text, "TUNNEL") == 0 || _stricmp(text, "RAW") == 0) {
        *action = TLS_INTERCEPT_ACTION_BYPASS;
        return 0;
    }

    if (_stricmp(text, "BLOCK") == 0 || _stricmp(text, "DENY") == 0) {
        *action = TLS_INTERCEPT_ACTION_BLOCK;
        return 0;
    }

    if (_stricmp(text, "AUDIT") == 0 || _stricmp(text, "LOG") == 0 || _stricmp(text, "LOG_ONLY") == 0) {
        *action = TLS_INTERCEPT_ACTION_AUDIT;
        return 0;
    }

    if (_stricmp(text, "IGNORE") == 0 || _stricmp(text, "SILENT") == 0 || _stricmp(text, "NOLOG") == 0) {
        *action = TLS_INTERCEPT_ACTION_IGNORE;
        return 0;
    }

    return -1;
}

static void tls_intercept_policy_set_default_reason(const char* reason)
{
    if (reason == NULL || reason[0] == '\0') {
        _snprintf_s(g_default_reason, sizeof(g_default_reason), _TRUNCATE, "default %s", tls_intercept_policy_action_to_string(g_default_action));
        return;
    }

    _snprintf_s(g_default_reason, sizeof(g_default_reason), _TRUNCATE, "%s", reason);
}

static void tls_intercept_policy_parse_process(
    const char* raw_process,
    char* out_process,
    size_t out_process_size,
    int* out_match_all
)
{
    char process_text[TLS_INTERCEPT_POLICY_PROCESS_SIZE];

    if (out_process == NULL || out_match_all == NULL) {
        return;
    }

    memset(out_process, 0, out_process_size);
    *out_match_all = 1;
    _snprintf_s(out_process, out_process_size, _TRUNCATE, "*");

    if (raw_process == NULL || raw_process[0] == '\0') {
        return;
    }

    memset(process_text, 0, sizeof(process_text));
    _snprintf_s(process_text, sizeof(process_text), _TRUNCATE, "%s", raw_process);
    tls_intercept_policy_trim(process_text);

    if (_strnicmp(process_text, "process=", 8) == 0) {
        memmove(process_text, process_text + 8, strlen(process_text + 8) + 1);
    }
    else if (_strnicmp(process_text, "proc=", 5) == 0) {
        memmove(process_text, process_text + 5, strlen(process_text + 5) + 1);
    }
    else if (_strnicmp(process_text, "app=", 4) == 0) {
        memmove(process_text, process_text + 4, strlen(process_text + 4) + 1);
    }

    tls_intercept_policy_trim(process_text);
    tls_intercept_policy_lowercase(process_text);

    if (process_text[0] == '\0' || strcmp(process_text, "*") == 0 || _stricmp(process_text, "ANY") == 0) {
        *out_match_all = 1;
        _snprintf_s(out_process, out_process_size, _TRUNCATE, "*");
        return;
    }

    *out_match_all = 0;
    _snprintf_s(out_process, out_process_size, _TRUNCATE, "%s", process_text);
}

static int tls_intercept_policy_parse_target(
    const char* raw_target,
    char* out_host,
    size_t out_host_size,
    int* out_port,
    int* out_match_all,
    int* out_wildcard_suffix
)
{
    char target[512];
    char* host_text;
    char* colon;
    int colon_count;
    int i;
    int port;

    if (raw_target == NULL || out_host == NULL || out_port == NULL || out_match_all == NULL || out_wildcard_suffix == NULL) {
        return -1;
    }

    memset(target, 0, sizeof(target));
    _snprintf_s(target, sizeof(target), _TRUNCATE, "%s", raw_target);
    tls_intercept_policy_trim(target);

    if (_strnicmp(target, "host=", 5) == 0) {
        memmove(target, target + 5, strlen(target + 5) + 1);
        tls_intercept_policy_trim(target);
    }

    if (target[0] == '\0') {
        return -1;
    }

    colon_count = 0;
    for (i = 0; target[i] != '\0'; i++) {
        if (target[i] == ':') {
            colon_count++;
        }
    }

    port = 0;
    host_text = target;

    if (colon_count == 1) {
        colon = strrchr(target, ':');
        if (colon != NULL) {
            int parsed_port;

            *colon = '\0';
            parsed_port = tls_intercept_policy_parse_port(colon + 1);
            if (parsed_port < 0) {
                return -1;
            }
            port = parsed_port;
        }
    }
    else if (colon_count > 1) {
        return -1;
    }

    tls_intercept_policy_trim(host_text);
    tls_intercept_policy_lowercase(host_text);

    if (host_text[0] == '\0') {
        return -1;
    }

    *out_match_all = 0;
    *out_wildcard_suffix = 0;
    *out_port = port;
    memset(out_host, 0, out_host_size);

    if (strcmp(host_text, "*") == 0) {
        *out_match_all = 1;
        _snprintf_s(out_host, out_host_size, _TRUNCATE, "*");
    }
    else if (strncmp(host_text, "*.", 2) == 0 && strlen(host_text) > 2) {
        *out_wildcard_suffix = 1;
        _snprintf_s(out_host, out_host_size, _TRUNCATE, "%s", host_text + 1);
    }
    else {
        _snprintf_s(out_host, out_host_size, _TRUNCATE, "%s", host_text);
    }

    return 0;
}

static int tls_intercept_policy_wildcard_match_ci(const char* pattern, const char* text)
{
    if (pattern == NULL || text == NULL) {
        return 0;
    }

    while (*pattern != '\0') {
        if (*pattern == '*') {
            pattern++;
            if (*pattern == '\0') {
                return 1;
            }
            while (*text != '\0') {
                if (tls_intercept_policy_wildcard_match_ci(pattern, text)) {
                    return 1;
                }
                text++;
            }
            return 0;
        }

        if (*text == '\0') {
            return 0;
        }

        if (tolower((unsigned char)*pattern) != tolower((unsigned char)*text)) {
            return 0;
        }

        pattern++;
        text++;
    }

    return *text == '\0';
}


static char* tls_intercept_policy_reason_after_action(const char* raw_text, const char* action_token, char* out_reason, size_t out_reason_size)
{
    const char* action_pos;

    if (raw_text == NULL || action_token == NULL || out_reason == NULL || out_reason_size == 0) {
        return NULL;
    }

    memset(out_reason, 0, out_reason_size);

    action_pos = strstr(raw_text, action_token);
    if (action_pos == NULL) {
        return NULL;
    }

    action_pos += strlen(action_token);
    while (*action_pos != '\0' && isspace((unsigned char)*action_pos)) {
        action_pos++;
    }

    if (*action_pos == '\0') {
        return NULL;
    }

    _snprintf_s(out_reason, out_reason_size, _TRUNCATE, "%s", action_pos);
    tls_intercept_policy_remove_inline_comment(out_reason);
    tls_intercept_policy_trim(out_reason);

    return out_reason[0] != '\0' ? out_reason : NULL;
}

static int tls_intercept_policy_add_rule_text(const char* raw_text, int line_number)
{
    char line[768];
    char* context;
    char* first_token;
    char* second_token;
    char* third_token;
    char* process_token;
    char* target_token;
    char* action_token;
    char* reason_text;
    char reason_storage[TLS_INTERCEPT_POLICY_REASON_SIZE];
    tls_intercept_action_t action;
    tls_intercept_rule_t* rule;

    if (raw_text == NULL) {
        return 0;
    }

    memset(line, 0, sizeof(line));
    memset(reason_storage, 0, sizeof(reason_storage));
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s", raw_text);

    tls_intercept_policy_remove_inline_comment(line);
    tls_intercept_policy_trim(line);

    if (line[0] == '\0') {
        return 0;
    }

    context = NULL;
    first_token = strtok_s(line, " \t\r\n", &context);
    second_token = strtok_s(NULL, " \t\r\n", &context);
    third_token = strtok_s(NULL, " \t\r\n", &context);

    if (first_token == NULL || second_token == NULL) {
        log_warn("TLS intercept policy ignored invalid line. line=%d text=%s", line_number, raw_text);
        return -1;
    }

    tls_intercept_policy_trim(first_token);
    tls_intercept_policy_trim(second_token);
    if (third_token != NULL) {
        tls_intercept_policy_trim(third_token);
    }

    if (_stricmp(first_token, "DEFAULT") == 0) {
        reason_text = tls_intercept_policy_reason_after_action(raw_text, second_token, reason_storage, sizeof(reason_storage));

        if (tls_intercept_policy_parse_action(second_token, &action) != 0) {
            log_warn(
                "TLS intercept policy ignored DEFAULT line with invalid action. line=%d action=%s text=%s",
                line_number,
                second_token,
                raw_text
            );
            return -1;
        }

        g_default_action = action;
        tls_intercept_policy_set_default_reason(reason_text);

        log_info(
            "TLS intercept policy default action loaded. action=%s reason=\"%s\"",
            tls_intercept_policy_action_to_string(g_default_action),
            g_default_reason
        );
        return 1;
    }

    process_token = "*";
    target_token = first_token;
    action_token = second_token;
    reason_text = third_token;

    if (tls_intercept_policy_parse_action(second_token, &action) == 0) {
        reason_text = third_token;
        if (reason_text != NULL && context != NULL && context[0] != '\0') {
            size_t used = strlen(reason_text);
            if (used + 1 < 512) {
                reason_text = second_token + strlen(second_token) + 1;
            }
        }
        reason_text = third_token;
        if (reason_text != NULL && context != NULL && context[0] != '\0') {
            /* strtok_s already placed the third token at the start of the reason. Use the raw context tail through reconstruction below. */
        }
    }
    else if (third_token != NULL && tls_intercept_policy_parse_action(third_token, &action) == 0) {
        process_token = first_token;
        target_token = second_token;
        action_token = third_token;
        reason_text = context;
    }
    else {
        log_warn(
            "TLS intercept policy ignored line with invalid action. line=%d text=%s",
            line_number,
            raw_text
        );
        return -1;
    }

    if (process_token == first_token && target_token == second_token) {
        /* Process-aware syntax: <process> <target> <action> [reason]. */
        if (reason_text != NULL) {
            tls_intercept_policy_trim(reason_text);
        }
    }
    else {
        /* Legacy syntax: <target> <action> [reason]. Need to keep the first reason word. */
        reason_text = tls_intercept_policy_reason_after_action(raw_text, action_token, reason_storage, sizeof(reason_storage));
    }

    if (reason_text != NULL) {
        char reason_copy[TLS_INTERCEPT_POLICY_REASON_SIZE];
        memset(reason_copy, 0, sizeof(reason_copy));
        _snprintf_s(reason_copy, sizeof(reason_copy), _TRUNCATE, "%s", reason_text);
        tls_intercept_policy_remove_inline_comment(reason_copy);
        tls_intercept_policy_trim(reason_copy);
        reason_text = reason_copy[0] != '\0' ? reason_text : NULL;
    }

    if (g_rule_count >= TLS_INTERCEPT_POLICY_MAX_RULES) {
        log_warn("TLS intercept policy rule limit reached. ignored line=%d text=%s", line_number, raw_text);
        return -1;
    }

    rule = &g_rules[g_rule_count];
    memset(rule, 0, sizeof(*rule));

    tls_intercept_policy_parse_process(
        process_token,
        rule->process,
        sizeof(rule->process),
        &rule->process_match_all
    );

    if (tls_intercept_policy_parse_target(
            target_token,
            rule->host,
            sizeof(rule->host),
            &rule->port,
            &rule->match_all,
            &rule->wildcard_suffix) != 0) {
        log_warn("TLS intercept policy ignored invalid target. line=%d target=%s", line_number, target_token);
        return -1;
    }

    rule->action = action;
    if (reason_text != NULL && reason_text[0] != '\0') {
        _snprintf_s(rule->reason, sizeof(rule->reason), _TRUNCATE, "%s", reason_text);
        tls_intercept_policy_remove_inline_comment(rule->reason);
        tls_intercept_policy_trim(rule->reason);
    }
    else {
        _snprintf_s(rule->reason, sizeof(rule->reason), _TRUNCATE, "%s rule", tls_intercept_policy_action_to_string(action));
    }

    g_rule_count++;

    log_info(
        "TLS intercept policy rule loaded. index=%d process=%s host=%s port=%d action=%s host_mode=%s reason=\"%s\"",
        g_rule_count,
        rule->process,
        rule->host,
        rule->port,
        tls_intercept_policy_action_to_string(rule->action),
        rule->match_all ? "match_all" : (rule->wildcard_suffix ? "wildcard_suffix" : "exact"),
        rule->reason
    );

    return 1;
}

static void tls_intercept_policy_load_safe_defaults(void)
{
    int dummy_line = 0;

    g_rule_count = 0;
    memset(g_rules, 0, sizeof(g_rules));
    g_default_action = TLS_INTERCEPT_ACTION_BYPASS;
    tls_intercept_policy_set_default_reason("safe default bypass for non-target CONNECT traffic");

    tls_intercept_policy_add_rule_text("demo.local:9443 MITM local_browser_test", ++dummy_line);
    tls_intercept_policy_add_rule_text("127.0.0.1:9443 MITM loopback_tls_test", ++dummy_line);
    tls_intercept_policy_add_rule_text("localhost:9443 MITM localhost_tls_test", ++dummy_line);

    log_warn(
        "TLS intercept policy using safe defaults. demo.local/127.0.0.1/localhost:9443 are MITM; all others are BYPASS."
    );
}

int tls_intercept_policy_load(const char* path)
{
    FILE* fp;
    char line[768];
    int line_number = 0;

    g_rule_count = 0;
    g_loaded = 0;
    memset(g_rules, 0, sizeof(g_rules));
    g_default_action = TLS_INTERCEPT_ACTION_BYPASS;
    tls_intercept_policy_set_default_reason("default bypass");

    if (path == NULL || path[0] == '\0') {
        tls_intercept_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        log_warn(
            "TLS intercept policy file not found. path=%s. Using safe defaults.",
            path
        );
        tls_intercept_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_number++;
        if (tls_intercept_policy_add_rule_text(line, line_number) < 0) {
            log_warn(
                "TLS intercept policy ignored invalid line. path=%s line=%d",
                path,
                line_number
            );
        }
    }

    fclose(fp);

    if (g_rule_count <= 0) {
        log_warn(
            "TLS intercept policy contains no explicit rules. path=%s. Using safe defaults.",
            path
        );
        tls_intercept_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    g_loaded = 1;

    log_info(
        "TLS intercept policy loaded. path=%s rule_count=%d default_action=%s default_reason=\"%s\"",
        path,
        g_rule_count,
        tls_intercept_policy_action_to_string(g_default_action),
        g_default_reason
    );

    return 0;
}

static int tls_intercept_policy_process_matches(
    const tls_intercept_rule_t* rule,
    const char* process_name
)
{
    if (rule == NULL) {
        return 0;
    }

    if (rule->process_match_all) {
        return 1;
    }

    if (process_name == NULL || process_name[0] == '\0') {
        return 0;
    }

    return tls_intercept_policy_wildcard_match_ci(rule->process, process_name);
}

static int tls_intercept_policy_host_matches(
    const tls_intercept_rule_t* rule,
    const char* host
)
{
    size_t host_len;
    size_t suffix_len;

    if (rule == NULL || host == NULL) {
        return 0;
    }

    if (rule->match_all) {
        return 1;
    }

    if (rule->wildcard_suffix) {
        host_len = strlen(host);
        suffix_len = strlen(rule->host);

        if (host_len <= suffix_len) {
            return 0;
        }

        return _stricmp(host + host_len - suffix_len, rule->host) == 0;
    }

    return _stricmp(host, rule->host) == 0;
}

static void tls_intercept_policy_fill_decision(
    tls_intercept_decision_t* decision,
    const char* host,
    int port,
    const char* process_name,
    const tls_intercept_rule_t* rule,
    int matched,
    int matched_default
)
{
    if (decision == NULL) {
        return;
    }

    memset(decision, 0, sizeof(*decision));
    decision->port = port;
    decision->matched = matched;
    decision->matched_default = matched_default;

    if (host != NULL) {
        _snprintf_s(decision->host, sizeof(decision->host), _TRUNCATE, "%s", host);
    }

    if (process_name != NULL) {
        _snprintf_s(decision->process_name, sizeof(decision->process_name), _TRUNCATE, "%s", process_name);
    }

    if (rule != NULL) {
        decision->action = rule->action;
        decision->rule_port = rule->port;
        _snprintf_s(decision->rule_process, sizeof(decision->rule_process), _TRUNCATE, "%s", rule->process);
        _snprintf_s(decision->rule_host, sizeof(decision->rule_host), _TRUNCATE, "%s", rule->host);
        _snprintf_s(decision->reason, sizeof(decision->reason), _TRUNCATE, "%s", rule->reason);
    }
    else {
        decision->action = g_default_action;
        decision->rule_port = 0;
        _snprintf_s(decision->rule_process, sizeof(decision->rule_process), _TRUNCATE, "DEFAULT");
        _snprintf_s(decision->rule_host, sizeof(decision->rule_host), _TRUNCATE, "DEFAULT");
        _snprintf_s(decision->reason, sizeof(decision->reason), _TRUNCATE, "%s", g_default_reason);
    }
}

static int tls_intercept_policy_decide_with_process_internal(
    const char* host,
    int port,
    const char* process_name,
    tls_intercept_decision_t* decision,
    int log_decision
)
{
    char clean_host[TLS_INTERCEPT_POLICY_HOST_SIZE];
    char clean_process[TLS_INTERCEPT_POLICY_PROCESS_SIZE];
    int i;

    if (!g_loaded) {
        tls_intercept_policy_load_safe_defaults();
        g_loaded = 1;
    }

    memset(clean_process, 0, sizeof(clean_process));
    if (process_name != NULL && process_name[0] != '\0') {
        _snprintf_s(clean_process, sizeof(clean_process), _TRUNCATE, "%s", process_name);
    }
    else {
        _snprintf_s(clean_process, sizeof(clean_process), _TRUNCATE, "-");
    }
    tls_intercept_policy_trim(clean_process);
    tls_intercept_policy_lowercase(clean_process);

    if (host == NULL || host[0] == '\0') {
        tls_intercept_policy_fill_decision(decision, "-", port, clean_process, NULL, 0, 1);
        if (log_decision) {
            log_info(
                "TLS intercept policy decision. process=%s host=- port=%d action=%s matched=default reason=\"%s\"",
                clean_process,
                port,
                tls_intercept_policy_action_to_string(g_default_action),
                g_default_reason
            );
        }
        return 0;
    }

    memset(clean_host, 0, sizeof(clean_host));
    _snprintf_s(clean_host, sizeof(clean_host), _TRUNCATE, "%s", host);
    tls_intercept_policy_trim(clean_host);
    tls_intercept_policy_lowercase(clean_host);

    for (i = 0; i < g_rule_count; i++) {
        const tls_intercept_rule_t* rule = &g_rules[i];

        if (!tls_intercept_policy_process_matches(rule, clean_process)) {
            continue;
        }

        if (rule->port != 0 && rule->port != port) {
            continue;
        }

        if (tls_intercept_policy_host_matches(rule, clean_host)) {
            tls_intercept_policy_fill_decision(decision, clean_host, port, clean_process, rule, 1, 0);

            if (log_decision && rule->action != TLS_INTERCEPT_ACTION_IGNORE) {
                log_info(
                    "TLS intercept policy decision. process=%s host=%s port=%d action=%s matched=rule rule_process=%s rule_host=%s rule_port=%d reason=\"%s\"",
                    clean_process,
                    clean_host,
                    port,
                    tls_intercept_policy_action_to_string(rule->action),
                    rule->process,
                    rule->host,
                    rule->port,
                    rule->reason
                );
            }

            return 1;
        }
    }

    tls_intercept_policy_fill_decision(decision, clean_host, port, clean_process, NULL, 0, 1);

    if (log_decision) {
        log_info(
            "TLS intercept policy decision. process=%s host=%s port=%d action=%s matched=default reason=\"%s\"",
            clean_process,
            clean_host,
            port,
            tls_intercept_policy_action_to_string(g_default_action),
            g_default_reason
        );
    }

    return 0;
}

int tls_intercept_policy_decide_with_process(
    const char* host,
    int port,
    const char* process_name,
    tls_intercept_decision_t* decision
)
{
    return tls_intercept_policy_decide_with_process_internal(host, port, process_name, decision, 1);
}

int tls_intercept_policy_decide_with_process_silent(
    const char* host,
    int port,
    const char* process_name,
    tls_intercept_decision_t* decision
)
{
    return tls_intercept_policy_decide_with_process_internal(host, port, process_name, decision, 0);
}

int tls_intercept_policy_decide(
    const char* host,
    int port,
    tls_intercept_decision_t* decision
)
{
    return tls_intercept_policy_decide_with_process(host, port, "-", decision);
}

void tls_intercept_policy_cleanup(void)
{
    g_rule_count = 0;
    g_loaded = 0;
    memset(g_rules, 0, sizeof(g_rules));
    g_default_action = TLS_INTERCEPT_ACTION_BYPASS;
    tls_intercept_policy_set_default_reason("default bypass");
}
