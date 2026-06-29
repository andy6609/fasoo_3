#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <Windows.h>

#include "mitm_target_policy.h"
#include "logger.h"

typedef struct mitm_target_rule {
    char host[MITM_TARGET_POLICY_HOST_SIZE];
    int port;
    int wildcard_suffix;
    int match_all;
} mitm_target_rule_t;

static mitm_target_rule_t g_rules[MITM_TARGET_POLICY_MAX_RULES];
static int g_rule_count = 0;
static int g_loaded = 0;

static void mitm_target_policy_lowercase(char* text)
{
    int i;

    if (text == NULL) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        text[i] = (char)tolower((unsigned char)text[i]);
    }
}

static void mitm_target_policy_trim(char* text)
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

static void mitm_target_policy_remove_inline_comment(char* text)
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

static int mitm_target_policy_parse_port(const char* text)
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

static int mitm_target_policy_add_rule_text(const char* raw_text)
{
    char line[512];
    char* host_text;
    char* colon;
    int colon_count = 0;
    int i;
    int port = 0;
    mitm_target_rule_t* rule;

    if (raw_text == NULL) {
        return 0;
    }

    memset(line, 0, sizeof(line));
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s", raw_text);

    mitm_target_policy_remove_inline_comment(line);
    mitm_target_policy_trim(line);

    if (line[0] == '\0') {
        return 0;
    }

    if (_strnicmp(line, "host=", 5) == 0) {
        memmove(line, line + 5, strlen(line + 5) + 1);
        mitm_target_policy_trim(line);
    }

    for (i = 0; line[i] != '\0'; i++) {
        if (line[i] == ':') {
            colon_count++;
        }
    }

    host_text = line;

    /* IPv6 literal rules are intentionally kept simple in this POC.
       For normal browser tests, use DNS names or IPv4 targets. */
    if (colon_count == 1) {
        colon = strrchr(line, ':');
        if (colon != NULL) {
            int parsed_port;

            *colon = '\0';
            parsed_port = mitm_target_policy_parse_port(colon + 1);
            if (parsed_port < 0) {
                log_warn("MITM target policy ignored invalid port rule: %s", raw_text);
                return -1;
            }

            port = parsed_port;
        }
    }
    else if (colon_count > 1) {
        log_warn("MITM target policy ignored IPv6-style or invalid rule: %s", raw_text);
        return -1;
    }

    mitm_target_policy_trim(host_text);
    mitm_target_policy_lowercase(host_text);

    if (host_text[0] == '\0') {
        return 0;
    }

    if (g_rule_count >= MITM_TARGET_POLICY_MAX_RULES) {
        log_warn("MITM target policy rule limit reached. ignored rule=%s", raw_text);
        return -1;
    }

    rule = &g_rules[g_rule_count];
    memset(rule, 0, sizeof(*rule));

    if (strcmp(host_text, "*") == 0) {
        rule->match_all = 1;
        _snprintf_s(rule->host, sizeof(rule->host), _TRUNCATE, "*");
    }
    else if (strncmp(host_text, "*.", 2) == 0 && strlen(host_text) > 2) {
        rule->wildcard_suffix = 1;
        _snprintf_s(rule->host, sizeof(rule->host), _TRUNCATE, "%s", host_text + 1);
    }
    else {
        _snprintf_s(rule->host, sizeof(rule->host), _TRUNCATE, "%s", host_text);
    }

    rule->port = port;
    g_rule_count++;

    log_info(
        "MITM target policy rule loaded. index=%d host=%s port=%s mode=%s",
        g_rule_count,
        rule->host,
        rule->port == 0 ? "any" : (port == 443 ? "443" : (port == 9443 ? "9443" : "custom")),
        rule->match_all ? "match_all" : (rule->wildcard_suffix ? "wildcard_suffix" : "exact")
    );

    return 1;
}

static void mitm_target_policy_load_safe_defaults(void)
{
    g_rule_count = 0;
    memset(g_rules, 0, sizeof(g_rules));

    mitm_target_policy_add_rule_text("demo.local:9443");
    mitm_target_policy_add_rule_text("127.0.0.1:9443");
    mitm_target_policy_add_rule_text("localhost:9443");

    log_warn(
        "MITM target policy using safe defaults. Only demo.local/127.0.0.1/localhost on port 9443 will be decrypted."
    );
}

int mitm_target_policy_load(const char* path)
{
    FILE* fp;
    char line[512];
    int line_number = 0;

    g_rule_count = 0;
    g_loaded = 0;
    memset(g_rules, 0, sizeof(g_rules));

    if (path == NULL || path[0] == '\0') {
        mitm_target_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        log_warn(
            "MITM target policy file not found. path=%s. Using safe defaults.",
            path
        );
        mitm_target_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_number++;
        if (mitm_target_policy_add_rule_text(line) < 0) {
            log_warn(
                "MITM target policy ignored invalid line. path=%s line=%d",
                path,
                line_number
            );
        }
    }

    fclose(fp);

    if (g_rule_count <= 0) {
        log_warn(
            "MITM target policy file contains no usable rules. path=%s. Using safe defaults.",
            path
        );
        mitm_target_policy_load_safe_defaults();
        g_loaded = 1;
        return -1;
    }

    g_loaded = 1;

    log_info(
        "MITM target policy loaded. path=%s rule_count=%d",
        path,
        g_rule_count
    );

    return 0;
}

static int mitm_target_policy_host_matches(
    const mitm_target_rule_t* rule,
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

int mitm_target_policy_is_allowed(const char* host, int port)
{
    char clean_host[MITM_TARGET_POLICY_HOST_SIZE];
    int i;

    if (!g_loaded) {
        mitm_target_policy_load_safe_defaults();
        g_loaded = 1;
    }

    if (host == NULL || host[0] == '\0') {
        return 0;
    }

    memset(clean_host, 0, sizeof(clean_host));
    _snprintf_s(clean_host, sizeof(clean_host), _TRUNCATE, "%s", host);
    mitm_target_policy_trim(clean_host);
    mitm_target_policy_lowercase(clean_host);

    for (i = 0; i < g_rule_count; i++) {
        const mitm_target_rule_t* rule = &g_rules[i];

        if (rule->port != 0 && rule->port != port) {
            continue;
        }

        if (mitm_target_policy_host_matches(rule, clean_host)) {
            log_info(
                "MITM target policy matched. host=%s port=%d rule_host=%s rule_port=%d",
                clean_host,
                port,
                rule->host,
                rule->port
            );
            return 1;
        }
    }

    log_info(
        "MITM target policy not matched. host=%s port=%d action=bypass_raw_tunnel",
        clean_host,
        port
    );

    return 0;
}

void mitm_target_policy_cleanup(void)
{
    g_rule_count = 0;
    g_loaded = 0;
    memset(g_rules, 0, sizeof(g_rules));
}
