#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

typedef enum {
    POLICY_ACTION_ALLOW = 0,
    POLICY_ACTION_BLOCK = 1,
    POLICY_ACTION_LOG_ONLY = 2
} policy_action_t;

typedef struct {
    policy_action_t action;
    int matched_rule_id;
    char keyword[128];
    char reason[256];
} policy_result_t;

int policy_engine_init(const char* policy_file_path);
int policy_engine_reload(const char* policy_file_path);
void policy_engine_cleanup(void);

policy_result_t inspect_policy_text(const char* data, int length);
/* Inspect text already extracted from a document or OCR result. File-envelope
 * rules are skipped so a generic FILE_UPLOAD log rule cannot hide a content
 * BLOCK rule. */
policy_result_t inspect_policy_document_text(const char* data, int length);

#endif
