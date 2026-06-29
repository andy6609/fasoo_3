#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#include "dlp_engine.h"
#include "policy_engine.h"
#include "body_decoder.h"
#include "logger.h"

#define DLP_INSPECTION_BODY_SIZE 8192

static dlp_result_t make_dlp_allow_result(void)
{
    dlp_result_t result;

    memset(&result, 0, sizeof(result));
    result.action = DLP_ACTION_ALLOW;
    result.matched_rule_id = 0;

    return result;
}

static dlp_action_t convert_policy_action_to_dlp_action(policy_action_t action)
{
    switch (action) {
    case POLICY_ACTION_BLOCK:
        return DLP_ACTION_BLOCK;

    case POLICY_ACTION_LOG_ONLY:
        return DLP_ACTION_LOG_ONLY;

    case POLICY_ACTION_ALLOW:
    default:
        return DLP_ACTION_ALLOW;
    }
}

static dlp_result_t convert_policy_result_to_dlp_result(policy_result_t policy_result)
{
    dlp_result_t result;

    memset(&result, 0, sizeof(result));

    result.action = convert_policy_action_to_dlp_action(policy_result.action);
    result.matched_rule_id = policy_result.matched_rule_id;

    strncpy_s(result.keyword, sizeof(result.keyword), policy_result.keyword, _TRUNCATE);
    strncpy_s(result.reason, sizeof(result.reason), policy_result.reason, _TRUNCATE);

    return result;
}

static dlp_result_t inspect_body(
    const char* direction,
    const char* content_type,
    const char* body,
    int body_length
)
{
    char inspection_body[DLP_INSPECTION_BODY_SIZE];
    int inspection_body_length;
    int decode_result;

    policy_result_t policy_result;

    if (body == NULL || body_length <= 0) {
        return make_dlp_allow_result();
    }

    memset(inspection_body, 0, sizeof(inspection_body));
    inspection_body_length = 0;

    decode_result = decode_body_for_inspection(
        content_type,
        body,
        body_length,
        inspection_body,
        sizeof(inspection_body),
        &inspection_body_length
    );

    if (decode_result != 0) {
        log_warn("decode_body_for_inspection() failed. direction=%s using raw body.", direction);

        policy_result = inspect_policy_text(
            body,
            body_length
        );

        return convert_policy_result_to_dlp_result(policy_result);
    }

    if (content_type != NULL && content_type[0] != '\0') {
        log_debug("DLP inspection direction=%s content-type: %s", direction, content_type);
    }
    else {
        log_debug("DLP inspection direction=%s content-type: -", direction);
    }

    log_debug("DLP inspection direction=%s body: %s", direction, inspection_body);

    policy_result = inspect_policy_text(
        inspection_body,
        inspection_body_length
    );

    return convert_policy_result_to_dlp_result(policy_result);
}

dlp_result_t inspect_dlp_request(const http_request_t* request)
{
    if (request == NULL) {
        return make_dlp_allow_result();
    }

    if (request->body_length <= 0) {
        return make_dlp_allow_result();
    }

    return inspect_body(
        "REQUEST",
        request->content_type,
        request->body,
        request->body_length
    );
}

dlp_result_t inspect_dlp_response(const http_response_t* response)
{
    if (response == NULL) {
        return make_dlp_allow_result();
    }

    if (response->body_length <= 0) {
        return make_dlp_allow_result();
    }

    return inspect_body(
        "RESPONSE",
        response->content_type,
        response->body,
        response->body_length
    );
}