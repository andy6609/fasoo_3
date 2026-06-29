#ifndef TLS_INTERCEPT_POLICY_H
#define TLS_INTERCEPT_POLICY_H

#define TLS_INTERCEPT_POLICY_HOST_SIZE 256
#define TLS_INTERCEPT_POLICY_PROCESS_SIZE 128
#define TLS_INTERCEPT_POLICY_REASON_SIZE 160
#define TLS_INTERCEPT_POLICY_MAX_RULES 256

typedef enum tls_intercept_action {
    TLS_INTERCEPT_ACTION_BYPASS = 0,
    TLS_INTERCEPT_ACTION_MITM = 1,
    TLS_INTERCEPT_ACTION_BLOCK = 2,
    TLS_INTERCEPT_ACTION_AUDIT = 3,
    TLS_INTERCEPT_ACTION_IGNORE = 4
} tls_intercept_action_t;

typedef struct tls_intercept_decision {
    tls_intercept_action_t action;
    char process_name[TLS_INTERCEPT_POLICY_PROCESS_SIZE];
    char host[TLS_INTERCEPT_POLICY_HOST_SIZE];
    int port;
    char rule_process[TLS_INTERCEPT_POLICY_PROCESS_SIZE];
    char rule_host[TLS_INTERCEPT_POLICY_HOST_SIZE];
    int rule_port;
    int matched;
    int matched_default;
    char reason[TLS_INTERCEPT_POLICY_REASON_SIZE];
} tls_intercept_decision_t;

int tls_intercept_policy_load(const char* path);
int tls_intercept_policy_decide(const char* host, int port, tls_intercept_decision_t* decision);
int tls_intercept_policy_decide_with_process(
    const char* host,
    int port,
    const char* process_name,
    tls_intercept_decision_t* decision
);
int tls_intercept_policy_decide_with_process_silent(
    const char* host,
    int port,
    const char* process_name,
    tls_intercept_decision_t* decision
);
const char* tls_intercept_policy_action_to_string(tls_intercept_action_t action);
void tls_intercept_policy_cleanup(void);

#endif
