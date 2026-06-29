#ifndef MITM_TARGET_POLICY_H
#define MITM_TARGET_POLICY_H

#define MITM_TARGET_POLICY_HOST_SIZE 256
#define MITM_TARGET_POLICY_MAX_RULES 128

int mitm_target_policy_load(const char* path);
int mitm_target_policy_is_allowed(const char* host, int port);
void mitm_target_policy_cleanup(void);

#endif
