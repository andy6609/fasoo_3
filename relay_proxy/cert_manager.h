#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#define CERT_MANAGER_HOST_SIZE 256
#define CERT_MANAGER_PATH_SIZE 512

int cert_manager_get_or_create_leaf_certificate(
    const char* host,
    char* cert_path,
    int cert_path_size,
    char* key_path,
    int key_path_size
);

int cert_manager_is_ip_literal(const char* host);

#endif
