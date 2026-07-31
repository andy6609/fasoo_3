#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "cert_manager.h"
#include "logger.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

#define MITM_CA_CERT_FILE "certs\\mitm.crt"
#define MITM_CA_KEY_FILE  "certs\\mitm.key"
#define GENERATED_CERT_DIR "certs\\generated"

static SRWLOCK g_certificate_generation_lock = SRWLOCK_INIT;

static void cert_manager_resolve_runtime_path(
    const char* relative_path,
    char* resolved,
    size_t resolved_size
)
{
    char repository_path[MAX_PATH];

    if (resolved == NULL || resolved_size == 0) return;
    resolved[0] = '\0';
    if (relative_path == NULL || relative_path[0] == '\0') return;

    _snprintf_s(
        repository_path,
        sizeof(repository_path),
        _TRUNCATE,
        "relay_proxy\\%s",
        relative_path
    );
    if (GetFileAttributesA(repository_path) != INVALID_FILE_ATTRIBUTES) {
        strcpy_s(resolved, resolved_size, repository_path);
        return;
    }

    strcpy_s(resolved, resolved_size, relative_path);
}

static void cert_manager_log_openssl_error(const char* message)
{
    unsigned long err;
    int has_error = 0;

    if (message == NULL) {
        message = "OpenSSL error";
    }

    while ((err = ERR_get_error()) != 0) {
        char error_text[256];

        memset(error_text, 0, sizeof(error_text));
        ERR_error_string_n(err, error_text, sizeof(error_text));

        log_error("%s: %s", message, error_text);
        has_error = 1;
    }

    if (!has_error) {
        log_error("%s", message);
    }
}

static int cert_manager_file_exists(const char* path)
{
    DWORD attr;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    attr = GetFileAttributesA(path);

    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        return 0;
    }

    return 1;
}

static int cert_manager_directory_exists(const char* path)
{
    DWORD attr;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    attr = GetFileAttributesA(path);

    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }

    return (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
}

static int cert_manager_ensure_directory(const char* path)
{
    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    if (cert_manager_directory_exists(path)) {
        return 0;
    }

    if (CreateDirectoryA(path, NULL)) {
        return 0;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    log_error(
        "failed to create directory. path=%s error=%lu",
        path,
        GetLastError()
    );

    return -1;
}

static void cert_manager_strip_ipv6_brackets(
    const char* host,
    char* out,
    int out_size
)
{
    if (out == NULL || out_size <= 0) {
        return;
    }

    out[0] = '\0';

    if (host == NULL || host[0] == '\0') {
        return;
    }

    if (host[0] == '[') {
        const char* end = strchr(host, ']');

        if (end != NULL && end > host + 1) {
            int len = (int)(end - host - 1);

            if (len >= out_size) {
                len = out_size - 1;
            }

            memcpy(out, host + 1, len);
            out[len] = '\0';
            return;
        }
    }

    _snprintf_s(out, out_size, _TRUNCATE, "%s", host);
}

int cert_manager_is_ip_literal(const char* host)
{
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    char clean_host[CERT_MANAGER_HOST_SIZE];

    if (host == NULL || host[0] == '\0') {
        return 0;
    }

    memset(clean_host, 0, sizeof(clean_host));
    cert_manager_strip_ipv6_brackets(host, clean_host, sizeof(clean_host));

    if (InetPtonA(AF_INET, clean_host, &ipv4_addr) == 1) {
        return 1;
    }

    if (InetPtonA(AF_INET6, clean_host, &ipv6_addr) == 1) {
        return 1;
    }

    return 0;
}

static void cert_manager_sanitize_host(
    const char* host,
    char* safe_host,
    int safe_host_size
)
{
    int i;
    int out = 0;

    if (safe_host == NULL || safe_host_size <= 0) {
        return;
    }

    safe_host[0] = '\0';

    if (host == NULL || host[0] == '\0') {
        _snprintf_s(safe_host, safe_host_size, _TRUNCATE, "unknown");
        return;
    }

    for (i = 0; host[i] != '\0' && out < safe_host_size - 1; i++) {
        unsigned char ch = (unsigned char)host[i];

        if (isalnum(ch) || ch == '.' || ch == '-' || ch == '_') {
            safe_host[out++] = (char)ch;
        }
        else if (ch == '*') {
            if (out + 8 < safe_host_size - 1) {
                memcpy(safe_host + out, "wildcard", 8);
                out += 8;
            }
            else {
                safe_host[out++] = '_';
            }
        }
        else {
            safe_host[out++] = '_';
        }
    }

    safe_host[out] = '\0';

    if (safe_host[0] == '\0') {
        _snprintf_s(safe_host, safe_host_size, _TRUNCATE, "unknown");
    }
}

static X509* cert_manager_load_x509_certificate(const char* path)
{
    BIO* bio = NULL;
    X509* cert = NULL;

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }

    bio = BIO_new_file(path, "rb");
    if (bio == NULL) {
        cert_manager_log_openssl_error("BIO_new_file() failed while opening certificate");
        log_error("failed to open certificate file. path=%s", path);
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (cert == NULL) {
        cert_manager_log_openssl_error("PEM_read_bio_X509() failed");
        return NULL;
    }

    return cert;
}

static EVP_PKEY* cert_manager_load_private_key(const char* path)
{
    BIO* bio = NULL;
    EVP_PKEY* key = NULL;

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }

    bio = BIO_new_file(path, "rb");
    if (bio == NULL) {
        cert_manager_log_openssl_error("BIO_new_file() failed while opening private key");
        log_error("failed to open private key file. path=%s", path);
        return NULL;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (key == NULL) {
        cert_manager_log_openssl_error("PEM_read_bio_PrivateKey() failed");
        return NULL;
    }

    return key;
}

static int cert_manager_cached_leaf_is_valid(
    const char* host,
    const char* cert_path,
    const char* key_path,
    const char* ca_cert_path
)
{
    X509* leaf = NULL;
    X509* ca = NULL;
    EVP_PKEY* leaf_key = NULL;
    EVP_PKEY* ca_public_key = NULL;
    unsigned char address_buffer[16];
    int host_matches = 0;
    int valid = 0;

    leaf = cert_manager_load_x509_certificate(cert_path);
    ca = cert_manager_load_x509_certificate(ca_cert_path);
    leaf_key = cert_manager_load_private_key(key_path);
    if (leaf == NULL || ca == NULL || leaf_key == NULL) goto cleanup;

    if (X509_cmp_current_time(X509_get0_notBefore(leaf)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(leaf)) < 0) goto cleanup;
    if (X509_check_private_key(leaf, leaf_key) != 1) goto cleanup;

    ca_public_key = X509_get_pubkey(ca);
    if (ca_public_key == NULL || X509_verify(leaf, ca_public_key) != 1) goto cleanup;

    if (InetPtonA(AF_INET, host, address_buffer) == 1 ||
        InetPtonA(AF_INET6, host, address_buffer) == 1) {
        host_matches = X509_check_ip_asc(leaf, host, 0) == 1;
    }
    else {
        host_matches = X509_check_host(leaf, host, 0, 0, NULL) == 1;
    }
    if (!host_matches) goto cleanup;

    valid = 1;

cleanup:
    EVP_PKEY_free(ca_public_key);
    EVP_PKEY_free(leaf_key);
    X509_free(ca);
    X509_free(leaf);
    ERR_clear_error();
    return valid;
}

static int cert_manager_write_x509_certificate(const char* path, X509* cert)
{
    BIO* bio = NULL;
    int result;

    if (path == NULL || path[0] == '\0' || cert == NULL) {
        return -1;
    }

    bio = BIO_new_file(path, "wb");
    if (bio == NULL) {
        cert_manager_log_openssl_error("BIO_new_file() failed while creating certificate");
        log_error("failed to create certificate file. path=%s", path);
        return -1;
    }

    result = PEM_write_bio_X509(bio, cert);
    BIO_free(bio);

    if (result != 1) {
        cert_manager_log_openssl_error("PEM_write_bio_X509() failed");
        return -1;
    }

    return 0;
}

static int cert_manager_write_private_key(const char* path, EVP_PKEY* key)
{
    BIO* bio = NULL;
    int result;

    if (path == NULL || path[0] == '\0' || key == NULL) {
        return -1;
    }

    bio = BIO_new_file(path, "wb");
    if (bio == NULL) {
        cert_manager_log_openssl_error("BIO_new_file() failed while creating private key");
        log_error("failed to create private key file. path=%s", path);
        return -1;
    }

    result = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio);

    if (result != 1) {
        cert_manager_log_openssl_error("PEM_write_bio_PrivateKey() failed");
        return -1;
    }

    return 0;
}

static int cert_manager_add_extension(
    X509* cert,
    X509* issuer_cert,
    int nid,
    const char* value
)
{
    X509V3_CTX ctx;
    X509_EXTENSION* ext;

    if (cert == NULL || value == NULL) {
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer_cert, cert, NULL, NULL, 0);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value);
    if (ext == NULL) {
        cert_manager_log_openssl_error("X509V3_EXT_conf_nid() failed");
        return -1;
    }

    if (X509_add_ext(cert, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        cert_manager_log_openssl_error("X509_add_ext() failed");
        return -1;
    }

    X509_EXTENSION_free(ext);
    return 0;
}

static void cert_manager_build_san_value(
    const char* host,
    char* san_value,
    int san_value_size
)
{
    char clean_host[CERT_MANAGER_HOST_SIZE];

    if (san_value == NULL || san_value_size <= 0) {
        return;
    }

    san_value[0] = '\0';

    if (host == NULL || host[0] == '\0') {
        _snprintf_s(san_value, san_value_size, _TRUNCATE, "DNS:localhost");
        return;
    }

    memset(clean_host, 0, sizeof(clean_host));
    cert_manager_strip_ipv6_brackets(host, clean_host, sizeof(clean_host));

    if (cert_manager_is_ip_literal(clean_host)) {
        _snprintf_s(san_value, san_value_size, _TRUNCATE, "IP:%s", clean_host);
    }
    else {
        _snprintf_s(san_value, san_value_size, _TRUNCATE, "DNS:%s", clean_host);
    }
}

static int cert_manager_create_leaf_certificate(
    const char* host,
    const char* cert_path,
    const char* key_path
)
{
    int result = -1;

    X509* ca_cert = NULL;
    EVP_PKEY* ca_key = NULL;

    EVP_PKEY* leaf_key = NULL;
    X509* leaf_cert = NULL;
    X509_NAME* subject_name = NULL;

    char san_value[512];
    char clean_host[CERT_MANAGER_HOST_SIZE];
    char ca_cert_path[MAX_PATH];
    char ca_key_path[MAX_PATH];
    long serial;

    if (host == NULL || host[0] == '\0' || cert_path == NULL || key_path == NULL) {
        return -1;
    }

    memset(clean_host, 0, sizeof(clean_host));
    cert_manager_strip_ipv6_brackets(host, clean_host, sizeof(clean_host));

    cert_manager_resolve_runtime_path(MITM_CA_CERT_FILE, ca_cert_path, sizeof(ca_cert_path));
    cert_manager_resolve_runtime_path(MITM_CA_KEY_FILE, ca_key_path, sizeof(ca_key_path));

    ca_cert = cert_manager_load_x509_certificate(ca_cert_path);
    if (ca_cert == NULL) {
        goto cleanup;
    }

    ca_key = cert_manager_load_private_key(ca_key_path);
    if (ca_key == NULL) {
        goto cleanup;
    }

    leaf_key = EVP_RSA_gen(2048);
    if (leaf_key == NULL) {
        cert_manager_log_openssl_error("EVP_RSA_gen() failed");
        goto cleanup;
    }

    leaf_cert = X509_new();
    if (leaf_cert == NULL) {
        cert_manager_log_openssl_error("X509_new() failed");
        goto cleanup;
    }

    if (X509_set_version(leaf_cert, 2) != 1) {
        cert_manager_log_openssl_error("X509_set_version() failed");
        goto cleanup;
    }

    serial = (long)(time(NULL) ^ GetCurrentProcessId() ^ GetTickCount());
    if (serial < 0) {
        serial = -serial;
    }
    if (serial == 0) {
        serial = 1;
    }

    if (ASN1_INTEGER_set(X509_get_serialNumber(leaf_cert), serial) != 1) {
        cert_manager_log_openssl_error("ASN1_INTEGER_set() failed");
        goto cleanup;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(leaf_cert), 0) == NULL) {
        cert_manager_log_openssl_error("X509_gmtime_adj(notBefore) failed");
        goto cleanup;
    }

    if (X509_gmtime_adj(X509_getm_notAfter(leaf_cert), 60L * 60L * 24L * 365L) == NULL) {
        cert_manager_log_openssl_error("X509_gmtime_adj(notAfter) failed");
        goto cleanup;
    }

    if (X509_set_pubkey(leaf_cert, leaf_key) != 1) {
        cert_manager_log_openssl_error("X509_set_pubkey() failed");
        goto cleanup;
    }

    subject_name = X509_get_subject_name(leaf_cert);
    if (subject_name == NULL) {
        cert_manager_log_openssl_error("X509_get_subject_name() failed");
        goto cleanup;
    }

    if (X509_NAME_add_entry_by_txt(
        subject_name,
        "C",
        MBSTRING_ASC,
        (const unsigned char*)"KR",
        -1,
        -1,
        0
    ) != 1) {
        cert_manager_log_openssl_error("X509_NAME_add_entry_by_txt(C) failed");
        goto cleanup;
    }

    if (X509_NAME_add_entry_by_txt(
        subject_name,
        "O",
        MBSTRING_ASC,
        (const unsigned char*)"Local DLP MITM",
        -1,
        -1,
        0
    ) != 1) {
        cert_manager_log_openssl_error("X509_NAME_add_entry_by_txt(O) failed");
        goto cleanup;
    }

    if (X509_NAME_add_entry_by_txt(
        subject_name,
        "CN",
        MBSTRING_ASC,
        (const unsigned char*)clean_host,
        -1,
        -1,
        0
    ) != 1) {
        cert_manager_log_openssl_error("X509_NAME_add_entry_by_txt(CN) failed");
        goto cleanup;
    }

    if (X509_set_issuer_name(leaf_cert, X509_get_subject_name(ca_cert)) != 1) {
        cert_manager_log_openssl_error("X509_set_issuer_name() failed");
        goto cleanup;
    }

    cert_manager_build_san_value(clean_host, san_value, sizeof(san_value));

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_basic_constraints,
        "critical,CA:FALSE"
    ) != 0) {
        goto cleanup;
    }

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_key_usage,
        "critical,digitalSignature,keyEncipherment"
    ) != 0) {
        goto cleanup;
    }

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_ext_key_usage,
        "serverAuth"
    ) != 0) {
        goto cleanup;
    }

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_subject_alt_name,
        san_value
    ) != 0) {
        goto cleanup;
    }

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_subject_key_identifier,
        "hash"
    ) != 0) {
        goto cleanup;
    }

    if (cert_manager_add_extension(
        leaf_cert,
        ca_cert,
        NID_authority_key_identifier,
        "keyid,issuer"
    ) != 0) {
        goto cleanup;
    }

    if (X509_sign(leaf_cert, ca_key, EVP_sha256()) <= 0) {
        cert_manager_log_openssl_error("X509_sign() failed");
        goto cleanup;
    }

    if (cert_manager_write_private_key(key_path, leaf_key) != 0) {
        goto cleanup;
    }

    if (cert_manager_write_x509_certificate(cert_path, leaf_cert) != 0) {
        goto cleanup;
    }

    log_info(
        "dynamic TLS leaf certificate generated. host=%s cert=%s key=%s san=%s",
        clean_host,
        cert_path,
        key_path,
        san_value
    );

    result = 0;

cleanup:
    if (leaf_cert != NULL) {
        X509_free(leaf_cert);
        leaf_cert = NULL;
    }

    if (leaf_key != NULL) {
        EVP_PKEY_free(leaf_key);
        leaf_key = NULL;
    }

    if (ca_key != NULL) {
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
    }

    if (ca_cert != NULL) {
        X509_free(ca_cert);
        ca_cert = NULL;
    }

    return result;
}

static int cert_manager_get_or_create_leaf_certificate_unlocked(
    const char* host,
    char* cert_path,
    int cert_path_size,
    char* key_path,
    int key_path_size
)
{
    char safe_host[CERT_MANAGER_HOST_SIZE];
    char ca_cert_path[MAX_PATH];
    char ca_key_path[MAX_PATH];
    char generated_cert_dir[MAX_PATH];

    if (host == NULL || host[0] == '\0') {
        log_error("cert_manager_get_or_create_leaf_certificate() failed. empty host");
        return -1;
    }

    if (cert_path == NULL || cert_path_size <= 0 || key_path == NULL || key_path_size <= 0) {
        return -1;
    }

    cert_manager_resolve_runtime_path(MITM_CA_CERT_FILE, ca_cert_path, sizeof(ca_cert_path));
    cert_manager_resolve_runtime_path(MITM_CA_KEY_FILE, ca_key_path, sizeof(ca_key_path));
    cert_manager_resolve_runtime_path(GENERATED_CERT_DIR, generated_cert_dir, sizeof(generated_cert_dir));

    if (!cert_manager_file_exists(ca_cert_path)) {
        log_error("MITM CA certificate not found. path=%s", ca_cert_path);
        return -1;
    }

    if (!cert_manager_file_exists(ca_key_path)) {
        log_error("MITM CA private key not found. path=%s", ca_key_path);
        return -1;
    }

    if (cert_manager_ensure_directory(generated_cert_dir) != 0) {
        return -1;
    }

    memset(safe_host, 0, sizeof(safe_host));
    cert_manager_sanitize_host(host, safe_host, sizeof(safe_host));

    _snprintf_s(
        cert_path,
        cert_path_size,
        _TRUNCATE,
        "%s\\%s.crt",
        generated_cert_dir,
        safe_host
    );

    _snprintf_s(
        key_path,
        key_path_size,
        _TRUNCATE,
        "%s\\%s.key",
        generated_cert_dir,
        safe_host
    );

    if (cert_manager_file_exists(cert_path) && cert_manager_file_exists(key_path) &&
        cert_manager_cached_leaf_is_valid(
            host,
            cert_path,
            key_path,
            ca_cert_path
        )) {
        log_info(
            "dynamic TLS leaf certificate cache hit. host=%s cert=%s key=%s",
            host,
            cert_path,
            key_path
        );

        return 0;
    }

    if (cert_manager_file_exists(cert_path) || cert_manager_file_exists(key_path)) {
        log_warn(
            "stale dynamic TLS leaf certificate rejected and will be regenerated. host=%s cert=%s key=%s",
            host,
            cert_path,
            key_path
        );
    }

    log_info(
        "dynamic TLS leaf certificate cache miss. generating. host=%s",
        host
    );

    return cert_manager_create_leaf_certificate(host, cert_path, key_path);
}

int cert_manager_get_or_create_leaf_certificate(
    const char* host,
    char* cert_path,
    int cert_path_size,
    char* key_path,
    int key_path_size
)
{
    int result;

    AcquireSRWLockExclusive(&g_certificate_generation_lock);
    result = cert_manager_get_or_create_leaf_certificate_unlocked(
        host,
        cert_path,
        cert_path_size,
        key_path,
        key_path_size
    );
    ReleaseSRWLockExclusive(&g_certificate_generation_lock);
    return result;
}
