#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "logger.h"
#include "upload_tracker.h"

#define UPLOAD_TRACKER_MAX_ENTRIES 128
#define UPLOAD_TRACKER_ENTRY_TTL_MS (10ULL * 60ULL * 1000ULL)

typedef struct upload_tracker_entry {
    int in_use;
    int matched;
    int resumable;
    unsigned long upload_id;
    unsigned long metadata_session_id;
    unsigned int metadata_stream_id;
    unsigned long long created_tick;
    upload_tracking_info_t info;
} upload_tracker_entry_t;

static upload_tracker_entry_t g_entries[UPLOAD_TRACKER_MAX_ENTRIES];
static CRITICAL_SECTION g_lock;
static int g_ready = 0;
static unsigned long g_next_upload_id = 1;

static int text_equals_ignore_case(const char* left, const char* right)
{
    return left != NULL && right != NULL && _stricmp(left, right) == 0;
}

static const char* request_header_value(const http_request_t* request, const char* name)
{
    int i;
    if (request == NULL || name == NULL) return NULL;
    for (i = 0; i < request->header_count; i++) {
        if (_stricmp(request->headers[i].name, name) == 0) return request->headers[i].value;
    }
    return NULL;
}

static int text_contains_ignore_case(const char* value, const char* needle)
{
    size_t needle_length;
    const char* cursor;
    if (value == NULL || needle == NULL || needle[0] == '\0') return 0;
    needle_length = strlen(needle);
    for (cursor = value; *cursor != '\0'; cursor++) {
        if (_strnicmp(cursor, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static int host_equals_or_is_subdomain(const char* host, const char* suffix)
{
    size_t host_length;
    size_t suffix_length;

    if (host == NULL || suffix == NULL) return 0;
    host_length = strcspn(host, ":");
    suffix_length = strlen(suffix);
    if (host_length == suffix_length && _strnicmp(host, suffix, suffix_length) == 0) return 1;
    return host_length > suffix_length && host[host_length - suffix_length - 1] == '.' &&
        _strnicmp(host + host_length - suffix_length, suffix, suffix_length) == 0;
}

static void sanitize_filename_in_place(char* value, size_t capacity)
{
    char cleaned[UPLOAD_TRACKER_FILENAME_SIZE];
    const char* base;
    const char* slash;
    const char* backslash;
    size_t input;
    size_t output = 0;
    if (value == NULL || capacity == 0) return;
    base = value;
    slash = strrchr(value, '/');
    backslash = strrchr(value, '\\');
    if (slash != NULL && slash + 1 > base) base = slash + 1;
    if (backslash != NULL && backslash + 1 > base) base = backslash + 1;
    for (input = 0; base[input] != '\0' && output + 1 < sizeof(cleaned); ++input) {
        unsigned char ch = (unsigned char)base[input];
        if (ch < 0x20 || ch == 0x7f) cleaned[output++] = '_';
        else if (ch == '"') cleaned[output++] = '\'';
        else cleaned[output++] = (char)ch;
    }
    if (output == 0) strcpy_s(cleaned, sizeof(cleaned), "unknown");
    else cleaned[output] = '\0';
    strncpy_s(value, capacity, cleaned, _TRUNCATE);
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static size_t append_utf8(unsigned int codepoint, char* output, size_t capacity, size_t offset)
{
    if (codepoint <= 0x7f) {
        if (offset + 1 < capacity) output[offset++] = (char)codepoint;
    }
    else if (codepoint <= 0x7ff) {
        if (offset + 2 < capacity) {
            output[offset++] = (char)(0xc0 | (codepoint >> 6));
            output[offset++] = (char)(0x80 | (codepoint & 0x3f));
        }
    }
    else {
        if (offset + 3 < capacity) {
            output[offset++] = (char)(0xe0 | (codepoint >> 12));
            output[offset++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
            output[offset++] = (char)(0x80 | (codepoint & 0x3f));
        }
    }
    return offset;
}

static int json_extract_string(
    const char* json,
    size_t json_length,
    const char* key,
    char* output,
    size_t output_size
)
{
    size_t key_length;
    size_t i;

    if (json == NULL || key == NULL || output == NULL || output_size == 0) return 0;
    output[0] = '\0';
    key_length = strlen(key);

    for (i = 0; i + key_length + 2 < json_length; i++) {
        size_t pos;
        size_t out = 0;
        if (json[i] != '"' || _strnicmp(json + i + 1, key, key_length) != 0 ||
            json[i + key_length + 1] != '"') {
            continue;
        }
        pos = i + key_length + 2;
        while (pos < json_length && isspace((unsigned char)json[pos])) pos++;
        if (pos >= json_length || json[pos++] != ':') continue;
        while (pos < json_length && isspace((unsigned char)json[pos])) pos++;
        if (pos >= json_length || json[pos++] != '"') continue;

        while (pos < json_length && out + 1 < output_size) {
            char ch = json[pos++];
            if (ch == '"') {
                output[out] = '\0';
                return 1;
            }
            if (ch != '\\') {
                output[out++] = ch;
                continue;
            }
            if (pos >= json_length) break;
            ch = json[pos++];
            if (ch == 'u' && pos + 4 <= json_length) {
                int h0 = hex_value(json[pos]);
                int h1 = hex_value(json[pos + 1]);
                int h2 = hex_value(json[pos + 2]);
                int h3 = hex_value(json[pos + 3]);
                if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                    unsigned int codepoint = (unsigned int)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                    out = append_utf8(codepoint, output, output_size, out);
                    pos += 4;
                    continue;
                }
            }
            switch (ch) {
            case 'n': output[out++] = '\n'; break;
            case 'r': output[out++] = '\r'; break;
            case 't': output[out++] = '\t'; break;
            case 'b': output[out++] = '\b'; break;
            case 'f': output[out++] = '\f'; break;
            default: output[out++] = ch; break;
            }
        }
        output[out] = '\0';
        return out > 0;
    }
    return 0;
}

static int json_extract_u64(
    const char* json,
    size_t json_length,
    const char* key,
    unsigned long long* value
)
{
    size_t key_length;
    size_t i;

    if (json == NULL || key == NULL || value == NULL) return 0;
    key_length = strlen(key);
    for (i = 0; i + key_length + 2 < json_length; i++) {
        size_t pos;
        char number[32];
        size_t out = 0;
        if (json[i] != '"' || _strnicmp(json + i + 1, key, key_length) != 0 ||
            json[i + key_length + 1] != '"') continue;
        pos = i + key_length + 2;
        while (pos < json_length && isspace((unsigned char)json[pos])) pos++;
        if (pos >= json_length || json[pos++] != ':') continue;
        while (pos < json_length && (isspace((unsigned char)json[pos]) || json[pos] == '"')) pos++;
        while (pos < json_length && isdigit((unsigned char)json[pos]) && out + 1 < sizeof(number)) {
            number[out++] = json[pos++];
        }
        if (out > 0) {
            number[out] = '\0';
            *value = _strtoui64(number, NULL, 10);
            return 1;
        }
    }
    return 0;
}

void upload_tracker_sanitize_path(const char* path, char* sanitized, size_t sanitized_size)
{
    size_t index;
    size_t length;
    const char* query;

    if (sanitized == NULL || sanitized_size == 0) return;
    sanitized[0] = '\0';
    if (path == NULL) return;
    query = strchr(path, '?');
    length = query != NULL ? (size_t)(query - path) : strlen(path);
    if (length >= sanitized_size) length = sanitized_size - 1;
    memcpy(sanitized, path, length);
    sanitized[length] = '\0';
    for (index = 0; index < length; ++index) {
        unsigned char ch = (unsigned char)sanitized[index];
        if (ch < 0x20 || ch == 0x7f || ch == '"') sanitized[index] = '_';
    }
}

static void parse_upload_url(const char* url, char* host, size_t host_size, char* path, size_t path_size)
{
    const char* authority;
    const char* slash;
    size_t host_length;

    if (host != NULL && host_size > 0) host[0] = '\0';
    if (path != NULL && path_size > 0) path[0] = '\0';
    if (url == NULL || host == NULL || path == NULL) return;
    authority = strstr(url, "://");
    authority = authority != NULL ? authority + 3 : url;
    slash = strchr(authority, '/');
    if (slash == NULL) return;
    host_length = (size_t)(slash - authority);
    if (host_length >= host_size) host_length = host_size - 1;
    memcpy(host, authority, host_length);
    host[host_length] = '\0';
    upload_tracker_sanitize_path(slash, path, path_size);
}

static upload_tracker_entry_t* find_entry_by_id_no_lock(unsigned long upload_id)
{
    int i;
    for (i = 0; i < UPLOAD_TRACKER_MAX_ENTRIES; i++) {
        if (g_entries[i].in_use && g_entries[i].upload_id == upload_id) return &g_entries[i];
    }
    return NULL;
}

static upload_tracker_entry_t* allocate_entry_no_lock(void)
{
    int i;
    int oldest_index = 0;
    unsigned long long oldest_tick = ~0ULL;
    unsigned long long now = GetTickCount64();

    for (i = 0; i < UPLOAD_TRACKER_MAX_ENTRIES; i++) {
        if (!g_entries[i].in_use || now - g_entries[i].created_tick > UPLOAD_TRACKER_ENTRY_TTL_MS) {
            memset(&g_entries[i], 0, sizeof(g_entries[i]));
            return &g_entries[i];
        }
        if (g_entries[i].created_tick < oldest_tick) {
            oldest_tick = g_entries[i].created_tick;
            oldest_index = i;
        }
    }
    memset(&g_entries[oldest_index], 0, sizeof(g_entries[oldest_index]));
    return &g_entries[oldest_index];
}

int upload_tracker_init(void)
{
    if (g_ready) return 0;
    memset(g_entries, 0, sizeof(g_entries));
    InitializeCriticalSection(&g_lock);
    g_next_upload_id = 1;
    g_ready = 1;
    return 0;
}

void upload_tracker_cleanup(void)
{
    if (!g_ready) return;
    EnterCriticalSection(&g_lock);
    memset(g_entries, 0, sizeof(g_entries));
    LeaveCriticalSection(&g_lock);
    DeleteCriticalSection(&g_lock);
    g_ready = 0;
}

int upload_tracker_is_metadata_request(const char* method, const char* host, const char* path)
{
    char clean_path[UPLOAD_TRACKER_PATH_SIZE];
    if (!text_equals_ignore_case(method, "POST") || !host_equals_or_is_subdomain(host, "chatgpt.com")) return 0;
    upload_tracker_sanitize_path(path, clean_path, sizeof(clean_path));
    return text_equals_ignore_case(clean_path, "/backend-api/files");
}

unsigned long upload_tracker_record_metadata_request(
    unsigned long session_id,
    unsigned int stream_id,
    const char* body,
    size_t body_length
)
{
    upload_tracker_entry_t* entry;
    unsigned long upload_id;

    if (!g_ready || body == NULL || body_length == 0) return 0;
    EnterCriticalSection(&g_lock);
    entry = allocate_entry_no_lock();
    entry->in_use = 1;
    entry->created_tick = GetTickCount64();
    entry->metadata_session_id = session_id;
    entry->metadata_stream_id = stream_id;
    entry->resumable = 0;
    entry->upload_id = g_next_upload_id++;
    if (g_next_upload_id == 0) g_next_upload_id = 1;

    if (!json_extract_string(body, body_length, "file_name", entry->info.filename, sizeof(entry->info.filename)) &&
        !json_extract_string(body, body_length, "filename", entry->info.filename, sizeof(entry->info.filename))) {
        json_extract_string(body, body_length, "name", entry->info.filename, sizeof(entry->info.filename));
    }
    if (!json_extract_string(body, body_length, "mime_type", entry->info.content_type, sizeof(entry->info.content_type)) &&
        !json_extract_string(body, body_length, "content_type", entry->info.content_type, sizeof(entry->info.content_type))) {
        json_extract_string(body, body_length, "type", entry->info.content_type, sizeof(entry->info.content_type));
    }
    if (!json_extract_u64(body, body_length, "file_size", &entry->info.declared_size)) {
        json_extract_u64(body, body_length, "size", &entry->info.declared_size);
    }
    sanitize_filename_in_place(entry->info.filename, sizeof(entry->info.filename));
    entry->info.upload_id = entry->upload_id;
    upload_id = entry->upload_id;
    LeaveCriticalSection(&g_lock);
    return upload_id;
}

unsigned long upload_tracker_record_resumable_start(
    unsigned long session_id,
    unsigned int stream_id,
    const http_request_t* request,
    const char* body,
    size_t body_length
)
{
    static const char prefix[] = "File name: ";
    const char* command;
    const char* declared_type;
    const char* declared_size;
    upload_tracker_entry_t* entry;
    upload_tracking_info_t snapshot;
    unsigned long upload_id;
    size_t filename_length;

    if (!g_ready || request == NULL || body == NULL || body_length <= sizeof(prefix) - 1) return 0;
    command = request_header_value(request, "X-Goog-Upload-Command");
    if (!text_contains_ignore_case(command, "start") ||
        memcmp(body, prefix, sizeof(prefix) - 1) != 0) return 0;

    memset(&snapshot, 0, sizeof(snapshot));
    EnterCriticalSection(&g_lock);
    entry = allocate_entry_no_lock();
    entry->in_use = 1;
    entry->resumable = 1;
    entry->created_tick = GetTickCount64();
    entry->metadata_session_id = session_id;
    entry->metadata_stream_id = stream_id;
    entry->upload_id = g_next_upload_id++;
    if (g_next_upload_id == 0) g_next_upload_id = 1;
    entry->info.upload_id = entry->upload_id;
    filename_length = body_length - (sizeof(prefix) - 1);
    while (filename_length > 0 &&
        (body[sizeof(prefix) - 1 + filename_length - 1] == '\r' ||
         body[sizeof(prefix) - 1 + filename_length - 1] == '\n')) filename_length--;
    if (filename_length >= sizeof(entry->info.filename)) filename_length = sizeof(entry->info.filename) - 1;
    memcpy(entry->info.filename, body + sizeof(prefix) - 1, filename_length);
    entry->info.filename[filename_length] = '\0';
    sanitize_filename_in_place(entry->info.filename, sizeof(entry->info.filename));
    declared_type = request_header_value(request, "X-Goog-Upload-Header-Content-Type");
    if (declared_type != NULL) strncpy_s(entry->info.content_type,
        sizeof(entry->info.content_type), declared_type, _TRUNCATE);
    declared_size = request_header_value(request, "X-Goog-Upload-Header-Content-Length");
    if (declared_size != NULL) entry->info.declared_size = _strtoui64(declared_size, NULL, 10);
    strncpy_s(entry->info.upload_host, sizeof(entry->info.upload_host), request->host, _TRUNCATE);
    upload_tracker_sanitize_path(request->path, entry->info.upload_path, sizeof(entry->info.upload_path));
    upload_id = entry->upload_id;
    snapshot = entry->info;
    LeaveCriticalSection(&g_lock);

    log_event(
        "UPLOAD PREPARED id=%lu service=Gemini session=%lu file=\"%s\" declared_bytes=%llu type=%s start_target=%s%s correlation=session_host_path_fifo",
        snapshot.upload_id, session_id, snapshot.filename[0] ? snapshot.filename : "unknown",
        snapshot.declared_size, snapshot.content_type[0] ? snapshot.content_type : "unknown",
        snapshot.upload_host, snapshot.upload_path);
    return upload_id;
}

int upload_tracker_match_resumable_finalize(
    unsigned long session_id,
    const http_request_t* request,
    unsigned long long content_length,
    upload_tracking_info_t* info
)
{
    const char* command;
    int i;
    upload_tracker_entry_t* best = NULL;
    unsigned long long oldest_tick = ~0ULL;
    unsigned long long now = GetTickCount64();
    char clean_path[UPLOAD_TRACKER_PATH_SIZE];

    if (info != NULL) memset(info, 0, sizeof(*info));
    if (!g_ready || request == NULL) return 0;
    command = request_header_value(request, "X-Goog-Upload-Command");
    if (!text_contains_ignore_case(command, "finalize")) return 0;
    upload_tracker_sanitize_path(request->path, clean_path, sizeof(clean_path));

    EnterCriticalSection(&g_lock);
    for (i = 0; i < UPLOAD_TRACKER_MAX_ENTRIES; i++) {
        upload_tracker_entry_t* entry = &g_entries[i];
        if (!entry->in_use || !entry->resumable || entry->matched ||
            entry->metadata_session_id != session_id ||
            now - entry->created_tick > UPLOAD_TRACKER_ENTRY_TTL_MS) continue;
        if (_stricmp(entry->info.upload_host, request->host) != 0 ||
            _stricmp(entry->info.upload_path, clean_path) != 0) continue;
        if (entry->created_tick < oldest_tick) {
            best = entry;
            oldest_tick = entry->created_tick;
        }
    }
    if (best != NULL) {
        best->matched = 1;
        strncpy_s(best->info.upload_host, sizeof(best->info.upload_host), request->host, _TRUNCATE);
        strncpy_s(best->info.upload_path, sizeof(best->info.upload_path), clean_path, _TRUNCATE);
        if (best->info.declared_size == 0) best->info.declared_size = content_length;
        if (info != NULL) *info = best->info;
    }
    LeaveCriticalSection(&g_lock);
    return best != NULL;
}

void upload_tracker_record_metadata_response(
    unsigned long upload_id,
    const char* body,
    size_t body_length
)
{
    upload_tracker_entry_t* entry;
    char upload_url[2048];
    upload_tracking_info_t snapshot;

    if (!g_ready || upload_id == 0 || body == NULL || body_length == 0) return;
    memset(&snapshot, 0, sizeof(snapshot));
    memset(upload_url, 0, sizeof(upload_url));
    json_extract_string(body, body_length, "upload_url", upload_url, sizeof(upload_url));
    if (upload_url[0] == '\0') json_extract_string(body, body_length, "url", upload_url, sizeof(upload_url));

    EnterCriticalSection(&g_lock);
    entry = find_entry_by_id_no_lock(upload_id);
    if (entry != NULL) {
        if (upload_url[0] != '\0') {
            parse_upload_url(upload_url, entry->info.upload_host, sizeof(entry->info.upload_host),
                entry->info.upload_path, sizeof(entry->info.upload_path));
        }
        snapshot = entry->info;
    }
    LeaveCriticalSection(&g_lock);

    if (snapshot.upload_id != 0) {
        log_event(
            "UPLOAD PREPARED id=%lu file=\"%s\" declared_bytes=%llu type=%s target=%s%s",
            snapshot.upload_id,
            snapshot.filename[0] ? snapshot.filename : "unknown",
            snapshot.declared_size,
            snapshot.content_type[0] ? snapshot.content_type : "unknown",
            snapshot.upload_host[0] ? snapshot.upload_host : "pending",
            snapshot.upload_path[0] ? snapshot.upload_path : ""
        );
    }
}

int upload_tracker_match_raw_put(
    const char* host,
    const char* path,
    const char* content_type,
    unsigned long long content_length,
    upload_tracking_info_t* info
)
{
    int i;
    upload_tracker_entry_t* best = NULL;
    int fallback_candidates = 0;
    unsigned long long now = GetTickCount64();
    char clean_path[UPLOAD_TRACKER_PATH_SIZE];

    if (info != NULL) memset(info, 0, sizeof(*info));
    if (!g_ready || host == NULL || path == NULL || !host_equals_or_is_subdomain(host, "oaiusercontent.com")) return 0;
    upload_tracker_sanitize_path(path, clean_path, sizeof(clean_path));

    EnterCriticalSection(&g_lock);
    for (i = 0; i < UPLOAD_TRACKER_MAX_ENTRIES; i++) {
        upload_tracker_entry_t* entry = &g_entries[i];
        int exact_target;
        int size_matches;
        int type_matches;
        if (!entry->in_use || entry->resumable ||
            now - entry->created_tick > UPLOAD_TRACKER_ENTRY_TTL_MS) continue;
        exact_target = entry->info.upload_host[0] && entry->info.upload_path[0] &&
            _stricmp(entry->info.upload_host, host) == 0 && _stricmp(entry->info.upload_path, clean_path) == 0;
        size_matches = entry->info.declared_size == 0 || content_length == 0 ||
            entry->info.declared_size == content_length;
        type_matches = entry->info.content_type[0] == '\0' || content_type == NULL ||
            content_type[0] == '\0' || _stricmp(entry->info.content_type, content_type) == 0;
        if (exact_target) {
            best = entry;
            break;
        }
        /*
         * A browser can retry the same signed PUT after a local DLP block.
         * Keep exact-target matches reusable for the entry TTL, but never use
         * an already matched entry for the weaker size-only fallback.  This
         * preserves the original filename on retries without correlating a
         * later, unrelated upload merely because its size happens to match.
        */
        if (entry->matched) continue;
        if (size_matches && type_matches) {
            fallback_candidates++;
            best = fallback_candidates == 1 ? entry : NULL;
        }
    }

    if (best != NULL) {
        best->matched = 1;
        if (best->info.upload_host[0] == '\0') strcpy_s(best->info.upload_host, sizeof(best->info.upload_host), host);
        if (best->info.upload_path[0] == '\0') strcpy_s(best->info.upload_path, sizeof(best->info.upload_path), clean_path);
        if (best->info.content_type[0] == '\0' && content_type != NULL) {
            strncpy_s(best->info.content_type, sizeof(best->info.content_type), content_type, _TRUNCATE);
        }
        if (best->info.declared_size == 0) best->info.declared_size = content_length;
        if (info != NULL) *info = best->info;
    }
    LeaveCriticalSection(&g_lock);
    return best != NULL;
}
