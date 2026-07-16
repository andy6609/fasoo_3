#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <Windows.h>

#include "logger.h"

static FILE* g_log_file = NULL;
static CRITICAL_SECTION g_log_lock;
static int g_logger_ready = 0;
static int g_debug_enabled = 0;
static __declspec(thread) int g_thread_suppressed = 0;

/*
 * Log messages are stored as UTF-8.  Writing those bytes with printf() makes
 * a Korean Windows console interpret them through its active ANSI code page,
 * which produces mojibake even though the log file itself is correct.  Use
 * the Unicode console API when stdout is attached to a console, and preserve
 * raw UTF-8 when output is redirected to a pipe or file.
 */
static void logger_write_console_utf8(const char* text)
{
    HANDLE output_handle;
    DWORD console_mode;
    DWORD characters_written;
    WCHAR wide_text[2048];
    int wide_length;

    if (text == NULL) {
        return;
    }

    output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output_handle != NULL && output_handle != INVALID_HANDLE_VALUE &&
        GetConsoleMode(output_handle, &console_mode)) {
        wide_length = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text,
            -1,
            wide_text,
            (int)(sizeof(wide_text) / sizeof(wide_text[0]))
        );

        if (wide_length > 0 && WriteConsoleW(
            output_handle,
            wide_text,
            (DWORD)(wide_length - 1),
            &characters_written,
            NULL
        )) {
            return;
        }
    }

    /* Redirected native output stays UTF-8 for PowerShell/file consumers. */
    fputs(text, stdout);
}

static int logger_info_is_verbose_diagnostic(const char* format)
{
    static const char* prefixes[] = {
        "HTTP_ANALYSIS",
        "HTTP2_ANALYSIS",
        "TLS MITM ",
        "CONNECT request detected.",
        "CONNECT TLS policy decision.",
        "CONNECT TLS MITM mode selected",
        "resolved upstream",
        "dynamic TLS leaf certificate",
        "process metadata found.",
        "========== SESSION BEGIN",
        "========== SESSION END",
        "HTTP2 GOAWAY observed."
    };
    size_t i;

    if (format == NULL) {
        return 0;
    }

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t prefix_length = strlen(prefixes[i]);
        if (strncmp(format, prefixes[i], prefix_length) == 0) {
            return 1;
        }
    }

    return 0;
}

int logger_init(const char* log_file_path)
{
    char level[32];
    size_t level_size = 0;

    if (log_file_path == NULL) {
        return -1;
    }

    InitializeCriticalSection(&g_log_lock);
    g_logger_ready = 1;

    g_log_file = fopen(log_file_path, "a");
    if (g_log_file == NULL) {
        printf("[LOGGER] failed to open log file: %s\n", log_file_path);
        return -1;
    }

    printf("[LOGGER] log file opened: %s\n", log_file_path);

    level[0] = '\0';
    if (getenv_s(&level_size, level, sizeof(level), "LOCAL_DLP_LOG_LEVEL") == 0 &&
        level_size > 0 && _stricmp(level, "DEBUG") == 0) {
        g_debug_enabled = 1;
    }
    printf("[LOGGER] level: %s (set LOCAL_DLP_LOG_LEVEL=DEBUG for verbose diagnostics)\n",
        g_debug_enabled ? "DEBUG" : "INFO");

    return 0;
}

void logger_close(void)
{
    if (g_logger_ready) {
        EnterCriticalSection(&g_log_lock);
    }

    if (g_log_file != NULL) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    if (g_logger_ready) {
        LeaveCriticalSection(&g_log_lock);
        DeleteCriticalSection(&g_log_lock);
        g_logger_ready = 0;
    }
}

static void log_write(const char* level, const char* format, va_list args)
{
    time_t now;
    struct tm local_time;
    char time_buffer[32];
    char message_buffer[1024];
    char line_buffer[1280];

    if (g_thread_suppressed) {
        return;
    }

    time(&now);
    localtime_s(&local_time, &now);

    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &local_time);

    vsnprintf(message_buffer, sizeof(message_buffer), format, args);

    if (g_logger_ready) {
        EnterCriticalSection(&g_log_lock);
    }

    _snprintf_s(
        line_buffer,
        sizeof(line_buffer),
        _TRUNCATE,
        "[%s] [%s] %s\n",
        time_buffer,
        level,
        message_buffer
    );

    logger_write_console_utf8(line_buffer);

    if (g_log_file != NULL) {
        fputs(line_buffer, g_log_file);
        fflush(g_log_file);
    }

    if (g_logger_ready) {
        LeaveCriticalSection(&g_log_lock);
    }
}

void log_debug(const char* format, ...)
{
    va_list args;

    if (!g_debug_enabled) {
        return;
    }
    va_start(args, format);
    log_write("DEBUG", format, args);
    va_end(args);
}

void log_info(const char* format, ...)
{
    va_list args;

    if (logger_info_is_verbose_diagnostic(format) && !g_debug_enabled) {
        return;
    }

    va_start(args, format);
    log_write(logger_info_is_verbose_diagnostic(format) ? "DEBUG" : "INFO", format, args);
    va_end(args);
}

void log_warn(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_write("WARN", format, args);
    va_end(args);
}

void log_error(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_write("ERROR", format, args);
    va_end(args);
}

void log_security(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_write("SECURITY", format, args);
    va_end(args);
}

int logger_is_debug_enabled(void)
{
    return g_debug_enabled;
}

void logger_set_thread_suppressed(int suppressed)
{
    g_thread_suppressed = suppressed ? 1 : 0;
}
