#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <Windows.h>

#include "logger.h"

static FILE* g_log_file = NULL;
static CRITICAL_SECTION g_log_lock;
static int g_logger_ready = 0;

int logger_init(const char* log_file_path)
{
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

    time(&now);
    localtime_s(&local_time, &now);

    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &local_time);

    vsnprintf(message_buffer, sizeof(message_buffer), format, args);

    if (g_logger_ready) {
        EnterCriticalSection(&g_log_lock);
    }

    printf("[%s] [%s] %s\n", time_buffer, level, message_buffer);

    if (g_log_file != NULL) {
        fprintf(g_log_file, "[%s] [%s] %s\n", time_buffer, level, message_buffer);
        fflush(g_log_file);
    }

    if (g_logger_ready) {
        LeaveCriticalSection(&g_log_lock);
    }
}

void log_debug(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_write("DEBUG", format, args);
    va_end(args);
}

void log_info(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_write("INFO", format, args);
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