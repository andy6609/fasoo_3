#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <process.h>
#include <Windows.h>

#include "command_thread.h"
#include "policy_engine.h"
#include "logger.h"

#define COMMAND_LINE_SIZE 128
#define COMMAND_POLICY_FILE_PATH_SIZE 260

static char g_policy_file_path[COMMAND_POLICY_FILE_PATH_SIZE];
static volatile LONG g_command_thread_started = 0;

static void print_command_help(void)
{
    log_info("command help: r=reload policy, h=help");
}

static unsigned __stdcall command_thread_proc(void* arg)
{
    char line[COMMAND_LINE_SIZE];

    (void)arg;

    log_info("command thread started. type 'r' to reload policy, 'h' for help.");
    print_command_help();

    while (1) {
        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), stdin) == NULL) {
            log_warn("command thread input closed");
            break;
        }

        if (line[0] == 'r' || line[0] == 'R') {
            log_info("reloading policy file...");

            if (policy_engine_reload(g_policy_file_path) == 0) {
                log_info("policy reload complete");
            }
            else {
                log_warn("policy reload failed");
            }
        }
        else if (line[0] == 'h' || line[0] == 'H' || line[0] == '?') {
            print_command_help();
        }
        else if (line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        else {
            log_warn("unknown command: %c", line[0]);
            print_command_help();
        }
    }

    InterlockedExchange(&g_command_thread_started, 0);

    log_info("command thread finished");

    return 0;
}

int command_thread_start(const char* policy_file_path)
{
    uintptr_t thread_handle;
    unsigned int thread_id;

    if (policy_file_path == NULL || policy_file_path[0] == '\0') {
        return -1;
    }

    if (InterlockedCompareExchange(&g_command_thread_started, 1, 0) != 0) {
        log_warn("command thread already started");
        return 0;
    }

    memset(g_policy_file_path, 0, sizeof(g_policy_file_path));
    strncpy_s(g_policy_file_path, sizeof(g_policy_file_path), policy_file_path, _TRUNCATE);

    thread_id = 0;

    thread_handle = _beginthreadex(
        NULL,
        0,
        command_thread_proc,
        NULL,
        0,
        &thread_id
    );

    if (thread_handle == 0) {
        InterlockedExchange(&g_command_thread_started, 0);
        return -1;
    }

    log_info("command thread created. thread_id=%u", thread_id);

    CloseHandle((HANDLE)thread_handle);

    return 0;
}