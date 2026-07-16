#ifndef LOGGER_H
#define LOGGER_H

int logger_init(const char* log_file_path);
void logger_close(void);
int logger_is_debug_enabled(void);
void logger_set_thread_suppressed(int suppressed);

void log_debug(const char* format, ...);
void log_info(const char* format, ...);
void log_warn(const char* format, ...);
void log_error(const char* format, ...);
void log_security(const char* format, ...);

#endif
