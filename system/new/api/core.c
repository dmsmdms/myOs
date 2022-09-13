#include "api/core.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#define MAX_LOG_SIZE    256

static void syslog_print(const char * const file, const unsigned line, const int log_level,
                         const char * const msg, va_list args)
{
    char buffer[MAX_LOG_SIZE], * buf = buffer;
    buf += sprintf(buf, "%s:%u", file, line);

    if (errno != EXIT_SUCCESS) {
        *buf++ = ' ';
        buf += sprintf(buf, "errno - %s", strerror(errno));
    }

    if (msg != NULL) {
        *buf++ = ' ';
        buf += vsprintf(buf, msg, args);
    }

    *buf++ = '\n';
    *buf++ = '\0';

    syslog(log_level, "%s", buffer);
}

noreturn void _assert(const char * const file, const uint16_t line, const char * msg, ...) {
    va_list args;
    va_start(args, msg);

    syslog_print(file, line, LOG_ERR, msg, args);

    va_end(args);
    exit(EXIT_FAILURE);
}

void _info(const char * const file, const uint16_t line, const char * msg, ...) {
    va_list args;
    va_start(args, msg);

    syslog_print(file, line, LOG_INFO, msg, args);

    va_end(args);
}

void deinit_core(void) {
    closelog();
}

void init_core(char * const proc_name, const char * const name) {
    if (proc_name != NULL) {
        memset(proc_name, '\0', strlen(proc_name));
        strcpy(proc_name, name);
    }

    openlog(name, LOG_CONS, LOG_DAEMON);
    try_fclose(stderr);
}

void init_env(void) {

}
