#pragma once

#include <stdbool.h>
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#define sys_assert(result, msg, ...)                                \
    do {                                                            \
        if (result < 0) {                                           \
            _sys_assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
        }                                                           \
    } while(false)

#define mem_assert(ptr, msg, ...)                                   \
    do {                                                            \
        if (ptr == NULL) {                                          \
            _sys_assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
        }                                                           \
    } while(false)

#define sig_assert(result, msg, ...)                                \
    do {                                                            \
        if (result == SIG_ERR) {                                    \
            _sys_assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
        }                                                           \
    } while(false)

#define sys_goto(result, point, msg, ...)                           \
    do {                                                            \
        if (result < 0) {                                           \
            _sys_warning(__FILE__, __LINE__, msg, ##__VA_ARGS__);   \
            goto point;                                             \
        }                                                           \
    } while(false)

#define sys_return(result, value)                                   \
    do {                                                            \
        if (result < 0) {                                           \
            return value;                                           \
        }                                                           \
    } while(false)

#define mem_return(ptr, value)                                      \
    do {                                                            \
        if (ptr == NULL) {                                          \
            return value;                                           \
        }                                                           \
    } while(false)

#define user_return(cond, value)                                    \
    do {                                                            \
        if (cond) {                                                 \
            return value;                                           \
        }                                                           \
    } while(false)

#define sys_break(result)                                           \
    if (result < 0) {                                               \
        break;                                                      \
    } (void)result

#define mem_break(ptr)                                              \
    if (ptr == NULL) {                                              \
        break;                                                      \
    } (void)ptr

extern char * env[];

void _sys_assert(const char * const file, const unsigned line, const char * const msg, ...);
void _sys_warning(const char * const file, const unsigned line, const char * const msg, ...);
int do_fork(char * const proc_name, const char * const name);
