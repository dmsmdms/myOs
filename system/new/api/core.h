#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define packed              __attribute__((packed))
#define unused              __attribute__((unused))
#define noreturn            __attribute__((noreturn))
#define MAX_ARGS_COUNT      1
#define MIN_VALID_RESULT    0
#define MIN_VALID_PID       1
#define MIN_VALID_FD        0
#define NULL_PID            0
#define INVALID_RESULT      -1
#define INVALID_PID         -1
#define INVALID_FD          -1

#define ARRAY_LENGTH(arr) \
    (sizeof(arr) / sizeof(arr[0]))

#define argc_assert(argc, msg, ...)                         \
    if (argc > MAX_ARGS_COUNT) {                            \
        _assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
    } (void)(argc)

#define try_close(fd)           \
    if (fd >= MIN_VALID_FD) {   \
        close(fd);              \
        fd = INVALID_FD;        \
    } (void)(fd)

#define try_fclose(file)    \
    if (file != NULL) {     \
        fclose(file);       \
        file = NULL;        \
    } (void)(file)

#define hard_close(fd)                      \
    do {                                    \
        const int close_result = close(fd); \
        sys_assert(close_result, NULL);     \
        fd = INVALID_FD;                    \
    } while(false)

#define hard_fclose(file)                       \
    do {                                        \
        const int close_result = fclose(file);  \
        sys_assert(close_result, NULL);         \
        file = NULL;                            \
    } while(false)

#define sys_assert(result, msg, ...)                        \
    if (result < MIN_VALID_RESULT) {                        \
        _assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
    } (void)(result)

#define sig_assert(result, msg, ...)                        \
    if (result == SIG_ERR) {                                \
        _assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
    } (void)(result)

#define io_assert(result, size, msg, ...)                   \
    if (result != size) {                                   \
        _assert(__FILE__, __LINE__, msg, ##__VA_ARGS__);    \
    }  (void)(result)

#define sys_return_void(result, msg, ...)                   \
    if (result < MIN_VALID_RESULT) {                        \
        if (msg != NULL) {                                  \
            _info(__FILE__, __LINE__, msg, ##__VA_ARGS__);  \
        }                                                   \
        return;                                             \
    } (void)(result)

noreturn void _assert(const char * const file, const uint16_t line, const char * msg, ...);
void _info(const char * const file, const uint16_t line, const char * msg, ...);
void deinit_core(void);
void init_core(char * const proc_name, const char * const name);
