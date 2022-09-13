#include "api/config.h"

#ifndef __USE_POSIX
#define __USE_POSIX
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>

#define SERVICE_NAME_LEN    16

typedef void (* serviceCallback_t)(void);

typedef enum {
    SERVICE_ID_CONTROL,
    SERVICE_ID_TELNET,
    SERVICE_ID_FTP,
} service_id_t;

typedef struct {
    serviceCallback_t   init;
    serviceCallback_t   deinit;
    pid_t               pid;
    const char          name[SERVICE_NAME_LEN];
} service_t;

static char * proc_name = NULL;

static service_t services[] = {
    [SERVICE_ID_CONTROL] = {
        .init   = NULL,
        .deinit = NULL,
        .pid    = NULL_PID,
        .name   = "control.service",
    },
    [SERVICE_ID_TELNET] = {
        .init   = NULL,
        .deinit = NULL,
        .pid    = NULL_PID,
        .name   = "telnet.service",
    },
    [SERVICE_ID_FTP] = {
        .init   = NULL,
        .deinit = NULL,
        .pid    = NULL_PID,
        .name   = "ftp.service",
    },
};

static void init_service(service_t * const restrict service) {
    if (service->pid == NULL_PID && service != &services[SERVICE_ID_CONTROL]) {
        const pid_t pid = fork();
        sys_assert(pid, NULL);

        if (pid == NULL_PID) {
            deinit_core();
            init_core(proc_name, service->name);

            service->init();
            exit(EXIT_SUCCESS);
        } else {
            service->pid = pid;
        }
    }
}

static void deinit_service(service_t * const restrict service) {
    if (service->pid != NULL_PID && service != &services[SERVICE_ID_CONTROL]) {
        const int result = kill(SIGTERM, service->pid);
        sys_assert(result, NULL);
    }
}

noreturn static void deinit_handler(unused const int code) {
    for (uint_fast8_t i = 0; i < ARRAY_LENGTH(services); i++) {
        service_t * const restrict service = services + i;

        if (service->pid != NULL_PID && service != &services[SERVICE_ID_CONTROL]) {
            kill(SIGTERM, service->pid);
        }
    }

    exit(EXIT_SUCCESS);
}

static void sigchild_handler(unused const int code) {
    while (true) {
        const pid_t pid = waitpid(INVALID_PID, NULL, WNOHANG);

        if (pid > MIN_VALID_PID) {
            for (uint_fast8_t i = 0; i < ARRAY_LENGTH(services); i++) {
                service_t * const restrict service = services + i;

                if (pid == service->pid) {
                    service->pid = NULL_PID;
                }
            }
        } else {
            break;
        }
    }
}

static void init_sighandler(void) {
    __sighandler_t result = signal(SIGSEGV, deinit_handler);
    sig_assert(result, NULL);

    result = signal(SIGTERM, deinit_handler);
    sig_assert(result, NULL);

    result = signal(SIGCHLD, sigchild_handler);
    sig_assert(result, NULL);
}

int main(const int argc, char * const * const argv) {
    init_core(NULL, argv[0]);
    argc_assert(argc, NULL);
    proc_name = argv[0];

    init_sighandler();
    load_config();
}
