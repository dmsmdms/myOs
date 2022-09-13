#include "service.h"
#include "init.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

extern const uint8_t service_html_gz[];
extern const uint8_t service_css_gz[];
extern const uint8_t service_js_gz[];
extern const unsigned service_html_gz_len;
extern const unsigned service_css_gz_len;
extern const unsigned service_js_gz_len;

#define MONITOR_SERVICE_NAME    "monitor.service"
#ifndef EMUL
#define SERVICE_PORT_DEFAULT    80
#else
#define SERVICE_PORT_DEFAULT    8080
#endif
#define SERVICE_BUFFER_SIZE     1024
#define MAX_PATH_LENGHT         256
#define GET_CMD_TYPE            "GET"
#define POST_CMD_TYPE           "POST"
#define FILE_PATH_DEFAULT       "service.html"
#define SERVICE_LISTEN_SIZE     1
#define INVALID_RESULT          -1
#define INVALID_FD              -1

#define MAKE_CMD(cmd, wr_callback) \
    { cmd, wr_callback, sizeof(cmd) - 1 }

#define MAKE_FILE(name, data, type) \
    { name, data, &data##_len, type }

#define CASE_CODE_STR(code, str) \
    case code: return str

#define ARRAY_LENGTH(arr) \
    (sizeof(arr) / sizeof(arr[0]))

typedef enum {
    STATUS_200,
    STATUS_404,
} status_t;

typedef enum {
    MIME_TYPE_HTML,
    MIME_TYPE_CSS,
    MIME_TYPE_JS,
} mime_type_t;

typedef struct session session_t;
typedef int (* io_callback_t)(session_t * const restrict);

typedef struct session {
    struct session * next;
    io_callback_t rd_callback;
    io_callback_t wr_callback;
    char arg[MAX_PATH_LENGHT];
    off_t offset;
    size_t size;
    int socket;
    int file;
} session_t;

typedef struct {
    char cmd[SERVICE_BUFFER_SIZE];
    io_callback_t wr_callback;
    uint_fast8_t cmd_len;
} command_t;

typedef struct {
    char name[MAX_PATH_LENGHT];
    const uint8_t * data;
    const unsigned * size;
    mime_type_t type;
} file_t;

uint16_t service_port = SERVICE_PORT_DEFAULT;
static session_t * sessions = NULL;
static fd_set rdfdset = { 0 };
static fd_set wrfdset = { 0 };
static int master_fd = INVALID_FD;
static int client_fd = INVALID_FD;

static int send_info(session_t * const restrict session);
static int send_file(session_t * const restrict session);

static command_t commands[] = {
    MAKE_CMD("info", send_info),
};

static file_t files[] = {
    MAKE_FILE("service.html", service_html_gz, MIME_TYPE_HTML),
    MAKE_FILE("service.css", service_css_gz, MIME_TYPE_CSS),
    MAKE_FILE("service.js", service_js_gz, MIME_TYPE_JS),
};

static int recv_command(session_t * const restrict session) {
    char buffer[SERVICE_BUFFER_SIZE];
    int result = recv(session->socket, buffer, sizeof(buffer), MSG_NOSIGNAL);
    user_return(result <= 0 && errno != EINTR, INVALID_RESULT);
    user_return(result < 0 && errno == EINTR, EXIT_SUCCESS);

    if (strcmp(buffer, GET_CMD_TYPE) == EXIT_SUCCESS) {
        char * const buf = buffer + sizeof(GET_CMD_TYPE);
        result -= sizeof(GET_CMD_TYPE);

        char * const restrict end = memchr(buf, ' ', result);
        mem_return(end, INVALID_RESULT);
        *end = '\0';

        for (uint_fast8_t i = 0; i < ARRAY_LENGTH(commands); i++) {
            const command_t * const restrict command = commands + i;
            if (memcmp(buf, command->cmd, command->cmd_len) == EXIT_SUCCESS) {
                session->wr_callback = command->wr_callback;
                break;
            }
        }

        if (session->wr_callback == NULL) {
            if (strcmp(buf, "/") == EXIT_SUCCESS) {
                strcpy(session->arg, FILE_PATH_DEFAULT);
            } else {
                strncpy(session->arg, buf, sizeof(session->arg));
            }

            session->wr_callback = send_file;
        }

        session->rd_callback = NULL;
        return EXIT_SUCCESS;
    }

    return INVALID_RESULT;
}

static const char * get_status_str(const status_t status) {

}

static void make_header(char * const buffer, const unsigned size, const status_t status,
                        const unsigned content_length)
{

}

static int send_info(session_t * const restrict session) {

}

static int send_file(session_t * const restrict session) {
    const file_t * restrict file = NULL;
    char buffer[SERVICE_BUFFER_SIZE];

    for (uint_fast8_t i = 0; i < ARRAY_LENGTH(files); i++) {
        const file_t * const restrict tmp_file = files + i;

        if (strcmp(session->arg, tmp_file->name) == EXIT_SUCCESS) {
            file = tmp_file;
            break;
        }
    }

    if (file != NULL) {

    }
}

static void real_free_session(session_t * const restrict session) {
    const int socket = session->socket;
    const int file = session->file;

    if (socket >= 0) {
        close(socket);
        FD_CLR(socket, &rdfdset);
        FD_CLR(socket, &wrfdset);
        session->socket = INVALID_FD;
    }

    if (file >= 0) {
        close(file);
        session->file = INVALID_FD;
    }

    if (socket == maxfd) {
        maxfd--;
    }

    free(session);
}

static void free_session(session_t * const restrict cur_session) {
    session_t ** restrict last_session = &sessions;
    session_t * restrict session = sessions;

    while (session != NULL) {
        if (session == cur_session) {
            break;
        }

        last_session = &session->next;
        session = session->next;
    }

    if (session != NULL) {
        *last_session = session->next;
        real_free_session(session);
    }
}

static void make_new_session(const int socket_fd) {
    if (socket_fd > maxfd) {
        maxfd = socket_fd;
    }

    session_t * const restrict session = malloc(sizeof(session_t));
    mem_assert(session, NULL);

    session->wr_callback = NULL;
    session->rd_callback = recv_command;
    session->socket = socket_fd;
    session->file = INVALID_FD;

    session->next = sessions;
    sessions = session;
}

void deinit_service(void) {
    if (master_fd >= 0) {
        close(master_fd);
        master_fd = INVALID_FD;
    }

    for (session_t * restrict session = sessions, * next; session != NULL; session = next) {
        next = session->next;
        real_free_session(session);
    }

    sessions = NULL;
}

void init_service(char * const proc_name) {
    set_proc_name(proc_name, MONITOR_SERVICE_NAME);

    master_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sys_assert(master_fd, NULL);
    maxfd = master_fd;

    struct sockaddr_in sockaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(service_port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    int result = bind(master_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    sys_assert(result, NULL);

    const int reuse_addr = true;
    result = setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    sys_assert(result, NULL);

    result = listen(master_fd, SERVICE_LISTEN_SIZE);
    sys_assert(result, NULL);

    while (true) {
        FD_ZERO(&rdfdset);
        FD_ZERO(&wrfdset);
        FD_SET(master_fd, &rdfdset);

        for (session_t * restrict session = sessions; session != NULL; session = session->next) {
            if (session->rd_callback != NULL) {
                FD_SET(session->socket, &rdfdset);
            }

            if (session->wr_callback != NULL) {
                FD_SET(session->socket, &wrfdset);
            }
        }

        int result = select(maxfd + 1, &rdfdset, &wrfdset, NULL, NULL);
        if (result < 0 && errno != EINTR) {
            sys_assert(INVALID_RESULT, NULL);
        }

        if (FD_ISSET(master_fd, &rdfdset)) {
            client_fd = accept(master_fd, NULL, NULL);
            sys_goto(client_fd, skip_session, NULL);

            make_new_session(client_fd);
        skip_session:
            client_fd = INVALID_FD;
        }

        for (session_t * restrict session = sessions, * next; session != NULL; session = next) {
            next = session->next;

            if (FD_ISSET(session->socket, &rdfdset)) {
                result = session->rd_callback(session);
                sys_goto(result, free_session, NULL);
            }

            if (FD_ISSET(session->socket, &wrfdset)) {
                result = session->wr_callback(session);
                sys_goto(result, free_session, NULL);
            }

            continue;
        free_session:
            free_session(session);
        }
    }
}
