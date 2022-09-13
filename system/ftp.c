#include "init.h"
#include "ftp.h"

#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/select.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <time.h>
#include <pwd.h>

#define FTP_SERVICE_NAME        "ftp.service"
#define FTP_ROOT_DIR            "/"
#define FTP_CURRENT_DIR         "."
#define FTP_PREVIOUS_DIR        ".."
#define FTP_DIRECTORY_DEFAULT   FTP_ROOT_DIR
#define FTP_MODE_DEFAULT        (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)
#define FTP_STOR_SIZE           (1024 * 1024)
#define FTP_BUFFER_SIZE         (64 * 1024)
#define FTP_LISTEN_SIZE         1
#ifndef EMUL
#define FTP_PORT_DEFAULT        21
#define FTP_DATA_PORT_DEFAULT   20
#else
#define FTP_PORT_DEFAULT        2121
#define FTP_DATA_PORT_DEFAULT   2120
#endif
#define FTP_CMD_LENGTH          5
#define FTP_DATA_TIMEOUT_SEC    0
#define FTP_DATA_TIMEOUT_USEC   (500 * 1000)
#define MAX_PATH_LENGTH         256
#define INVALID_RESULT          -1
#define INVALID_FD              -1

#define MAKE_CMD(cmd, wr_callback, data_rd_callback, data_wr_callback, status) \
    { cmd, wr_callback, data_rd_callback, data_wr_callback, status, sizeof(cmd) - 1 }

#define MAKE_STATUS_STR(code, str)                              \
    case STATUS_##code: return (status_str_t) {                 \
        #code " " str "\r\n", sizeof(#code " " str "\r\n") - 1  \
    }

#define ARRAY_LENGTH(arr) \
    (sizeof(arr) / sizeof(arr[0]))

typedef enum {
    STATUS_150,
    STATUS_200,
    STATUS_211,
    STATUS_215,
    STATUS_220,
    STATUS_226,
    STATUS_227,
    STATUS_230,
    STATUS_250,
    STATUS_257,
    STATUS_550,
} status_t;

typedef struct session session_t;
typedef int (* io_callback_t)(session_t * const restrict);

typedef struct session {
    struct session * next;
    io_callback_t wr_callback;
    io_callback_t rd_callback;
    io_callback_t data_wr_callback;
    io_callback_t data_rd_callback;
    char recv_arg[MAX_PATH_LENGTH];
    char directory[MAX_PATH_LENGTH];
    off_t file_offset;
    ssize_t file_size;
    int file_fd;
    int data_socket;
    int socket;
    status_t status;
} session_t;

typedef struct {
    char cmd[FTP_CMD_LENGTH];
    io_callback_t wr_callback;
    io_callback_t data_rd_callback;
    io_callback_t data_wr_callback;
    status_t status;
    uint_fast8_t cmd_len;
} command_t;

typedef struct {
    const char * str;
    int length;
} status_str_t;

uint16_t ftp_port = FTP_PORT_DEFAULT;
uint16_t ftp_data_port = FTP_DATA_PORT_DEFAULT;
static uint32_t ftp_addr = INADDR_ANY;
static char directory[MAX_PATH_LENGTH] = FTP_DIRECTORY_DEFAULT;
static session_t * sessions = NULL;
static session_t * data_session = NULL;
static struct timeval data_timeout = { 0, 0 };
static DIR * opened_dir = NULL;
static int master_fd = INVALID_FD;
static int data_fd = INVALID_FD;
static int client_fd = INVALID_FD;
static fd_set rdfdset = { 0 };
static fd_set wrfdset = { 0 };

static int recv_command(session_t * const restrict session);
static int send_response_simple(session_t * const restrict session);
static int send_response_feat(session_t * const restrict session);
static int send_response_pwd(session_t * const restrict session);
static int send_response_pasv(session_t * const restrict session);
static int send_response_list_data(session_t * const restrict session);
static int send_response_cwd(session_t * const restrict session);
static int send_response_cdup(session_t * const restrict session);
static int send_response_retr_data(session_t * const restrict session);
static int send_response_stor_data(session_t * const restrict session);

static const command_t commands[] = {
    MAKE_CMD("USER", send_response_simple, NULL, NULL, STATUS_230),
    MAKE_CMD("SYST", send_response_simple, NULL, NULL, STATUS_215),
    MAKE_CMD("FEAT", send_response_feat, NULL, NULL, STATUS_211),
    MAKE_CMD("PWD", send_response_pwd, NULL, NULL, STATUS_257),
    MAKE_CMD("TYPE", send_response_simple, NULL, NULL, STATUS_200),
    MAKE_CMD("PASV", send_response_pasv, NULL, NULL, STATUS_227),
    MAKE_CMD("LIST", send_response_simple, NULL, send_response_list_data, STATUS_150),
    MAKE_CMD("CWD", send_response_cwd, NULL, NULL, STATUS_250),
    MAKE_CMD("CDUP", send_response_cdup, NULL, NULL, STATUS_200),
    MAKE_CMD("RETR", send_response_simple, NULL, send_response_retr_data, STATUS_150),
    MAKE_CMD("STOR", send_response_simple, send_response_stor_data, NULL, STATUS_150),
};

static status_str_t get_status_str(const status_t status) {
    switch (status) {
        MAKE_STATUS_STR(150, "File status okay; about to open data connection.");
        MAKE_STATUS_STR(200, "Command okay.");
        MAKE_STATUS_STR(211, "System status, or system help reply.");
        MAKE_STATUS_STR(215, "UNIX Type: L8");
        MAKE_STATUS_STR(220, "Service ready for new user.");
        MAKE_STATUS_STR(226, "Closing data connection.");
        MAKE_STATUS_STR(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d).");
        MAKE_STATUS_STR(230, "User logged in, proceed.");
        MAKE_STATUS_STR(250, "Requested file action okay, completed.");
        MAKE_STATUS_STR(257, "\"%s\"");
        MAKE_STATUS_STR(550, "Requested action not taken. File unavailable (e.g., file not found, no access).");
    }

    return (status_str_t){ NULL, 0 };
}

static int recv_command(session_t * const restrict session) {
    char buffer[FTP_BUFFER_SIZE];
    const int result = recv(session->socket, buffer, sizeof(buffer), MSG_NOSIGNAL);
    user_return(result <= 0 && errno != EINTR, INVALID_RESULT);
    user_return(result < 0 && errno == EINTR, EXIT_SUCCESS);

    for (uint_fast8_t i = 0; i < ARRAY_LENGTH(commands); i++) {
        const command_t * const restrict command = commands + i;
        if (memcmp(buffer, command->cmd, command->cmd_len) == EXIT_SUCCESS) {
            int i = command->cmd_len + 1;
            char * restrict arg = session->recv_arg;

            while (i < result && buffer[i] != '\r') {
                *arg++ = buffer[i];
                i++;
            }

            *arg++ = '\0';

            session->rd_callback = NULL;
            session->wr_callback = command->wr_callback;
            session->data_rd_callback = command->data_rd_callback;
            session->data_wr_callback = command->data_wr_callback;
            session->status = command->status;

            return EXIT_SUCCESS;
        }
    }

    return INVALID_RESULT;
}

static int send_response_simple(session_t * const restrict session) {
    const status_str_t response = get_status_str(session->status);
    const int result = send(session->socket, response.str, response.length, MSG_NOSIGNAL);
    user_return(result != response.length, INVALID_RESULT);

    if (session->data_rd_callback == NULL && session->data_wr_callback == NULL) {
        session->rd_callback = recv_command;
    }

    session->wr_callback = NULL;
    return EXIT_SUCCESS;
}

static int send_response_feat(session_t * const restrict session) {
    const status_str_t response = get_status_str(session->status);
    char buffer[FTP_BUFFER_SIZE];
    int buffer_length = 0;

    memcpy(buffer + buffer_length, response.str, response.length);
    buffer_length += response.length;
    memcpy(buffer + buffer_length, response.str, response.length);
    buffer_length += response.length;

    const int result = send(session->socket, buffer, buffer_length, MSG_NOSIGNAL);
    user_return(result != buffer_length, INVALID_RESULT);

    session->rd_callback = recv_command;
    session->wr_callback = NULL;
    return EXIT_SUCCESS;
}

static int send_response_pwd(session_t * const restrict session) {
    char buffer[FTP_BUFFER_SIZE];
    const status_str_t response = get_status_str(session->status);
    int buffer_length = snprintf(buffer, sizeof(buffer), response.str, session->directory);

    const int result = send(session->socket, buffer, buffer_length, MSG_NOSIGNAL);
    user_return(result != buffer_length, INVALID_RESULT);

    session->rd_callback = recv_command;
    session->wr_callback = NULL;
    return EXIT_SUCCESS;
}

static int send_response_pasv(session_t * const restrict session) {
    if (data_session != NULL) {
        return EXIT_SUCCESS;
    }

    struct sockaddr_in sockaddr;
    socklen_t sockaddr_len = sizeof(sockaddr);
    int result = getsockname(session->socket, (struct sockaddr *)&sockaddr, &sockaddr_len);
    sys_return(result, INVALID_RESULT, NULL);

    const uint32_t real_addr = htonl(sockaddr.sin_addr.s_addr);
    const uint8_t * const restrict addr = (void *)&real_addr;
    const uint8_t * const restrict port = (void *)&ftp_data_port;
    const status_str_t response = get_status_str(session->status);

    char buffer[FTP_BUFFER_SIZE];
    const int buffer_length = snprintf(buffer, sizeof(buffer), response.str,
        addr[3], addr[2], addr[1], addr[0], port[1], port[0]);

    result = send(session->socket, buffer, buffer_length, MSG_NOSIGNAL);
    user_return(result != buffer_length, INVALID_RESULT);

    static const struct timeval add_timeout = {
        .tv_sec = FTP_DATA_TIMEOUT_SEC,
        .tv_usec = FTP_DATA_TIMEOUT_USEC,
    };

    result = gettimeofday(&data_timeout, NULL);
    sys_return(result, INVALID_RESULT, NULL);
    timeradd(&data_timeout, &add_timeout, &data_timeout);

    session->rd_callback = recv_command;
    session->wr_callback = NULL;
    data_session = session;
    return EXIT_SUCCESS;
}

static int send_response_list_data(session_t * const restrict session) {
    char buffer[FTP_BUFFER_SIZE];
    int buffer_length = 0;

    opened_dir = opendir(session->directory);
    mem_return(opened_dir, INVALID_RESULT);

    char path[MAX_PATH_LENGTH];
    const int path_length = strlen(session->directory);
    memcpy(path, session->directory, path_length);

    while (buffer_length < (int)(sizeof(buffer) - MAX_PATH_LENGTH)) {
        struct dirent * entry = readdir(opened_dir);
        mem_break(entry);

        if (strcmp(entry->d_name, FTP_CURRENT_DIR) == EXIT_SUCCESS ||
           (strcmp(entry->d_name, FTP_PREVIOUS_DIR) == EXIT_SUCCESS))
        {
            continue;
        }

        struct stat info;
        strcpy(path + path_length, entry->d_name);
        int result = stat(path, &info);
        sys_return(result, INVALID_RESULT, NULL);

        buffer[buffer_length++] = (info.st_mode & S_IFDIR ? 'd' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IRUSR ? 'r' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IWUSR ? 'w' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IXUSR ? 'x' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IRGRP ? 'r' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IWGRP ? 'w' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IXGRP ? 'x' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IROTH ? 'r' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IWOTH ? 'w' : '-');
        buffer[buffer_length++] = (info.st_mode & S_IXOTH ? 'x' : '-');

        struct passwd user_passwd;
        struct passwd group_passwd;
        struct passwd * passwd_ptr;
        char uid_buffer[MAX_PATH_LENGTH];

        result = getpwuid_r(info.st_uid, &user_passwd, uid_buffer, sizeof(uid_buffer), &passwd_ptr);
        sys_return(result, INVALID_RESULT, NULL);

        result = getpwuid_r(info.st_gid, &group_passwd, uid_buffer, sizeof(uid_buffer), &passwd_ptr);
        sys_return(result, INVALID_RESULT, NULL);

        char * buf = buffer + buffer_length;
        int size = sizeof(buffer) - buffer_length;
        buffer_length += snprintf(buf, size, " %u %s %s %lu",
            (unsigned)info.st_nlink, user_passwd.pw_name, group_passwd.pw_name, info.st_size);

        struct tm mod_time;
        struct tm * const time_result = gmtime_r(&info.st_mtime, &mod_time);
        mem_return(time_result, INVALID_RESULT);

        buf = buffer + buffer_length;
        size = sizeof(buffer) - buffer_length;
        buffer_length += strftime(buf, size, " %b %d %G", time_result);

        buf = buffer + buffer_length;
        size = sizeof(buffer) - buffer_length;
        buffer_length += snprintf(buf, size, " %s\r\n", entry->d_name);
    }

    int result = closedir(opened_dir);
    sys_return(result, INVALID_RESULT, NULL);
    opened_dir = NULL;

    result = send(session->data_socket, buffer, buffer_length, MSG_NOSIGNAL);
    user_return(result != buffer_length, INVALID_RESULT);

    result = close(session->data_socket);
    sys_return(result, INVALID_RESULT, NULL);
    session->data_socket = INVALID_FD;

    session->wr_callback = send_response_simple;
    session->data_wr_callback = NULL;
    session->status = STATUS_226;
    return EXIT_SUCCESS;
}

static int send_response_cwd(session_t * const restrict session) {
    char path[MAX_PATH_LENGTH];

    if (session->recv_arg[0] == '/') {
        strcpy(path, session->recv_arg);
    } else {
        int path_length = strlen(session->directory);
        memcpy(path, session->directory, path_length);
        strcpy(path + path_length, session->recv_arg);
    }

    struct stat info;
    status_str_t response;
    int result = stat(path, &info);

    if ((result == EXIT_SUCCESS) && (info.st_mode & S_IFDIR)) {
        int path_length = strlen(path);
        memcpy(session->directory, path, path_length);
        session->directory[path_length++] = '/';
        session->directory[path_length++] = '\0';
        response = get_status_str(session->status);
    } else {
        response = get_status_str(STATUS_550);
    }

    result = send(session->socket, response.str, response.length, MSG_NOSIGNAL);
    user_return(result != response.length, INVALID_RESULT);

    session->rd_callback = recv_command;
    session->wr_callback = NULL;
    return EXIT_SUCCESS;
}

static int send_response_cdup(session_t * const restrict session) {
    char path[MAX_PATH_LENGTH];
    int path_length = strlen(session->directory) - 1;
    memcpy(path, session->directory, path_length);

    while (path_length > 0 && path[path_length] != '/') {
        path_length--;
    }

    struct stat info;
    status_str_t response;
    path[path_length > 0 ? path_length : 1] = '\0';
    int result = stat(path, &info);

    if ((result == EXIT_SUCCESS) && (info.st_mode & S_IFDIR)) {
        memcpy(session->directory, path, path_length);
        session->directory[path_length++] = '/';
        session->directory[path_length++] = '\0';
        response = get_status_str(session->status);
    } else {
        response = get_status_str(STATUS_550);
    }

    result = send(session->socket, response.str, response.length, MSG_NOSIGNAL);
    user_return(result != response.length, INVALID_RESULT);

    session->rd_callback = recv_command;
    session->wr_callback = NULL;
    return EXIT_SUCCESS;
}

static int send_response_retr_data(session_t * const restrict session) {
    if (session->file_fd < 0) {
        char path[MAX_PATH_LENGTH];

        if (session->recv_arg[0] == '/') {
            strcpy(path, session->recv_arg);
        } else {
            int path_length = strlen(session->directory);
            memcpy(path, session->directory, path_length);
            strcpy(path + path_length, session->recv_arg);
        }

        const int file_fd = open(path, O_RDONLY);
        sys_return(file_fd, INVALID_FD, NULL);
        session->file_fd = file_fd;

        struct stat info;
        const int result = fstat(file_fd, &info);
        sys_return(result, INVALID_FD, NULL);

        session->file_size = info.st_size;
        session->file_offset = 0;
    }

    int result = sendfile(session->data_socket, session->file_fd,
        &session->file_offset, session->file_size - session->file_offset);
    sys_return(result, INVALID_RESULT, NULL);

    if (session->file_offset == session->file_size) {
        result = close(session->file_fd);
        sys_return(result, INVALID_RESULT, NULL);
        session->file_fd = INVALID_FD;

        result = close(session->data_socket);
        sys_return(result, INVALID_RESULT, NULL);
        session->data_socket = INVALID_FD;

        session->wr_callback = send_response_simple;
        session->data_wr_callback = NULL;
        session->status = STATUS_226;
    }

    return EXIT_SUCCESS;
}

static int send_response_stor_data(session_t * const restrict session) {
    if (session->file_fd < 0) {
        char path[MAX_PATH_LENGTH];

        if (session->recv_arg[0] == '/') {
            strcpy(path, session->recv_arg);
        } else {
            int path_length = strlen(session->directory);
            memcpy(path, session->directory, path_length);
            strcpy(path + path_length, session->recv_arg);
        }

        const int file_fd = creat(path, FTP_MODE_DEFAULT);
        sys_return(file_fd, INVALID_FD, NULL);
        session->file_fd = file_fd;
    }

    int result = sendfile(session->file_fd, session->data_socket, NULL, FTP_STOR_SIZE);
    if (result < 0) {
        if (errno != EINVAL) {
            sys_return(result, INVALID_RESULT, NULL);
        } else {
            result = close(session->file_fd);
            sys_return(result, INVALID_RESULT, NULL);
            session->file_fd = INVALID_FD;

            result = close(session->data_socket);
            sys_return(result, INVALID_RESULT, NULL);
            session->data_socket = INVALID_FD;

            session->wr_callback = send_response_simple;
            session->data_wr_callback = NULL;
            session->status = STATUS_226;
        }
    }

    return EXIT_SUCCESS;
}

static void real_free_session(session_t * const restrict session) {
    const int socket_fd = session->socket;
    const int data_socket_fd = session->data_socket;

    if (socket_fd >= 0) {
        close(socket_fd);
        FD_CLR(socket_fd, &rdfdset);
        FD_CLR(socket_fd, &wrfdset);
        session->socket = INVALID_FD;
    }

    if (data_socket_fd >= 0) {
        close(data_socket_fd);
        FD_CLR(data_socket_fd, &rdfdset);
        FD_CLR(data_socket_fd, &wrfdset);
        session->data_socket = INVALID_FD;
    }

    if (session->file_fd >= 0) {
        close(session->file_fd);
        session->file_fd = INVALID_FD;
    }

    if (socket_fd == maxfd || data_socket_fd == maxfd) {
        maxfd--;
    }

    if (socket_fd == maxfd || data_socket_fd == maxfd) {
        maxfd--;
    }

    if (data_session == session) {
        data_session = NULL;
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

    strcpy(session->directory, directory);
    session->wr_callback = send_response_simple;
    session->rd_callback = NULL;
    session->data_wr_callback = NULL;
    session->data_rd_callback = NULL;
    session->file_fd = INVALID_FD;
    session->data_socket = INVALID_FD;
    session->socket = socket_fd;
    session->status = STATUS_220;

    session->next = sessions;
    sessions = session;
}

static void init_socket(int * const restrict socket_ptr, const uint16_t port) {
    const int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sys_assert(socket_fd, NULL);
    *socket_ptr = socket_fd;

    if (maxfd < socket_fd) {
        maxfd = socket_fd;
    }

    struct sockaddr_in sockaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(ftp_addr),
    };

    int result = bind(socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    sys_assert(result, NULL);

    const int reuse_addr = true;
    result = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    sys_assert(result, NULL);

    result = listen(socket_fd, FTP_LISTEN_SIZE);
    sys_assert(result, NULL);
}

void deinit_ftp(void) {
    if (master_fd >= 0) {
        close(master_fd);
        master_fd = INVALID_FD;
    }

    if (client_fd >= 0) {
        close(client_fd);
        client_fd = INVALID_FD;
    }

    if (opened_dir != NULL) {
        closedir(opened_dir);
        opened_dir = NULL;
    }

    for (session_t * restrict session = sessions, * next; session != NULL; session = next) {
        next = session->next;
        real_free_session(session);
    }

    sessions = NULL;
}

void init_ftp(char * const proc_name) {
    const pid_t pid = do_fork(proc_name, FTP_SERVICE_NAME);
    user_return(pid != EXIT_SUCCESS, (void)pid);

    init_socket(&master_fd, ftp_port);
    init_socket(&data_fd, ftp_data_port);

    while (true) {
        FD_ZERO(&rdfdset);
        FD_ZERO(&wrfdset);
        FD_SET(master_fd, &rdfdset);

        if (data_session != NULL) {
            struct timeval cur_time;
            const int result = gettimeofday(&cur_time, NULL);
            sys_assert(result, NULL);

            if (timercmp(&cur_time, &data_timeout, <)) {
                FD_SET(data_fd, &rdfdset);
            } else {
                free_session(data_session);
            }
        }

        for (session_t * restrict session = sessions; session != NULL; session = session->next) {
            if (session->rd_callback != NULL) {
                FD_SET(session->socket, &rdfdset);
            }

            if (session->wr_callback != NULL) {
                FD_SET(session->socket, &wrfdset);
            }

            if (session->data_socket >= 0) {
                if (session->data_rd_callback != NULL) {
                    FD_SET(session->data_socket, &rdfdset);
                }

                if (session->data_wr_callback != NULL) {
                    FD_SET(session->data_socket, &wrfdset);
                }
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

        if (FD_ISSET(data_fd, &rdfdset)) {
            client_fd = accept(data_fd, NULL, NULL);
            sys_goto(client_fd, skip_data, NULL);

            if (maxfd < client_fd) {
                maxfd = client_fd;
            }

            data_session->data_socket = client_fd;
            data_session = NULL;
        skip_data:
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

            if (session->data_socket >= 0) {
                if (FD_ISSET(session->data_socket, &rdfdset)) {
                    result = session->data_rd_callback(session);
                    sys_goto(result, free_session, NULL);
                }
            }

            if (session->data_socket >= 0) {
                if (FD_ISSET(session->data_socket, &wrfdset)) {
                    result = session->data_wr_callback(session);
                    sys_goto(result, free_session, NULL);
                }
            }

            continue;
        free_session:
            free_session(session);
        }
    }
}
